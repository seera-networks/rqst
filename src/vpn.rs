use crate::quic::*;
use bytes::BytesMut;
use pcap_file::pcap::PcapWriter;
use std::fs::{File, OpenOptions};
use std::os::windows::prelude::*;
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::net::windows::named_pipe;
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use windows::{Win32::Foundation::*, Win32::Storage::FileSystem::*, Win32::System::IO::*};
use winreg::enums::*;
use winreg::RegKey;

const TAP_WIN_IOCTL_SET_MEDIA_STATUS: u32 = 0x00000022 << 16 | 0 << 14 | 6 << 2 | 0;

pub fn get_tap_entries() -> std::io::Result<Vec<String>> {
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let net_adapter = hklm.open_subkey(
        "SYSTEM\\CurrentControlSet\\Control\\Class\\{4D36E972-E325-11CE-BFC1-08002BE10318}",
    )?;
    let tap_entries = net_adapter
        .enum_keys()
        .filter_map(|x| {
            if let Ok(name) = x {
                if let Ok(entry) = net_adapter.open_subkey(name) {
                    if let Ok(component_id) = entry.get_value::<String, &str>("ComponentId") {
                        if component_id == "root\\tap0901" {
                            if let Ok(instance_id) =
                                entry.get_value::<String, &str>("NetCfgInstanceId")
                            {
                                return Some(instance_id);
                            }
                        }
                    }
                }
            }
            None
        })
        .collect::<Vec<String>>();
    Ok(tap_entries)
}

pub fn open_tap(instance_id: &String) -> std::io::Result<std::fs::File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(false)
        .attributes(FILE_ATTRIBUTE_SYSTEM.0 | FILE_FLAG_OVERLAPPED.0)
        .open(format!("\\\\.\\Global\\{}.tap", instance_id))?;
    let mut info: [u32; 1] = [1; 1];
    let mut len: u32 = 0;
    unsafe {
        if DeviceIoControl(
            HANDLE(file.as_raw_handle() as isize),
            TAP_WIN_IOCTL_SET_MEDIA_STATUS,
            info.as_mut_ptr() as _,
            4,
            info.as_mut_ptr() as _,
            4,
            &mut len,
            std::ptr::null_mut(),
        )
        .as_bool()
        {
            return Ok(file);
        } else {
            return Err(std::io::Error::last_os_error());
        }
    }
}

pub async fn transfer(
    quic: QuicConnectionHandle,
    tap_entries: Arc<Mutex<Vec<String>>>,
    notify_shutdown: broadcast::Receiver<()>,
    notify_shutdown1: broadcast::Receiver<()>,
    shutdown_complete: mpsc::Sender<()>,
    enable_pktlog: bool,
    show_stats: bool,
) {
    let instance_id = tap_entries.lock().unwrap().pop();
    if instance_id.is_none() {
        error!(
            "No available tap I/F for ConnectionID: {:?}",
            quiche::ConnectionId::from_vec(quic.conn_id.clone())
        );
        quic.close().await.unwrap();
        return;
    }
    let instance_id = instance_id.unwrap();

    if let Ok(tap) = open_tap(&instance_id) {
        let tap = Arc::new(unsafe {
            named_pipe::NamedPipeClient::from_raw_handle(tap.as_raw_handle()).unwrap()
        });
        let pcap_writer = if enable_pktlog {
            let path = format!(
                "{}.pcap",
                SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH)
                    .unwrap()
                    .as_secs()
            );
            let file = OpenOptions::new()
                .write(true)
                .create(true)
                .open(path)
                .unwrap();

            let pcap_writer = PcapWriter::new(file).unwrap();
            Some(Arc::new(Mutex::new(pcap_writer)))
        } else {
            None
        };

        info!(
            "Transfer starts: ConnectionID: {:?}, Tap: {}",
            quiche::ConnectionId::from_vec(quic.conn_id.clone()),
            &instance_id
        );
        let quic1 = quic.clone();
        let quic2 = quic.clone();
        let tap1 = tap.clone();
        let pcap_writer1 = pcap_writer.clone();
        let shutdown_complete1 = shutdown_complete.clone();
        let mut task = tokio::spawn(async move {
            remote_to_local(quic, tap, pcap_writer, notify_shutdown, shutdown_complete).await;
        });
        let mut task1 = tokio::spawn(async move {
            local_to_remote(
                quic1,
                tap1,
                pcap_writer1,
                notify_shutdown1,
                shutdown_complete1,
            )
            .await;
        });
        let mut task_finished = false;
        let mut task1_finished = false;
        loop {
            tokio::select! {
                _ = &mut task, if !task_finished => {
                    task_finished = true;
                }
                _ = &mut task1, if !task1_finished => {
                    task1_finished = true;
                }
                _ = sleep(Duration::from_secs(1)), if show_stats => {
                    if let Ok(stats) = quic2.stats().await {
                        info!(
                            "lost: {}, rtt: {:?}, cwnd: {} bytes, delivery_rate: {:.3} Mbps",
                            stats.lost,
                            stats.rtt,
                            stats.cwnd,
                            stats.delivery_rate as f64 * 8.0 / (1024.0 * 1024.0)
                        );
                    }
                    if let Ok((front_len, queue_byte_size, queue_len)) = quic2.recv_dgram_info().await {
                        info!(
                            "front_len: {} bytes, queue_byte_size: {} bytes, queue_len: {} counts",
                            front_len.unwrap_or(0),
                            queue_byte_size,
                            queue_len
                        );
                    }
                }
            }
            if task_finished && task1_finished {
                break;
            }
        }
        info!("Transfer ends: Tap: {}", &instance_id);
    }
    tap_entries.lock().unwrap().push(instance_id);
}

async fn remote_to_local(
    quic: QuicConnectionHandle,
    tap: Arc<named_pipe::NamedPipeClient>,
    pcap_writer: Option<Arc<Mutex<PcapWriter<File>>>>,
    mut notify_shutdown: broadcast::Receiver<()>,
    _shutdown_complete: mpsc::Sender<()>,
) {
    'main: loop {
        tokio::select! {
            _ = quic.recv_dgram_ready() => {
                let ret = quic.recv_dgram_vectored(usize::MAX).await;
                match ret {
                    Ok(bufs) => {
                        tap.writable().await.unwrap();
                        for buf in bufs {
                            trace!("{:?} Recv dgram {} bytes", std::thread::current().id(), buf.len());
                            if let Some(pcap_writer) = &pcap_writer {
                                if let Ok(mut pcap_writer) = pcap_writer.lock() {
                                    let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                                    let ts_sec = time.as_secs().try_into().unwrap();
                                    let ts_nsec = time.subsec_nanos();
                                    let orig_len = buf.len().try_into().unwrap();
                                    pcap_writer.write(ts_sec, ts_nsec, &buf[..], orig_len).unwrap();
                                }
                            }
                            loop {
                                match tap.try_write(&buf[..]) {
                                    Ok(n) => {
                                        trace!("Write packet {} bytes", n);
                                        break;
                                    }
                                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                                        tap.writable().await.unwrap();
                                        continue;
                                    }
                                    Err(e) => {
                                        error!("Write failed {:?}", e);
                                        break 'main;
                                    }
                                }
                            }
                        }
                    }
                    Err(e) => {
                        error!("Recv dgram failed: {:?}", e);
                        break 'main;
                    }
                }
            },
            _ = notify_shutdown.recv() => {
                break 'main;
            },
        }
    }
}

async fn local_to_remote(
    quic: QuicConnectionHandle,
    tap: Arc<named_pipe::NamedPipeClient>,
    pcap_writer: Option<Arc<Mutex<PcapWriter<File>>>>,
    mut notify_shutdown: broadcast::Receiver<()>,
    _shutdown_complete: mpsc::Sender<()>,
) {
    'main: loop {
        tokio::select! {
            Ok(()) = tap.readable() => {
                loop {
                    let mut buf = BytesMut::with_capacity(1350);
                    buf.resize(1350, 0);
                    match tap.try_read(&mut buf[..]) {
                        Ok(n) => {
                            buf.truncate(n);
                            trace!("{:?} Read packet {} bytes", std::thread::current().id(), n);
                            if let Some(pcap_writer) = &pcap_writer {
                                if let Ok(mut pcap_writer) = pcap_writer.lock() {
                                    let time = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap();
                                    let ts_sec = time.as_secs().try_into().unwrap();
                                    let ts_nsec = time.subsec_nanos();
                                    let orig_len = buf.len().try_into().unwrap();
                                    pcap_writer.write(ts_sec, ts_nsec, &buf[..], orig_len).unwrap();
                                }
                            }
                            let buf = buf.freeze();
                            match quic.send_dgram(&buf).await {
                                Ok(_) => {
                                    trace!("Send dgram {} bytes", n);
                                }
                                Err(e) => {
                                    error!("Send dgram failed: {:?}", e);
                                    break 'main;
                                }
                            }
                        }
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                            break;
                        }
                        Err(e) => {
                            error!("Read failed {:?}", e);
                            break 'main;
                        }
                    }
                }
            },
            _ = notify_shutdown.recv() => {
                break 'main;
            },
        }
    }
}
