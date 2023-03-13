use crate::quic::*;
use crate::tap::Tap;
use bytes::{Bytes, BytesMut, Buf, BufMut};
use pcap_file::pcap::PcapWriter;
use std::fs::{File, OpenOptions};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use std::collections::{BTreeMap, btree_map};
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;
use serde::{Deserialize, Serialize};
use anyhow::anyhow;


#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelMsg {
    dscp: u8,
    group_id: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum RequestMsg {
    Start,
    Tunnel(TunnelMsg),
    Stop,
}

#[derive(Debug, Serialize, Deserialize)]
pub enum ResponseMsg {
    Ok,
    Err(String)
}

#[derive(Debug, Serialize, Deserialize)]
pub enum Message {
    Request(RequestMsg),
    Response(ResponseMsg),
}

pub struct ControlManager {
    next_msg_seq: u64,
    request_buf: BTreeMap<u64, Vec<u8>>,
    response_buf: BTreeMap<u64, Vec<u8>>,
    is_server: bool,
}

impl ControlManager {
    pub fn new(is_server: bool) -> Self {
        ControlManager {
            next_msg_seq: 0,
            request_buf: BTreeMap::new(),
            response_buf: BTreeMap::new(),
            is_server,
        }
    }

    pub async fn send_start(&mut self, quic: &QuicConnectionHandle) -> anyhow::Result<()> {
        if self.is_server {
            return(Err(anyhow!("Sending Start not allowed by server")));
        }
        let j = serde_json::to_string(&RequestMsg::Start)?;

        let mut buf = BytesMut::new();
        buf.put(j.as_bytes());
        let stream_id = self.next_msg_seq.saturating_mul(4);
        self.next_msg_seq = self.next_msg_seq.saturating_add(1);
        quic.send_stream(&buf.freeze(), stream_id, true).await.map_err(|e| anyhow!(e))?;
        Ok(())
    }

    pub async fn recv_message(&mut self, quic: &QuicConnectionHandle, stream_id: u64) -> anyhow::Result<Option<(u64, Message)>> {
        let (buf, fin) = quic.recv_stream(stream_id).await
            .map_err(|e| anyhow!(e))?
            .ok_or(anyhow!("Not readable stream"))?;

        let (seq, mut entry) = match (stream_id & 0x03, self.is_server) {
            (0x00, true) | (0x01, false) => {
                let seq = if self.is_server {
                    stream_id.saturating_div(4)
                } else {
                    stream_id.saturating_sub(1).saturating_div(4)
                };
                let storage = self.request_buf
                    .entry(seq)
                    .or_insert(Vec::new());
                storage.put(buf);
                let entry = self.request_buf.entry(seq);
                (seq, entry)
            },
            (0x00, false) | (0x01, true) => {
                let seq = if self.is_server {
                    stream_id.saturating_div(4)
                } else {
                    stream_id.saturating_sub(1).saturating_div(4)
                };
                let storage = self.response_buf
                    .entry(seq)
                    .or_insert(Vec::new());
                storage.put(buf);
                let entry = self.response_buf.entry(seq);
                (seq, entry)
            },
            _ => {
                return Err(anyhow!("Invalid stream: {}", stream_id));
            }
        };

        if fin {
            if let btree_map::Entry::Occupied(entry) = entry {
                let storage = entry.get();
                let msg: Message = serde_json::from_slice(&storage[..])?;
                entry.remove();
                Ok(Some((seq, msg)))
            } else {
                unreachable!()
            }
        } else {
            Ok(None)
        }
    }
}


pub async fn transfer(
    quic: QuicConnectionHandle,
    notify_shutdown: broadcast::Receiver<()>,
    notify_shutdown1: broadcast::Receiver<()>,
    shutdown_complete: mpsc::Sender<()>,
    enable_pktlog: bool,
    show_stats: bool,
) {
    if let Ok(tap) = Tap::new() {
        let tap = Arc::new(tap);
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
            "Transfer starts: ConnectionHandle: {}, Tap: {:?}",
            quic.conn_handle, &tap
        );
        let quic1 = quic.clone();
        let quic2 = quic.clone();
        let tap1 = tap.clone();
        let tap2 = tap.clone();
        let pcap_writer1 = pcap_writer.clone();
        let shutdown_complete1 = shutdown_complete.clone();
        let mut task = tokio::spawn(async move {
            remote_to_local(quic, tap1, pcap_writer, notify_shutdown, shutdown_complete).await;
        });
        let mut task1 = tokio::spawn(async move {
            local_to_remote(
                quic1,
                tap2,
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
                        info!("lost: {}", stats.lost);
                    }
                    if let Ok(paths) = quic2.path_stats().await {
                        for stats in paths {
                            info!("local_addr: {}, peer_addr: {}, rtt: {:?}, cwnd: {} bytes, delivery_rate: {:.3} Mbps",
                                stats.local_addr,
                                stats.peer_addr,
                                stats.rtt,
                                stats.cwnd,
                                stats.delivery_rate as f64 * 8.0 / (1024.0 * 1024.0)
                            );
                        }
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
        info!("Transfer ends: Tap: {:?}", &tap);
    }
}

async fn remote_to_local(
    quic: QuicConnectionHandle,
    tap: Arc<Tap>,
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
                            match tap.write(&buf[..]).await {
                                Ok(n) => {
                                    trace!("Write packet {} bytes", n);
                                }
                                Err(e) => {
                                    error!("Write failed {:?}", e);
                                    break 'main;
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
    tap: Arc<Tap>,
    pcap_writer: Option<Arc<Mutex<PcapWriter<File>>>>,
    mut notify_shutdown: broadcast::Receiver<()>,
    _shutdown_complete: mpsc::Sender<()>,
) {
    'main: loop {
        let mut buf = BytesMut::with_capacity(1350);
        buf.resize(1350, 0);
        tokio::select! {
            res = tap.read(&mut buf[..]) => {
                match res {
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
                        match quic.send_dgram(&buf, 0).await {
                            Ok(_) => {
                                trace!("Send dgram {} bytes", n);
                            }
                            Err(e) => {
                                error!("Send dgram failed: {:?}", e);
                                break 'main;
                            }
                        }
                    }
                    Err(e) => {
                        error!("Read failed {:?}", e);
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
