use crate::config::*;
use crate::quic::*;
use crate::tap::Tap;
use anyhow::{anyhow, Context};
use bytes::{BufMut, BytesMut};
use etherparse::{IpHeader, PacketHeaders};
use pcap_file::pcap::PcapWriter;
use serde::{Deserialize, Serialize};
use socket2::Socket;
use std::collections::BTreeMap;
use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::{broadcast, mpsc};
use tokio::time::sleep;

#[derive(Debug, Serialize, Deserialize)]
pub struct TunnelMsg {
    pub dscp: u8,
    pub group_id: u64,
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
    Err(String),
}

pub struct ControlManager {
    next_msg_seq: u64,
    request_buf: BTreeMap<u64, Vec<u8>>,
    is_server: bool,
}

impl ControlManager {
    pub fn new(is_server: bool) -> Self {
        ControlManager {
            next_msg_seq: 0,
            request_buf: BTreeMap::new(),
            is_server,
        }
    }

    pub async fn send_start_request(&mut self, conn: &QuicConnectionHandle) -> anyhow::Result<u64> {
        if self.is_server {
            return Err(anyhow!("Sending Start not allowed by server"));
        }
        let msg = serde_json::to_string(&RequestMsg::Start).context("serialize message")?;

        self.send_request(conn, &msg)
            .await
            .context("sending request")
    }

    pub async fn send_stop_request(&mut self, conn: &QuicConnectionHandle) -> anyhow::Result<u64> {
        if self.is_server {
            return Err(anyhow!("Sending Stop not allowed by server"));
        }
        let msg = serde_json::to_string(&RequestMsg::Stop).context("serialize message")?;
        self.send_request(conn, &msg)
            .await
            .context("sending request")
    }

    async fn send_request(
        &mut self,
        conn: &QuicConnectionHandle,
        msg: &String,
    ) -> anyhow::Result<u64> {
        let seq = self.next_msg_seq;
        let stream_id = if !self.is_server {
            // Client -> Server
            seq.saturating_mul(4)
        } else {
            // Server -> Client
            seq.saturating_mul(4).saturating_add(1)
        };
        self.next_msg_seq = seq.saturating_add(1);

        let mut buf = BytesMut::new();
        buf.put(msg.as_bytes());
        conn.send_stream(&buf.freeze(), stream_id, true)
            .await
            .map_err(|e| anyhow!(e))
            .context("send_stream()")?;

        Ok(seq)
    }

    pub async fn send_response_ok(
        &self,
        conn: &QuicConnectionHandle,
        seq: u64,
    ) -> anyhow::Result<()> {
        let msg = serde_json::to_string(&ResponseMsg::Ok).context("serialize message")?;

        self.send_response(conn, seq, &msg)
            .await
            .context("sending response")
    }

    pub async fn send_response_err(
        &self,
        conn: &QuicConnectionHandle,
        seq: u64,
        reason: &str,
    ) -> anyhow::Result<()> {
        let msg = serde_json::to_string(&ResponseMsg::Err(reason.to_string()))
            .context("serialize message")?;

        self.send_response(conn, seq, &msg)
            .await
            .context("sending response")
    }

    async fn send_response(
        &self,
        conn: &QuicConnectionHandle,
        seq: u64,
        msg: &String,
    ) -> anyhow::Result<()> {
        let stream_id = if self.is_server {
            // Server -> Client
            seq.saturating_mul(4)
        } else {
            // Client -> Server
            seq.saturating_mul(4).saturating_add(1)
        };

        let mut buf = BytesMut::new();
        buf.put(msg.as_bytes());
        conn.send_stream(&buf.freeze(), stream_id, true)
            .await
            .map_err(|e| anyhow!(e))
            .context("send_stream()")?;
        Ok(())
    }

    pub async fn recv_request(
        &mut self,
        quic: &QuicConnectionHandle,
        stream_id: u64,
    ) -> anyhow::Result<Option<(u64, RequestMsg)>> {
        let seq = match (stream_id & 0x03, self.is_server) {
            (0x00, true) | (0x01, false) => {
                if self.is_server {
                    stream_id.saturating_div(4)
                } else {
                    stream_id.saturating_sub(1).saturating_div(4)
                }
            }
            _ => {
                return Err(anyhow!("Invalid stream: {}", stream_id));
            }
        };

        let (buf, fin) = quic
            .recv_stream(stream_id)
            .await
            .map_err(|e| anyhow!(e))
            .with_context(|| format!("recv_stream() for {} stream", stream_id))?
            .ok_or(anyhow!("Not readable stream"))?;

        let storage = self.request_buf.entry(seq).or_insert(Vec::new());

        storage.put(buf);

        if fin {
            let msg: RequestMsg =
                serde_json::from_slice(&storage[..]).context("deserialize message")?;
            self.request_buf.remove(&seq);
            Ok(Some((seq, msg)))
        } else {
            Ok(None)
        }
    }

    pub async fn recv_response(
        &mut self,
        conn: &QuicConnectionHandle,
        seq: u64,
    ) -> anyhow::Result<ResponseMsg> {
        let stream_id = if !self.is_server {
            // Server -> Client
            seq.saturating_mul(4)
        } else {
            // Client -> Server
            seq.saturating_mul(4).saturating_add(1)
        };

        let mut storage = Vec::new();

        loop {
            let (buf, fin) = conn
                .recv_stream(stream_id)
                .await
                .map_err(|e| anyhow!(e))
                .with_context(|| format!("recv_stream() for {} stream", stream_id))?
                .ok_or(anyhow!("Not readable stream"))?;

            storage.put(buf);

            if fin {
                let msg: ResponseMsg =
                    serde_json::from_slice(&storage[..]).context("deserialize message")?;
                return Ok(msg);
            }
        }
    }
}

pub struct PathManager {
    conn: QuicConnectionHandle,
    client_config: ClientConfig,
    path_groups: BTreeMap<String, u64>,
    peer_addr: Option<SocketAddr>,
    local_addrs: BTreeMap<SocketAddr, HashSet<u64>>,
}

impl PathManager {
    pub fn new(conn: QuicConnectionHandle, config_toml: &str) -> anyhow::Result<Self> {
        let client_config: ClientConfig =
            toml::from_str(config_toml).context("parse client config")?;

        let mut path_groups = BTreeMap::new();
        for (i, path_group) in client_config.path_groups.iter().enumerate() {
            path_groups.insert(path_group.name().to_string(), i as u64 + 1);
        }
        Ok(PathManager {
            conn,
            client_config,
            path_groups,
            peer_addr: None,
            local_addrs: BTreeMap::new(),
        })
    }

    pub fn register_local_addr(
        &mut self,
        local_addr: SocketAddr,
        metered: bool,
    ) -> bool {
        if self.local_addrs.contains_key(&local_addr) {
            return false;
        }
        let mut group_ids = HashSet::new();
        for path_group in &self.client_config.path_groups {
            let name = match (path_group, local_addr.ip(), metered) {
                (PathGroup::Ipv4Net(Ipv4NetPathGroup { ipnet, .. }), IpAddr::V4(ipaddr), _) => {
                    if ipnet.contains(&ipaddr) {
                        Some(path_group.name().to_string())
                    } else {
                        None
                    }
                }
                (PathGroup::IfType(IfTypePathGroup::Metred { .. }), _, true) => {
                    Some(path_group.name().to_string())
                }
                (PathGroup::IfType(IfTypePathGroup::NotMetred { .. }), _, false) => {
                    Some(path_group.name().to_string())
                }
                _ => None,
            };
            if let Some(name) = name {
                let group_id = self
                    .path_groups
                    .get(&name)
                    .copied()
                    .expect("old path_groups?");
                group_ids.insert(group_id);
            }
        }
        self.local_addrs.insert(local_addr, group_ids);
        true
    }

    pub fn register_peer_addr(
        &mut self,
        peer_addr: SocketAddr,
    ) -> bool {
        if self.peer_addr.is_some() {
            return false;
        }
        self.peer_addr = Some(peer_addr);
        true
    }

    pub async fn probe(&self) -> anyhow::Result<usize> {
        if self.peer_addr.is_none() {
            return Err(anyhow!("peer_addr not set"));
        }

        let peer_addr = self.peer_addr.as_ref().unwrap();

        let paths = self.local_addrs
            .keys()
            .map(|local_addr| {
                (*local_addr, peer_addr.clone())
            })
            .collect::<HashSet<(SocketAddr, SocketAddr)>>();

        let paths1 = self.conn
            .path_stats().await
            .map_err(|e| anyhow!(e))
            .context("path_stats()")?
            .into_iter()
            .filter_map(|stats|{
                if stats.validation_state != quiche::PathValidationState::Unknown {
                    Some((stats.local_addr, stats.peer_addr))
                } else {
                    None
                }
            })
            .collect::<HashSet<(SocketAddr, SocketAddr)>>();

        let mut count: usize = 0;
        for (local_addr, peer_addr) in paths.difference(&paths1) {
            let seq = self.conn
                .probe_path(*local_addr, *peer_addr).await
                .map_err(|e| anyhow!(e))
                .context("probe_path()")?;
            info!("Probing ({}, {}) with seq={}", local_addr, peer_addr, seq);
            count = count.saturating_add(1);
        }
        Ok(count)
    }

    pub async fn set_group(&self, local_addr: SocketAddr) -> anyhow::Result<usize> {
        if self.peer_addr.is_none() {
            return Err(anyhow!("peer_addr not set"));
        }

        let peer_addr = self.peer_addr.as_ref().unwrap();

        let group_ids = self.local_addrs
            .iter()
            .find(|(local_addr1, _)| {
                **local_addr1 == local_addr
            })
            .map(|(_, group_ids)| group_ids)
            .ok_or(anyhow!("local_addr"))?;

        let mut count: usize = 0;

        for group_id in group_ids {
            self.conn
                .insert_group(local_addr, *peer_addr, *group_id).await
                .map_err(|e| anyhow!(e))
                .context("insert_group()")?;
            info!("Inserting ({}, {}) into group {}", local_addr, *peer_addr, *group_id);
            count = count.saturating_add(1);
        }
        Ok(count)
    }
}

pub async fn transfer(
    quic: QuicConnectionHandle,
    notify_shutdown: broadcast::Receiver<()>,
    notify_shutdown1: broadcast::Receiver<()>,
    shutdown_complete: mpsc::Sender<()>,
    enable_pktlog: bool,
    show_stats: bool,
) -> anyhow::Result<()> {
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
    Ok(())
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
) -> anyhow::Result<()> {
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
                        let frame = PacketHeaders::from_ethernet_slice(&buf[..])
                            .context("parse ether frame")?;
                        match frame.ip {
                            Some(IpHeader::Version4(hdr, _)) => {
                                match hdr.differentiated_services_code_point {
                                    40 => {
                                        info!("Zoom Video");
                                    }
                                    56 => {
                                        info!("Zoom Audio");
                                    }
                                    _ => {}
                                }
                            }
                            Some(IpHeader::Version6(hdr, _)) => {
                                if hdr.traffic_class != 0 {
                                    info!("{:?}", hdr);
                                }
                            }
                            _ => {}
                        }
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
    Ok(())
}
