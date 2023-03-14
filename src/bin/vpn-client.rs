use anyhow::{anyhow, Context};
use flexi_logger::{detailed_format, FileSpec, Logger, WriteMode};
use log::{error, info};
use rqst::config::*;
use rqst::quic::*;
use rqst::vpn::*;
use std::collections::HashMap;
use std::env;
use std::io::prelude::*;
use std::path::PathBuf;
use tokio::sync::{broadcast, mpsc};
use tokio::task::JoinSet;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cert_default_path = std::env::current_exe()
        .unwrap()
        .with_file_name("client.crt");
    let key_default_path = std::env::current_exe()
        .unwrap()
        .with_file_name("client.key");
    let ca_default_path = std::env::current_exe().unwrap().with_file_name("ca.crt");

    let log_default_path = FileSpec::default()
        .directory(std::env::current_exe().unwrap().parent().unwrap())
        .as_pathbuf(None);

    let config_default_path = std::env::current_exe().unwrap().with_file_name("rqst.toml");

    let matches = clap::command!()
        .propagate_version(true)
        .subcommand_required(false)
        .arg_required_else_help(false)
        .arg(clap::arg!(<URL>).help("Url to connect").required(true))
        .arg(clap::arg!(-d - -disable_verify).help("Disable to verify the server certificate"))
        .arg(clap::arg!(-v - -verbose).help("Print logs to Stderr"))
        .arg(clap::arg!(-p - -pktlog).help("Write packets to a pcap file"))
        .arg(
            clap::arg!(--cert <file>)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .default_value(cert_default_path.to_str().unwrap())
                .help("TLS certificate path"),
        )
        .arg(
            clap::arg!(--key <file>)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .default_value(key_default_path.to_str().unwrap())
                .help("TLS key path"),
        )
        .arg(
            clap::arg!(--ca <file>)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .default_value(ca_default_path.to_str().unwrap())
                .help("CA certificate path"),
        )
        .arg(
            clap::arg!(--log <file>)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .default_value(log_default_path.to_str().unwrap())
                .help("log path"),
        )
        .arg(
            clap::arg!(--config <file>)
                .required(false)
                .value_parser(clap::value_parser!(PathBuf))
                .default_value(config_default_path.to_str().unwrap())
                .help("config path"),
        )
        .get_matches();

    let mut log_path = std::env::current_dir().unwrap();
    log_path.push(
        matches
            .get_one::<PathBuf>("log")
            .ok_or(anyhow!("log not provided"))?,
    );
    let logger = Logger::try_with_env_or_str("info")?
        .write_mode(WriteMode::BufferAndFlush)
        .format(detailed_format);
    let logger = if matches.is_present("verbose") {
        logger.log_to_stderr()
    } else {
        logger.log_to_file(FileSpec::try_from(log_path)?)
    };
    let _logger_handle = logger.start()?;

    if let Err(e) = do_service(&matches).await {
        error!("{:?}", e);
    }
    Ok(())
}

async fn do_service(matches: &clap::ArgMatches) -> anyhow::Result<()> {
    let url = matches.value_of("URL").unwrap();
    let url = url::Url::parse(url).unwrap();

    let mut config = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

    if matches.is_present("disable_verify") {
        config.verify_peer(false);
    } else {
        config
            .load_verify_locations_from_file(
                matches
                    .get_one::<PathBuf>("ca")
                    .ok_or(anyhow!("ca's path not provided"))?
                    .to_str()
                    .ok_or(anyhow!("ca's path includes non-UTF-8"))?,
            )
            .context("load CA cert file")?;
        config.verify_peer(true);
    }

    config
        .load_cert_chain_from_pem_file(
            matches
                .get_one::<PathBuf>("cert")
                .ok_or(anyhow!("cert's path not provided"))?
                .to_str()
                .ok_or(anyhow!("cert's path includes non-UTF-8"))?,
        )
        .context("load cert file")?;
    config
        .load_priv_key_from_pem_file(
            matches
                .get_one::<PathBuf>("key")
                .ok_or(anyhow!("key's path not provided"))?
                .to_str()
                .ok_or(anyhow!("key's path includes non-UTF-8"))?,
        )
        .context("load key file")?;

    config.set_application_protos(&[b"vpn"])?;

    config.set_max_idle_timeout(0);
    config.set_max_recv_udp_payload_size(1350);
    config.set_max_send_udp_payload_size(1350);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    config.enable_early_data();
    config.enable_dgram(true, 1000, 1000);
    config.set_multipath(true);

    let mut keylog = None;

    if let Some(keylog_path) = env::var_os("SSLKEYLOGFILE") {
        let file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(keylog_path)?;
        keylog = Some(file);
        config.log_keys();
    }

    let mut file = std::fs::OpenOptions::new()
        .read(true)
        .open(
            matches
                .get_one::<PathBuf>("config")
                .ok_or(anyhow!("config's path not provided"))?
                .to_str()
                .ok_or(anyhow!("config's path includes non-UTF-8"))?,
        )
        .context("open config file")?;

    let mut config_toml = String::new();
    file.read_to_string(&mut config_toml)
        .context("read from toml file")?;
    let client_config: ClientConfig =
        toml::from_str(&config_toml).context("parse client config")?;

    let cpus = num_cpus::get();
    info!("logical cores: {}", cpus);

    let (notify_shutdown_tx, _) = broadcast::channel(1);
    let (shutdown_complete_tx, mut shutdown_complete_rx) = mpsc::channel(1);

    let quic = QuicHandle::new(
        config,
        keylog,
        quiche::MAX_CONN_ID_LEN,
        false,
        shutdown_complete_tx.clone(),
    );

    info!("Connecting to {}", &url);
    let conn = tokio::select! {
        res = quic.connect(url) => {
            let conn = res.map_err(|e| anyhow!(e)).context("connect()")?;
            info!("Connection established: {}", conn.conn_handle);
            conn
        },
        _ = tokio::signal::ctrl_c() => {
            info!("Control C signaled");
            drop(quic);
            drop(shutdown_complete_tx);
            let _ = shutdown_complete_rx.recv().await;
            return Ok(());
        },
    };

    let mut set = JoinSet::new();
    let mut pathmng = PathManager::new(conn.clone(), client_config.clone());

    let paths = conn
        .path_stats()
        .await
        .map_err(|e| anyhow!(e))
        .context("path_stats()")?;

    assert_eq!(paths.len(), 1);
    let mut local_addr = paths[0].local_addr;
    let peer_addr = paths[0].peer_addr;

    pathmng.register_local_addr(local_addr, false);
    pathmng.register_peer_addr(peer_addr);

    pathmng
        .set_group(local_addr)
        .await
        .context("insert path into group")?;

    let mut tunnels = HashMap::new();

    client_config
        .tunnels
        .iter()
        .filter_map(|tunnel| {
            if let Some(group_id) = pathmng.names_to_path_groups.get(&tunnel.path_group) {
                Some((tunnel.dscp, *group_id))
            } else {
                None
            }
        })
        .for_each(|(dscp, group_id)| {
            tunnels.insert(dscp, group_id);
        });

    let mut tunnelmng = TunnelManager::new(conn.clone(), tunnels.clone());

    let available = tunnelmng
        .available()
        .await
        .context("get available tunnels")?;

    info!("tunnels: {:?}, available: {:?}", tunnels, available);

    {
        local_addr.set_port(local_addr.port() + 1);

        pathmng.register_local_addr(local_addr, true);

        pathmng.probe().await.context("probing new path")?;
    }

    let mut ctrlmng = ControlManager::new(false);
    let mut running_vpn = false;

    for (dscp, group_id) in &tunnels {
        notify_tunnel(&conn,
            &mut ctrlmng,
            *dscp,
            *group_id
        )
            .await
            .context("notify tunnel")?;
    }
    if !running_vpn {
        start_vpn(&conn,
            &mut ctrlmng,
            &mut set,
            &notify_shutdown_tx,
            shutdown_complete_tx.clone(),
            matches.is_present("pktlog")
        )
            .await
            .context("start vpn")?;
        running_vpn = true;
    }

    loop {
        tokio::select! {
            res = conn.path_event() => {
                let event = res.map_err(|e| anyhow!(e))
                    .context("path_event()")?;
                match event {
                    quiche::PathEvent::New(..) => unreachable!(),

                    quiche::PathEvent::Validated(local_addr, peer_addr) => {
                        info!("Path ({}, {}) is now validated", local_addr, peer_addr);
                        conn.set_active(local_addr, peer_addr, true).await.ok();
                    }

                    quiche::PathEvent::ReturnAvailable(local_addr, peer_addr) => {
                        info!("Path ({}, {})'s return is now available", local_addr, peer_addr);
                        pathmng.set_group(local_addr).await
                            .context("insert path into group")?;

                    }

                    quiche::PathEvent::FailedValidation(local_addr, peer_addr) => {
                        info!("Path ({}, {}) failed validation", local_addr, peer_addr);
                    }

                    quiche::PathEvent::Closed(local_addr, peer_addr, e, reason) => {
                        info!("Path ({}, {}) is now closed and unusable; err = {}, reason = {:?}",
                            local_addr, peer_addr, e, reason);
                    }

                    quiche::PathEvent::ReusedSourceConnectionId(cid_seq, old, new) => {
                        info!("Peer reused cid seq {} (initially {:?}) on {:?}",
                            cid_seq, old, new);
                    }

                    quiche::PathEvent::PeerMigrated(..) => unreachable!(),

                    quiche::PathEvent::PeerPathStatus(..) => {},

                    quiche::PathEvent::InsertGroup(..) => unreachable!(),

                    quiche::PathEvent::RemoveGroup(..) => unreachable!(),
                }
            }

            res = set.join_next(), if !set.is_empty() => {
                if let Some(res) = res {
                    if let Err(e) = res? {
                        error!("Error occured in spawned task: {:?}", e);
                    }
                }
            }

            _ = tokio::signal::ctrl_c() => {
                info!("Control C signaled");
                drop(notify_shutdown_tx);
                drop(shutdown_complete_tx);
                break;
            }
        }
    }
    drop(conn);
    drop(quic);
    let _ = shutdown_complete_rx.recv().await;
    Ok(())
}

async fn start_vpn(
    conn: &QuicConnectionHandle,
    ctrlmng: &mut ControlManager,
    set: &mut JoinSet<anyhow::Result<()>>,
    notify_shutdown_tx: &broadcast::Sender<()>,
    shutdown_complete_tx: mpsc::Sender<()>,
    enable_pktlog: bool,
) -> anyhow::Result<()> {
    info!("Sending start request");
    let seq = ctrlmng
        .send_start_request(&conn)
        .await
        .context("send start request")?;
    match ctrlmng
        .recv_response(&conn, seq)
        .await
        .context("recv response")?
    {
        ResponseMsg::Ok => {
            info!("VPN service started");
            set.spawn(transfer(
                conn.clone(),
                notify_shutdown_tx.subscribe(),
                notify_shutdown_tx.subscribe(),
                shutdown_complete_tx,
                enable_pktlog,
                false,
            ));
        }
        ResponseMsg::Err(reason) => {
            error!("Cannot start VPN service: {}", reason);
        }
    }
    Ok(())
}

async fn notify_tunnel(
    conn: &QuicConnectionHandle,
    ctrlmng: &mut ControlManager,
    dscp: u8,
    group_id: u64
) -> anyhow::Result<()> {
    let seq = ctrlmng.send_tunnel_request(&conn, dscp, group_id)
        .await
        .context("sending tunnel request")?;
    info!("Notify tunnel: dscp={}, group_id={}", dscp, group_id);
    match ctrlmng
        .recv_response(&conn, seq)
        .await
        .context("recv response")?
    {
        ResponseMsg::Ok => {
            info!("Tunnel notified successfuly");
        }
        ResponseMsg::Err(reason) => {
            error!("Cannot notify tunnel: {}", reason);
        }
    }
    Ok(())
}
