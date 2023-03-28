//! # wsl-auto-forward - A tool that can automatically forward local TCP requests to WSL2
//!
//! ## Why another tool
//! - Accessing WSL2 via localhost occasionally fails
//! - Windows portproxy: need manually setup forwarding port
//!
//! ## Installation
//!
//! use cargo (need **nightly**)
//! ```
//! cargo install wsl-auto-forward
//! ```
//!
//! or download from Release
//!
//! ## Features
//! - Auto detect WSL2 listening port changes, and apply forwarding
//!     - only detect ports bound to 0.0.0.0
//!     - detecting interval can be set
//! - Fixed port forwarding
//!
#![feature(windows_process_extensions_force_quotes)]

use anyhow::{anyhow, bail, Context, Result};
use bytes::BytesMut;
use log::{debug, error, info, warn};
use paste::paste;
use std::{
    collections::HashMap,
    env::set_var,
    net::{IpAddr, SocketAddr},
    os::windows::process::CommandExt,
    sync::Arc,
    vec,
};
use structopt::StructOpt;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpSocket, UdpSocket},
    process::Command,
    sync::{
        mpsc::{self, Receiver, Sender},
        Notify,
    },
    time::{sleep, Duration},
};

async fn get_wsl_ip() -> Result<String> {
    let output = Command::new("bash")
        .args(&["-c", "ifconfig eth0"])
        .output()
        .await
        .context("start wsl bash error in get_wsl_ip")?;
    if !output.status.success() {
        bail!(
            "get wsl ip error, you may not enabled wsl correctly:\n{}\n{}",
            String::from_utf8_lossy(&output.stderr),
            String::from_utf8_lossy(&output.stdout)
        )
    }

    let output = String::from_utf8_lossy(&output.stdout);
    for line in output.lines() {
        let line = line.trim();
        if line.starts_with("inet ") {
            let ip = line
                .split(' ')
                .skip(1)
                .next()
                .ok_or_else(|| anyhow!("invalid inet line: {}", line))?;
            return Ok(ip.trim().to_string());
        }
    }

    bail!("invalid ipconfig output: {}", output)
}

async fn get_wsl_open_port(tx: Sender<(Vec<u16>, Vec<u16>)>) -> Result<()> {
    let task = tokio::task::spawn_blocking(|| {
        let output = std::process::Command::new("bash")
            .args(&["-c", "netstat -an"])
            .force_quotes(true)
            .output()
            .context("call wsl netstat error")?;
        if !output.status.success() {
            bail!(
                "get wsl netstat error:\n{}\n{}",
                String::from_utf8_lossy(&output.stderr),
                String::from_utf8_lossy(&output.stdout)
            )
        }

        let output = String::from_utf8_lossy(&output.stdout);
        debug!("get wsl netstat:\n{}", output);
        let mut tcp_ports = vec![];
        let mut udp_ports = vec![];
        for line in output.lines() {
            let mut spans = line.split(' ').filter(|l| !l.is_empty()).map(|l| l.trim());
            if let Some(protocol) = spans.next() {
                let ports = match protocol {
                    "tcp" => {
                        if !line.contains("LISTEN") {
                            continue;
                        }
                        &mut tcp_ports
                    }
                    "udp" => &mut udp_ports,
                    _ => {
                        continue;
                    }
                };

                if let Some(addr) = spans.skip(2).next() {
                    if let Some((addr, port)) = addr.split_once(':') {
                        if addr == "0.0.0.0" {
                            ports.push(port.parse::<u16>()?);
                        }
                    }
                }
            }
        }

        info!(
            "detected wsl tcp port {:?} udp port {:?}",
            tcp_ports, udp_ports
        );
        return Ok((tcp_ports, udp_ports));
    });

    let ports = task.await?.context("get wsl listening port error")?;
    tx.send(ports).await?;
    Ok(())
}

struct Proxy {
    target_ip: IpAddr,
}

impl Proxy {
    async fn serve_tcp(target_ip: IpAddr, port: u16) -> Result<()> {
        let tcp_listener = TcpListener::bind(format!("0.0.0.0:{}", port)).await?;
        loop {
            let (from, _) = tcp_listener.accept().await?;
            let socket = TcpSocket::new_v4()?;
            let wsl_addr = SocketAddr::new(target_ip, port);
            let to = match socket.connect(wsl_addr).await {
                Ok(s) => s,
                Err(e) => {
                    error!("can not connect wsl {}: {:#}", wsl_addr, e);
                    continue;
                }
            };

            info!("host connect {}, forward begins", port);
            let (from_read, from_write) = from.into_split();
            let (to_read, to_write) = to.into_split();
            forward_tcp(from_read, to_write, port, "tcp host -> wsl");
            forward_tcp(to_read, from_write, port, "tcp wsl -> host");
        }
    }

    async fn serve_udp(target_ip: IpAddr, port: u16) -> Result<()> {
        let from_read = Arc::new(UdpSocket::bind(format!("0.0.0.0:{}", port)).await?);
        let from_write = from_read.clone();
        let to_read = Arc::new(UdpSocket::bind(format!("0.0.0.0:0")).await?);
        to_read.connect(SocketAddr::new(target_ip, port)).await?;
        let to_write = to_read.clone();
        let _ = futures::join!(
            forward_udp(from_read, to_write, port, "udp host -> wsl"),
            forward_udp(from_write, to_read, port, "udp wsl -> host")
        );

        Ok(())
    }

    async fn start(self, mut rx: Receiver<(Vec<u16>, Vec<u16>)>) {
        let mut old_tcp_ports = Vec::new();
        let mut old_udp_ports = Vec::new();
        let mut udp_port_map: HashMap<u16, Arc<Notify>> = HashMap::new();
        let mut tcp_port_map: HashMap<u16, Arc<Notify>> = HashMap::new();
        while let Some((new_tcp_ports, new_udp_ports)) = rx.recv().await {
            macro_rules! exchange {
                ($p: tt) => {
                    paste! {
                        for op in [<old_ $p _ports>].iter() {
                            if ![<new_ $p _ports>].iter().any(|np| np == op) {
                                if let Some(exit) = [<$p _port_map>].remove(&op) {
                                    info!("remove port listening at {} {}", stringify!($p), op);
                                    exit.notify_one();
                                } else {
                                    error!("port map can not found {} port {}", stringify!($p), op);
                                }
                            }
                        }

                        for np in [<new_ $p _ports>].iter().map(|p| *p) {
                            if ![<old_ $p _ports>].iter().any(|op| &np == op) {
                                let exit = Arc::new(Notify::new());
                                [<$p _port_map>].insert(np, exit.clone());
                                tokio::spawn(async move {
                                    info!("add new {} port listening at {}", stringify!($p), np);
                                    tokio::select! {
                                        r = Self::[<serve_ $p>](self.target_ip, np) => {
                                            if let Err(e) = r {
                                                error!("{} {} serve error: {:#}", stringify!($p), np, e);
                                            }
                                        }
                                        _ = exit.notified() => { warn!("listening task on {} {} abort", stringify!($p), np) }
                                    };
                                });
                            }
                        }

                        [<old_ $p _ports>] = [<new_ $p _ports>];
                    }
                };
            }

            exchange!(tcp);
            exchange!(udp);
        }

        debug!("channel is dropped");
    }
}

fn forward_udp(
    read: Arc<UdpSocket>,
    write: Arc<UdpSocket>,
    port: u16,
    prefix: impl AsRef<str> + Send + 'static,
) -> tokio::task::JoinHandle<Result<(), anyhow::Error>> {
    tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(2048);
        loop {
            let n = read.recv(&mut buf).await?;
            if n == 0 {
                break;
            }

            debug!("{} forward {} bytes", prefix.as_ref(), n);
            write.send(&mut buf).await?;
        }

        warn!("{} forward {} exited", prefix.as_ref(), port);
        Ok::<_, anyhow::Error>(())
    })
}

fn forward_tcp<R, W>(mut read: R, mut write: W, port: u16, prefix: impl AsRef<str> + Send + 'static)
where
    R: AsyncRead + Unpin + Send + 'static,
    W: AsyncWrite + Unpin + Send + 'static,
{
    tokio::spawn(async move {
        let mut buf = BytesMut::with_capacity(2048);
        loop {
            let n = read.read_buf(&mut buf).await?;
            if n == 0 {
                break;
            }

            debug!("{} forward {} bytes", prefix.as_ref(), n);
            write.write_all_buf(&mut buf).await?;
        }

        warn!("{} forward {} exited", prefix.as_ref(), port);
        Ok::<_, anyhow::Error>(())
    });
}

#[tokio::main]
async fn main() -> Result<()> {
    let opts = Options::from_args();
    set_var(
        "RUST_LOG",
        format!(
            "{}={}",
            env!("CARGO_PKG_NAME").replace('-', "_"),
            if opts.verbose { "debug" } else { "info" }
        ),
    );
    env_logger::init();

    let (tx, rx) = mpsc::channel(4);

    let wsl_ip = get_wsl_ip().await?;
    info!("got wsl ip is {}", wsl_ip);
    let proxy = Proxy {
        target_ip: wsl_ip.parse()?,
    };

    if opts.tcp_port.is_empty() && opts.udp_port.is_empty() {
        info!("no port specified, enable port auto detecting");
        tokio::spawn(async move {
            loop {
                get_wsl_open_port(tx.clone()).await?;
                sleep(Duration::from_secs(opts.interval)).await;
            }

            #[allow(unreachable_code)]
            Ok::<_, anyhow::Error>(())
        });
    } else {
        tx.send((opts.tcp_port, opts.udp_port)).await?;
    }

    proxy.start(rx).await;
    debug!("proxy exited");
    Ok(())
}

#[derive(StructOpt)]
struct Options {
    #[structopt(
        long,
        short,
        help = "forward tcp port list, if not specific tcp and udp ports, will use auto detecting"
    )]
    tcp_port: Vec<u16>,

    #[structopt(
        long,
        short,
        help = "forward udp port list, if not specific tcp and udp ports, will use auto detecting"
    )]
    udp_port: Vec<u16>,

    #[structopt(
        long,
        short,
        help = "auto detect wsl port interval, in seconds",
        default_value = "30"
    )]
    interval: u64,

    #[structopt(long, short, help = "verbose output")]
    verbose: bool,
}
