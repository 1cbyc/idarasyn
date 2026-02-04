use anyhow::Result;
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

#[derive(Debug, Clone)]
pub struct ServiceInfo {
    pub port: u16,
    pub banner: String,
    pub service: String,
}

pub struct Prober {
    target_ip: Ipv4Addr,
    timeout_duration: Duration,
}

impl Prober {
    pub fn new(target_ip: Ipv4Addr, timeout_secs: u64) -> Self {
        Self {
            target_ip,
            timeout_duration: Duration::from_secs(timeout_secs),
        }
    }

    pub async fn probe(&self, port: u16) -> Result<ServiceInfo> {
        let addr = SocketAddrV4::new(self.target_ip, port);
        
        let mut stream = timeout(self.timeout_duration, TcpStream::connect(addr))
            .await
            .map_err(|_| anyhow::anyhow!("Connection timeout"))?
            .map_err(|e| anyhow::anyhow!("Connection failed: {}", e))?;

        let probe_data = self.get_probe_for_port(port);
        
        if let Some(data) = probe_data {
            let _ = timeout(
                Duration::from_secs(1),
                stream.write_all(data.as_bytes())
            ).await;
        }

        let mut buffer = vec![0u8; 1024];
        let n = timeout(
            Duration::from_secs(2),
            stream.read(&mut buffer)
        )
        .await
        .unwrap_or(Ok(0))?;

        let banner = if n > 0 {
            String::from_utf8_lossy(&buffer[..n])
                .trim()
                .to_string()
        } else {
            String::new()
        };

        let service = self.identify_service(port, &banner);

        Ok(ServiceInfo {
            port,
            banner,
            service,
        })
    }

    fn get_probe_for_port(&self, port: u16) -> Option<&'static str> {
        match port {
            80 | 8080 | 8000 => Some("GET / HTTP/1.0\r\n\r\n"),
            443 | 8443 => Some("GET / HTTP/1.1\r\nHost: localhost\r\n\r\n"),
            21 => None,
            22 => None,
            25 => Some("EHLO probe\r\n"),
            110 => Some("USER probe\r\n"),
            143 => Some("A001 CAPABILITY\r\n"),
            _ => None,
        }
    }

    fn identify_service(&self, port: u16, banner: &str) -> String {
        if banner.is_empty() {
            return self.guess_service_by_port(port);
        }

        let lower_banner = banner.to_lowercase();

        if lower_banner.contains("http") {
            "HTTP".to_string()
        } else if lower_banner.contains("ssh") {
            "SSH".to_string()
        } else if lower_banner.contains("ftp") {
            "FTP".to_string()
        } else if lower_banner.contains("smtp") {
            "SMTP".to_string()
        } else if lower_banner.contains("pop3") {
            "POP3".to_string()
        } else if lower_banner.contains("imap") {
            "IMAP".to_string()
        } else if lower_banner.contains("mysql") {
            "MySQL".to_string()
        } else if lower_banner.contains("postgres") {
            "PostgreSQL".to_string()
        } else {
            self.guess_service_by_port(port)
        }
    }

    fn guess_service_by_port(&self, port: u16) -> String {
        match port {
            21 => "FTP",
            22 => "SSH",
            23 => "Telnet",
            25 => "SMTP",
            53 => "DNS",
            80 => "HTTP",
            110 => "POP3",
            143 => "IMAP",
            443 => "HTTPS",
            445 => "SMB",
            3306 => "MySQL",
            3389 => "RDP",
            5432 => "PostgreSQL",
            5900 => "VNC",
            8080 => "HTTP-Proxy",
            _ => "Unknown",
        }
        .to_string()
    }
}
