use anyhow::{Context, Result};
use pnet::datalink;
use std::net::Ipv4Addr;

pub fn get_network_interface(name: Option<&str>) -> Result<(String, Ipv4Addr)> {
    let interfaces = datalink::interfaces();

    if let Some(iface_name) = name {
        let iface = interfaces
            .iter()
            .find(|i| i.name == iface_name)
            .ok_or_else(|| anyhow::anyhow!("Interface '{}' not found", iface_name))?;

        let ip = iface
            .ips
            .iter()
            .find_map(|ip| {
                if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                    Some(ipv4)
                } else {
                    None
                }
            })
            .ok_or_else(|| anyhow::anyhow!("No IPv4 address found for interface '{}'", iface_name))?;

        return Ok((iface.name.clone(), ip));
    }

    for iface in interfaces {
        if iface.is_up() && !iface.is_loopback() {
            if let Some(ip) = iface.ips.iter().find_map(|ip| {
                if let std::net::IpAddr::V4(ipv4) = ip.ip() {
                    if !ipv4.is_loopback() {
                        return Some(ipv4);
                    }
                }
                None
            }) {
                return Ok((iface.name.clone(), ip));
            }
        }
    }

    Err(anyhow::anyhow!("No suitable network interface found"))
}

pub fn check_privileges() -> Result<()> {
    #[cfg(unix)]
    {
        use nix::unistd::Uid;
        if !Uid::effective().is_root() {
            anyhow::bail!("This program requires root privileges (CAP_NET_RAW). Run with sudo.");
        }
    }

    #[cfg(windows)]
    {
        eprintln!("Warning: This program requires Administrator privileges.");
    }

    Ok(())
}

pub fn parse_port_range(range: &str) -> Result<Vec<u16>> {
    if range.contains('-') {
        let parts: Vec<&str> = range.split('-').collect();
        if parts.len() != 2 {
            anyhow::bail!("Invalid port range format");
        }
        let start: u16 = parts[0].parse().context("Invalid start port")?;
        let end: u16 = parts[1].parse().context("Invalid end port")?;
        if start > end {
            anyhow::bail!("Start port must be less than or equal to end port");
        }
        Ok((start..=end).collect())
    } else if range.contains(',') {
        range
            .split(',')
            .map(|p| p.trim().parse::<u16>().context("Invalid port"))
            .collect()
    } else {
        let port: u16 = range.parse().context("Invalid port")?;
        Ok(vec![port])
    }
}
