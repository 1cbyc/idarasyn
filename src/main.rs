mod cli;
mod listener;
mod packet_factory;
mod prober;
mod scanner;
mod utils;

use anyhow::Result;
use clap::Parser;
use cli::Args;
use listener::{PortState, ResponseListener, ScanResult};
use prober::Prober;
use scanner::Scanner;
use serde::Serialize;
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::sync::mpsc;
use std::time::Duration;
use tokio;

#[derive(Serialize)]
struct OutputResult {
    port: u16,
    state: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    service: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    banner: Option<String>,
}

#[derive(Serialize)]
struct JsonOutput {
    target: String,
    scan_results: Vec<OutputResult>,
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    utils::check_privileges()?;

    let target_ip: Ipv4Addr = args
        .target
        .parse()
        .map_err(|_| anyhow::anyhow!("Invalid target IP address"))?;

    let ports = utils::parse_port_range(&args.ports)?;

    let (iface_name, source_ip) = utils::get_network_interface(args.interface.as_deref())?;

    if !args.json {
        println!("IdaraSYN - High-Speed SYN Port Scanner");
        println!("========================================");
        println!("Target: {}", target_ip);
        println!("Interface: {} ({})", iface_name, source_ip);
        println!("Ports: {} ports to scan", ports.len());
        println!("Source Port: {}", args.source_port);
        println!("Rate Limit: {} packets/burst", args.rate_limit);
        println!("Jitter: 0-{} ms", args.jitter);
        println!("Banner Grabbing: {}", if args.banner_grab { "enabled" } else { "disabled" });
        println!("========================================\n");
    }

    let (tx, rx) = mpsc::channel::<ScanResult>();

    let listener = ResponseListener::new(
        iface_name.clone(),
        source_ip,
        target_ip,
        args.source_port,
        tx,
    );

    let timeout_duration = Duration::from_secs(args.timeout);

    let listener_handle = std::thread::spawn(move || {
        listener.start_listening(timeout_duration)
    });

    tokio::time::sleep(Duration::from_millis(500)).await;

    let scanner = Scanner::new(
        source_ip,
        target_ip,
        args.source_port,
        ports.clone(),
        args.rate_limit,
        args.jitter,
    );

    scanner.scan().await?;

    let mut results: HashMap<u16, ScanResult> = HashMap::new();

    for result in rx.try_iter() {
        if result.state == PortState::Open && !args.json {
            println!("[+] Port {} is OPEN", result.port);
        }
        results.insert(result.port, result);
    }

    tokio::time::sleep(timeout_duration).await;

    listener_handle.join().unwrap()?;

    let open_ports: Vec<u16> = results
        .values()
        .filter(|r| r.state == PortState::Open)
        .map(|r| r.port)
        .collect();

    let mut service_info = HashMap::new();

    if args.banner_grab && !open_ports.is_empty() {
        if !args.json {
            println!("\n[*] Grabbing banners for {} open ports...\n", open_ports.len());
        }

        let prober = Prober::new(target_ip, args.banner_timeout);

        for port in &open_ports {
            match prober.probe(*port).await {
                Ok(info) => {
                    if !args.json {
                        println!("[+] Port {}: {} - {}", info.port, info.service, 
                            if info.banner.is_empty() { "No banner" } else { &info.banner });
                    }
                    service_info.insert(*port, info);
                }
                Err(e) => {
                    if !args.json {
                        println!("[-] Port {}: Failed to grab banner - {}", port, e);
                    }
                }
            }
        }
    }

    if args.json {
        let output = JsonOutput {
            target: target_ip.to_string(),
            scan_results: results
                .values()
                .filter(|r| r.state == PortState::Open)
                .map(|r| {
                    let info = service_info.get(&r.port);
                    OutputResult {
                        port: r.port,
                        state: "open".to_string(),
                        service: info.map(|i| i.service.clone()),
                        banner: info.and_then(|i| {
                            if i.banner.is_empty() {
                                None
                            } else {
                                Some(i.banner.clone())
                            }
                        }),
                    }
                })
                .collect(),
        };

        println!("{}", serde_json::to_string_pretty(&output)?);
    } else {
        println!("\n========================================");
        println!("Scan Complete");
        println!("Open Ports: {}", open_ports.len());
        println!("========================================");
    }

    Ok(())
}
