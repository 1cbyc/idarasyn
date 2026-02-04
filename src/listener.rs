use anyhow::Result;
use pnet::datalink::{self, Channel};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::Packet;
use std::collections::HashSet;
use std::net::Ipv4Addr;
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[derive(Debug, Clone)]
pub struct ScanResult {
    pub port: u16,
    pub state: PortState,
}

#[derive(Debug, Clone, PartialEq)]
pub enum PortState {
    Open,
    Closed,
    Filtered,
}

pub struct ResponseListener {
    interface_name: String,
    source_ip: Ipv4Addr,
    target_ip: Ipv4Addr,
    source_port: u16,
    result_tx: Sender<ScanResult>,
    seen_ports: Arc<Mutex<HashSet<u16>>>,
}

impl ResponseListener {
    pub fn new(
        interface_name: String,
        source_ip: Ipv4Addr,
        target_ip: Ipv4Addr,
        source_port: u16,
        result_tx: Sender<ScanResult>,
    ) -> Self {
        Self {
            interface_name,
            source_ip,
            target_ip,
            source_port,
            result_tx,
            seen_ports: Arc::new(Mutex::new(HashSet::new())),
        }
    }

    pub fn start_listening(self, timeout: Duration) -> Result<()> {
        let interfaces = datalink::interfaces();
        let interface = interfaces
            .into_iter()
            .find(|iface| iface.name == self.interface_name)
            .ok_or_else(|| anyhow::anyhow!("Interface not found"))?;

        let (_tx, mut rx) = match datalink::channel(&interface, Default::default())? {
            Channel::Ethernet(tx, rx) => (tx, rx),
            _ => anyhow::bail!("Unsupported channel type"),
        };

        let start_time = Instant::now();

        loop {
            if start_time.elapsed() > timeout {
                break;
            }

            match rx.next() {
                Ok(packet) => {
                    if let Some(ethernet) = EthernetPacket::new(packet) {
                        if ethernet.get_ethertype() == EtherTypes::Ipv4 {
                            if let Some(ip_packet) = Ipv4Packet::new(ethernet.payload()) {
                                if ip_packet.get_next_level_protocol() == IpNextHeaderProtocols::Tcp
                                    && ip_packet.get_source() == self.target_ip
                                    && ip_packet.get_destination() == self.source_ip
                                {
                                    if let Some(tcp_packet) = TcpPacket::new(ip_packet.payload()) {
                                        if tcp_packet.get_destination() == self.source_port {
                                            self.process_tcp_packet(&tcp_packet);
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Err(e) => {
                    if e.kind() != std::io::ErrorKind::TimedOut {
                        eprintln!("Listener error: {}", e);
                    }
                }
            }
        }

        Ok(())
    }

    fn process_tcp_packet(&self, tcp: &TcpPacket) {
        let port = tcp.get_source();
        let flags = tcp.get_flags();

        let mut seen = self.seen_ports.lock().unwrap();
        if seen.contains(&port) {
            return;
        }
        seen.insert(port);
        drop(seen);

        let state = if flags & TcpFlags::SYN != 0 && flags & TcpFlags::ACK != 0 {
            PortState::Open
        } else if flags & TcpFlags::RST != 0 {
            PortState::Closed
        } else {
            return;
        };

        let _ = self.result_tx.send(ScanResult { port, state });
    }
}
