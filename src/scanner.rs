use crate::packet_factory::PacketFactory;
use anyhow::Result;
use rand::seq::SliceRandom;
use rand::Rng;
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{Ipv4Addr, SocketAddrV4};
use std::time::Duration;
use tokio::time::sleep;

pub struct Scanner {
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    ports: Vec<u16>,
    rate_limit: usize,
    jitter_ms: u64,
}

impl Scanner {
    pub fn new(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        mut ports: Vec<u16>,
        rate_limit: usize,
        jitter_ms: u64,
    ) -> Self {
        let mut rng = rand::thread_rng();
        ports.shuffle(&mut rng);

        Self {
            src_ip,
            dst_ip,
            src_port,
            ports,
            rate_limit,
            jitter_ms,
        }
    }

    pub async fn scan(self) -> Result<()> {
        let socket = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::TCP))?;
        socket.set_header_included(true)?;

        let mut rng = rand::thread_rng();
        let mut count = 0;

        for port in self.ports {
            let seq = rng.gen::<u32>();
            let packet = PacketFactory::build_syn_packet(
                self.src_ip,
                self.dst_ip,
                self.src_port,
                port,
                seq,
            )?;

            let dst_addr = SocketAddrV4::new(self.dst_ip, port);
            socket.send_to(&packet, &dst_addr.into())?;

            count += 1;

            if count >= self.rate_limit {
                let jitter = rng.gen_range(0..=self.jitter_ms);
                sleep(Duration::from_millis(jitter)).await;
                count = 0;
            }
        }

        Ok(())
    }
}
