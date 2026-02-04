use anyhow::Result;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::{Ipv4Packet, MutableIpv4Packet};
use pnet::packet::tcp::{MutableTcpPacket, TcpFlags};
use pnet::packet::Packet;
use std::net::Ipv4Addr;

const IPV4_HEADER_LEN: usize = 20;
const TCP_HEADER_LEN: usize = 20;

pub struct PacketFactory;

impl PacketFactory {
    pub fn build_syn_packet(
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Result<Vec<u8>> {
        let total_len = IPV4_HEADER_LEN + TCP_HEADER_LEN;
        let mut buffer = vec![0u8; total_len];

        Self::build_ipv4_header(&mut buffer[..IPV4_HEADER_LEN], src_ip, dst_ip, TCP_HEADER_LEN)?;
        Self::build_tcp_header(
            &mut buffer[IPV4_HEADER_LEN..],
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            seq,
        )?;

        Ok(buffer)
    }

    fn build_ipv4_header(
        buffer: &mut [u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        payload_len: usize,
    ) -> Result<()> {
        let mut ip_packet = MutableIpv4Packet::new(buffer)
            .ok_or_else(|| anyhow::anyhow!("Failed to create IPv4 packet"))?;

        ip_packet.set_version(4);
        ip_packet.set_header_length(5);
        ip_packet.set_total_length((IPV4_HEADER_LEN + payload_len) as u16);
        ip_packet.set_ttl(64);
        ip_packet.set_next_level_protocol(IpNextHeaderProtocols::Tcp);
        ip_packet.set_source(src_ip);
        ip_packet.set_destination(dst_ip);

        let checksum = pnet::packet::ipv4::checksum(&ip_packet.to_immutable());
        ip_packet.set_checksum(checksum);

        Ok(())
    }

    fn build_tcp_header(
        buffer: &mut [u8],
        src_ip: Ipv4Addr,
        dst_ip: Ipv4Addr,
        src_port: u16,
        dst_port: u16,
        seq: u32,
    ) -> Result<()> {
        let mut tcp_packet = MutableTcpPacket::new(buffer)
            .ok_or_else(|| anyhow::anyhow!("Failed to create TCP packet"))?;

        tcp_packet.set_source(src_port);
        tcp_packet.set_destination(dst_port);
        tcp_packet.set_sequence(seq);
        tcp_packet.set_acknowledgement(0);
        tcp_packet.set_data_offset(5);
        tcp_packet.set_flags(TcpFlags::SYN);
        tcp_packet.set_window(64240);
        tcp_packet.set_urgent_ptr(0);

        let checksum = pnet::packet::tcp::ipv4_checksum(
            &tcp_packet.to_immutable(),
            &src_ip,
            &dst_ip,
        );
        tcp_packet.set_checksum(checksum);

        Ok(())
    }
}
