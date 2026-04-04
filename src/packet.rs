use std::net::IpAddr;

use chrono::{DateTime, Local};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::icmp::IcmpPacket;
use pnet::packet::ip::IpNextHeaderProtocols;
use pnet::packet::ipv4::Ipv4Packet;
use pnet::packet::tcp::{TcpFlags, TcpPacket};
use pnet::packet::udp::UdpPacket;
use pnet::packet::Packet;
use serde::Serialize;

#[derive(Debug, Clone, clap::ValueEnum)]
pub enum ProtocolFilter {
    All,
    Tcp,
    Udp,
    Icmp,
}

#[derive(Debug, Clone, Serialize)]
#[allow(dead_code)] // Unknown(u8) reserved for future use
pub enum Protocol {
    #[serde(rename = "TCP")]
    Tcp,
    #[serde(rename = "UDP")]
    Udp,
    #[serde(rename = "ICMP")]
    Icmp,
    #[serde(rename = "UNKNOWN")]
    Unknown(u8),
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "TCP"),
            Protocol::Udp => write!(f, "UDP"),
            Protocol::Icmp => write!(f, "ICMP"),
            Protocol::Unknown(n) => write!(f, "?({n})"),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct CapturedPacket {
    pub timestamp: DateTime<Local>,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
    pub size: usize,
    pub flags: Option<String>,
    pub payload: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process: Option<String>,
}

pub fn parse_packet(ethernet: &EthernetPacket) -> Option<CapturedPacket> {
    if ethernet.get_ethertype() != EtherTypes::Ipv4 {
        return None;
    }

    let ipv4 = Ipv4Packet::new(ethernet.payload())?;
    let src_ip = IpAddr::V4(ipv4.get_source());
    let dst_ip = IpAddr::V4(ipv4.get_destination());
    let size = ethernet.packet().len();

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(ipv4.payload())?;
            Some(CapturedPacket {
                timestamp: Local::now(),
                protocol: Protocol::Tcp,
                src_ip,
                dst_ip,
                src_port: Some(tcp.get_source()),
                dst_port: Some(tcp.get_destination()),
                size,
                flags: Some(parse_tcp_flags(&tcp)),
                payload: None,
                process: None,
            })
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(ipv4.payload())?;
            Some(CapturedPacket {
                timestamp: Local::now(),
                protocol: Protocol::Udp,
                src_ip,
                dst_ip,
                src_port: Some(udp.get_source()),
                dst_port: Some(udp.get_destination()),
                size,
                flags: None,
                payload: None,
                process: None,
            })
        }
        IpNextHeaderProtocols::Icmp => {
            // Validate the frame is a well-formed ICMP packet
            let _icmp = IcmpPacket::new(ipv4.payload())?;
            Some(CapturedPacket {
                timestamp: Local::now(),
                protocol: Protocol::Icmp,
                src_ip,
                dst_ip,
                src_port: None,
                dst_port: None,
                size,
                flags: None,
                payload: None,
                process: None,
            })
        }
        _ => None,
    }
}

fn parse_tcp_flags(tcp: &TcpPacket) -> String {
    let mut parts = Vec::new();
    let f = tcp.get_flags();

    if f & TcpFlags::SYN != 0 {
        parts.push("SYN");
    }
    if f & TcpFlags::ACK != 0 {
        parts.push("ACK");
    }
    if f & TcpFlags::FIN != 0 {
        parts.push("FIN");
    }
    if f & TcpFlags::RST != 0 {
        parts.push("RST");
    }
    if f & TcpFlags::PSH != 0 {
        parts.push("PSH");
    }
    if f & TcpFlags::URG != 0 {
        parts.push("URG");
    }

    if parts.is_empty() {
        "\u{2014}".to_string()
    } else {
        parts.join("+")
    }
}
