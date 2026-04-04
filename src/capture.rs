use std::sync::mpsc::Sender;

use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::EthernetPacket;

use crate::packet::{parse_packet, CapturedPacket, Protocol, ProtocolFilter};

pub fn start_capture(interface_name: &str, filter: &ProtocolFilter, tx: Sender<CapturedPacket>) {
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .find(|iface| iface.name == interface_name)
        .expect("Interface not found");

    let mut rx = match datalink::channel(&interface, Default::default()) {
        Ok(Ethernet(_, rx)) => rx,
        Ok(_) => panic!("Unhandled channel type"),
        Err(e) => panic!("Could not open datalink channel: {e}"),
    };

    loop {
        match rx.next() {
            Ok(frame) => {
                if let Some(ethernet) = EthernetPacket::new(frame) {
                    if let Some(packet) = parse_packet(&ethernet) {
                        if !matches_filter(&packet, filter) {
                            continue;
                        }
                        if tx.send(packet).is_err() {
                            break; // receiver dropped, exit cleanly
                        }
                    }
                }
            }
            Err(e) => eprintln!("Capture error: {e}"),
        }
    }
}

fn matches_filter(pkt: &CapturedPacket, filter: &ProtocolFilter) -> bool {
    match filter {
        ProtocolFilter::All => true,
        ProtocolFilter::Tcp => matches!(pkt.protocol, Protocol::Tcp),
        ProtocolFilter::Udp => matches!(pkt.protocol, Protocol::Udp),
        ProtocolFilter::Icmp => matches!(pkt.protocol, Protocol::Icmp),
    }
}
