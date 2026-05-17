use std::sync::mpsc::Sender;

use pnet::datalink::{self, Channel::Ethernet};
use pnet::packet::ethernet::{EtherTypes, EthernetPacket};
use pnet::packet::arp::{ArpOperations, ArpPacket};
use pnet::packet::Packet;

use crate::packet::{parse_packet, CapturedPacket, Protocol, ProtocolFilter};

pub fn start_capture(
    interface_name: &str,
    filter: &ProtocolFilter,
    tx: Sender<CapturedPacket>,
    passive_tx: Option<Sender<(String, std::net::IpAddr)>>
) {
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
                    // --- ARP packet harvesting (zero-noise passive discovery) ---
                    // ARP replies and gratuitous ARP from iPhones/devices are
                    // emitted on wake/join but were silently dropped because
                    // parse_packet only handles IPv4/IPv6. Catch them here first.
                    if ethernet.get_ethertype() == EtherTypes::Arp {
                        if let Some(ref p_tx) = passive_tx {
                            if let Some(arp) = ArpPacket::new(ethernet.payload()) {
                                let op = arp.get_operation();
                                let sender_ip = arp.get_sender_proto_addr();
                                let target_ip = arp.get_target_proto_addr();
                                // Accept ARP Reply (op=2) or Gratuitous ARP (sender==target)
                                if op == ArpOperations::Reply || sender_ip == target_ip {
                                    let sender_hw = arp.get_sender_hw_addr();
                                    let mac_str = format!(
                                        "{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}",
                                        sender_hw.0, sender_hw.1, sender_hw.2,
                                        sender_hw.3, sender_hw.4, sender_hw.5
                                    );
                                    let ip = std::net::IpAddr::V4(sender_ip);
                                    // Skip zero/broadcast MACs
                                    if mac_str != "00:00:00:00:00:00" && mac_str != "FF:FF:FF:FF:FF:FF" {
                                        let _ = p_tx.send((mac_str, ip));
                                    }
                                }
                            }
                        }
                        // ARP frames have no IP layer — skip to next frame
                        continue;
                    }

                    if let Some(packet) = parse_packet(&ethernet) {
                        // Passive discovery: harvest source MAC + IP
                        if let Some(ref p_tx) = passive_tx {
                            let src_mac = ethernet.get_source().to_string().to_uppercase();
                            let _ = p_tx.send((src_mac, packet.src_ip));
                        }

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
