// src/dhcp_probe.rs
// Active DHCP Inform probing — sends DHCP Inform packets to ARP-discovered
// devices to solicit their Option 55 (Parameter Request List) fingerprint
// without triggering a full DHCP lease negotiation.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

/// Send DHCP Inform probes to a batch of target IPs and collect Option 55 fingerprints.
///
/// DHCP Inform (message type 8) tells the device "I already have an IP, just send me
/// config parameters." The device responds with a DHCP ACK containing its Parameter
/// Request List, which uniquely identifies the OS network stack.
///
/// This is completely non-destructive: no IP assignment, no lease negotiation.
#[cfg(windows)]
pub fn probe_dhcp_fingerprints(
    targets: &[Ipv4Addr],
    source_ip: Ipv4Addr,
    source_mac: [u8; 6],
    timeout_ms: u64,
) -> HashMap<IpAddr, String> {
    let mut results = HashMap::new();
    if targets.is_empty() {
        return results;
    }

    // Bind to an ephemeral port — we send FROM port 68 (DHCP client) to port 67 (DHCP server)
    // But since we're the probe initiator, we bind to 0 and set giaddr/flags appropriately
    let sock = match UdpSocket::bind("0.0.0.0:0") {
        Ok(s) => s,
        Err(_) => return results,
    };
    let _ = sock.set_read_timeout(Some(Duration::from_millis(timeout_ms)));
    let _ = sock.set_broadcast(true);

    // Send DHCP Inform to each target
    for (i, target) in targets.iter().enumerate() {
        let xid = 0xD0C0_0000u32 + i as u32; // Unique transaction ID per target
        let packet = build_dhcp_inform(*target, source_ip, source_mac, xid);
        let dest = SocketAddr::new(IpAddr::V4(*target), 67);
        let _ = sock.send_to(&packet, dest);
        std::thread::sleep(Duration::from_millis(5));
    }

    // Collect responses
    let start = std::time::Instant::now();
    let mut buf = [0u8; 1500];
    while start.elapsed() < Duration::from_millis(timeout_ms) {
        match sock.recv_from(&mut buf) {
            Ok((len, src_addr)) => {
                if len < 240 {
                    continue;
                }
                let data = &buf[..len];

                // Verify it's a DHCP response (op=2, BOOTREPLY)
                if data[0] != 2 {
                    continue;
                }

                // Verify DHCP magic cookie at bytes 236-239
                if data[236] != 99 || data[237] != 130 || data[238] != 83 || data[239] != 99 {
                    continue;
                }

                // Check transaction ID matches our range
                let xid = u32::from_be_bytes([data[4], data[5], data[6], data[7]]);
                if xid < 0xD0C0_0000 || xid >= 0xD0C0_0000 + targets.len() as u32 {
                    continue;
                }

                // Extract Option 55 (Parameter Request List)
                if let Some(fingerprint) = parse_option55(data) {
                    let responder_ip = src_addr.ip();
                    results.insert(responder_ip, fingerprint);
                }
            }
            Err(_) => {
                // Timeout — check if we've exceeded total timeout
                if start.elapsed() >= Duration::from_millis(timeout_ms) {
                    break;
                }
            }
        }
    }

    results
}

/// Build a DHCP Inform packet (message type 8).
///
/// Layout follows RFC 2131 §4.4.3:
/// - op=1 (BOOTREQUEST)
/// - ciaddr = target_ip (the IP we're informing about)
/// - chaddr = our MAC
/// - Options: message type 8 (Inform), parameter request list
fn build_dhcp_inform(
    target_ip: Ipv4Addr,
    _source_ip: Ipv4Addr,
    source_mac: [u8; 6],
    xid: u32,
) -> Vec<u8> {
    let mut pkt = vec![0u8; 300];

    // op: BOOTREQUEST
    pkt[0] = 1;
    // htype: Ethernet
    pkt[1] = 1;
    // hlen: 6 (MAC address length)
    pkt[2] = 6;
    // hops
    pkt[3] = 0;

    // xid: transaction ID
    pkt[4..8].copy_from_slice(&xid.to_be_bytes());

    // secs: 0
    pkt[8] = 0;
    pkt[9] = 0;

    // flags: 0 (unicast response requested)
    pkt[10] = 0;
    pkt[11] = 0;

    // ciaddr: client IP — set to target IP for Inform
    let target_octets = target_ip.octets();
    pkt[12..16].copy_from_slice(&target_octets);

    // yiaddr, siaddr, giaddr: all zero
    // (bytes 16-27 already zero)

    // chaddr: our MAC address (padded to 16 bytes)
    pkt[28..34].copy_from_slice(&source_mac);

    // sname: zero (bytes 44-107)
    // file: zero (bytes 108-235)

    // DHCP magic cookie
    pkt[236] = 99;
    pkt[237] = 130;
    pkt[238] = 83;
    pkt[239] = 99;

    // DHCP Options starting at byte 240
    let mut pos = 240;

    // Option 53: DHCP Message Type = 8 (Inform)
    pkt[pos] = 53;
    pkt[pos + 1] = 1;
    pkt[pos + 2] = 8;
    pos += 3;

    // Option 55: Parameter Request List (request common options to look like a real client)
    let prl = [1u8, 3, 6, 15, 31, 33, 43, 44, 46, 47, 119, 121, 249, 252];
    pkt[pos] = 55;
    pkt[pos + 1] = prl.len() as u8;
    pos += 2;
    pkt[pos..pos + prl.len()].copy_from_slice(&prl);
    pos += prl.len();

    // Option 255: End
    pkt[pos] = 255;
    pos += 1;

    pkt.truncate(pos);
    pkt
}

/// Parse DHCP options to extract Option 55 (Parameter Request List).
/// Works on both BOOTREQUEST and BOOTREPLY packets.
fn parse_option55(data: &[u8]) -> Option<String> {
    if data.len() < 240 {
        return None;
    }

    // Verify DHCP magic cookie
    if data[236] != 99 || data[237] != 130 || data[238] != 83 || data[239] != 99 {
        return None;
    }

    let mut pos = 240;
    while pos < data.len() {
        let opt_code = data[pos];
        if opt_code == 255 {
            break;
        } // End
        if opt_code == 0 {
            pos += 1;
            continue;
        } // Pad

        if pos + 1 >= data.len() {
            break;
        }
        let opt_len = data[pos + 1] as usize;
        let data_start = pos + 2;
        if data_start + opt_len > data.len() {
            break;
        }

        if opt_code == 55 && opt_len > 0 {
            let prl: Vec<String> = data[data_start..data_start + opt_len]
                .iter()
                .map(|b| b.to_string())
                .collect();
            return Some(prl.join(","));
        }

        pos = data_start + opt_len;
    }
    None
}
