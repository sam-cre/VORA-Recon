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

#[derive(Debug, Clone, Serialize, Eq, Hash, PartialEq)]
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

#[derive(Debug, Clone, Serialize)]
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
    /// IPv4 TTL value for passive OS fingerprinting
    pub ttl: Option<u8>,
    /// TCP window size for OS disambiguation (Linux vs macOS)
    pub tcp_window: Option<u16>,
    /// DNS answers extracted from port 53 responses: (queried_domain, resolved_ips)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_answers: Option<(String, Vec<IpAddr>)>,
    /// Domain name extracted from TLS SNI (port 443) or HTTP Host header (port 80/8080)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain_hint: Option<String>,
    /// JA4-style TLS fingerprint from ClientHello structure (identifies client software)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_fingerprint: Option<String>,
    /// DHCP Parameter Request List (Option 55) — used for OS fingerprinting
    /// Format: comma-separated option codes, e.g. "1,3,6,15,119,252"
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dhcp_fingerprint: Option<String>,
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
    let ttl = ipv4.get_ttl();

    match ipv4.get_next_level_protocol() {
        IpNextHeaderProtocols::Tcp => {
            let tcp = TcpPacket::new(ipv4.payload())?;
            let dst_port = tcp.get_destination();
            let payload = tcp.payload();

            // Extract domain hints and TLS fingerprints from application-layer payloads
            let (domain_hint, tls_fingerprint) = match dst_port {
                443 => parse_tls_client_hello(payload),
                80 | 8080 => (parse_http_host(payload), None),
                _ => (None, None),
            };

            Some(CapturedPacket {
                timestamp: Local::now(),
                protocol: Protocol::Tcp,
                src_ip,
                dst_ip,
                src_port: Some(tcp.get_source()),
                dst_port: Some(dst_port),
                size,
                flags: Some(parse_tcp_flags(&tcp)),
                payload: None,
                ttl: Some(ttl),
                tcp_window: Some(tcp.get_window()),
                dns_answers: None,
                domain_hint,
                tls_fingerprint,
                dhcp_fingerprint: None,
                process: None,
            })
        }
        IpNextHeaderProtocols::Udp => {
            let udp = UdpPacket::new(ipv4.payload())?;
            let src_port = udp.get_source();
            let dst_port = udp.get_destination();

            // Parse DNS responses (source port 53 = reply from DNS server)
            let dns_answers = if src_port == 53 {
                parse_dns_answers(udp.payload())
            } else {
                None
            };
            
            // DHCP fingerprinting ingestion
            let dhcp_fingerprint = if (src_port == 68 && dst_port == 67) || (src_port == 67 && dst_port == 68) {
                parse_dhcp_fingerprint(udp.payload())
            } else {
                None
            };

            Some(CapturedPacket {
                timestamp: Local::now(),
                protocol: Protocol::Udp,
                src_ip,
                dst_ip,
                src_port: Some(src_port),
                dst_port: Some(dst_port),
                size,
                flags: None,
                payload: None,
                ttl: Some(ttl),
                tcp_window: None,
                dns_answers,
                domain_hint: None,
                tls_fingerprint: None,
                dhcp_fingerprint,
                process: None,
            })
        }
        IpNextHeaderProtocols::Icmp => {
            // Validate the frame is a well-formed ICMP packet and extract type/code
            let icmp = IcmpPacket::new(ipv4.payload())?;
            let icmp_type = icmp.get_icmp_type().0;
            let icmp_code = icmp.get_icmp_code().0;
            let icmp_info = format_icmp_type_code(icmp_type, icmp_code);
            Some(CapturedPacket {
                timestamp: Local::now(),
                protocol: Protocol::Icmp,
                src_ip,
                dst_ip,
                src_port: None,
                dst_port: None,
                size,
                flags: Some(icmp_info),
                payload: None,
                ttl: Some(ttl),
                tcp_window: None,
                dns_answers: None,
                domain_hint: None,
                tls_fingerprint: None,
                dhcp_fingerprint: None,
                process: None,
            })
        }
        _ => None,
    }
}

fn format_icmp_type_code(icmp_type: u8, icmp_code: u8) -> String {
    // Common ICMP types with human-readable names
    let type_name = match icmp_type {
        0 => "Echo-Reply",
        3 => "Dest-Unreach",
        8 => "Echo-Request",
        9 => "Router-Adv",
        10 => "Router-Sel",
        11 => "Time-Excd",
        12 => "Param-Prob",
        13 => "Timestamp",
        14 => "Timestamp-Rep",
        15 => "Info-Request",
        16 => "Info-Reply",
        17 => "Addr-Request",
        18 => "Addr-Reply",
        _ => "ICMP",
    };
    if icmp_code == 0 {
        type_name.to_string()
    } else {
        format!("{}(c{})", type_name, icmp_code)
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

// ---------------------------------------------------------------------------
// DNS response parser — extracts queried domain + resolved IPs from answers
// ---------------------------------------------------------------------------

/// Parse a DNS response payload and extract (queried_domain, resolved_ips).
/// Returns None if the packet is a query, malformed, or has no A/AAAA answers.
fn parse_dns_answers(data: &[u8]) -> Option<(String, Vec<IpAddr>)> {
    // DNS header is 12 bytes minimum
    if data.len() < 12 {
        return None;
    }

    let flags = u16::from_be_bytes([data[2], data[3]]);
    let qr = (flags >> 15) & 1;
    if qr != 1 {
        return None; // Not a response
    }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;

    if qdcount == 0 || ancount == 0 {
        return None;
    }

    // Parse the first question to get the QNAME
    let mut offset = 12;
    let qname = read_dns_name(data, &mut offset)?;

    // Skip QTYPE (2 bytes) + QCLASS (2 bytes)
    offset += 4;

    // Skip remaining questions
    for _ in 1..qdcount {
        skip_dns_name(data, &mut offset)?;
        offset += 4; // QTYPE + QCLASS
    }

    // Parse answer records
    let mut ips = Vec::new();
    for _ in 0..ancount {
        if offset >= data.len() {
            break;
        }

        // Skip the NAME field (may be compressed)
        skip_dns_name(data, &mut offset)?;

        if offset + 10 > data.len() {
            break;
        }

        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10; // TYPE(2) + CLASS(2) + TTL(4) + RDLENGTH(2)

        if offset + rdlength > data.len() {
            break;
        }

        match rtype {
            1 if rdlength == 4 => {
                // A record — IPv4
                let ip = std::net::Ipv4Addr::new(
                    data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
                );
                ips.push(IpAddr::V4(ip));
            }
            28 if rdlength == 16 => {
                // AAAA record — IPv6
                let mut octets = [0u8; 16];
                octets.copy_from_slice(&data[offset..offset + 16]);
                ips.push(IpAddr::V6(std::net::Ipv6Addr::from(octets)));
            }
            _ => {} // Skip CNAME, MX, etc.
        }

        offset += rdlength;
    }

    if ips.is_empty() {
        None
    } else {
        Some((qname, ips))
    }
}

/// Read a DNS domain name from the wire format, handling label compression.
fn read_dns_name(data: &[u8], offset: &mut usize) -> Option<String> {
    let mut labels = Vec::new();
    let mut pos = *offset;
    let mut jumped = false;
    let mut jump_count = 0;

    loop {
        if pos >= data.len() {
            return None;
        }

        let len = data[pos] as usize;

        if len == 0 {
            // End of name
            if !jumped {
                *offset = pos + 1;
            }
            break;
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer
            if pos + 1 >= data.len() {
                return None;
            }
            if !jumped {
                *offset = pos + 2;
            }
            pos = ((len & 0x3F) << 8 | data[pos + 1] as usize) as usize;
            jumped = true;
            jump_count += 1;
            if jump_count > 10 {
                return None; // Prevent infinite loops
            }
            continue;
        }

        pos += 1;
        if pos + len > data.len() {
            return None;
        }

        let label = std::str::from_utf8(&data[pos..pos + len]).ok()?;
        labels.push(label.to_string());
        pos += len;
    }

    if labels.is_empty() {
        None
    } else {
        Some(labels.join("."))
    }
}

/// Skip over a DNS name in the wire format (advancing offset) without allocating.
fn skip_dns_name(data: &[u8], offset: &mut usize) -> Option<()> {
    loop {
        if *offset >= data.len() {
            return None;
        }

        let len = data[*offset] as usize;

        if len == 0 {
            *offset += 1;
            return Some(());
        }

        if len & 0xC0 == 0xC0 {
            // Compression pointer — 2 bytes total, then done
            *offset += 2;
            return Some(());
        }

        *offset += 1 + len;
    }
}

// ---------------------------------------------------------------------------
// TLS SNI extraction — parse ClientHello to find the server_name extension
// ---------------------------------------------------------------------------

/// FNV-1a hash of a slice of u16 values, returning 12 hex characters.
fn fnv1a_hash_u16(values: &[u16]) -> String {
    let mut hash: u64 = 0xcbf29ce484222325;
    for &v in values {
        for b in v.to_be_bytes() {
            hash ^= b as u64;
            hash = hash.wrapping_mul(0x100000001b3);
        }
    }
    format!("{:012x}", hash & 0xffffffffffff)
}

/// Extract SNI hostname AND compute a JA4-style TLS fingerprint from a ClientHello.
/// The fingerprint encodes TLS version, cipher count, extension count, and hashes of
/// the cipher suite and extension type lists — uniquely identifying the TLS client library.
/// Returns (sni_hostname, ja4_fingerprint).
fn parse_tls_client_hello(data: &[u8]) -> (Option<String>, Option<String>) {
    if data.len() < 43 {
        return (None, None);
    }

    // TLS record header
    if data[0] != 0x16 {
        return (None, None);
    }
    let record_len = u16::from_be_bytes([data[3], data[4]]) as usize;
    if data.len() < 5 + record_len {
        return (None, None);
    }

    let hs = &data[5..5 + record_len];
    if hs.is_empty() || hs[0] != 0x01 {
        return (None, None);
    }
    let hs_len = ((hs[1] as usize) << 16) | ((hs[2] as usize) << 8) | (hs[3] as usize);
    if hs.len() < 4 + hs_len {
        return (None, None);
    }

    let ch = &hs[4..4 + hs_len];
    if ch.len() < 34 {
        return (None, None);
    }

    // Client version from ClientHello (ch[0..2])
    let ch_version = u16::from_be_bytes([ch[0], ch[1]]);

    let mut pos = 34;

    // Session ID
    if pos >= ch.len() { return (None, None); }
    let sid_len = ch[pos] as usize;
    pos += 1 + sid_len;

    // Cipher Suites — collect them for JA4
    if pos + 2 > ch.len() { return (None, None); }
    let cs_len = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    let cs_end = pos + cs_len;
    if cs_end > ch.len() { return (None, None); }

    let mut cipher_suites: Vec<u16> = Vec::new();
    let mut cs_pos = pos;
    while cs_pos + 2 <= cs_end {
        let suite = u16::from_be_bytes([ch[cs_pos], ch[cs_pos + 1]]);
        // Skip GREASE values (0x?A?A pattern)
        if suite & 0x0f0f != 0x0a0a {
            cipher_suites.push(suite);
        }
        cs_pos += 2;
    }
    pos = cs_end;

    // Compression Methods
    if pos >= ch.len() { return (None, None); }
    let cm_len = ch[pos] as usize;
    pos += 1 + cm_len;

    // Extensions
    if pos + 2 > ch.len() { return (None, None); }
    let ext_total = u16::from_be_bytes([ch[pos], ch[pos + 1]]) as usize;
    pos += 2;
    let ext_end = pos + ext_total;
    if ext_end > ch.len() { return (None, None); }

    let mut sni: Option<String> = None;
    let mut extension_types: Vec<u16> = Vec::new();
    let mut has_tls13_version = false;

    while pos + 4 <= ext_end {
        let ext_type = u16::from_be_bytes([ch[pos], ch[pos + 1]]);
        let ext_len = u16::from_be_bytes([ch[pos + 2], ch[pos + 3]]) as usize;
        pos += 4;
        if pos + ext_len > ext_end { break; }

        // Skip GREASE extension types
        if ext_type & 0x0f0f != 0x0a0a {
            extension_types.push(ext_type);
        }

        // SNI extraction (type 0x0000)
        if ext_type == 0x0000 && ext_len >= 5 {
            let name_type = ch[pos + 2];
            if name_type == 0x00 {
                let name_len = u16::from_be_bytes([ch[pos + 3], ch[pos + 4]]) as usize;
                if pos + 5 + name_len <= ext_end {
                    sni = std::str::from_utf8(&ch[pos + 5..pos + 5 + name_len])
                        .ok()
                        .map(|s| s.to_lowercase());
                }
            }
        }

        // Detect TLS 1.3 via supported_versions extension (type 0x002b)
        if ext_type == 0x002b && ext_len >= 3 {
            let sv_len = ch[pos] as usize;
            let mut sv_pos = pos + 1;
            while sv_pos + 2 <= pos + 1 + sv_len {
                let ver = u16::from_be_bytes([ch[sv_pos], ch[sv_pos + 1]]);
                if ver == 0x0304 { has_tls13_version = true; }
                sv_pos += 2;
            }
        }

        pos += ext_len;
    }

    // Compute JA4 fingerprint
    let tls_ver = if has_tls13_version { "13" }
        else if ch_version == 0x0303 { "12" }
        else if ch_version == 0x0302 { "11" }
        else if ch_version == 0x0301 { "10" }
        else { "00" };

    cipher_suites.sort();
    extension_types.sort();

    let ja4 = format!("t{}d{:02}{:02}_{}_{}" ,
        tls_ver,
        cipher_suites.len().min(99),
        extension_types.len().min(99),
        fnv1a_hash_u16(&cipher_suites),
        fnv1a_hash_u16(&extension_types),
    );

    (sni, Some(ja4))
}

// ---------------------------------------------------------------------------
// DHCP fingerprinting — extract Option 55 (Parameter Request List)
// ---------------------------------------------------------------------------

/// Parse a DHCP packet and extract the Parameter Request List (Option 55).
/// Only processes client→server packets (op=1, BOOTREQUEST).
/// Returns a string like "1,3,6,15,119,252".
fn parse_dhcp_fingerprint(data: &[u8]) -> Option<String> {
    // Minimum DHCP header is 240 bytes (236 fixed + 4 magic cookie)
    if data.len() < 240 { return None; }

    // op=1 means BOOTREQUEST (client→server). We only want client requests.
    if data[0] != 1 { return None; }

    // Verify DHCP magic cookie at bytes 236-239: 99.130.83.99
    if data[236] != 99 || data[237] != 130 || data[238] != 83 || data[239] != 99 {
        return None;
    }

    // Walk options starting at byte 240
    let mut pos = 240;
    while pos < data.len() {
        let opt_code = data[pos];
        if opt_code == 255 { break; }  // End option
        if opt_code == 0  { pos += 1; continue; }  // Pad option

        if pos + 1 >= data.len() { break; }
        let opt_len = data[pos + 1] as usize;
        let data_start = pos + 2;
        if data_start + opt_len > data.len() { break; }

        // Option 55 = Parameter Request List
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

// ---------------------------------------------------------------------------
// HTTP Host header extraction — lightweight string matching on port 80/8080
// ---------------------------------------------------------------------------

/// Extract the Host header value from an HTTP request payload.
/// Only inspects the first ~512 bytes for efficiency.
fn parse_http_host(data: &[u8]) -> Option<String> {
    // Quick check: must start with an HTTP verb
    let verbs: &[&[u8]] = &[b"GET ", b"POST ", b"PUT ", b"HEAD ", b"DELETE ", b"PATCH ", b"OPTIONS "];
    let starts_with_verb = verbs.iter().any(|v| data.starts_with(v));
    if !starts_with_verb {
        return None;
    }

    // Only scan the first 512 bytes for the Host header
    let scan_len = data.len().min(512);
    let text = std::str::from_utf8(&data[..scan_len]).ok()?;

    for line in text.lines() {
        // Headers are case-insensitive per HTTP spec
        if line.len() > 6 && line[..5].eq_ignore_ascii_case("Host:") {
            let host = line[5..].trim();
            // Strip port if present (e.g., "example.com:8080" → "example.com")
            let host = host.split(':').next().unwrap_or(host);
            if !host.is_empty() {
                return Some(host.to_lowercase());
            }
        }
    }

    None
}
