use std::collections::{HashMap, HashSet};
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;
use std::process::Command;
use dashmap::DashMap;

/// Detailed rich metadata collected from mDNS TXT records and SSDP/UPnP XML descriptions.
#[derive(Clone, Debug, Default, serde::Serialize, serde::Deserialize)]
pub struct DeviceDetails {
    pub services: HashSet<String>,
    pub properties: HashMap<String, String>,
}

impl DeviceDetails {
    pub fn get(&self, key: &str) -> Option<&String> {
        self.properties.get(key)
    }

    pub fn is_empty(&self) -> bool {
        self.services.is_empty() && self.properties.is_empty()
    }
}

pub type DeviceMetadata = HashMap<IpAddr, DeviceDetails>;

/// Detailed information about a discovered network device.
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
pub struct DeviceInfo {
    pub mac: String,
    pub vendor: String,
    pub hostname: String,
    pub miss_count: u32,
    #[serde(skip, default = "std::time::Instant::now")]
    pub last_seen: std::time::Instant,
    #[serde(default = "default_unix_now")]
    pub last_seen_unix: u64,
}

pub fn default_unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
#[cfg(not(windows))]
use dns_lookup::lookup_addr;

/// Helper to process an mDNS packet, harvesting A records, service instance names, and TXT record metadata.
#[cfg(windows)]
fn process_mdns_packet(
    data: &[u8],
    src_ip: std::net::Ipv4Addr,
    hosts: &mut HashMap<IpAddr, String>,
    metadata: &mut HashMap<IpAddr, DeviceDetails>,
) {
    let mut packet_ipv4 = src_ip;
    let mut a_record_found = false;

    // Harvest any A record names from the response
    for (name, resolved_ip) in parse_mdns_a_records(data) {
        let clean = name.trim_end_matches(".local").trim_end_matches('.').to_string();
        if !clean.is_empty() {
            if let IpAddr::V4(v4) = resolved_ip {
                // Only the first A record sets packet_ipv4 — prevents misattribution
                // when a sleep-proxy packet carries A records for multiple devices.
                if !a_record_found {
                    packet_ipv4 = v4;
                    a_record_found = true;
                }
                hosts.entry(IpAddr::V4(v4)).or_insert(clean);
            }
        }
    }

    // Map any service instances found in the packet to the determined IPv4 address
    for instance_name in parse_mdns_service_instances(data) {
        let clean = instance_name
            .trim_end_matches(".local")
            .trim_end_matches('.')
            .to_string();
        let device_name = clean.split("._").next().unwrap_or(&clean);
        let device_name = device_name.split('@').last().unwrap_or(device_name);
        // Strip sleep-proxy eero prefix: "70-35-60-63.1 Master Bedroom" -> "Master Bedroom"
        let device_name = if let Some(space_pos) = device_name.find(' ') {
            let pre = &device_name[..space_pos];
            if pre.contains('.') || pre.chars().all(|c| c.is_ascii_hexdigit() || c == '-') {
                device_name[space_pos + 1..].trim()
            } else {
                device_name.trim()
            }
        } else {
            device_name.trim()
        }.to_string();

        if !device_name.is_empty() {
            hosts.entry(IpAddr::V4(packet_ipv4)).or_insert(device_name);
        }
    }

    // Parse TXT records for rich device metadata
    for (record_name, pairs) in parse_mdns_txt_records(data) {
        let ip_key = IpAddr::V4(packet_ipv4);
        let meta = metadata.entry(ip_key).or_insert_with(DeviceDetails::default);
        for (key, value) in &pairs {
            match key.as_str() {
                // Apple _companion-link rpMd = device model code
                "rpmd" => {
                    meta.properties.insert("model_code".to_string(), value.clone());
                    if let Some(human) = resolve_apple_model(value) {
                        meta.properties.insert("model".to_string(), human.to_string());
                    }
                }
                // _device-info model/wmodel field
                "model" | "wmodel" => {
                    if !meta.properties.contains_key("model_code") {
                        meta.properties.insert("model_code".to_string(), value.clone());
                    }
                    if !meta.properties.contains_key("model") {
                        if let Some(human) = resolve_apple_model(value) {
                            meta.properties.insert("model".to_string(), human.to_string());
                        }
                    }
                }
                // _raop am = AirPlay device model
                "am" => {
                    if !meta.properties.contains_key("model_code") {
                        meta.properties.insert("model_code".to_string(), value.clone());
                        if let Some(human) = resolve_apple_model(value) {
                            meta.properties.insert("model".to_string(), human.to_string());
                        }
                    }
                }
                // macOS version
                "osxvers" => {
                    let os_name = match value.as_str() {
                        "24" => "macOS 15 Sequoia",
                        "23" => "macOS 14 Sonoma",
                        "22" => "macOS 13 Ventura",
                        "21" => "macOS 12 Monterey",
                        "20" => "macOS 11 Big Sur",
                        _ => value.as_str(),
                    };
                    meta.properties.insert("os_version".to_string(), os_name.to_string());
                }
                // Chromecast / Google device friendly name
                "fn" => { meta.properties.insert("friendly_name".to_string(), value.clone()); }
                // Model name
                "md" => {
                    if !meta.properties.contains_key("model") {
                        meta.properties.insert("model".to_string(), value.clone());
                    }
                }
                // AirPlay source version
                "srcvers" | "vs" => { meta.properties.insert("firmware".to_string(), value.clone()); }
                // HomeKit category
                "ci" => {
                    let category = match value.as_str() {
                        "1" => "Other",
                        "2" => "Bridge",
                        "3" => "Fan",
                        "4" => "Garage Door",
                        "5" => "Lightbulb",
                        "6" => "Door Lock",
                        "7" => "Outlet",
                        "8" => "Switch",
                        "9" => "Thermostat",
                        "10" => "Sensor",
                        "11" => "Security System",
                        "12" => "Door",
                        "13" => "Window",
                        "14" => "Window Covering",
                        "17" => "Sprinkler",
                        "28" => "TV",
                        "32" => "Router",
                        _ => value.as_str(),
                    };
                    meta.properties.insert("homekit_category".to_string(), category.to_string());
                }
                _ => {}
            }
        }
        // Track which service this came from
        if record_name.contains("_airplay") { meta.services.insert("AirPlay".to_string()); }
        if record_name.contains("_raop") { meta.services.insert("AirPlay Audio".to_string()); }
        if record_name.contains("_hap") { meta.services.insert("HomeKit".to_string()); }
        if record_name.contains("_googlecast") { meta.services.insert("Chromecast".to_string()); }
        if record_name.contains("_spotify") { meta.services.insert("Spotify Connect".to_string()); }
        if record_name.contains("_companion-link") { meta.services.insert("Apple Companion".to_string()); }
        if record_name.contains("_apple-mobdev2") { meta.services.insert("iPhone/iPad".to_string()); }
        if record_name.contains("_airdrop") { meta.services.insert("AirDrop".to_string()); }
        if record_name.contains("_remotepairing") { meta.services.insert("iPhone".to_string()); }
        if record_name.contains("_continuity") { meta.services.insert("Continuity".to_string()); }
    }
}

/// Resolve hostnames via raw mDNS PTR queries (bypasses mdns_sd daemon port conflict)
/// Sends mDNS reverse lookup queries for each IP and parses responses directly
#[cfg(windows)]
fn collect_mdns_hostnames(ips: &[IpAddr], timeout_secs: u64) -> (HashMap<IpAddr, String>, HashMap<IpAddr, DeviceDetails>) {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    let mut result: HashMap<IpAddr, String> = HashMap::new();
    let mut txt_metadata: HashMap<IpAddr, DeviceDetails> = HashMap::new();
    if ips.is_empty() { return (result, txt_metadata); }

    // Filter to only IPv4 private IPs (mDNS reverse lookup targets)
    let v4_ips: Vec<Ipv4Addr> = ips.iter().filter_map(|ip| {
        if let IpAddr::V4(v4) = ip { Some(*v4) } else { None }
    }).collect();
    if v4_ips.is_empty() { return (result, txt_metadata); }

    // Create UDP socket to coexist with Chrome/svchost on port 5353
    let sock = match socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP)) {
        Ok(s) => s,
        Err(_) => return (result, txt_metadata),
    };
    let _ = sock.set_reuse_address(true);
    let addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
    // Try port 5353 for multicast receive; fall back to ephemeral so QU-bit queries
    // still get unicast responses when Chrome or Windows mDNS already holds 5353.
    let bound_multicast = sock.bind(&addr.into()).is_ok();
    if !bound_multicast {
        let ephemeral: SocketAddr = "0.0.0.0:0".parse().unwrap();
        if sock.bind(&ephemeral.into()).is_err() {
            return (result, txt_metadata);
        }
    }
    let socket: UdpSocket = sock.into();

    let _ = socket.set_read_timeout(Some(Duration::from_millis(800)));
    // Join the mDNS multicast group to receive responses (requires port 5353)
    let mdns_addr: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
    if bound_multicast {
        let _ = socket.join_multicast_v4(&mdns_addr, &Ipv4Addr::UNSPECIFIED);
    }

    let mdns_target: SocketAddr = SocketAddr::new(IpAddr::V4(mdns_addr), 5353);

    // Strategy 1: Send PTR queries for each IPv4 address (reverse DNS lookup)
    for ip in &v4_ips {
        let octets = ip.octets();
        let ptr_name = format!("{}.{}.{}.{}.in-addr.arpa", octets[3], octets[2], octets[1], octets[0]);
        let query = build_mdns_service_query(&ptr_name, (octets[3] as u16) + 100);
        let _ = socket.send_to(&query, mdns_target);
        std::thread::sleep(Duration::from_millis(2));
    }

    // Strategy 2: Send DNS-SD service browse query to discover Apple/Sonos device names
    let browse_services = [
        "_services._dns-sd._udp.local",
        "_airplay._tcp.local",
        "_companion-link._tcp.local",
        "_raop._tcp.local",
        "_sonos._tcp.local",
        "_hap._tcp.local",
        "_sleep-proxy._udp.local",
        "_apple-mobdev2._tcp.local",
        "_apple-tv._tcp.local",
        "_home-sharing._tcp.local",
        "_device-info._tcp.local",
        "_googlecast._tcp.local",
        "_spotify-connect._tcp.local",
        "_smb._tcp.local",
        "_ssh._tcp.local",
        "_http._tcp.local",
        "_printer._tcp.local",
        "_ipp._tcp.local",
        "_scanner._tcp.local",
        // iPhone-specific / iPhone-common services
        "_airdrop._tcp.local",
        "_remotepairing._tcp.local",
        "_apple-pairable._tcp.local",
        "_continuity._tcp.local",
        "_rdlink._tcp.local",
        "_nse._tcp.local",
        "_matter._tcp.local",
        "_meshcop._udp.local",
    ];
    for (i, service) in browse_services.iter().enumerate() {
        let query = build_mdns_service_query(service, (i + 200) as u16);
        let _ = socket.send_to(&query, mdns_target);
        std::thread::sleep(Duration::from_millis(5));
    }



    // Collect responses for the timeout period
    let start = std::time::Instant::now();
    let mut buf = [0u8; 4096];
    let timeout = Duration::from_secs(timeout_secs);
    while start.elapsed() < timeout {
        match socket.recv_from(&mut buf) {
            Ok((len, src_addr)) => {
                let data = &buf[..len];
                // Try parsing as PTR response (reverse lookup)
                for (ip, hostname) in parse_mdns_ptr_responses(data) {
                    let clean = hostname
                        .trim_end_matches(".local")
                        .trim_end_matches('.')
                        .to_string();
                    if !clean.is_empty() && clean != ip.to_string() {
                        result.insert(IpAddr::V4(ip), clean);
                    }
                }
                if let IpAddr::V4(src_v4) = src_addr.ip() {
                    process_mdns_packet(data, src_v4, &mut result, &mut txt_metadata);
                }
            }
            Err(_) => {
                // Timeout on recv, send another round of queries for unresolved IPs
                // Use sub(2) so retries keep firing until 6s into an 8s window,
                // giving sleepy iPhones (3-6s response time) a chance to reply
                if start.elapsed() < Duration::from_secs(timeout_secs.saturating_sub(2)) {
                    // Re-send service browse queries too
                    for (i, service) in browse_services.iter().enumerate() {
                        let query = build_mdns_service_query(service, (i + 300) as u16);
                        let _ = socket.send_to(&query, mdns_target);
                    }
                }
            }
        }
    }

    if bound_multicast {
        let _ = socket.leave_multicast_v4(&mdns_addr, &Ipv4Addr::UNSPECIFIED);
    }

    (result, txt_metadata)
}


/// Build a DNS-SD service browse query (PTR query for a service type like "_airplay._tcp.local")
/// This discovers Apple/Sonos/HomeKit devices that register services on the network
fn build_mdns_service_query(service: &str, id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);

    // DNS Header
    pkt.extend_from_slice(&id.to_be_bytes());  // Transaction ID
    pkt.extend_from_slice(&[0x00, 0x00]);       // Flags: standard query
    pkt.extend_from_slice(&[0x00, 0x01]);       // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]);       // Answers: 0
    pkt.extend_from_slice(&[0x00, 0x00]);       // Authority: 0
    pkt.extend_from_slice(&[0x00, 0x00]);       // Additional: 0

    // Question: service name as DNS labels (e.g. "_airplay._tcp.local")
    for part in service.split('.') {
        if part.is_empty() { continue; }
        pkt.push(part.len() as u8);
        pkt.extend_from_slice(part.as_bytes());
    }
    pkt.push(0); // Null terminator

    // Type: PTR (12), Class: IN with QU bit (0x8001)
    // QU bit forces iPhone to respond via unicast — critical for modern iOS
    // which ignores standard multicast queries for many service types
    pkt.extend_from_slice(&[0x00, 0x0C]); // Type PTR
    pkt.extend_from_slice(&[0x80, 0x01]); // Class IN + QU bit (unicast response requested)

    pkt
}

/// Parse an mDNS response to extract ALL A record → (hostname, IPv4 address) mappings
fn parse_mdns_a_records(data: &[u8]) -> Vec<(String, std::net::IpAddr)> {
    let mut results = Vec::new();
    if data.len() < 12 { return results; }
    if data[2] & 0x80 == 0 { return results; } // Not a response

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;
    let total_records = ancount + nscount + arcount;

    let mut offset = 12;
    for _ in 0..qdcount {
        if let Some(next) = skip_dns_name(data, offset) {
            offset = next + 4;
        } else {
            return results;
        }
    }

    for _ in 0..total_records {
        if offset >= data.len() { break; }
        let (name, next) = match read_dns_name(data, offset) {
            Some(res) => res,
            None => break,
        };
        offset = next;

        if offset + 10 > data.len() { break; }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if rtype == 1 && rdlength == 4 && offset + 4 <= data.len() {
            let ip = std::net::Ipv4Addr::new(
                data[offset], data[offset + 1], data[offset + 2], data[offset + 3]
            );
            results.push((name, std::net::IpAddr::V4(ip)));
        }
        offset += rdlength;
    }
    results
}

/// Parse an mDNS response to extract ALL service instance names from PTR answers
fn parse_mdns_service_instances(data: &[u8]) -> Vec<String> {
    let mut results = Vec::new();
    if data.len() < 12 { return results; }
    if data[2] & 0x80 == 0 { return results; }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;
    let total_records = ancount + nscount + arcount;
    if total_records == 0 { return results; }

    let mut offset = 12;
    for _ in 0..qdcount {
        if let Some(next) = skip_dns_name(data, offset) {
            offset = next + 4;
        } else {
            return results;
        }
    }

    for _ in 0..total_records {
        if offset >= data.len() { break; }
        let (_, next) = match read_dns_name(data, offset) {
            Some(res) => res,
            None => break,
        };
        offset = next;

        if offset + 10 > data.len() { break; }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if rtype == 12 { // PTR record
            if let Some((instance, _)) = read_dns_name(data, offset) {
                if instance.contains("._") {
                    results.push(instance);
                }
            }
        }
        offset += rdlength;
    }
    results
}

/// Parse ALL TXT resource records from an mDNS response packet.
/// TXT records contain key=value pairs that reveal device models, firmware, etc.
/// Returns: Vec<(record_name, Vec<(key, value)>)>
fn parse_mdns_txt_records(data: &[u8]) -> Vec<(String, Vec<(String, String)>)> {
    let mut results = Vec::new();
    if data.len() < 12 { return results; }
    if data[2] & 0x80 == 0 { return results; } // Not a response

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;
    let total_records = ancount + nscount + arcount;

    let mut offset = 12;
    for _ in 0..qdcount {
        if let Some(next) = skip_dns_name(data, offset) {
            offset = next + 4;
        } else {
            return results;
        }
    }

    for _ in 0..total_records {
        if offset >= data.len() { break; }
        let (name, next) = match read_dns_name(data, offset) {
            Some(res) => res,
            None => break,
        };
        offset = next;

        if offset + 10 > data.len() { break; }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if rtype == 16 && rdlength > 0 && offset + rdlength <= data.len() {
            // TXT record: sequence of length-prefixed strings
            let mut txt_pairs = Vec::new();
            let txt_end = offset + rdlength;
            let mut pos = offset;
            while pos < txt_end {
                let str_len = data[pos] as usize;
                pos += 1;
                if pos + str_len > txt_end { break; }
                if let Ok(s) = std::str::from_utf8(&data[pos..pos + str_len]) {
                    if let Some(eq_pos) = s.find('=') {
                        let key = s[..eq_pos].to_lowercase();
                        let value = s[eq_pos + 1..].to_string();
                        if !key.is_empty() {
                            txt_pairs.push((key, value));
                        }
                    }
                }
                pos += str_len;
            }
            if !txt_pairs.is_empty() {
                results.push((name, txt_pairs));
            }
        }
        offset += rdlength;
    }
    results
}

/// Resolve Apple model identifier codes to human-readable names.
/// These codes appear in mDNS TXT records (rpMd, model, am fields).
pub fn resolve_apple_model(code: &str) -> Option<&'static str> {
    // Strip any trailing comma or whitespace
    let code = code.trim().trim_end_matches(',');
    match code {
        // === iPhones ===
        // iPhone 16 series (newest)
        "iPhone17,1" => Some("iPhone 16 Pro"),
        "iPhone17,2" => Some("iPhone 16 Pro Max"),
        "iPhone17,3" => Some("iPhone 16"),
        "iPhone17,4" => Some("iPhone 16 Plus"),
        // iPhone SE (4th gen)
        "iPhone16,3" => Some("iPhone SE (4th gen)"),
        // iPhone 15 series
        "iPhone16,2" => Some("iPhone 15 Pro Max"),
        "iPhone16,1" => Some("iPhone 15 Pro"),
        "iPhone15,5" => Some("iPhone 15 Plus"),
        "iPhone15,4" => Some("iPhone 15"),
        // iPhone 14 series
        "iPhone15,3" => Some("iPhone 14 Pro Max"),
        "iPhone15,2" => Some("iPhone 14 Pro"),
        "iPhone14,8" => Some("iPhone 14 Plus"),
        "iPhone14,7" => Some("iPhone 14"),
        // iPhone SE (3rd gen)
        "iPhone14,6" => Some("iPhone SE (3rd gen)"),
        // iPhone 13 series
        "iPhone14,5" => Some("iPhone 13"),
        "iPhone14,4" => Some("iPhone 13 mini"),
        "iPhone14,3" => Some("iPhone 13 Pro Max"),
        "iPhone14,2" => Some("iPhone 13 Pro"),
        // iPhone 12 series
        "iPhone13,4" => Some("iPhone 12 Pro Max"),
        "iPhone13,3" => Some("iPhone 12 Pro"),
        "iPhone13,2" => Some("iPhone 12"),
        "iPhone13,1" => Some("iPhone 12 mini"),
        // iPhone SE (2nd gen)
        "iPhone12,8" => Some("iPhone SE (2nd gen)"),
        // iPhone 11 series
        "iPhone12,5" => Some("iPhone 11 Pro Max"),
        "iPhone12,3" => Some("iPhone 11 Pro"),
        "iPhone12,1" => Some("iPhone 11"),
        // iPhone X series
        "iPhone11,2" => Some("iPhone XS"),
        "iPhone11,4" | "iPhone11,6" => Some("iPhone XS Max"),
        "iPhone11,8" => Some("iPhone XR"),
        // iPhone X
        "iPhone10,3" | "iPhone10,6" => Some("iPhone X"),
        // iPhone 8 series
        "iPhone10,1" | "iPhone10,4" => Some("iPhone 8"),
        "iPhone10,2" | "iPhone10,5" => Some("iPhone 8 Plus"),
        // iPhone 7 series
        "iPhone9,1" | "iPhone9,3" => Some("iPhone 7"),
        "iPhone9,2" | "iPhone9,4" => Some("iPhone 7 Plus"),
        // iPhone 6s series
        "iPhone8,1" => Some("iPhone 6s"),
        "iPhone8,2" => Some("iPhone 6s Plus"),
        // iPhone SE (1st gen)
        "iPhone8,4" => Some("iPhone SE (1st gen)"),
        // iPhone 6 series
        "iPhone7,2" => Some("iPhone 6"),
        "iPhone7,1" => Some("iPhone 6 Plus"),

        // === iPads ===
        // iPad Pro M4 (newest)
        "iPad16,3" | "iPad16,4" => Some("iPad Pro 11\" (M4)"),
        "iPad16,5" | "iPad16,6" => Some("iPad Pro 13\" (M4)"),
        // iPad Air M2
        "iPad14,8" | "iPad14,9" => Some("iPad Air 11\" (M2)"),
        "iPad14,10" | "iPad14,11" => Some("iPad Air 13\" (M2)"),
        // iPad mini (6th gen)
        "iPad14,1" | "iPad14,2" => Some("iPad mini (6th gen)"),
        // iPad (10th gen)
        "iPad13,18" | "iPad13,19" => Some("iPad (10th gen)"),
        // iPad Air (5th gen)
        "iPad13,16" | "iPad13,17" => Some("iPad Air (5th gen)"),
        // iPad Pro 12.9" (5th gen)
        "iPad13,8" | "iPad13,9" | "iPad13,10" | "iPad13,11" => Some("iPad Pro 12.9\" (5th gen)"),
        // iPad Pro 11" (3rd gen)
        "iPad13,4" | "iPad13,5" | "iPad13,6" | "iPad13,7" => Some("iPad Pro 11\" (3rd gen)"),
        // iPad Air (4th gen)
        "iPad13,1" | "iPad13,2" => Some("iPad Air (4th gen)"),
        // iPad (9th gen)
        "iPad12,1" | "iPad12,2" => Some("iPad (9th gen)"),
        // iPad mini (5th gen)
        "iPad11,1" | "iPad11,2" => Some("iPad mini (5th gen)"),
        // iPad Air (3rd gen)
        "iPad11,3" | "iPad11,4" => Some("iPad Air (3rd gen)"),
        // iPad (8th gen)
        "iPad11,6" | "iPad11,7" => Some("iPad (8th gen)"),
        // iPad Pro 11" (2nd gen)
        "iPad8,9" | "iPad8,10" => Some("iPad Pro 11\" (2nd gen)"),
        // iPad Pro 12.9" (4th gen)
        "iPad8,11" | "iPad8,12" => Some("iPad Pro 12.9\" (4th gen)"),
        // iPad Pro 11" (1st gen)
        "iPad8,1" | "iPad8,2" | "iPad8,3" | "iPad8,4" => Some("iPad Pro 11\" (1st gen)"),
        // iPad Pro 12.9" (3rd gen)
        "iPad8,5" | "iPad8,6" | "iPad8,7" | "iPad8,8" => Some("iPad Pro 12.9\" (3rd gen)"),
        // iPad (7th gen)
        "iPad7,11" | "iPad7,12" => Some("iPad (7th gen)"),

        // === MacBooks ===
        "MacBookPro18,4" => Some("MacBook Pro 14\" (M1 Max)"),
        "MacBookPro18,3" => Some("MacBook Pro 16\" (M1 Pro)"),
        "MacBookPro18,2" => Some("MacBook Pro 16\" (M1 Max)"),
        "MacBookPro18,1" => Some("MacBook Pro 16\" (M1 Pro)"),
        "MacBookPro17,1" => Some("MacBook Pro 13\" (M1)"),
        "MacBookAir10,1" => Some("MacBook Air (M1)"),
        "Mac14,2" => Some("MacBook Air (M2)"),
        "Mac14,7" => Some("MacBook Pro 13\" (M2)"),
        "Mac14,5" | "Mac14,9" => Some("MacBook Pro 14\" (M2 Pro)"),
        "Mac14,6" | "Mac14,10" => Some("MacBook Pro 16\" (M2 Max)"),
        // M3 Laptops
        "Mac15,3" => Some("MacBook Pro 14\" (M3)"),
        "Mac15,12" => Some("MacBook Air 13\" (M3)"),
        "Mac15,13" => Some("MacBook Air 15\" (M3)"),
        "Mac15,6" | "Mac15,8" | "Mac15,10" => Some("MacBook Pro 14\" (M3 Pro)"),
        "Mac15,7" | "Mac15,9" | "Mac15,11" => Some("MacBook Pro 16\" (M3 Max)"),
        // M4 Laptops
        "Mac16,1" => Some("MacBook Pro 14\" (M4)"),
        "Mac16,5" => Some("MacBook Pro 16\" (M4 Max)"),
        "Mac16,6" => Some("MacBook Pro 14\" (M4 Max)"),
        "Mac16,7" => Some("MacBook Pro 16\" (M4 Pro)"),
        "Mac16,8" => Some("MacBook Pro 14\" (M4 Pro)"),
        "Mac16,12" => Some("MacBook Air 13\" (M4)"),
        "Mac16,13" => Some("MacBook Air 15\" (M4)"),

        // === iMac / Mac Desktop ===
        "iMac21,1" | "iMac21,2" => Some("iMac 24\" (M1)"),
        "Mac14,3" => Some("Mac mini (M2)"),
        "Mac13,1" => Some("Mac Studio (M1 Max)"),
        "Mac13,2" => Some("Mac Studio (M1 Ultra)"),
        "Mac14,13" | "Mac14,14" => Some("Mac Studio (M2)"),
        "Mac14,8" => Some("Mac Pro (2023)"),
        // M3 Desktops
        "Mac15,4" | "Mac15,5" => Some("iMac 24\" (M3)"),
        "Mac15,14" => Some("Mac Studio (M3)"),
        // M4 Desktops
        "Mac16,2" | "Mac16,3" => Some("iMac 24\" (M4)"),
        "Mac16,9" => Some("Mac Studio (M4 Max)"),
        "Mac16,10" => Some("Mac mini (M4)"),
        "Mac16,11" => Some("Mac mini (M4 Pro)"),

        // === Apple TV ===
        "AppleTV6,2" => Some("Apple TV 4K (1st gen)"),
        "AppleTV11,1" => Some("Apple TV 4K (2nd gen)"),
        "AppleTV14,1" => Some("Apple TV 4K (3rd gen)"),
        "AppleTV5,3" => Some("Apple TV (4th gen)"),

        // === HomePod ===
        "AudioAccessory1,1" | "AudioAccessory1,2" => Some("HomePod"),
        "AudioAccessory5,1" => Some("HomePod mini"),
        "AudioAccessory6,1" => Some("HomePod (2nd gen)"),

        // === Apple Watch ===
        // BUG FIX: Watch6,1–4 are Series 6, not Series 7
        "Watch6,1" | "Watch6,2" | "Watch6,3" | "Watch6,4" => Some("Apple Watch Series 6"),
        "Watch6,6" | "Watch6,7" | "Watch6,8" | "Watch6,9" => Some("Apple Watch Series 8"),
        "Watch6,10" | "Watch6,11" | "Watch6,12" | "Watch6,13" => Some("Apple Watch SE (2nd gen)"),
        "Watch6,14" | "Watch6,15" | "Watch6,16" | "Watch6,17" => Some("Apple Watch Ultra"),
        "Watch6,18" | "Watch6,19" => Some("Apple Watch Ultra 2"),
        "Watch7,1" | "Watch7,2" | "Watch7,3" | "Watch7,4" => Some("Apple Watch Series 9"),
        "Watch7,5" | "Watch7,6" | "Watch7,7" | "Watch7,8" => Some("Apple Watch Series 10"),

        // === Apple Vision Pro ===
        "RealityDevice14,1" => Some("Apple Vision Pro"),

        _ => {
            // Try prefix matching for unknown models
            if code.starts_with("iPhone") { Some("iPhone (unknown model)") }
            else if code.starts_with("iPad") { Some("iPad (unknown model)") }
            else if code.starts_with("MacBook") { Some("MacBook (unknown model)") }
            else if code.starts_with("Mac16,") { Some("Mac (unknown model)") }
            else if code.starts_with("Mac") { Some("Mac (unknown model)") }
            else if code.starts_with("AppleTV") { Some("Apple TV (unknown model)") }
            else if code.starts_with("AudioAccessory") { Some("HomePod (unknown model)") }
            else if code.starts_with("Watch") { Some("Apple Watch (unknown model)") }
            else if code.starts_with("HomePod") { Some("HomePod") }
            else if code.starts_with("RealityDevice") { Some("Apple Vision Pro (unknown)") }
            else { None }
        }
    }
}

/// Extract a simple XML tag value from an XML string.
/// e.g. extract_xml_tag(xml, "friendlyName") from "<friendlyName>Roku</friendlyName>" → Some("Roku")
fn extract_xml_tag(xml: &str, tag: &str) -> Option<String> {
    let open = format!("<{}>", tag);
    let close = format!("</{}>", tag);
    let start = xml.find(&open)? + open.len();
    let end = xml[start..].find(&close)? + start;
    let value = xml[start..end].trim().to_string();
    if value.is_empty() { None } else { Some(value) }
}

/// Validate that a SSDP LOCATION URL points to a local IP to prevent SSRF.
/// Rejects hostnames (DNS rebinding) and any non-local IP address.
fn is_local_ssdp_url(url: &str) -> bool {
    let host = url
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .split('/')
        .next()
        .and_then(|h| h.split(':').next())
        .unwrap_or("");
    if let Ok(ip) = host.parse::<std::net::IpAddr>() {
        crate::display::is_local_ip(&ip)
    } else {
        false
    }
}

/// Discover UPnP/SSDP devices on the local network via M-SEARCH multicast.
/// Returns a map of IP → device metadata extracted from XML descriptions.
#[cfg(windows)]
fn ssdp_discover(timeout_secs: u64) -> HashMap<IpAddr, HashMap<String, String>> {
    use std::net::{SocketAddr, UdpSocket};

    let mut results: HashMap<IpAddr, HashMap<String, String>> = HashMap::new();

    // Create UDP socket
    let sock = match socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP)) {
        Ok(s) => s,
        Err(_) => return results,
    };
    let _ = sock.set_reuse_address(true);
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    if sock.bind(&bind_addr.into()).is_err() {
        return results;
    }
    let socket: UdpSocket = sock.into();
    let _ = socket.set_read_timeout(Some(Duration::from_millis(1500)));

    let ssdp_addr: SocketAddr = "239.255.255.250:1900".parse().unwrap();

    // Send M-SEARCH request
    let search_msg = "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 2\r\n\
        ST: ssdp:all\r\n\
        \r\n";
    let _ = socket.send_to(search_msg.as_bytes(), ssdp_addr);

    // Also search specifically for root devices
    let search_root = "M-SEARCH * HTTP/1.1\r\n\
        HOST: 239.255.255.250:1900\r\n\
        MAN: \"ssdp:discover\"\r\n\
        MX: 2\r\n\
        ST: upnp:rootdevice\r\n\
        \r\n";
    let _ = socket.send_to(search_root.as_bytes(), ssdp_addr);

    // Collect responses and extract LOCATION URLs
    let mut locations: HashMap<IpAddr, String> = HashMap::new();
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let mut buf = [0u8; 4096];

    while start.elapsed() < timeout {
        match socket.recv_from(&mut buf) {
            Ok((len, src_addr)) => {
                if let Ok(response) = std::str::from_utf8(&buf[..len]) {
                    // Extract LOCATION header
                    for line in response.lines() {
                        let lower = line.to_lowercase();
                        if lower.starts_with("location:") {
                            let url = line[9..].trim().to_string();
                            if url.starts_with("http") && is_local_ssdp_url(&url) {
                                locations.entry(src_addr.ip()).or_insert(url);
                            }
                        }
                    }
                }
            }
            Err(_) => {
                if start.elapsed() < timeout {
                    continue;
                } else {
                    break;
                }
            }
        }
    }

    // Fetch XML descriptions from each unique LOCATION
    for (ip, url) in &locations {
        let xml = match ureq::get(url)
            .timeout(Duration::from_secs(3))
            .call()
        {
            Ok(resp) => match resp.into_string() {
                Ok(body) => body,
                Err(_) => continue,
            },
            Err(_) => continue,
        };

        let mut meta = HashMap::new();

        if let Some(name) = extract_xml_tag(&xml, "friendlyName") {
            meta.insert("friendly_name".to_string(), name);
        }
        if let Some(mfr) = extract_xml_tag(&xml, "manufacturer") {
            meta.insert("manufacturer".to_string(), mfr);
        }
        if let Some(model) = extract_xml_tag(&xml, "modelName") {
            meta.insert("model_name".to_string(), model);
        }
        if let Some(num) = extract_xml_tag(&xml, "modelNumber") {
            meta.insert("model_number".to_string(), num);
        }
        if let Some(serial) = extract_xml_tag(&xml, "serialNumber") {
            meta.insert("serial".to_string(), serial);
        }
        if let Some(desc) = extract_xml_tag(&xml, "modelDescription") {
            meta.insert("description".to_string(), desc);
        }

        // Collect service types
        let mut services = Vec::new();
        let mut search_from = 0;
        while let Some(start_pos) = xml[search_from..].find("<serviceType>") {
            let abs_start = search_from + start_pos + 13;
            if let Some(end_pos) = xml[abs_start..].find("</serviceType>") {
                let svc = xml[abs_start..abs_start + end_pos].trim();
                // Shorten URN to just the service name
                let short = svc.rsplit(':').nth(1).unwrap_or(svc);
                services.push(short.to_string());
                search_from = abs_start + end_pos;
            } else {
                break;
            }
        }
        if !services.is_empty() {
            meta.insert("services".to_string(), services.join(", "));
        }

        if !meta.is_empty() {
            results.insert(*ip, meta);
        }
    }

    results
}

/// Discover Windows devices via WS-Discovery (WSD) Probe multicast.
/// Windows PCs, printers, and NAS devices respond to WSD probes with their name and type.
#[cfg(windows)]
fn wsd_discover(timeout_secs: u64) -> HashMap<IpAddr, HashMap<String, String>> {
    use std::net::{SocketAddr, UdpSocket};

    let mut results: HashMap<IpAddr, HashMap<String, String>> = HashMap::new();

    let sock = match socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP)) {
        Ok(s) => s,
        Err(_) => return results,
    };
    let _ = sock.set_reuse_address(true);
    let bind_addr: SocketAddr = "0.0.0.0:0".parse().unwrap();
    if sock.bind(&bind_addr.into()).is_err() {
        return results;
    }
    let socket: UdpSocket = sock.into();
    let _ = socket.set_read_timeout(Some(Duration::from_millis(1500)));

    let wsd_addr: SocketAddr = "239.255.255.250:3702".parse().unwrap();

    // WS-Discovery Probe message
    // Build a UUID that won't repeat within the same second: mix nanosecond time
    // with pid using a multiplicative hash so sequential scans get distinct IDs.
    let now_ns = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos() as u64;
    let pid = std::process::id() as u64;
    let mix = now_ns.wrapping_mul(6364136223846793005u64).wrapping_add(pid);
    let msg_id = format!("urn:uuid:{:08x}-{:04x}-4{:03x}-{:04x}-{:012x}",
        (mix >> 32) as u32,
        (mix >> 16) as u16,
        mix as u16 & 0x0FFF,
        0x8000u16 | ((mix >> 48) as u16 & 0x3FFF),
        now_ns & 0x0000_FFFF_FFFF_FFFF);

    let probe = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<soap:Envelope xmlns:soap="http://www.w3.org/2003/05/soap-envelope" xmlns:wsa="http://schemas.xmlsoap.org/ws/2004/08/addressing" xmlns:wsd="http://schemas.xmlsoap.org/ws/2005/04/discovery" xmlns:wsdp="http://schemas.xmlsoap.org/ws/2006/02/devprof">
  <soap:Header>
    <wsa:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</wsa:To>
    <wsa:Action>http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</wsa:Action>
    <wsa:MessageID>{}</wsa:MessageID>
  </soap:Header>
  <soap:Body>
    <wsd:Probe/>
  </soap:Body>
</soap:Envelope>"#, msg_id);

    let _ = socket.send_to(probe.as_bytes(), wsd_addr);

    // Collect responses
    let start = std::time::Instant::now();
    let timeout = Duration::from_secs(timeout_secs);
    let mut buf = [0u8; 8192];

    while start.elapsed() < timeout {
        match socket.recv_from(&mut buf) {
            Ok((len, src_addr)) => {
                if let Ok(response) = std::str::from_utf8(&buf[..len]) {
                    let mut meta = HashMap::new();

                    // Extract device types
                    if let Some(types) = extract_xml_tag(response, "wsd:Types")
                        .or_else(|| extract_xml_tag(response, "d:Types")) {
                        let short_types: Vec<&str> = types.split_whitespace()
                            .map(|t| t.rsplit(':').next().unwrap_or(t))
                            .collect();
                        if !short_types.is_empty() {
                            meta.insert("wsd_types".to_string(), short_types.join(", "));
                        }
                        // Detect device class from WSD types
                        let types_lower = types.to_lowercase();
                        if types_lower.contains("computer") {
                            meta.insert("wsd_class".to_string(), "Computer".to_string());
                        } else if types_lower.contains("printer") || types_lower.contains("print") {
                            meta.insert("wsd_class".to_string(), "Printer".to_string());
                        } else if types_lower.contains("scanner") {
                            meta.insert("wsd_class".to_string(), "Scanner".to_string());
                        } else if types_lower.contains("device") {
                            meta.insert("wsd_class".to_string(), "Device".to_string());
                        }
                    }

                    // Extract XAddrs (device service URLs — often contain hostname)
                    if let Some(xaddrs) = extract_xml_tag(response, "wsd:XAddrs")
                        .or_else(|| extract_xml_tag(response, "d:XAddrs")) {
                        // Try to extract hostname from URL like "http://DESKTOP-ABC123:5357/..."
                        for addr in xaddrs.split_whitespace() {
                            if let Some(host_start) = addr.find("://") {
                                let after = &addr[host_start + 3..];
                                let host = after.split(':').next()
                                    .unwrap_or(after.split('/').next().unwrap_or(""));
                                // Only use if it looks like a hostname (not an IP)
                                if !host.is_empty() && !host.chars().next().unwrap_or('0').is_ascii_digit() {
                                    meta.insert("wsd_hostname".to_string(), host.to_string());
                                    break;
                                }
                            }
                        }
                    }

                    if !meta.is_empty() {
                        results.insert(src_addr.ip(), meta);
                    }
                }
            }
            Err(_) => {
                if start.elapsed() < timeout {
                    continue;
                } else {
                    break;
                }
            }
        }
    }

    results
}

/// Parse an mDNS response packet to extract ALL IP → hostname mappings from PTR answers
fn parse_mdns_ptr_responses(data: &[u8]) -> Vec<(std::net::Ipv4Addr, String)> {
    let mut results = Vec::new();
    if data.len() < 12 { return results; }

    // Check if this is a response (QR bit set)
    if data[2] & 0x80 == 0 { return results; }

    let qdcount = u16::from_be_bytes([data[4], data[5]]) as usize;
    let ancount = u16::from_be_bytes([data[6], data[7]]) as usize;
    let nscount = u16::from_be_bytes([data[8], data[9]]) as usize;
    let arcount = u16::from_be_bytes([data[10], data[11]]) as usize;
    let total_records = ancount + nscount + arcount;
    if total_records == 0 { return results; }

    let mut offset = 12;
    for _ in 0..qdcount {
        if let Some(next) = skip_dns_name(data, offset) {
            offset = next + 4; // QTYPE + QCLASS
        } else {
            return results;
        }
    }

    // Parse all records
    for _ in 0..total_records {
        // Read the name (should be the reverse IP)
        let (name, next) = match read_dns_name(data, offset) {
            Some(res) => res,
            None => break,
        };
        offset = next;

        if offset + 10 > data.len() { break; }
        let rtype = u16::from_be_bytes([data[offset], data[offset + 1]]);
        let rdlength = u16::from_be_bytes([data[offset + 8], data[offset + 9]]) as usize;
        offset += 10;

        if rtype == 12 { // PTR record
            // Parse the PTR data (hostname)
            if let Some((hostname, _)) = read_dns_name(data, offset) {
                // Extract IP from the reverse name (e.g. "25.4.168.192.in-addr.arpa")
                let parts: Vec<&str> = name.split('.').collect();
                if parts.len() >= 4 {
                    if let (Ok(a), Ok(b), Ok(c), Ok(d)) = (
                        parts[3].parse::<u8>(), parts[2].parse::<u8>(),
                        parts[1].parse::<u8>(), parts[0].parse::<u8>()
                    ) {
                        let ip = std::net::Ipv4Addr::new(a, b, c, d);
                        results.push((ip, hostname));
                    }
                }
            }
        }
        offset += rdlength;
    }
    results
}

/// Skip a DNS name in a packet, returning the offset after it
fn skip_dns_name(data: &[u8], mut offset: usize) -> Option<usize> {
    let mut visited = std::collections::HashSet::new();
    loop {
        if offset >= data.len() { return None; }
        let len = data[offset] as usize;
        if len == 0 { return Some(offset + 1); }
        if len >= 0xC0 {
            // Compression pointer
            if offset + 1 >= data.len() { return None; }
            if !visited.insert(offset) { return None; }
            return Some(offset + 2);
        }
        // Normal label bounds check
        if offset + 1 + len > data.len() { return None; }
        offset += 1 + len;
    }
}

fn read_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut end_offset = None;
    let mut jumps = 0;
    let mut visited = std::collections::HashSet::new();

    loop {
        if offset >= data.len() || jumps > 10 { return None; }
        let len = data[offset] as usize;

        if len == 0 {
            if end_offset.is_none() { end_offset = Some(offset + 1); }
            break;
        }

        if len >= 0xC0 {
            // Compression pointer
            if offset + 1 >= data.len() { return None; }
            if !visited.insert(offset) { return None; }
            if end_offset.is_none() { end_offset = Some(offset + 2); }
            let ptr = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            offset = ptr;
            jumps += 1;
            continue;
        }

        // Normal label bounds check before label read
        if offset + 1 + len > data.len() { return None; }
        offset += 1;
        parts.push(String::from_utf8_lossy(&data[offset..offset + len]).to_string());
        offset += len;
    }

    Some((parts.join("."), end_offset.unwrap_or(offset)))
}

/// Try to resolve hostname via NetBIOS on Windows (more reliable than DNS for local devices)
#[cfg(windows)]
fn resolve_netbios_name(ip: &IpAddr) -> Option<String> {
    let ip_str = ip.to_string();
    let (tx, rx) = std::sync::mpsc::channel();

    let ip_str_clone = ip_str.clone();
    std::thread::spawn(move || {
        let result = Command::new("nbtstat")
            .args(["-A", &ip_str_clone])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output();
        let _ = tx.send(result);
    });

    let output = rx.recv_timeout(Duration::from_secs(5)).ok()?.ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);

    // Parse output for the machine name (line with <00> and UNIQUE)
    for line in stdout.lines() {
        let line_upper = line.to_uppercase();
        if line_upper.contains("<00>") && line_upper.contains("UNIQUE") {
            // Extract the name (first 15 chars before <00>)
            let name = line.split('<').next()?.trim();
            if !name.is_empty() && name != ip_str {
                return Some(name.to_string());
            }
        }
    }
    None
}

/// Batch-resolve hostnames for multiple IPs in a single PowerShell process.
/// Replaces per-IP spawning which created one powershell.exe per device.
#[cfg(windows)]
fn resolve_powershell_dns_batch(ips: &[IpAddr]) -> HashMap<IpAddr, String> {
    let mut results = HashMap::new();
    if ips.is_empty() { return results; }

    let ip_list = ips.iter()
        .map(|ip| format!("'{}'", ip))
        .collect::<Vec<_>>()
        .join(",");
    let script = format!(
        "foreach ($ip in @({})) {{ try {{ $h = (Resolve-DnsName -Name $ip -DnsOnly -EA Stop).NameHost | Select-Object -First 1; if ($h) {{ \"$ip=$h\" }} }} catch {{}} }}",
        ip_list
    );

    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let out = Command::new("powershell")
            .args(["-NoProfile", "-Command", &script])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output();
        let _ = tx.send(out);
    });

    let timeout = Duration::from_secs((ips.len() as u64 / 5).max(10) + 10);
    if let Ok(Ok(output)) = rx.recv_timeout(timeout) {
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines() {
            let line = line.trim();
            if let Some(eq) = line.find('=') {
                let ip_str = &line[..eq];
                let hostname = line[eq + 1..].trim();
                if hostname.is_empty() || hostname.contains("Error") { continue; }
                if let Ok(ip) = ip_str.parse::<IpAddr>() {
                    let clean = hostname.split('.').next().unwrap_or(hostname).to_string();
                    if !clean.is_empty() && clean != ip_str {
                        results.insert(ip, clean);
                    }
                }
            }
        }
    }
    results
}



/// Get the baseline directory path: %APPDATA%\VoraRecon\baselines\
fn get_baseline_dir() -> Option<PathBuf> {
    let appdata = std::env::var("APPDATA").ok()?;
    let mut path = PathBuf::from(appdata);
    path.push("VoraRecon");
    path.push("baselines");
    Some(path)
}

/// Get the baseline file path for a given network name
fn get_baseline_path(network_name: &str) -> Option<PathBuf> {
    let mut path = get_baseline_dir()?;
    // Sanitize network name for filename
    let safe_name = network_name.chars().map(|c| if c.is_alphanumeric() || c == '-' || c == '_' { c } else { '_' }).collect::<String>();
    path.push(format!("{}.json", safe_name));
    Some(path)
}



/// Save baseline to disk
pub fn save_baseline(network_name: &str, devices: &HashMap<IpAddr, DeviceInfo>) {
    let path = match get_baseline_path(network_name) {
        Some(p) => p,
        None => return,
    };

    // Ensure directory exists
    if let Some(parent) = path.parent() {
        let _ = fs::create_dir_all(parent);
    }

    // Serialize and write
    if let Ok(json) = serde_json::to_string_pretty(devices) {
        let _ = fs::write(&path, json);
    }
}

/// Load baseline from disk for a given network.
/// All loaded entries are marked stale (miss_count ≥ 1) so they display
/// with relative timestamps ("Xm ago") until re-confirmed by a live scan.
pub fn load_baseline(network_name: &str) -> HashMap<IpAddr, DeviceInfo> {
    let path = match get_baseline_path(network_name) {
        Some(p) => p,
        None => return HashMap::new(),
    };

    match fs::read_to_string(&path) {
        Ok(json) => {
            match serde_json::from_str::<HashMap<IpAddr, DeviceInfo>>(&json) {
                Ok(mut devices) => {
                    // Mark all baseline entries as stale so they show
                    // "Xm ago" timestamps until re-confirmed by a live scan
                    for entry in devices.values_mut() {
                        entry.miss_count = entry.miss_count.max(1);
                    }
                    devices
                }
                Err(_) => HashMap::new(),
            }
        }
        Err(_) => HashMap::new(),
    }
}

#[cfg(windows)]
use winapi::shared::ws2def::{AF_INET, AF_INET6, AF_UNSPEC};
#[cfg(windows)]
use winapi::shared::netioapi::{MIB_IPNET_ROW2, MIB_IPNET_TABLE2, FreeMibTable, GetIpNetTable2};

// NL_NEIGHBOR_STATE values for ARP table filtering
// Accept all states that indicate the device has been seen on the network,
// not just REACHABLE/PERMANENT which decay quickly between scans.
#[cfg(windows)]
const NLNS_REACHABLE: u32 = 2;
#[cfg(windows)]
const NLNS_DELAY: u32 = 3;
#[cfg(windows)]
const NLNS_STALE: u32 = 4;
#[cfg(windows)]
const NLNS_PROBE: u32 = 5;
#[cfg(windows)]
const NLNS_PERMANENT: u32 = 7;

pub enum DiscoverySignal {
    ScanNow,
}

pub fn start_discovery_thread(
    passive_discovery: Arc<Mutex<HashMap<IpAddr, DeviceInfo>>>,
    active_discovery: Arc<Mutex<HashMap<IpAddr, DeviceInfo>>>,
    device_metadata: Arc<Mutex<DeviceMetadata>>,
    signal_rx: mpsc::Receiver<DiscoverySignal>,
    status_tx: mpsc::Sender<String>,
    alert_tx: mpsc::Sender<String>,
    interface_name: String,
    network_name: String,
) {
    thread::spawn(move || {
        let mut last_cancel_flag: Option<Arc<std::sync::atomic::AtomicBool>> = None;
        let mut pending_scan = false;
        loop {
            // WAIT indefinitely for manual signal or run a pending scan
            let run_scan = if pending_scan {
                pending_scan = false;
                true
            } else {
                match signal_rx.recv() {
                    Ok(DiscoverySignal::ScanNow) => true,
                    Err(mpsc::RecvError) => break,
                }
            };

            if run_scan {
                // Set the previous flag to true (cancelling any running background thread)
                if let Some(prev) = last_cancel_flag.take() {
                    prev.store(true, std::sync::atomic::Ordering::Relaxed);
                }
                
                // Create a new cancellation flag
                let current_cancel = Arc::new(std::sync::atomic::AtomicBool::new(false));
                last_cancel_flag = Some(Arc::clone(&current_cancel));

                // Create Arc<DashMap> for passive, active, metadata
                let passive_dash = Arc::new(DashMap::new());
                {
                    if let Ok(g) = passive_discovery.lock() {
                        for (k, v) in g.iter() {
                            passive_dash.insert(*k, v.clone());
                        }
                    }
                }
                let active_dash = Arc::new(DashMap::new());
                {
                    if let Ok(g) = active_discovery.lock() {
                        for (k, v) in g.iter() {
                            active_dash.insert(*k, v.clone());
                        }
                    }
                }
                let metadata_dash = Arc::new(DashMap::new());
                {
                    if let Ok(g) = device_metadata.lock() {
                        for (k, v) in g.iter() {
                            metadata_dash.insert(*k, v.clone());
                        }
                    }
                }

                // Spawn a background thread that periodically syncs changes from the DashMaps back to the Arc<Mutex<HashMap>>
                let active_clone = Arc::clone(&active_discovery);
                let metadata_clone = Arc::clone(&device_metadata);
                let active_dash_clone = Arc::clone(&active_dash);
                let metadata_dash_clone = Arc::clone(&metadata_dash);
                
                let sync_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
                let sync_stop_clone = Arc::clone(&sync_stop);
                
                let sync_handle = thread::spawn(move || {
                    while !sync_stop_clone.load(std::sync::atomic::Ordering::Relaxed) {
                        // Sync active
                        if let Ok(mut g) = active_clone.lock() {
                            for r in active_dash_clone.iter() {
                                let (k, v) = r.pair();
                                g.insert(*k, v.clone());
                            }
                            g.retain(|k, _| active_dash_clone.contains_key(k));
                        }
                        // Sync metadata
                        if let Ok(mut g) = metadata_clone.lock() {
                            for r in metadata_dash_clone.iter() {
                                let (k, v) = r.pair();
                                g.insert(*k, v.clone());
                            }
                            g.retain(|k, _| metadata_dash_clone.contains_key(k));
                        }
                        thread::sleep(Duration::from_millis(200));
                    }
                    
                    // Perform one final sync upon stopping to ensure all final state is saved
                    if let Ok(mut g) = active_clone.lock() {
                        for r in active_dash_clone.iter() {
                            let (k, v) = r.pair();
                            g.insert(*k, v.clone());
                        }
                        g.retain(|k, _| active_dash_clone.contains_key(k));
                    }
                    if let Ok(mut g) = metadata_clone.lock() {
                        for r in metadata_dash_clone.iter() {
                            let (k, v) = r.pair();
                            g.insert(*k, v.clone());
                        }
                        g.retain(|k, _| metadata_dash_clone.contains_key(k));
                    }
                });

                // Perform scan using the DashMaps
                let bg_handle = perform_scan(&passive_dash, &active_dash, &metadata_dash, &interface_name, &network_name, &status_tx, &alert_tx, Arc::clone(&current_cancel));

                // Polling loop to wait for bg_handle to complete or handle new incoming ScanNow signals
                while !bg_handle.is_finished() {
                    match signal_rx.try_recv() {
                        Ok(DiscoverySignal::ScanNow) => {
                            // Set cancel flag to true to abort the current background scan immediately
                            current_cancel.store(true, std::sync::atomic::Ordering::Relaxed);
                            pending_scan = true;
                            break;
                        }
                        Err(mpsc::TryRecvError::Empty) => {
                            thread::sleep(Duration::from_millis(50));
                        }
                        Err(mpsc::TryRecvError::Disconnected) => {
                            break;
                        }
                    }
                }

                // Join the background handle to clean up
                let _ = bg_handle.join();

                // Signal the sync thread to stop and join it
                sync_stop.store(true, std::sync::atomic::Ordering::Relaxed);
                let _ = sync_handle.join();
            }
        }
    });
}



#[cfg(windows)]
fn arp_scan(
    interface_name: &str,
    status_tx: &mpsc::Sender<String>,
) -> HashMap<IpAddr, (String, String)> {
    use pnet::datalink::{Channel, MacAddr};
    use pnet::packet::ethernet::{EtherTypes, MutableEthernetPacket};
    use pnet::packet::arp::{ArpHardwareTypes, ArpOperations, ArpPacket, MutableArpPacket};
    use pnet::packet::{MutablePacket, Packet};
    use std::net::Ipv4Addr;

    let mut harvested_results = HashMap::new();
    let interfaces = pnet::datalink::interfaces();

    // Stage 1: Robust Interface Fallback
    let iface = interfaces.into_iter().find(|i| i.name == interface_name || i.description == interface_name)
        .or_else(|| {
            pnet::datalink::interfaces().into_iter().find(|i| {
                !i.is_loopback() && i.ips.iter().any(|ip| ip.is_ipv4())
            })
        });

    if let Some(iface) = iface {
        let source_mac = match iface.mac {
            Some(mac) => mac,
            None => {
                let _ = status_tx.send("Error: Interface has no MAC".to_string());
                return harvested_results;
            }
        };

        let mut source_ip = None;
        let mut subnets_to_sweep = Vec::new();

        for ip_net in &iface.ips {
            if let IpAddr::V4(ipv4) = ip_net.ip() {
                if source_ip.is_none() {
                    source_ip = Some(ipv4);
                }
                
                let mask = ip_net.mask();
                if let IpAddr::V4(v4_mask) = mask {
                    let ip_u32 = u32::from_be_bytes(ipv4.octets());
                    let mask_u32 = u32::from_be_bytes(v4_mask.octets());
                    let network = ip_u32 & mask_u32;
                    let broadcast = network | !mask_u32;
                    subnets_to_sweep.push((network, broadcast));
                }
            }
        }

        let source_ip = match source_ip {
            Some(ip) => ip,
            None => {
                let _ = status_tx.send("Error: Interface has no IPv4".to_string());
                return harvested_results;
            }
        };

        let mut config = pnet::datalink::Config::default();
        config.read_timeout = Some(Duration::from_millis(200));

        let (mut tx, mut rx) = match pnet::datalink::channel(&iface, config) {
            Ok(Channel::Ethernet(tx, rx)) => (tx, rx),
            Ok(_) => {
                let _ = status_tx.send("Error: Unhandled channel type".to_string());
                return harvested_results;
            }
            Err(e) => {
                let _ = status_tx.send(format!("Error creating datalink channel: {}", e));
                return harvested_results;
            }
        };

        let (result_tx, result_rx) = mpsc::channel();
        
        // Receiver thread
        let receiver_handle = thread::spawn(move || {
            let mut results = HashMap::new();
            let start = std::time::Instant::now();
            // Read for 3 seconds
            while start.elapsed() < Duration::from_secs(3) {
                match rx.next() {
                    Ok(packet) => {
                        if let Some(ether) = pnet::packet::ethernet::EthernetPacket::new(packet) {
                            if ether.get_ethertype() == EtherTypes::Arp {
                                if let Some(arp) = ArpPacket::new(ether.payload()) {
                                    if arp.get_operation() == ArpOperations::Reply {
                                        let sender_ip = IpAddr::V4(arp.get_sender_proto_addr());
                                        let sender_mac = arp.get_sender_hw_addr();
                                        
                                        let mac_str = format!("{:02X}:{:02X}:{:02X}:{:02X}:{:02X}:{:02X}", 
                                            sender_mac.0, sender_mac.1, sender_mac.2, sender_mac.3, sender_mac.4, sender_mac.5);
                                        let vendor = crate::oui::get_vendor(&mac_str);
                                        results.insert(sender_ip, (mac_str, vendor));
                                    }
                                }
                            }
                        }
                    }
                    Err(_) => continue,
                }
            }
            let _ = result_tx.send(results);
        });

        // Sender thread
        let total_subnets = subnets_to_sweep.len();
        for (subnet_idx, (network, broadcast)) in subnets_to_sweep.iter().enumerate() {
            let _ = status_tx.send(format!("ARP Scanning Subnet {}/{}...", subnet_idx + 1, total_subnets));

            let max_hosts = broadcast.saturating_sub(*network);
            if max_hosts > 65536 {
                continue; // Skip huge subnets
            }
            
            for i in (*network + 1)..*broadcast {
                let target_ip = Ipv4Addr::from(i);
                
                let mut ethernet_buffer = [0u8; 42];
                let mut ethernet_packet = MutableEthernetPacket::new(&mut ethernet_buffer).unwrap();

                ethernet_packet.set_destination(MacAddr::broadcast());
                ethernet_packet.set_source(source_mac);
                ethernet_packet.set_ethertype(EtherTypes::Arp);

                let mut arp_buffer = [0u8; 28];
                let mut arp_packet = MutableArpPacket::new(&mut arp_buffer).unwrap();

                arp_packet.set_hardware_type(ArpHardwareTypes::Ethernet);
                arp_packet.set_protocol_type(EtherTypes::Ipv4);
                arp_packet.set_hw_addr_len(6);
                arp_packet.set_proto_addr_len(4);
                arp_packet.set_operation(ArpOperations::Request);
                arp_packet.set_sender_hw_addr(source_mac);
                arp_packet.set_sender_proto_addr(source_ip);
                arp_packet.set_target_hw_addr(MacAddr::zero());
                arp_packet.set_target_proto_addr(target_ip);

                ethernet_packet.set_payload(arp_packet.packet_mut());

                let _ = tx.send_to(ethernet_packet.packet(), None);
                
                thread::sleep(Duration::from_micros(100));
            }
        }
        
        let _ = status_tx.send("Waiting for ARP replies...".to_string());
        let _ = receiver_handle.join();
        if let Ok(res) = result_rx.recv() {
            harvested_results = res;
        }

        let _ = status_tx.send("Scan complete.".to_string());
    } else {
        let _ = status_tx.send("Error: No active interface".to_string());
    }
    harvested_results
}

/// Native Windows SendARP probe to bypass firewalls and fill ARP table reliably
#[cfg(windows)]
#[allow(dead_code)]
fn send_arp_probe(target: std::net::Ipv4Addr) -> Option<[u8; 6]> {
    use winapi::um::iphlpapi::SendARP;
    
    // SendARP expects the IP in network byte order as a u32
    let dest_ip_val = u32::from_ne_bytes(target.octets());

    let mut mac_addr = [0u8; 6];
    let mut mac_len = 6u32;
    
    unsafe {
        let res = SendARP(dest_ip_val, 0, mac_addr.as_mut_ptr() as *mut _, &mut mac_len);
        if res == 0 && mac_addr != [0u8; 6] {
            Some(mac_addr)
        } else {
            None
        }
    }
}


/// Check if an IP is a private/local address worth resolving hostname for
fn should_resolve_hostname(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            // Only resolve for private networks: 10.x.x.x, 172.16-31.x.x, 192.168.x.x
            matches!(o, [192, 168, _, _] | [10, _, _, _] | [172, 16..=31, _, _])
        }
        IpAddr::V6(v6) => {
            // Resolve link-local IPv6 (fe80::) — Apple devices often only appear here
            let seg = v6.segments();
            seg[0] == 0xfe80
        }
    }
}

fn has_hex_segment(name: &str) -> bool {
    let chars: Vec<char> = name.chars().collect();
    if chars.len() < 10 { return false; }
    for window in chars.windows(10) {
        if window.iter().all(|c| c.is_ascii_hexdigit()) {
            return true;
        }
    }
    false
}

fn select_best_hostname(candidates: &[String]) -> Option<String> {
    if candidates.is_empty() { return None; }
    let best = candidates.iter().enumerate().max_by_key(|(idx, c)| {
        (!has_hex_segment(c), c.len(), std::cmp::Reverse(*idx))
    }).map(|(_, c)| c.clone())?;
    // Reject even the "best" candidate if it's still a hex string (e.g. a MAC-derived .local name)
    if has_hex_segment(&best) { None } else { Some(best) }
}

/// Probe a single Apple device via unicast mDNS to extract model info.
/// Sends QU-bit queries directly to the target IP on port 5353.
#[cfg(windows)]
fn probe_apple_unicast_mdns(target: std::net::Ipv4Addr, timeout_ms: u64) -> Option<(String, DeviceDetails)> {
    use std::net::UdpSocket;

    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.set_read_timeout(Some(Duration::from_millis(timeout_ms))).ok()?;

    let target_addr = std::net::SocketAddr::new(IpAddr::V4(target), 5353);

    // Services to probe for model identification
    // _rdlink (rapportd) is the most reliably present service on modern iOS.
    // _device-info has been deprioritized by iOS — don't rely on it.
    let probe_services = [
        "_rdlink._tcp.local",
        "_companion-link._tcp.local",
        "_apple-mobdev2._tcp.local",
        "_raop._tcp.local",
        "_continuity._tcp.local",
    ];

    // Build and send QU-bit queries (unicast-response requested)
    for (i, service) in probe_services.iter().enumerate() {
        let query = build_mdns_qu_query(service, (i + 500) as u16);
        let _ = sock.send_to(&query, target_addr);
    }

    let mut a_candidates = Vec::new();
    let mut instance_candidates = Vec::new();
    let mut metadata = DeviceDetails::default();
    let start = std::time::Instant::now();
    let mut sent_a_query = false;

    while start.elapsed() < Duration::from_millis(timeout_ms) {
        let mut buf = [0u8; 4096];
        match sock.recv_from(&mut buf) {
            Ok((len, _)) => {
                let data = &buf[..len];
                // Extract hostname from A records
                for (name, _ip) in parse_mdns_a_records(data) {
                    let clean = name.trim_end_matches(".local").trim_end_matches('.').to_string();
                    if !clean.is_empty() {
                        if !sent_a_query {
                            let a_query = build_mdns_a_query(&format!("{}.local", clean), 600);
                            let _ = sock.send_to(&a_query, target_addr);
                            sent_a_query = true;
                        }
                        a_candidates.push(clean);
                    }
                }
                // Extract hostname from PTR service instances too
                for instance_name in parse_mdns_service_instances(data) {
                    let device_name = instance_name.split("._").next().unwrap_or("");
                    let device_name = device_name.split('@').last().unwrap_or(device_name).trim();
                    if !device_name.is_empty() {
                        instance_candidates.push(device_name.to_string());
                    }
                }
                // Extract model info from TXT records
                for (record_name, pairs) in parse_mdns_txt_records(data) {
                    for (key, value) in &pairs {
                        match key.as_str() {
                            "rpmd" | "model" | "wmodel" => {
                                metadata.properties.insert("model_code".to_string(), value.clone());
                                if let Some(human) = resolve_apple_model(value) {
                                    metadata.properties.insert("model".to_string(), human.to_string());
                                }
                            }
                            "am" => {
                                if !metadata.properties.contains_key("model_code") {
                                    metadata.properties.insert("model_code".to_string(), value.clone());
                                    if let Some(human) = resolve_apple_model(value) {
                                        metadata.properties.insert("model".to_string(), human.to_string());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    // Track services from unicast probe responses
                    if record_name.contains("_rdlink") { metadata.services.insert("Rapport".to_string()); }
                    if record_name.contains("_companion-link") { metadata.services.insert("Apple Companion".to_string()); }
                    if record_name.contains("_apple-mobdev2") { metadata.services.insert("iPhone/iPad".to_string()); }
                    if record_name.contains("_continuity") { metadata.services.insert("Continuity".to_string()); }
                }
            }
            Err(_) => {
                // Timeout on recv — if we have candidates, send follow-up A query on the best so far
                let current_best = select_best_hostname(&a_candidates)
                    .or_else(|| select_best_hostname(&instance_candidates));
                if let Some(ref name) = current_best {
                    if !sent_a_query {
                        let a_query = build_mdns_a_query(&format!("{}.local", name), 601);
                        let _ = sock.send_to(&a_query, target_addr);
                        sent_a_query = true;
                        continue; // Keep listening for the A response
                    }
                }
                break;
            }
        }
    }

    let best_a = select_best_hostname(&a_candidates);
    let best_inst = select_best_hostname(&instance_candidates);

    let final_hostname = match (best_a, best_inst) {
        (Some(a), Some(inst)) => {
            if has_hex_segment(&a) && !has_hex_segment(&inst) {
                Some(inst)
            } else {
                Some(a)
            }
        }
        (Some(a), None) => Some(a),
        (None, Some(inst)) => Some(inst),
        (None, None) => None,
    };

    if final_hostname.is_some() || !metadata.is_empty() {
        Some((final_hostname.unwrap_or_default(), metadata))
    } else {
        None
    }
}

/// Build a unicast mDNS query with the QU bit set (class 0x8001 instead of 0x0001).
/// This requests a unicast response directly to the querier, rather than multicast.
#[cfg(windows)]
fn build_mdns_qu_query(service: &str, id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);

    // DNS Header
    pkt.extend_from_slice(&id.to_be_bytes());  // Transaction ID
    pkt.extend_from_slice(&[0x00, 0x00]);       // Flags: standard query
    pkt.extend_from_slice(&[0x00, 0x01]);       // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]);       // Answers: 0
    pkt.extend_from_slice(&[0x00, 0x00]);       // Authority: 0
    pkt.extend_from_slice(&[0x00, 0x00]);       // Additional: 0

    // Question: service name as DNS labels
    for part in service.split('.') {
        if part.is_empty() { continue; }
        pkt.push(part.len() as u8);
        pkt.extend_from_slice(part.as_bytes());
    }
    pkt.push(0); // Null terminator

    // Type: PTR (12), Class: IN with QU bit (0x8001)
    pkt.extend_from_slice(&[0x00, 0x0C]); // Type PTR
    pkt.extend_from_slice(&[0x80, 0x01]); // Class IN + QU bit (unicast response requested)

    pkt
}

/// Build a unicast mDNS A record query with the QU bit set.
/// Used to directly resolve a hostname (e.g., "iPhone.local") when we already
/// know the hostname from a previous mDNS announcement.
#[cfg(windows)]
fn build_mdns_a_query(hostname: &str, id: u16) -> Vec<u8> {
    let mut pkt = Vec::with_capacity(64);

    // DNS Header
    pkt.extend_from_slice(&id.to_be_bytes());  // Transaction ID
    pkt.extend_from_slice(&[0x00, 0x00]);       // Flags: standard query
    pkt.extend_from_slice(&[0x00, 0x01]);       // Questions: 1
    pkt.extend_from_slice(&[0x00, 0x00]);       // Answers: 0
    pkt.extend_from_slice(&[0x00, 0x00]);       // Authority: 0
    pkt.extend_from_slice(&[0x00, 0x00]);       // Additional: 0

    // Question: hostname as DNS labels
    for part in hostname.split('.') {
        if part.is_empty() { continue; }
        pkt.push(part.len() as u8);
        pkt.extend_from_slice(part.as_bytes());
    }
    pkt.push(0); // Null terminator

    // Type: A (1), Class: IN with QU bit (0x8001)
    pkt.extend_from_slice(&[0x00, 0x01]); // Type A
    pkt.extend_from_slice(&[0x80, 0x01]); // Class IN + QU bit (unicast response requested)

    pkt
}

/// Passive mDNS listener that captures unsolicited announcements from Apple devices.
/// Runs for the specified duration, recording any device that broadcasts on 224.0.0.251:5353.
/// Returns: (ip_to_hostname, ip_to_metadata)
#[cfg(windows)]
fn passive_mdns_listener(
    duration: Duration,
    stop_flag: Arc<std::sync::atomic::AtomicBool>,
    interface_ip: std::net::Ipv4Addr,
    hosts: Arc<DashMap<IpAddr, String>>,
    metadata: Arc<DashMap<IpAddr, DeviceDetails>>,
) {
    use std::net::{SocketAddr, UdpSocket, Ipv4Addr};
    let mut local_hosts = HashMap::new();
    let mut local_metadata = HashMap::new();

    let sock = match socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP)) {
        Ok(s) => s,
        Err(_) => return,
    };
    let _ = sock.set_reuse_address(true);
    let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
    if sock.bind(&bind_addr.into()).is_err() {
        return;
    }
    
    let mdns_group = Ipv4Addr::new(224, 0, 0, 251);
    let _ = sock.join_multicast_v4(&mdns_group, &interface_ip);

    let socket: UdpSocket = sock.into();
    let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));

    let start = std::time::Instant::now();
    let mut buf = [0u8; 4096];

    while start.elapsed() < duration && !stop_flag.load(std::sync::atomic::Ordering::Relaxed) {
        match socket.recv_from(&mut buf) {
            Ok((len, src_addr)) => {
                let data = &buf[..len];
                if let IpAddr::V4(src_v4) = src_addr.ip() {
                    process_mdns_packet(data, src_v4, &mut local_hosts, &mut local_metadata);
                    // Write to the shared DashMaps in real-time
                    for (ip, name) in &local_hosts {
                        hosts.insert(*ip, name.clone());
                    }
                    for (ip, details) in &local_metadata {
                        metadata.insert(*ip, details.clone());
                    }
                }
            }
            Err(_) => continue,
        }
    }
    
    let _ = socket.leave_multicast_v4(&mdns_group, &interface_ip);
}

/// Wake stale Apple/unknown iPhones in sleep-proxy mode and probe them
#[cfg(windows)]
fn wake_iphones_and_probe(
    stale_candidates: &[std::net::Ipv4Addr],
    interface_v4: std::net::Ipv4Addr,
    device_metadata: &Arc<DashMap<IpAddr, DeviceDetails>>,
    harvested_results: &mut HashMap<IpAddr, (String, String)>,
    new_map: &mut HashMap<IpAddr, DeviceInfo>,
    status_tx: &mpsc::Sender<String>,
) {
    if stale_candidates.is_empty() { return; }
    
    let _ = status_tx.send(format!("Waking and probing {} stale Apple/unknown device(s)...", stale_candidates.len()));
    
    // 1. Send _sleep-proxy._udp.local PTR query to multicast group
    if let Ok(sock) = socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP)) {
        let _ = sock.bind(&"0.0.0.0:0".parse::<std::net::SocketAddr>().unwrap().into());
        let _ = sock.set_multicast_if_v4(&interface_v4);
        let mdns_multicast_addr = socket2::SockAddr::from("224.0.0.251:5353".parse::<std::net::SocketAddr>().unwrap());
        let query = build_mdns_service_query("_sleep-proxy._udp.local", 1234);
        let _ = sock.send_to(&query, &mdns_multicast_addr);
    }
    
    // Give sleep proxies a tiny moment to wake devices
    std::thread::sleep(std::time::Duration::from_millis(100));
    
    // 2. Send unicast QU probes to the candidates in parallel using 4-second response window
    let (result_tx, result_rx) = mpsc::channel();
    let ips_to_probe = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from(stale_candidates.to_vec())));
    
    thread::scope(|s| {
        for _ in 0..8 {
            let ips = Arc::clone(&ips_to_probe);
            let tx = result_tx.clone();
            s.spawn(move || {
                loop {
                    let next_ip = {
                        let mut guard = ips.lock().unwrap();
                        guard.pop_front()
                    };
                    match next_ip {
                        Some(v4) => {
                            // Use 4-second response window
                            let result = probe_apple_unicast_mdns(v4, 4000);
                            let _ = tx.send((v4, result));
                        }
                        None => break,
                    }
                }
            });
        }
    });
    drop(result_tx);
    
    for (v4, probe_result) in result_rx {
        if let Some((hostname, meta)) = probe_result {
            let ip_key = IpAddr::V4(v4);
            
            // Update new_map entry
            if let Some(entry) = new_map.get_mut(&ip_key) {
                if !hostname.is_empty() {
                    entry.hostname = hostname.clone();
                }
                if meta.properties.contains_key("model") || meta.properties.contains_key("model_code") {
                    if entry.vendor == "Unknown" || entry.vendor == "Randomized MAC" {
                        entry.vendor = "Apple Inc.".to_string();
                    }
                }
            }

            if !meta.is_empty() {
                let mut entry = device_metadata.entry(ip_key).or_insert_with(DeviceDetails::default);
                for (k, v) in &meta.properties {
                    entry.properties.insert(k.clone(), v.clone());
                }
                for svc in &meta.services {
                    entry.services.insert(svc.clone());
                }
                drop(entry);
                
                if meta.properties.contains_key("model") || meta.properties.contains_key("model_code") {
                    if let Some((_mac, vendor)) = harvested_results.get_mut(&ip_key) {
                        if vendor == "Randomized MAC" || vendor == "Unknown" {
                            *vendor = "Apple Inc.".to_string();
                        }
                    }
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Device category classification
// ---------------------------------------------------------------------------

/// Classify a device into a compact category tag based on vendor, hostname, and metadata.
pub fn classify_device_category(
    vendor: &str,
    hostname: &str,
    meta: Option<&DeviceDetails>,
) -> Option<&'static str> {
    let v = vendor.to_ascii_lowercase();
    let h = hostname.to_ascii_lowercase();

    let model = meta.and_then(|m| m.get("model").map(|s| s.to_ascii_lowercase()))
        .unwrap_or_default();
    let friendly = meta.and_then(|m| m.get("friendly_name").map(|s| s.to_ascii_lowercase()))
        .unwrap_or_default();
    let services: Vec<String> = meta.map(|m| m.services.iter().map(|s| s.to_ascii_lowercase()).collect())
        .unwrap_or_default();

    let any_contains = |needle: &str| {
        v.contains(needle) || h.contains(needle)
            || model.contains(needle) || friendly.contains(needle)
            || services.iter().any(|s| s.contains(needle))
    };

    // Most-specific matches first
    if any_contains("router") || any_contains("gateway") || h == "eerogw" || h == "eero gateway"
        || v.contains("eero") || v.contains("ubiquiti") || v.contains("netgear") && h.contains("router")
        || v.contains("cisco") && (h.contains("router") || h.contains("gateway"))
    {
        return Some("Router");
    }
    if any_contains("thermostat") || v.contains("ecobee") || v.contains("nest") && h.contains("therm") {
        return Some("Thermostat");
    }
    if any_contains("camera") || any_contains("doorbell") || v.contains("ring") || v.contains("arlo")
        || v.contains("wyze") || v.contains("reolink") || v.contains("hikvision") || v.contains("dahua")
    {
        return Some("Camera");
    }
    if any_contains("printer") || any_contains("laserjet") || v.contains("hp inc") || v.contains("canon")
        || v.contains("brother") || v.contains("epson") || v.contains("lexmark") || h.starts_with("npi")
    {
        return Some("Printer");
    }
    if any_contains("playstation") || any_contains("xbox") || any_contains("nintendo")
        || v.contains("sony interactive") || v.contains("microsoft") && h.contains("xbox")
    {
        return Some("Console");
    }
    if any_contains("apple tv") || any_contains("appletv") || any_contains("fire tv")
        || any_contains("chromecast") || any_contains("roku") || v.contains("google") && h.contains("tv")
        || v.contains("amazon") && h.contains("tv") || any_contains("shield")
    {
        return Some("Streamer");
    }
    if any_contains("homepod") || any_contains("sonos") || any_contains("bose soundbar")
        || any_contains("airplay") && !any_contains("iphone") && !any_contains("macbook")
        || v.contains("sonos") || v.contains("bose") && any_contains("speaker")
        || v.contains("denon") || v.contains("harman") || v.contains("bang & olufsen")
    {
        return Some("Speaker");
    }
    if any_contains("samsung tv") || any_contains("lg tv") || any_contains("vizio") || any_contains("tcl tv")
        || friendly.contains("tv") && (v.contains("samsung") || v.contains("lg electronics"))
        || v.contains("samsung electronics") && (
            h.contains("frame") || h.contains("qled") || h.contains("oled")
            || h.contains("crystal") || h.contains("serif") || h.contains("terrace")
            || h.starts_with("samsung q") || h.starts_with("samsung un")
            || h.starts_with("samsung the") || h.starts_with("samsung s9")
        )
        || v.contains("lg electronics") && (h.contains("oled") || h.contains("nanocell") || h.contains("qned"))
    {
        return Some("TV");
    }
    if any_contains("echo") && (v.contains("amazon") || h.contains("echo"))
        || any_contains("alexa") || h.starts_with("echo-") || h.starts_with("echo ")
    {
        return Some("Echo");
    }
    if any_contains("smart plug") || any_contains("outlet") || any_contains("kasa")
        || v.contains("tp-link") && any_contains("plug") || v.contains("wemo") || v.contains("belkin")
    {
        return Some("SmartPlug");
    }
    if any_contains("hub") || any_contains("bridge") && !h.contains("air")
        || v.contains("phillips") || v.contains("philips lighting") || v.contains("signify")
        || v.contains("samsung smarthings") || v.contains("smartthings")
        || h.contains("hue bridge") || h.contains("hue hub")
    {
        return Some("Hub");
    }
    if any_contains("sprinkler") || any_contains("rachio") || v.contains("rachio") {
        return Some("Sprinkler");
    }
    if any_contains("garage") || v.contains("chamberlain") || v.contains("liftmaster") {
        return Some("Garage");
    }
    if any_contains("washer") || any_contains("dryer") || any_contains("refrigerator")
        || any_contains("dishwasher") || any_contains("oven") || any_contains("microwave")
    {
        return Some("Appliance");
    }
    if any_contains("iphone") || any_contains("galaxy") || any_contains("pixel phone")
        || h.contains("android") && (h.contains("phone") || h.contains("mobile"))
    {
        return Some("Phone");
    }
    if any_contains("ipad") || any_contains("macbook")
        || any_contains("imac") || any_contains("mac mini") || any_contains("mac pro")
        || any_contains("windows") || any_contains("linux") && !any_contains("router")
        || any_contains("android")
    {
        return Some("PC");
    }
    // Catch-all for ESP/Arduino/unknown IoT
    if v.contains("espressif") || v.contains("arduino") || any_contains("iot") {
        return Some("IoT");
    }

    None
}

// ---------------------------------------------------------------------------
// HTTP banner scanning — tries common ports and extracts device identity
// ---------------------------------------------------------------------------

/// Extract the content of the first <title> tag from HTML.
fn extract_html_title(html: &str) -> Option<String> {
    let lower = html.to_ascii_lowercase();
    let start = lower.find("<title>")? + 7;
    let end = lower[start..].find("</title>").map(|i| start + i)?;
    let title = html[start..end].trim().to_string();
    if title.is_empty() { None } else { Some(title) }
}

/// Attempt a quick HTTP GET, returning (status, headers_as_text, body_preview).
/// Timeout is 2 seconds — we don't want to block the scan.
fn http_get_with_timeout(url: &str) -> Option<(u16, String, String)> {
    let resp = ureq::get(url)
        .timeout(std::time::Duration::from_secs(2))
        .call()
        .ok()?;
    let status = resp.status();
    let server_header = resp.header("Server").unwrap_or("").to_string();
    let content_type = resp.header("Content-Type").unwrap_or("").to_string();
    let headers = format!("Server: {}\nContent-Type: {}", server_header, content_type);
    let body = resp.into_string().unwrap_or_default();
    let body = if body.len() > 8192 { body[..8192].to_string() } else { body };
    Some((status, headers, body))
}

/// Parse Sonos/UPnP XML description for friendlyName, modelName, manufacturer.
fn parse_xml_description(xml: &str) -> (Option<String>, Option<String>, Option<String>) {
    fn extract_tag<'a>(xml: &'a str, tag: &str) -> Option<String> {
        let open = format!("<{}>", tag);
        let close = format!("</{}>", tag);
        let start = xml.find(&open)? + open.len();
        let end = xml[start..].find(&close).map(|i| start + i)?;
        let v = xml[start..end].trim().to_string();
        if v.is_empty() { None } else { Some(v) }
    }
    (
        extract_tag(xml, "friendlyName"),
        extract_tag(xml, "modelName"),
        extract_tag(xml, "manufacturer"),
    )
}

/// Scan a list of IPs over HTTP to collect device banners, friendly names, and model info.
/// Results are written directly into `meta`.
/// Runs at most 8 concurrent threads per batch to avoid hammering the router and
/// to work around Windows ignoring ureq's timeout on firewall-dropped ports.
fn http_banner_scan(
    ips: &[IpAddr],
    meta: &Arc<DashMap<IpAddr, DeviceDetails>>,
    devices: &Arc<DashMap<IpAddr, DeviceInfo>>,
    status_tx: &mpsc::Sender<String>,
) {
    use std::sync::atomic::{AtomicUsize, Ordering};

    // Skip IPs that already have HTTP banner data from a previous scan this session
    let scan_ips: Vec<IpAddr> = ips.iter().copied()
        .filter(|ip| {
            meta.get(ip)
                .map(|m| !m.properties.contains_key("http_server")
                       && !m.properties.contains_key("html_title")
                       && !m.properties.contains_key("friendly_name"))
                .unwrap_or(true)
        })
        .collect();

    if scan_ips.is_empty() { return; }

    let total = scan_ips.len();
    let done = Arc::new(AtomicUsize::new(0));

    // Process in batches of 8 — wait for each batch to finish before starting the next
    for batch in scan_ips.chunks(8) {
        let handles: Vec<_> = batch.iter().copied().map(|ip| {
            let meta_r = Arc::clone(meta);
            let devices_r = Arc::clone(devices);
            let done_r = Arc::clone(&done);
            let status_r = status_tx.clone();
            let total = total;

            thread::spawn(move || {
                // Port 1400 = Sonos device description
                let sonos_url = format!("http://{}:1400/xml/device_description.xml", ip);
                if let Some((_s, _h, body)) = http_get_with_timeout(&sonos_url) {
                    let (friendly, model, mfr) = parse_xml_description(&body);
                    let mut e = meta_r.entry(ip).or_insert_with(DeviceDetails::default);
                    if let Some(n) = friendly { e.properties.entry("friendly_name".into()).or_insert(n); }
                    if let Some(m) = model    { e.properties.entry("model".into()).or_insert(m); }
                    if let Some(f) = mfr      { e.properties.entry("manufacturer".into()).or_insert(f); }
                }

                // Ports 80, 8080: UPnP XML then HTML fallback
                for port in &[80u16, 8080u16] {
                    let xml_url = format!("http://{}:{}/xml/device_description.xml", ip, port);
                    if let Some((_s, _h, body)) = http_get_with_timeout(&xml_url) {
                        let (friendly, model, mfr) = parse_xml_description(&body);
                        let mut e = meta_r.entry(ip).or_insert_with(DeviceDetails::default);
                        if let Some(n) = friendly { e.properties.entry("friendly_name".into()).or_insert(n); }
                        if let Some(m) = model    { e.properties.entry("model".into()).or_insert(m); }
                        if let Some(f) = mfr      { e.properties.entry("manufacturer".into()).or_insert(f); }
                    }

                    let root_url = format!("http://{}:{}/", ip, port);
                    if let Some((_s, headers, body)) = http_get_with_timeout(&root_url) {
                        if let Some(server) = headers.lines()
                            .find(|l| l.starts_with("Server: "))
                            .map(|l| l[8..].trim().to_string())
                            .filter(|s| !s.is_empty())
                        {
                            meta_r.entry(ip).or_insert_with(DeviceDetails::default)
                                .properties.entry("http_server".into()).or_insert(server);
                        }
                        if let Some(title) = extract_html_title(&body) {
                            meta_r.entry(ip).or_insert_with(DeviceDetails::default)
                                .properties.entry("html_title".into()).or_insert(title.clone());
                            if let Some(mut dev) = devices_r.get_mut(&ip) {
                                if dev.hostname == "\u{2014}" || dev.hostname == "Resolving..." {
                                    dev.hostname = title;
                                }
                            }
                        }
                        break; // port 80 responded — skip 8080
                    }
                }

                let n = done_r.fetch_add(1, Ordering::Relaxed) + 1;
                if n % 8 == 0 || n == total {
                    let _ = status_r.send(format!("HTTP banner scan ({}/{})...", n, total));
                }
            })
        }).collect();

        // Wait for this batch of 8 before starting the next
        for h in handles { let _ = h.join(); }
    }
}

fn perform_scan(
    passive_discovery: &Arc<DashMap<IpAddr, DeviceInfo>>,
    active_discovery: &Arc<DashMap<IpAddr, DeviceInfo>>,
    device_metadata: &Arc<DashMap<IpAddr, DeviceDetails>>,
    interface_name: &str,
    network_name: &str,
    status_tx: &mpsc::Sender<String>,
    alert_tx: &mpsc::Sender<String>,
    cancel_flag: Arc<std::sync::atomic::AtomicBool>,
) -> thread::JoinHandle<()> {
    let _ = status_tx.send("Initializing...".to_string());

    // Resolve capture interface IP for multicast
    let mut interface_v4 = std::net::Ipv4Addr::UNSPECIFIED;
    let mut interface_mac = [0u8; 6];
    let interfaces = pnet::datalink::interfaces();
    if let Some(iface) = interfaces.iter().find(|i| i.name == interface_name || i.description == interface_name)
        .or_else(|| interfaces.iter().find(|i| !i.is_loopback() && i.ips.iter().any(|ip| ip.is_ipv4()))) {
        if let Some(mac) = iface.mac {
            interface_mac = mac.octets();
        }
        for ip_net in &iface.ips {
            if let IpAddr::V4(ipv4) = ip_net.ip() {
                interface_v4 = ipv4;
                break;
            }
        }
    }

    // Spawn passive mDNS listener to capture unsolicited Apple announcements
    // during the entire scan window (ARP sweep + probes)
    let passive_hosts = Arc::new(DashMap::new());
    let passive_meta = Arc::new(DashMap::new());
    let passive_hosts_clone = Arc::clone(&passive_hosts);
    let passive_meta_clone = Arc::clone(&passive_meta);

    let mdns_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mdns_stop_clone = Arc::clone(&mdns_stop);
    let mdns_listener_handle = thread::spawn(move || {
        passive_mdns_listener(Duration::from_secs(60), mdns_stop_clone, interface_v4, passive_hosts_clone, passive_meta_clone)
    });

    // Stage 1: Read the Windows ARP table FIRST (Fix 2)
    let mut new_map = HashMap::new();
    let mut snapshot: Vec<IpAddr> = Vec::new();
    let mut stale_apple_candidates = Vec::new();

    let _ = status_tx.send("Reading ARP table...".to_string());
    let mut table_ptr: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    unsafe {
        if GetIpNetTable2(AF_UNSPEC as u16, &mut table_ptr as *mut _ as *mut _) == 0 {
            let table = &*table_ptr;

            let target_if_index = pnet::datalink::interfaces().into_iter()
                .find(|i| i.name == interface_name || i.description == interface_name)
                .map(|i| i.index);

            let num_entries = table.NumEntries as usize;
            let base_ptr = &table.Table as *const MIB_IPNET_ROW2;

            for i in 0..num_entries {
                let row = &*base_ptr.add(i);
                
                if let Some(target_idx) = target_if_index {
                    if row.InterfaceIndex != target_idx { continue; }
                }

                let state = row.State as u32;
                if state != NLNS_REACHABLE && state != NLNS_PERMANENT
                    && state != NLNS_STALE && state != NLNS_DELAY && state != NLNS_PROBE {
                    continue;
                }

                let family = row.Address.si_family();
                let ip = if *family == AF_INET as u16 {
                    let addr_bytes = row.Address.Ipv4().sin_addr.S_un.S_addr();
                    IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(*addr_bytes)))
                } else if *family == AF_INET6 as u16 {
                    let addr_bytes = row.Address.Ipv6().sin6_addr.u.Byte();
                    IpAddr::V6(std::net::Ipv6Addr::from(*addr_bytes))
                } else {
                    continue;
                };

                if !crate::display::is_local_ip(&ip) {
                    continue;
                }

                let mac_len = row.PhysicalAddressLength as usize;
                if mac_len == 0 { continue; }

                let mac_str = row.PhysicalAddress[..mac_len].iter()
                    .map(|b| format!("{:02X}", b))
                    .collect::<Vec<_>>()
                    .join(":");

                if mac_str == "00:00:00:00:00:00" || mac_str.starts_with("33:33:") || mac_str.starts_with("01:00:5E:") || mac_str == "FF:FF:FF:FF:FF:FF" {
                    continue;
                }

                let vendor = crate::oui::get_vendor(&mac_str);
                
                // Identify STALE iPhones/devices for wake/probe
                if state == NLNS_STALE {
                    let is_apple = vendor.to_lowercase().contains("apple");
                    let is_unknown = vendor == "Unknown" || vendor == "Randomized MAC";
                    if is_apple || is_unknown {
                        if let IpAddr::V4(v4) = ip {
                            stale_apple_candidates.push(v4);
                        }
                    }
                }

                let hostname = if should_resolve_hostname(&ip) {
                    snapshot.push(ip);
                    "Resolving...".to_string()
                } else {
                    "—".to_string()
                };

                new_map.insert(ip, DeviceInfo {
                    mac: mac_str,
                    vendor,
                    hostname,
                    miss_count: 0,
                    last_seen: std::time::Instant::now(),
                    last_seen_unix: default_unix_now(),
                });
            }
            FreeMibTable(table_ptr as *mut _);
        }
    }

    // Populate initial harvested_results from ARP table
    let mut harvested_results = HashMap::new();
    for (ip, dev_info) in &new_map {
        harvested_results.insert(*ip, (dev_info.mac.clone(), dev_info.vendor.clone()));
    }

    // Stage 2: Run active ARP scan sweep (returns map of discovered IPs -> (mac, vendor))
    let active_arp_results = arp_scan(interface_name, status_tx);
    
    // Merge active ARP sweep results into harvested_results and new_map
    for (ip, (mac, vendor)) in active_arp_results {
        if !crate::display::is_local_ip(&ip) { continue; }
        harvested_results.insert(ip, (mac.clone(), vendor.clone()));
        new_map.insert(ip, DeviceInfo {
            mac,
            vendor,
            hostname: "Resolving...".to_string(),
            miss_count: 0,
            last_seen: std::time::Instant::now(),
            last_seen_unix: default_unix_now(),
        });
        if !snapshot.contains(&ip) && should_resolve_hostname(&ip) {
            snapshot.push(ip);
        }
    }

    // Stage 3: Dedicated iPhone wake probe (Fix 3, Part 2)
    wake_iphones_and_probe(
        &stale_apple_candidates,
        interface_v4,
        device_metadata,
        &mut harvested_results,
        &mut new_map,
        status_tx,
    );

    // Stage 4: Merge passive listener hosts discovered so far (Fix 1)
    for r in passive_hosts.iter() {
        let ip = *r.key();
        if !crate::display::is_local_ip(&ip) { continue; }
        let name = r.value().clone();
        harvested_results.entry(ip).or_insert_with(|| ("Unknown".to_string(), "Unknown".to_string()));
        new_map.entry(ip).or_insert_with(|| DeviceInfo {
            mac: "Unknown".to_string(),
            vendor: "Unknown".to_string(),
            hostname: name,
            miss_count: 0,
            last_seen: std::time::Instant::now(),
            last_seen_unix: default_unix_now(),
        });
        if !snapshot.contains(&ip) && should_resolve_hostname(&ip) {
            snapshot.push(ip);
        }
    }
    for r in passive_meta.iter() {
        let ip = *r.key();
        if !crate::display::is_local_ip(&ip) { continue; }
        let txt_meta = r.value();
        let mut entry = device_metadata.entry(ip).or_insert_with(DeviceDetails::default);
        for (k, v) in &txt_meta.properties {
            entry.properties.insert(k.clone(), v.clone());
        }
        for svc in &txt_meta.services {
            entry.services.insert(svc.clone());
        }
    }

    // Stage 5: Run a short (3-second) collect_mdns_hostnames call (Fix 1)
    let ips_for_collect: Vec<IpAddr> = harvested_results.keys().copied().collect();
    let (mdns_collected_hosts, mdns_collected_meta) = collect_mdns_hostnames(&ips_for_collect, 3);
    
    // Merge new discoveries from 3-second collect_mdns_hostnames call
    for (ip, hostname) in mdns_collected_hosts {
        if !crate::display::is_local_ip(&ip) { continue; }
        harvested_results.entry(ip).or_insert_with(|| ("Unknown".to_string(), "Unknown".to_string()));
        new_map.entry(ip).or_insert_with(|| DeviceInfo {
            mac: "Unknown".to_string(),
            vendor: "Unknown".to_string(),
            hostname: hostname.clone(),
            miss_count: 0,
            last_seen: std::time::Instant::now(),
            last_seen_unix: default_unix_now(),
        });
        if !snapshot.contains(&ip) && should_resolve_hostname(&ip) {
            snapshot.push(ip);
        }
    }
    for (ip, meta) in mdns_collected_meta {
        if !crate::display::is_local_ip(&ip) { continue; }
        let mut entry = device_metadata.entry(ip).or_insert_with(DeviceDetails::default);
        for (k, v) in meta.properties {
            entry.properties.insert(k, v);
        }
        for svc in meta.services {
            entry.services.insert(svc);
        }
    }

    // Stage 6: Probe discovered devices via unicast mDNS
    // Filter out devices that were already successfully wake-probed
    let probe_ips: Vec<std::net::Ipv4Addr> = harvested_results.iter()
        .filter_map(|(ip, _)| match ip {
            IpAddr::V4(v4) => {
                if let Some(meta) = device_metadata.get(ip) {
                    if meta.properties.contains_key("model") {
                        return None;
                    }
                }
                Some(*v4)
            }
            _ => None,
        })
        .collect();

    if !probe_ips.is_empty() {
        let _ = status_tx.send(format!("Probing {} device(s) via mDNS...", probe_ips.len()));
        
        let (result_tx, result_rx) = mpsc::channel();
        let ips_to_probe = Arc::new(std::sync::Mutex::new(std::collections::VecDeque::from(probe_ips)));
        
        thread::scope(|s| {
            for _ in 0..8 {
                let ips = Arc::clone(&ips_to_probe);
                let tx = result_tx.clone();
                s.spawn(move || {
                    loop {
                        let next_ip = {
                            let mut guard = ips.lock().unwrap();
                            guard.pop_front()
                        };
                        match next_ip {
                            Some(v4) => {
                                let result = probe_apple_unicast_mdns(v4, 1200);
                                let _ = tx.send((v4, result));
                            }
                            None => break,
                        }
                    }
                });
            }
        });
        drop(result_tx);
        
        for (v4, probe_result) in result_rx {
            if let Some((hostname, meta)) = probe_result {
                let ip_key = IpAddr::V4(v4);
                
                if let Some(entry) = new_map.get_mut(&ip_key) {
                    if !hostname.is_empty() {
                        entry.hostname = hostname.clone();
                    }
                    if meta.properties.contains_key("model") || meta.properties.contains_key("model_code") {
                        if entry.vendor == "Unknown" || entry.vendor == "Randomized MAC" {
                            entry.vendor = "Apple Inc.".to_string();
                        }
                    }
                }

                if !meta.is_empty() {
                    let mut entry = device_metadata.entry(ip_key).or_insert_with(DeviceDetails::default);
                    for (k, v) in &meta.properties {
                        entry.properties.insert(k.clone(), v.clone());
                    }
                    for svc in &meta.services {
                        entry.services.insert(svc.clone());
                    }
                    drop(entry);
                    
                    if meta.properties.contains_key("model") || meta.properties.contains_key("model_code") {
                        if let Some((_mac, vendor)) = harvested_results.get_mut(&ip_key) {
                            if vendor == "Randomized MAC" || vendor == "Unknown" {
                                *vendor = "Apple Inc.".to_string();
                            }
                        }
                    }
                }
            }
        }
    }

    // Merge passive packet-sniffer discoveries from perform_scan parameter
    for r in passive_discovery.iter() {
        let (ip, entry) = r.pair();
        if !crate::display::is_local_ip(ip) { continue; }
        if !new_map.contains_key(ip) {
            new_map.insert(*ip, entry.clone());
        }
    }

    // Age devices not seen in this scan
    for mut r in active_discovery.iter_mut() {
        let ip = *r.key();
        let entry = r.value_mut();
        if !new_map.contains_key(&ip) {
            entry.miss_count = entry.miss_count.saturating_add(1);
        }
    }

    // Merge found devices: update changed properties, preserve resolved hostname
    for (ip, new_entry) in &new_map {
        active_discovery.entry(*ip)
            .and_modify(|existing| {
                if new_entry.hostname != "Resolving..." && new_entry.hostname != "\u{2014}" {
                    existing.hostname = new_entry.hostname.clone();
                }
                existing.mac = new_entry.mac.clone();
                existing.vendor = new_entry.vendor.clone();
                existing.miss_count = 0;
                existing.last_seen = std::time::Instant::now();
                existing.last_seen_unix = default_unix_now();
            })
            .or_insert(new_entry.clone());
    }
    let found = active_discovery.len();

    // Save baseline immediately before spawning the enrichment thread so that
    // cancel/restart/quit can never skip this write. The bg_handle will re-save
    // after hostname enrichment to flush updated names.
    {
        let ipv4_macs: std::collections::HashSet<String> = active_discovery.iter()
            .filter(|r| matches!(r.key(), IpAddr::V4(_)))
            .map(|r| r.value().mac.clone())
            .collect();
        let early_baseline: HashMap<IpAddr, DeviceInfo> = active_discovery.iter()
            .filter(|r| {
                let ip = r.key();
                if !crate::display::is_local_ip(ip) { return false; }
                if let IpAddr::V6(v6) = ip {
                    !(v6.segments()[0] == 0xfe80 && ipv4_macs.contains(&r.value().mac))
                } else {
                    true
                }
            })
            .map(|r| (*r.key(), r.value().clone()))
            .collect();
        save_baseline(network_name, &early_baseline);
    }

    let _ = status_tx.send(format!("Ready ({} discovered)", found));

    // Run hostname resolution in background thread
    let devices_clone = Arc::clone(active_discovery);
    let mut snapshot_clone = snapshot.clone();
    let network_name_clone = network_name.to_string();

    // Retry hostname resolution for cached devices still showing "—" or "Resolving..."
    for r in active_discovery.iter() {
        let (ip, dev) = r.pair();
        if (dev.hostname == "—" || dev.hostname == "Resolving...") && should_resolve_hostname(ip) {
            if !snapshot_clone.contains(ip) {
                snapshot_clone.push(*ip);
            }
        }
    }

    let meta_clone = Arc::clone(device_metadata);
    let cancel_clone = Arc::clone(&cancel_flag);

    let passive_hosts_thread = Arc::clone(&passive_hosts);
    let passive_meta_thread = Arc::clone(&passive_meta);
    let alert_tx_clone = alert_tx.clone();
    let status_tx_clone = status_tx.clone();

    let bg_handle = thread::spawn(move || {
        if cancel_clone.load(std::sync::atomic::Ordering::Relaxed) {
            mdns_stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = mdns_listener_handle.join();
            return;
        }

        // Step 1: Run mDNS service browsing (8s scan)
        let (mdns_hostnames, mdns_txt_meta) = collect_mdns_hostnames(&snapshot_clone, 8);
        let mdns_clone = Arc::new(mdns_hostnames);

        // Insert mDNS-discovered devices that were missed by ARP/ping sweep
        {
            let mut mdns_only_ips = Vec::new();
            for (ip, mdns_name) in mdns_clone.iter() {
                if !crate::display::is_local_ip(ip) { continue; }
                let mut inserted = false;
                devices_clone.entry(*ip).or_insert_with(|| {
                    inserted = true;
                    DeviceInfo {
                        mac: "Unknown".to_string(),
                        vendor: "Unknown".to_string(),
                        hostname: mdns_name.clone(),
                        miss_count: 0,
                        last_seen: std::time::Instant::now(),
                        last_seen_unix: default_unix_now(),
                    }
                });
                if inserted {
                    mdns_only_ips.push(*ip);
                }
            }
            if !mdns_only_ips.is_empty() {
                for ip in &mdns_only_ips {
                    if let Some(txt_meta) = mdns_txt_meta.get(ip) {
                        let mut entry = meta_clone.entry(*ip).or_insert_with(DeviceDetails::default);
                        for (k, v) in &txt_meta.properties {
                            entry.properties.insert(k.clone(), v.clone());
                        }
                        for svc in &txt_meta.services {
                            entry.services.insert(svc.clone());
                        }
                    }
                }
            }
        }

        // Store mDNS TXT metadata into shared device_metadata store
        if !mdns_txt_meta.is_empty() {
            for (ip, txt_meta) in mdns_txt_meta {
                if !crate::display::is_local_ip(&ip) { continue; }
                let mut entry = meta_clone.entry(ip).or_insert_with(DeviceDetails::default);
                for (k, v) in txt_meta.properties {
                    entry.properties.insert(k, v);
                }
                for svc in txt_meta.services {
                    entry.services.insert(svc);
                }
            }
        }

        if cancel_clone.load(std::sync::atomic::Ordering::Relaxed) {
            mdns_stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = mdns_listener_handle.join();
            return;
        }

        // Step 2: Run one batched PowerShell DNS lookup for all IPv4 IPs (single process,
        // not one per IP). Results are shared into per-IP threads via Arc.
        #[cfg(windows)]
        let ps_results = {
            let ipv4_ips: Vec<IpAddr> = snapshot_clone.iter()
                .filter(|ip| ip.is_ipv4())
                .copied()
                .collect();
            Arc::new(resolve_powershell_dns_batch(&ipv4_ips))
        };

        // Step 2: Per-IP fallback threads for standard DNS and NetBIOS
        let handles: Vec<(IpAddr, mpsc::Receiver<_>)> = snapshot_clone.iter().map(|&ip| {
            let (tx, rx) = mpsc::channel();
            let mdns_ref = Arc::clone(&mdns_clone);
            let dev_ref = Arc::clone(&devices_clone);
            #[cfg(windows)]
            let ps_ref = Arc::clone(&ps_results);

            thread::spawn(move || {
                let is_link_local_v6 = match ip {
                    IpAddr::V6(v6) => v6.segments()[0] == 0xfe80,
                    _ => false,
                };

                let result = if is_link_local_v6 {
                    let mdns_res = mdns_ref.get(&ip).cloned();
                    if mdns_res.is_some() {
                        mdns_res
                    } else {
                        // Look up MAC address for this fe80:: IP from active_discovery (dev_ref)
                        let mac_opt = dev_ref.get(&ip).map(|r| r.mac.clone());
                        let mut resolved_from_mac = None;
                        if let Some(mac) = mac_opt {
                            if mac != "Unknown" && !mac.is_empty() {
                                // Iterate and find an IPv4 counterpart with the same MAC and a resolved name
                                for r in dev_ref.iter() {
                                    let (other_ip, other_dev) = r.pair();
                                    if other_ip.is_ipv4() && other_dev.mac == mac {
                                        let name = &other_dev.hostname;
                                        if name != "Resolving..." && name != "—" && name != "\u{2014}" && !name.is_empty() {
                                            resolved_from_mac = Some(name.clone());
                                            break;
                                        }
                                    }
                                }
                            }
                        }
                        resolved_from_mac
                    }
                } else {
                    #[cfg(windows)]
                    {
                        // mDNS result → batched PS DNS (already resolved, instant) → NetBIOS.
                        // lookup_addr is omitted: it has no timeout guarantee on Windows and
                        // leaks threads when the system resolver stalls.
                        mdns_ref.get(&ip)
                            .cloned()
                            .or_else(|| ps_ref.get(&ip).cloned())
                            .or_else(|| resolve_netbios_name(&ip))
                    }
                    #[cfg(not(windows))]
                    {
                        mdns_ref.get(&ip)
                            .cloned()
                            .or_else(|| lookup_addr(&ip).ok())
                    }
                };

                let _ = tx.send(result);
            });
            (ip, rx)
        }).collect();

        // Step 2: Partition handles into fe80_handles (link-local IPv6) and remaining handles (IPv4/other)
        let (fe80_handles, ipv4_handles): (Vec<_>, Vec<_>) = handles.into_iter().partition(|(ip, _)| {
            match ip {
                IpAddr::V6(v6) => v6.segments()[0] == 0xfe80,
                _ => false,
            }
        });

        // Drain fe80_handles first with 200ms timeout
        for (ip, rx) in fe80_handles {
            let hostname = match rx.recv_timeout(Duration::from_millis(200)) {
                Ok(Some(name)) => {
                    let name_str = name.trim().to_string();
                    if name_str.is_empty() || name_str == ip.to_string() {
                        None
                    } else {
                        Some(name_str)
                    }
                }
                Ok(None) | Err(_) => None,
            };

            if let Some(resolved_name) = hostname {
                if let Some(mut entry) = devices_clone.get_mut(&ip) {
                    if entry.hostname == "Resolving..." || entry.hostname == "\u{2014}" || entry.hostname.is_empty() {
                        entry.hostname = resolved_name;
                    }
                }
            } else {
                if let Some(mut entry) = devices_clone.get_mut(&ip) {
                    if entry.hostname == "Resolving..." {
                        entry.hostname = "\u{2014}".to_string();
                    }
                }
            }
        }

        // Drain remaining handles with 15s timeout
        for (ip, rx) in ipv4_handles {
            let hostname = match rx.recv_timeout(Duration::from_secs(15)) {
                Ok(Some(name)) => {
                    let name_str = name.trim().to_string();
                    if name_str.is_empty() || name_str == ip.to_string() {
                        None
                    } else {
                        Some(name_str)
                    }
                }
                Ok(None) | Err(_) => None,
            };

            if let Some(resolved_name) = hostname {
                let mut mac_to_update = None;
                if let Some(mut entry) = devices_clone.get_mut(&ip) {
                    if entry.hostname == "Resolving..." || entry.hostname == "\u{2014}" || entry.hostname.is_empty() {
                        entry.hostname = resolved_name.clone();
                        mac_to_update = Some(entry.mac.clone());
                    }
                }

                // Inline cross-MAC fe80 update: update counterpart instantly as each IPv4 resolves
                if let Some(mac) = mac_to_update {
                    if mac != "Unknown" && !mac.is_empty() {
                        let mut fe80_ips = Vec::new();
                        for r in devices_clone.iter() {
                            let (other_ip, other_dev) = r.pair();
                            let is_fe80 = match other_ip {
                                IpAddr::V6(v6) => v6.segments()[0] == 0xfe80,
                                _ => false,
                            };
                            if is_fe80 && other_dev.mac == mac {
                                let name = &other_dev.hostname;
                                if name == "Resolving..." || name == "—" || name == "\u{2014}" || name.is_empty() {
                                    fe80_ips.push(*other_ip);
                                }
                            }
                        }
                        for fe80_ip in fe80_ips {
                            if let Some(mut fe80_entry) = devices_clone.get_mut(&fe80_ip) {
                                fe80_entry.hostname = resolved_name.clone();
                            }
                        }
                    }
                }
            } else {
                if let Some(mut entry) = devices_clone.get_mut(&ip) {
                    if entry.hostname == "Resolving..." {
                        entry.hostname = "\u{2014}".to_string();
                    }
                }
            }
        }

        if cancel_clone.load(std::sync::atomic::Ordering::Relaxed) {
            mdns_stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = mdns_listener_handle.join();
            return;
        }

        // Step 3: SSDP/UPnP device enumeration (smart TVs, Roku, Sonos, routers)
        let ssdp_results = ssdp_discover(3);
        if !ssdp_results.is_empty() {
            for (ip, ssdp_meta) in ssdp_results {
                if !crate::display::is_local_ip(&ip) { continue; }
                let mut entry = meta_clone.entry(ip).or_insert_with(DeviceDetails::default);
                for (k, v) in ssdp_meta {
                    if k == "services" {
                        for s in v.split(',') {
                            let clean_s = s.trim();
                            if !clean_s.is_empty() {
                                entry.services.insert(clean_s.to_string());
                            }
                        }
                    } else {
                        entry.properties.insert(k, v);
                    }
                }
            }
        }

        if cancel_clone.load(std::sync::atomic::Ordering::Relaxed) {
            mdns_stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = mdns_listener_handle.join();
            return;
        }

        // Step 4: WSD probe for Windows devices (printers, PCs, NAS)
        let wsd_results = wsd_discover(3);
        if !wsd_results.is_empty() {
            for (ip, wsd_meta) in &wsd_results {
                if !crate::display::is_local_ip(ip) { continue; }
                let mut entry = meta_clone.entry(*ip).or_insert_with(DeviceDetails::default);
                for (k, v) in wsd_meta {
                    if k == "services" {
                        for s in v.split(',') {
                            let clean_s = s.trim();
                            if !clean_s.is_empty() {
                                entry.services.insert(clean_s.to_string());
                            }
                        }
                    } else {
                        entry.properties.insert(k.clone(), v.clone());
                    }
                }
            }
            for (ip, wsd_meta) in wsd_results {
                if !crate::display::is_local_ip(&ip) { continue; }
                if let Some(hostname) = wsd_meta.get("wsd_hostname") {
                    if let Some(mut entry) = devices_clone.get_mut(&ip) {
                        if entry.hostname == "\u{2014}" || entry.hostname == "Resolving..." {
                            entry.hostname = hostname.clone();
                        }
                    }
                }
            }
        }

        if cancel_clone.load(std::sync::atomic::Ordering::Relaxed) {
            mdns_stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = mdns_listener_handle.join();
            return;
        }

        // Step 4.5: Active DHCP Inform Probing for unidentified devices
        {
            let mut unident_ips = Vec::new();
            for r in devices_clone.iter() {
                let (ip, dev) = r.pair();
                if let IpAddr::V4(v4) = ip {
                    let has_model = meta_clone.get(ip).map_or(false, |m| m.properties.contains_key("model"));
                    let is_apple = dev.vendor == "Apple, Inc." || dev.vendor == "Apple Inc." || dev.vendor == "Apple" || dev.vendor == "Apple Device";
                    if !has_model && (dev.vendor == "Unknown" || dev.vendor == "Randomized MAC" || is_apple) {
                        unident_ips.push(*v4);
                    }
                }
            }

            if !unident_ips.is_empty() {
                let dhcp_fps = crate::dhcp_probe::probe_dhcp_fingerprints(
                    &unident_ips,
                    interface_v4,
                    interface_mac,
                    1500
                );
                
                if !dhcp_fps.is_empty() {
                    for (ip, fp) in dhcp_fps {
                        let mut entry = meta_clone.entry(ip).or_insert_with(DeviceDetails::default);
                        entry.properties.insert("dhcp_fingerprint".to_string(), fp);
                    }
                }
            }
        }

        if cancel_clone.load(std::sync::atomic::Ordering::Relaxed) {
            mdns_stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = mdns_listener_handle.join();
            return;
        }

        // Step 4.8: HTTP banner scan — extracts friendly names from web interfaces
        {
            let scan_ips: Vec<IpAddr> = devices_clone.iter()
                .map(|r| *r.key())
                .filter(|ip| crate::display::is_local_ip(ip))
                .collect();
            http_banner_scan(&scan_ips, &meta_clone, &devices_clone, &status_tx_clone);
        }

        if cancel_clone.load(std::sync::atomic::Ordering::Relaxed) {
            mdns_stop.store(true, std::sync::atomic::Ordering::Relaxed);
            let _ = mdns_listener_handle.join();
            return;
        }

        // Step 5: Final Enrichment - replace technical junk with friendly names
        for mut r in devices_clone.iter_mut() {
            let ip = *r.key();
            let entry = r.value_mut();
            
            if entry.hostname.starts_with('_') || entry.hostname == "\u{2014}" || entry.hostname == "Resolving..." {
                if let Some(dev_meta) = meta_clone.get(&ip) {
                    if let Some(model) = dev_meta.get("model")
                        .or(dev_meta.get("friendly_name"))
                        .or(dev_meta.get("model_name")) 
                    {
                        entry.hostname = model.clone();
                    }
                }
            }
            
            let mut clean_name = entry.hostname.trim_start_matches('_').to_string();
            if let Some(pos) = clean_name.find("._") {
                clean_name.truncate(pos);
            }
            if clean_name.starts_with("I49B8F") { clean_name = "eero Node".to_string(); }
            if clean_name == "eerogw" { clean_name = "eero Gateway".to_string(); }
            if clean_name == "trel" { clean_name = "eero Link".to_string(); }
            if clean_name == "asquic" {
                if let Some(dev_meta) = meta_clone.get(&ip) {
                    if let Some(model) = dev_meta.get("model") {
                        if model.starts_with("iPhone") || model.starts_with("iPad") {
                            clean_name = model.clone();
                        } else {
                            clean_name = "Apple Device".to_string();
                        }
                    } else {
                        clean_name = "Apple Device".to_string();
                    }
                } else {
                    clean_name = "Apple Device".to_string();
                }
            }
            if clean_name != entry.hostname {
                entry.hostname = clean_name;
            }

            if entry.vendor == "Unknown" || entry.vendor == "Randomized MAC" || entry.vendor == "Apple Device" {
                if let Some(dev_meta) = meta_clone.get(&ip) {
                    if let Some(mfr) = dev_meta.get("manufacturer") {
                        if !mfr.is_empty() && mfr != "—" {
                            entry.vendor = mfr.clone();
                        }
                    }
                }
            }

            let mut is_apple = false;
            let host_lower = entry.hostname.to_lowercase();
            if host_lower.contains("iphone")
                || host_lower.contains("ipad")
                || host_lower.contains("macbook")
                || host_lower.contains("imac")
                || host_lower.contains("apple tv")
                || host_lower.contains("appletv")
                || host_lower.contains("homepod")
                || host_lower.contains("apple watch")
                || host_lower.contains("applewatch")
            {
                is_apple = true;
            }

            if let Some(dev_meta) = meta_clone.get(&ip) {
                if let Some(model) = dev_meta.get("model") {
                    let model_lower = model.to_lowercase();
                    if model_lower.contains("iphone")
                        || model_lower.contains("ipad")
                        || model_lower.contains("macbook")
                        || model_lower.contains("imac")
                        || model_lower.contains("apple tv")
                        || model_lower.contains("appletv")
                        || model_lower.contains("homepod")
                        || model_lower.contains("apple watch")
                        || model_lower.contains("applewatch")
                        || model_lower.starts_with("apple")
                    {
                        is_apple = true;
                    }
                }
                for s in &dev_meta.services {
                    let s_lower = s.to_lowercase();
                    if s_lower.contains("airplay")
                        || s_lower.contains("apple companion")
                        || s_lower.contains("apple accessory")
                        || s_lower.contains("asquic")
                    {
                        is_apple = true;
                        break;
                    }
                }
            }

            // Only stamp Apple when vendor is still unresolved — prevents overwriting
            // real vendors like "Sonos, Inc." that legitimately expose AirPlay.
            if is_apple && (entry.vendor == "Unknown" || entry.vendor == "Randomized MAC") {
                entry.vendor = "Apple, Inc.".to_string();
            }

            // Classify device category — drop the read ref BEFORE acquiring write access
            // to avoid a DashMap shard deadlock (read + write on same shard, same thread).
            let cat = {
                let meta_ref = meta_clone.get(&ip);
                classify_device_category(&entry.vendor, &entry.hostname, meta_ref.as_deref())
            };
            if let Some(cat) = cat {
                let mut meta_entry = meta_clone.entry(ip).or_insert_with(DeviceDetails::default);
                meta_entry.properties.entry("category".to_string()).or_insert_with(|| cat.to_string());
            }
        }

        // Final Stage: Stop the passive listener and merge final results (Fix 3, Part 1)
        mdns_stop.store(true, std::sync::atomic::Ordering::Relaxed);
        let _ = mdns_listener_handle.join();

        // Merge all accumulated passive hosts into active_discovery
        for r in passive_hosts_thread.iter() {
            let ip = *r.key();
            if !crate::display::is_local_ip(&ip) { continue; }
            let hostname = r.value().clone();
            devices_clone.entry(ip).and_modify(|entry| {
                if entry.hostname == "Resolving..." || entry.hostname == "\u{2014}" || entry.hostname.is_empty() {
                    entry.hostname = hostname.clone();
                }
            }).or_insert_with(|| DeviceInfo {
                mac: "Unknown".to_string(),
                vendor: "Unknown".to_string(),
                hostname,
                miss_count: 0,
                last_seen: std::time::Instant::now(),
                last_seen_unix: default_unix_now(),
            });
        }
        
        // Merge all accumulated passive metadata into device_metadata
        for r in passive_meta_thread.iter() {
            let ip = *r.key();
            if !crate::display::is_local_ip(&ip) { continue; }
            let txt_meta = r.value();
            let mut entry = meta_clone.entry(ip).or_insert_with(DeviceDetails::default);
            for (k, v) in &txt_meta.properties {
                entry.properties.insert(k.clone(), v.clone());
            }
            for svc in &txt_meta.services {
                entry.services.insert(svc.clone());
            }
        }

        // Stage 7: Duplicate MAC address and Espressif/hardware batch pairing checks
        {
            // 1. Group devices by MAC address
            let mut mac_to_ips: HashMap<String, Vec<IpAddr>> = HashMap::new();
            let mut devices_list: Vec<(IpAddr, String, String, String)> = Vec::new();
            
            for r in devices_clone.iter() {
                let (ip, dev) = r.pair();
                if dev.mac != "Unknown" && !dev.mac.is_empty() {
                    mac_to_ips.entry(dev.mac.clone()).or_insert_with(Vec::new).push(*ip);
                    devices_list.push((*ip, dev.mac.clone(), dev.vendor.clone(), dev.hostname.clone()));
                }
            }

            // Sonos & Multi-room duplicate MAC check
            for (mac, ips) in mac_to_ips {
                if ips.len() > 1 {
                    // Suppress same-device fe80 + IPv4 duplicate MAC warnings
                    let is_fe80_ipv4_pair = if ips.len() == 2 {
                        let is_link_local = |ip: &IpAddr| match ip {
                            IpAddr::V6(v6) => v6.segments()[0] == 0xfe80,
                            _ => false,
                        };
                        (is_link_local(&ips[0]) && ips[1].is_ipv4()) || (is_link_local(&ips[1]) && ips[0].is_ipv4())
                    } else {
                        false
                    };

                    if is_fe80_ipv4_pair {
                        continue;
                    }

                    let vendor = crate::oui::get_vendor(&mac);
                    let vendor_lower = vendor.to_lowercase();
                    let known_multiroom_audio = [
                        "sonos", "bose", "denon", "yamaha", "bang & olufsen", "bang and olufsen"
                    ];
                    let is_multiroom = known_multiroom_audio.iter().any(|&m| vendor_lower.contains(m));

                    if is_multiroom {
                        let msg = format!("Sonos group MAC shared across {} speakers — expected behavior. (MAC: {}, IPs: {:?})", ips.len(), mac, ips);
                        let _ = alert_tx_clone.send(msg);
                    } else {
                        let msg = format!("Duplicate MAC address detected! MAC: {} shared by {} IPs: {:?}", mac, ips.len(), ips);
                        let _ = alert_tx_clone.send(msg);
                    }
                }
            }

            // Sequential MAC hardware batch pairing heuristic
            for i in 0..devices_list.len() {
                for j in (i + 1)..devices_list.len() {
                    let (ip1, mac1, vendor1, host1) = &devices_list[i];
                    let (ip2, mac2, vendor2, host2) = &devices_list[j];

                    let clean1 = mac1.replace(":", "").replace("-", "").to_uppercase();
                    let clean2 = mac2.replace(":", "").replace("-", "").to_uppercase();

                    if clean1.len() == 12 && clean2.len() == 12 {
                        let oui1 = &clean1[..6];
                        let oui2 = &clean2[..6];

                        if oui1 == oui2 {
                            if let (Ok(val1), Ok(val2)) = (u64::from_str_radix(&clean1, 16), u64::from_str_radix(&clean2, 16)) {
                                let diff = if val1 > val2 { val1 - val2 } else { val2 - val1 };
                                if diff <= 512 {
                                    let mut note = "Device Pair — likely same hardware batch".to_string();
                                    let is_espressif = vendor1.to_lowercase().contains("espressif") || vendor2.to_lowercase().contains("espressif");
                                    if is_espressif {
                                        let name1 = if host1 != "—" && host1 != "Resolving..." { host1.as_str() } else { "ESP32" };
                                        let name2 = if host2 != "—" && host2 != "Resolving..." { host2.as_str() } else { "ESP32" };
                                        note = format!("Device Pair — likely same hardware batch (ESP32 pair: {} & {})", name1, name2);
                                    }

                                    for ip in &[ip1, ip2] {
                                        let mut entry = meta_clone.entry(**ip).or_insert_with(DeviceDetails::default);
                                        entry.properties.insert("note".to_string(), note.clone());
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }

        // Final save of baseline with enriched names
        {
            let mut baseline_copy = HashMap::new();
            for r in devices_clone.iter() {
                let (ip, dev) = r.pair();
                baseline_copy.insert(*ip, dev.clone());
            }
            let ipv4_macs: std::collections::HashSet<String> = baseline_copy.iter()
                .filter(|(ip, _)| matches!(ip, IpAddr::V4(_)))
                .map(|(_, dev)| dev.mac.clone())
                .collect();
            baseline_copy.retain(|ip, dev| {
                if !crate::display::is_local_ip(ip) {
                    return false;
                }
                if let IpAddr::V6(v6) = ip {
                    !(v6.segments()[0] == 0xfe80 && ipv4_macs.contains(&dev.mac))
                } else {
                    true
                }
            });
            save_baseline(&network_name_clone, &baseline_copy);
        }
    });
    bg_handle
}

#[cfg(not(windows))]
fn perform_scan(
    _passive_discovery: &Arc<DashMap<IpAddr, DeviceInfo>>,
    _active_discovery: &Arc<DashMap<IpAddr, DeviceInfo>>,
    _device_metadata: &Arc<DashMap<IpAddr, DeviceDetails>>,
    _: &str,
    _: &str,
    status_tx: &mpsc::Sender<String>,
    _: &mpsc::Sender<String>,
    _cancel_flag: Arc<std::sync::atomic::AtomicBool>,
) -> thread::JoinHandle<()> {
    let _ = status_tx.send("Discovery not supported".to_string());
    thread::spawn(|| {})
}
