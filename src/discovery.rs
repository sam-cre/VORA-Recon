use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::Duration;
use std::process::Command;

/// Device metadata collected from mDNS TXT records and SSDP/UPnP XML descriptions.
/// Keys include: "model", "firmware", "friendly_name", "manufacturer", "serial", "services", etc.
pub type DeviceMetadata = HashMap<IpAddr, HashMap<String, String>>;

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
use dns_lookup::lookup_addr;

/// Resolve hostnames via raw mDNS PTR queries (bypasses mdns_sd daemon port conflict)
/// Sends mDNS reverse lookup queries for each IP and parses responses directly
#[cfg(windows)]
fn collect_mdns_hostnames(ips: &[IpAddr], timeout_secs: u64) -> (HashMap<IpAddr, String>, HashMap<IpAddr, HashMap<String, String>>) {
    use std::net::{Ipv4Addr, SocketAddr, UdpSocket};

    let mut result: HashMap<IpAddr, String> = HashMap::new();
    let mut txt_metadata: HashMap<IpAddr, HashMap<String, String>> = HashMap::new();
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
    if sock.bind(&addr.into()).is_err() {
        return (result, txt_metadata);
    }
    let socket: UdpSocket = sock.into();

    let _ = socket.set_read_timeout(Some(Duration::from_millis(800)));
    // Join the mDNS multicast group to receive responses
    let mdns_addr: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
    let _ = socket.join_multicast_v4(&mdns_addr, &Ipv4Addr::UNSPECIFIED);

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

    // Build IP-to-MAC lookup from the IPs we know about for matching service responses
    let mut name_to_ip: HashMap<String, IpAddr> = HashMap::new();

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
                // Determine the IPv4 address for this packet (either from UDP source or from an A record inside)
                let mut packet_ipv4 = None;
                if let IpAddr::V4(src_v4) = src_addr.ip() {
                    packet_ipv4 = Some(src_v4);
                }

                // Also harvest any A record names from the response
                for (hostname, resolved_ip) in parse_mdns_a_records(data) {
                    let clean = hostname
                        .trim_end_matches(".local")
                        .trim_end_matches('.')
                        .to_string();
                    if !clean.is_empty() {
                        name_to_ip.insert(clean.clone(), resolved_ip);
                        if let IpAddr::V4(v4) = resolved_ip {
                            // If this IP is in our target list, map it
                            if v4_ips.contains(&v4) {
                                result.entry(resolved_ip).or_insert(clean);
                            }
                            packet_ipv4 = Some(v4); // Use this IP for the rest of the packet
                        }
                    }
                }

                // Map any service instances found in the packet to the determined IPv4 address
                if let Some(src_v4) = packet_ipv4 {
                    if v4_ips.contains(&src_v4) {
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
                                result.insert(IpAddr::V4(src_v4), device_name);
                            }
                        }
                    }

                    // Parse TXT records for rich device metadata
                    for (record_name, pairs) in parse_mdns_txt_records(data) {
                        let ip_key = IpAddr::V4(src_v4);
                        let meta = txt_metadata.entry(ip_key).or_insert_with(HashMap::new);
                        for (key, value) in &pairs {
                            match key.as_str() {
                                // Apple _companion-link rpMd = device model code
                                "rpmd" => {
                                    meta.insert("model_code".to_string(), value.clone());
                                    if let Some(human) = resolve_apple_model(value) {
                                        meta.insert("model".to_string(), human.to_string());
                                    }
                                }
                                // _device-info model field
                                "model" | "wmodel" => {
                                    if !meta.contains_key("model_code") {
                                        meta.insert("model_code".to_string(), value.clone());
                                    }
                                    if !meta.contains_key("model") {
                                        if let Some(human) = resolve_apple_model(value) {
                                            meta.insert("model".to_string(), human.to_string());
                                        }
                                    }
                                }
                                // _raop am = AirPlay device model
                                "am" => {
                                    if !meta.contains_key("model_code") {
                                        meta.insert("model_code".to_string(), value.clone());
                                        if let Some(human) = resolve_apple_model(value) {
                                            meta.insert("model".to_string(), human.to_string());
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
                                    meta.insert("os_version".to_string(), os_name.to_string());
                                }
                                // Chromecast / Google device
                                "fn" => { meta.insert("friendly_name".to_string(), value.clone()); }
                                "md" => {
                                    if !meta.contains_key("model") {
                                        meta.insert("model".to_string(), value.clone());
                                    }
                                }
                                // AirPlay source version
                                "srcvers" | "vs" => { meta.insert("firmware".to_string(), value.clone()); }
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
                                    meta.insert("homekit_category".to_string(), category.to_string());
                                }
                                // Service name used in the record
                                _ => {}
                            }
                        }
                        // Track which service this came from
                        if record_name.contains("_airplay") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "AirPlay"); }
                        if record_name.contains("_raop") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "AirPlay Audio"); }
                        if record_name.contains("_hap") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "HomeKit"); }
                        if record_name.contains("_googlecast") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "Chromecast"); }
                        if record_name.contains("_spotify") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "Spotify Connect"); }
                        if record_name.contains("_companion-link") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "Apple Companion"); }
                        if record_name.contains("_apple-mobdev2") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "iPhone/iPad"); }
                        if record_name.contains("_airdrop") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "AirDrop"); }
                        if record_name.contains("_remotepairing") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "iPhone"); }
                        if record_name.contains("_continuity") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "Continuity"); }
                    }
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

    let _ = socket.leave_multicast_v4(&mdns_addr, &Ipv4Addr::UNSPECIFIED);

    // Clean up trailing commas from service lists
    for meta in txt_metadata.values_mut() {
        if let Some(svc) = meta.get_mut("services") {
            *svc = svc.trim_end_matches(", ").to_string();
        }
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
        "Mac15,3" => Some("MacBook Air 15\" (M3)"),
        "Mac15,12" | "Mac15,13" => Some("MacBook Air 13\" (M3)"),
        "Mac15,6" | "Mac15,8" | "Mac15,10" => Some("MacBook Pro 14\" (M3 Pro)"),
        "Mac15,7" | "Mac15,9" | "Mac15,11" => Some("MacBook Pro 16\" (M3 Max)"),

        // === iMac / Mac Desktop ===
        "iMac21,1" | "iMac21,2" => Some("iMac 24\" (M1)"),
        "Mac14,3" => Some("Mac mini (M2)"),
        "Mac13,1" => Some("Mac Studio (M1 Max)"),
        "Mac13,2" => Some("Mac Studio (M1 Ultra)"),
        "Mac14,13" | "Mac14,14" => Some("Mac Studio (M2)"),
        "Mac14,8" => Some("Mac Pro (2023)"),

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
                            if url.starts_with("http") {
                                locations.entry(src_addr.ip()).or_insert(url);
                            }
                        }
                    }
                }
            }
            Err(_) => break,
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
    let msg_id = format!("urn:uuid:{:08x}-{:04x}-{:04x}-{:04x}-{:012x}",
        std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap_or_default().as_secs() as u32,
        std::process::id() as u16, 0x4000u16, 0x8000u16, std::process::id() as u64);

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
            Err(_) => break,
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
    loop {
        if offset >= data.len() { return None; }
        let len = data[offset] as usize;
        if len == 0 { return Some(offset + 1); }
        if len >= 0xC0 { return Some(offset + 2); } // Compression pointer
        offset += 1 + len;
    }
}

/// Read a DNS name from a packet, handling compression pointers
fn add_service(existing_services: &mut String, new_service: &str) {
    let new_service = new_service.trim();
    if new_service.is_empty() { return; }
    
    let already_present = existing_services
        .split(',')
        .map(|s| s.trim())
        .any(|s| s.eq_ignore_ascii_case(new_service));
    
    if !already_present {
        if !existing_services.is_empty() {
            existing_services.push_str(", ");
        }
        existing_services.push_str(new_service);
    }
}

fn read_dns_name(data: &[u8], mut offset: usize) -> Option<(String, usize)> {
    let mut parts: Vec<String> = Vec::new();
    let mut end_offset = None;
    let mut jumps = 0;

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
            if end_offset.is_none() { end_offset = Some(offset + 2); }
            let ptr = ((len & 0x3F) << 8) | (data[offset + 1] as usize);
            offset = ptr;
            jumps += 1;
            continue;
        }

        offset += 1;
        if offset + len > data.len() { return None; }
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

/// Try to resolve hostname via PowerShell Resolve-DnsName (catches devices registered with router DNS)
#[cfg(windows)]
fn resolve_powershell_dns(ip: &IpAddr) -> Option<String> {
    let ip_str = ip.to_string();
    let (tx, rx) = std::sync::mpsc::channel();

    let ip_str_clone = ip_str.clone();
    std::thread::spawn(move || {
        let result = Command::new("powershell")
            .args(["-NoProfile", "-Command",
                &format!("try {{ (Resolve-DnsName -Name '{}' -DnsOnly -ErrorAction Stop).NameHost }} catch {{}}", ip_str_clone)])
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::null())
            .output();
        let _ = tx.send(result);
    });

    let output = rx.recv_timeout(Duration::from_secs(5)).ok()?.ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if stdout.is_empty() || stdout == ip_str || stdout.contains("Error") {
        return None;
    }
    // Clean up the hostname — strip domain suffix if present
    let clean = stdout.split('.').next().unwrap_or(&stdout).to_string();
    if clean.is_empty() || clean == ip_str { None } else { Some(clean) }
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
        loop {
            // WAIT indefinitely for manual signal (Auto-refresh removed for safety)
            match signal_rx.recv() {
                Ok(DiscoverySignal::ScanNow) => {
                    #[cfg(windows)]
                    perform_scan(&passive_discovery, &active_discovery, &device_metadata, &interface_name, &network_name, &status_tx, &alert_tx);
                }
                Err(mpsc::RecvError) => break,
            }
        }
    });
}



#[cfg(windows)]
fn arp_scan(
    interface_name: &str,
    status_tx: &mpsc::Sender<String>,
) -> HashMap<IpAddr, (String, String)> {
    use pnet::datalink::{self, Channel, MacAddr};
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

/// Probe a single Apple device via unicast mDNS to extract model info.
/// Sends QU-bit queries directly to the target IP on port 5353.
#[cfg(windows)]
fn probe_apple_unicast_mdns(target: std::net::Ipv4Addr, timeout_ms: u64) -> Option<(String, HashMap<String, String>)> {
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

    let mut hostname = None;
    let mut metadata = HashMap::new();
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
                    if !clean.is_empty() && hostname.is_none() {
                        hostname = Some(clean.clone());
                        // Follow-up: send a direct A record query for this hostname
                        // to reliably resolve its IP even if PTR failed
                        if !sent_a_query {
                            let a_query = build_mdns_a_query(&format!("{}.local", clean), 600);
                            let _ = sock.send_to(&a_query, target_addr);
                            sent_a_query = true;
                        }
                    }
                }
                // Extract hostname from PTR service instances too
                for instance_name in parse_mdns_service_instances(data) {
                    let device_name = instance_name.split("._").next().unwrap_or("");
                    let device_name = device_name.split('@').last().unwrap_or(device_name).trim();
                    if !device_name.is_empty() && hostname.is_none() {
                        hostname = Some(device_name.to_string());
                    }
                }
                // Extract model info from TXT records
                for (record_name, pairs) in parse_mdns_txt_records(data) {
                    for (key, value) in &pairs {
                        match key.as_str() {
                            "rpmd" | "model" | "wmodel" => {
                                metadata.insert("model_code".to_string(), value.clone());
                                if let Some(human) = resolve_apple_model(value) {
                                    metadata.insert("model".to_string(), human.to_string());
                                }
                            }
                            "am" => {
                                if !metadata.contains_key("model_code") {
                                    metadata.insert("model_code".to_string(), value.clone());
                                    if let Some(human) = resolve_apple_model(value) {
                                        metadata.insert("model".to_string(), human.to_string());
                                    }
                                }
                            }
                            _ => {}
                        }
                    }
                    // Track services from unicast probe responses
                    if record_name.contains("_rdlink") { metadata.entry("services".to_string()).or_insert_with(String::new); add_service(metadata.get_mut("services").unwrap(), "Rapport"); }
                    if record_name.contains("_companion-link") { metadata.entry("services".to_string()).or_insert_with(String::new); add_service(metadata.get_mut("services").unwrap(), "Apple Companion"); }
                    if record_name.contains("_apple-mobdev2") { metadata.entry("services".to_string()).or_insert_with(String::new); add_service(metadata.get_mut("services").unwrap(), "iPhone/iPad"); }
                    if record_name.contains("_continuity") { metadata.entry("services".to_string()).or_insert_with(String::new); add_service(metadata.get_mut("services").unwrap(), "Continuity"); }
                }
            }
            Err(_) => {
                // Timeout on recv — if we have a hostname, send follow-up A query
                if let Some(ref name) = hostname {
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

    if hostname.is_some() || !metadata.is_empty() {
        Some((hostname.unwrap_or_default(), metadata))
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
) -> (HashMap<IpAddr, String>, HashMap<IpAddr, HashMap<String, String>>) {
    use std::net::{SocketAddr, UdpSocket, Ipv4Addr};
    let mut hosts = HashMap::new();
    let mut metadata: HashMap<IpAddr, HashMap<String, String>> = HashMap::new();

    let sock = match socket2::Socket::new(socket2::Domain::IPV4, socket2::Type::DGRAM, Some(socket2::Protocol::UDP)) {
        Ok(s) => s,
        Err(_) => return (hosts, metadata),
    };
    let _ = sock.set_reuse_address(true);
    let bind_addr: SocketAddr = "0.0.0.0:5353".parse().unwrap();
    if sock.bind(&bind_addr.into()).is_err() {
        return (hosts, metadata);
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
                let mut packet_ipv4 = None;
                if let IpAddr::V4(src_v4) = src_addr.ip() {
                    packet_ipv4 = Some(src_v4);
                }

                for (name, resolved_ip) in parse_mdns_a_records(data) {
                    let clean = name.trim_end_matches(".local").trim_end_matches('.').to_string();
                    if !clean.is_empty() {
                        if let IpAddr::V4(v4) = resolved_ip {
                            packet_ipv4 = Some(v4);
                            hosts.entry(IpAddr::V4(v4)).or_insert(clean);
                        }
                    }
                }

                if let Some(src_v4) = packet_ipv4 {
                    for instance in parse_mdns_service_instances(data) {
                        let clean = instance.trim_end_matches(".local").trim_end_matches('.').to_string();
                        let device_name = clean.split("._").next().unwrap_or(&clean);
                        let device_name = device_name.split('@').last().unwrap_or(device_name);
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
                            hosts.entry(IpAddr::V4(src_v4)).or_insert(device_name);
                        }
                    }

                    for (record_name, pairs) in parse_mdns_txt_records(data) {
                        let ip_key = IpAddr::V4(src_v4);
                        let meta = metadata.entry(ip_key).or_insert_with(HashMap::new);
                        for (key, value) in &pairs {
                            match key.as_str() {
                                "rpmd" | "model" | "wmodel" => {
                                    meta.insert("model_code".to_string(), value.clone());
                                    if let Some(human) = resolve_apple_model(value) {
                                        meta.insert("model".to_string(), human.to_string());
                                    }
                                }
                                "am" => {
                                    if !meta.contains_key("model_code") {
                                        meta.insert("model_code".to_string(), value.clone());
                                        if let Some(human) = resolve_apple_model(value) {
                                            meta.insert("model".to_string(), human.to_string());
                                        }
                                    }
                                }
                                "osxvers" => {
                                    let os_name = match value.as_str() {
                                        "24" => "macOS 15 Sequoia",
                                        "23" => "macOS 14 Sonoma",
                                        "22" => "macOS 13 Ventura",
                                        "21" => "macOS 12 Monterey",
                                        "20" => "macOS 11 Big Sur",
                                        _ => value.as_str(),
                                    };
                                    meta.insert("os_version".to_string(), os_name.to_string());
                                }
                                "fn" => { meta.insert("friendly_name".to_string(), value.clone()); }
                                "md" => {
                                    if !meta.contains_key("model") {
                                        meta.insert("model".to_string(), value.clone());
                                    }
                                }
                                "srcvers" | "vs" => { meta.insert("firmware".to_string(), value.clone()); }
                                "ci" => {
                                    let category = match value.as_str() {
                                        "1" => "Other", "2" => "Bridge", "3" => "Fan", "4" => "Garage Door",
                                        "5" => "Lightbulb", "6" => "Door Lock", "7" => "Outlet", "8" => "Switch",
                                        "9" => "Thermostat", "10" => "Sensor", "11" => "Security System", "12" => "Door",
                                        "13" => "Window", "14" => "Window Covering", "17" => "Sprinkler", "28" => "TV",
                                        "32" => "Router", _ => value.as_str(),
                                    };
                                    meta.insert("homekit_category".to_string(), category.to_string());
                                }
                                _ => {}
                            }
                        }
                        if record_name.contains("_airplay") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "AirPlay"); }
                        if record_name.contains("_raop") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "AirPlay Audio"); }
                        if record_name.contains("_hap") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "HomeKit"); }
                        if record_name.contains("_googlecast") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "Chromecast"); }
                        if record_name.contains("_spotify") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "Spotify Connect"); }
                        if record_name.contains("_companion-link") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "Apple Companion"); }
                        if record_name.contains("_apple-mobdev2") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "iPhone/iPad"); }
                        if record_name.contains("_airdrop") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "AirDrop"); }
                        if record_name.contains("_remotepairing") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "iPhone"); }
                        if record_name.contains("_continuity") { add_service(meta.entry("services".to_string()).or_insert_with(String::new), "Continuity"); }
                    }
                }
            }
            Err(_) => continue,
        }
    }
    
    for meta in metadata.values_mut() {
        if let Some(svc) = meta.get_mut("services") {
            *svc = svc.trim_end_matches(", ").to_string();
        }
    }
    
    let _ = socket.leave_multicast_v4(&mdns_group, &interface_ip);

    (hosts, metadata)
}

fn perform_scan(
    passive_discovery: &Arc<Mutex<HashMap<IpAddr, DeviceInfo>>>,
    active_discovery: &Arc<Mutex<HashMap<IpAddr, DeviceInfo>>>,
    device_metadata: &Arc<Mutex<DeviceMetadata>>,
    interface_name: &str,
    network_name: &str,
    status_tx: &mpsc::Sender<String>,
    _alert_tx: &mpsc::Sender<String>
) {
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
    let mdns_stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let mdns_stop_clone = Arc::clone(&mdns_stop);
    let mdns_listener_handle = thread::spawn(move || {
        passive_mdns_listener(Duration::from_secs(60), mdns_stop_clone, interface_v4)
    });

    // Use the new arp_scan to discover devices on the local subnet directly via pnet
    let mut harvested_results = arp_scan(interface_name, status_tx);

    // Probe ALL ARP-discovered devices via unicast mDNS for model identification
    {
        let probe_ips: Vec<std::net::Ipv4Addr> = harvested_results.iter()
            .filter_map(|(ip, _)| match ip {
                IpAddr::V4(v4) => Some(*v4),
                _ => None,
            })
            .collect();

        if !probe_ips.is_empty() {
            let _ = status_tx.send(format!("Probing {} device(s) via mDNS...", probe_ips.len()));
            
            let (result_tx, result_rx) = mpsc::channel();
            let ips_to_probe = Arc::new(Mutex::new(probe_ips.into_iter()));
            
            thread::scope(|s| {
                for _ in 0..8 {
                    let ips = Arc::clone(&ips_to_probe);
                    let tx = result_tx.clone();
                    s.spawn(move || {
                        loop {
                            let next_ip = {
                                let mut lock = ips.lock().unwrap();
                                lock.next()
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
                if let Some((_hostname, meta)) = probe_result {
                    let ip_key = IpAddr::V4(v4);
                    if !meta.is_empty() {
                        if let Ok(mut device_meta) = device_metadata.lock() {
                            let entry = device_meta.entry(ip_key).or_insert_with(HashMap::new);
                            for (k, v) in &meta {
                                entry.insert(k.clone(), v.clone());
                            }
                        }
                        if meta.contains_key("model") || meta.contains_key("model_code") {
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
    }

    // Stop the passive listener and merge results
    mdns_stop.store(true, std::sync::atomic::Ordering::Relaxed);
    if let Ok((passive_hosts, passive_meta)) = mdns_listener_handle.join() {
        for (ip, _hostname) in &passive_hosts {
            if let IpAddr::V4(_v4) = ip {
                if !harvested_results.contains_key(ip) {
                    harvested_results.insert(*ip, ("Unknown".to_string(), "Apple Device".to_string()));
                }
            }
        }
        if let Ok(mut meta) = device_metadata.lock() {
            for (ip, txt_meta) in passive_meta {
                let entry = meta.entry(ip).or_insert_with(HashMap::new);
                for (k, v) in txt_meta { 
                    entry.insert(k, v); 
                }
            }
        }
    }

    let _ = status_tx.send("Reading ARP table...".to_string());
    let mut table_ptr: *mut MIB_IPNET_TABLE2 = std::ptr::null_mut();
    unsafe {
        if GetIpNetTable2(AF_UNSPEC as u16, &mut table_ptr as *mut _ as *mut _) == 0 {
            let table = &*table_ptr;
            let mut new_map = HashMap::new();
            let mut snapshot: Vec<IpAddr> = Vec::new();

            // Stage 1: Identification of the active interface index for filtering
            let target_if_index = pnet::datalink::interfaces().into_iter()
                .find(|i| i.name == interface_name || i.description == interface_name)
                .map(|i| i.index);

            let num_entries = table.NumEntries as usize;
            let base_ptr = &table.Table as *const MIB_IPNET_ROW2;

            for i in 0..num_entries {
                let row = &*base_ptr.add(i);
                
                // Filter by Interface Index
                if let Some(target_idx) = target_if_index {
                    if row.InterfaceIndex != target_idx { continue; }
                }

                // Filter by Neighbor State — accept any state indicating the device
                // has been on the network (not just REACHABLE which decays in seconds)
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

                // Problem 2 Fix: Filter by RFC 1918 + link-local + exclude 0.0.0.0
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

            // Merge harvested results (SendARP results)
            for (ip, (mac, vendor)) in &harvested_results {
                new_map.insert(*ip, DeviceInfo {
                    mac: mac.clone(),
                    vendor: vendor.clone(),
                    hostname: "Resolving...".to_string(),
                    miss_count: 0,
                    last_seen: std::time::Instant::now(),
                    last_seen_unix: default_unix_now(),
                });
                if !snapshot.contains(ip) && should_resolve_hostname(ip) {
                    snapshot.push(*ip);
                }
            }

            // Problem 1 Fix: Merge passive_discovery into scan results at scan-time
            if let Ok(passive) = passive_discovery.lock() {
                for (ip, entry) in passive.iter() {
                    if !new_map.contains_key(ip) {
                        new_map.insert(*ip, entry.clone());
                    }
                }
            }

            // Stage 3: Merge scan results into active_discovery with persistence
            // Devices already in the map keep their resolved hostnames and metadata.
            // Only miss_count and last_seen are updated based on scan results.
            let mut devices = active_discovery.lock().unwrap();

            // Age devices that were NOT found in this scan
            for (ip, entry) in devices.iter_mut() {
                if !new_map.contains_key(ip) {
                    // Device not found — increment miss count but preserve all other fields
                    // (hostname, MAC, vendor, last_seen all stay as they were)
                    entry.miss_count = entry.miss_count.saturating_add(1);
                }
                // Devices that WERE found are handled below in the merge loop
            }

            // Merge found devices: update what changed, preserve what was already resolved
            for (ip, new_entry) in &new_map {
                match devices.get_mut(ip) {
                    Some(existing) => {
                        // Preserve already-resolved hostname — only overwrite if new entry
                        // actually has a real name (not the placeholder "Resolving...")
                        if new_entry.hostname != "Resolving..." && new_entry.hostname != "\u{2014}" {
                            existing.hostname = new_entry.hostname.clone();
                        }
                        // Update MAC/vendor in case they changed (e.g. MAC randomization)
                        existing.mac = new_entry.mac.clone();
                        existing.vendor = new_entry.vendor.clone();
                        // Reset aging — device is confirmed present
                        existing.miss_count = 0;
                        existing.last_seen = std::time::Instant::now();
                        existing.last_seen_unix = default_unix_now();
                    }
                    None => {
                        // Brand new device — insert as-is
                        devices.insert(*ip, new_entry.clone());
                    }
                }
            }
            let found = devices.len();
            drop(devices);
            let _ = status_tx.send(format!("Ready ({} discovered)", found));

            // Baseline will be saved after hostname resolution finishes in the background thread

            FreeMibTable(table_ptr as *mut _);

            // Fix 1: Run hostname resolution in background thread
            // Resolution priority: mDNS → NetBIOS → PowerShell Resolve-DnsName → DNS reverse → "—"
            let devices_clone = Arc::clone(active_discovery);
            let mut snapshot_clone = snapshot.clone();
            let network_name_clone = network_name.to_string();

            // Also retry hostname resolution for any cached devices still showing "—"
            // This ensures baseline entries that failed resolution last time get another chance
            {
                let existing = active_discovery.lock().unwrap();
                for (ip, dev) in existing.iter() {
                    if (dev.hostname == "—" || dev.hostname == "Resolving...") && should_resolve_hostname(ip) {
                        if !snapshot_clone.contains(ip) {
                            snapshot_clone.push(*ip);
                        }
                    }
                }
            } // lock dropped

            let meta_clone = Arc::clone(device_metadata);

            thread::spawn(move || {
                // Step 1: Run mDNS service browsing (8s scan) - primary method for IoT devices
                // Extended from 5s to 8s to catch iPhones in low-power/sleep state (3-6s response)
                // This now also collects TXT record metadata (device models, firmware, etc.)
                let (mdns_hostnames, mdns_txt_meta) = collect_mdns_hostnames(&snapshot_clone, 8);
                let mdns_clone = Arc::new(mdns_hostnames);

                // Prompt C fix: Insert mDNS-discovered devices that were missed by ARP/ping sweep
                // iPhones with screen off often don't respond to SendARP but do respond to mDNS
                {
                    let mut mdns_only_ips: Vec<IpAddr> = Vec::new();
                    if let Ok(mut map) = devices_clone.lock() {
                        for (ip, mdns_name) in mdns_clone.iter() {
                            if !map.contains_key(ip) {
                                map.insert(*ip, DeviceInfo {
                                    mac: "Unknown".to_string(),
                                    vendor: "Apple Device".to_string(),
                                    hostname: mdns_name.clone(),
                                    miss_count: 0,
                                    last_seen: std::time::Instant::now(),
                                    last_seen_unix: default_unix_now(),
                                });
                                mdns_only_ips.push(*ip);
                            }
                        }
                    }
                    // Also add mDNS TXT metadata for these devices
                    if !mdns_only_ips.is_empty() {
                        for ip in &mdns_only_ips {
                            if let Some(txt_meta) = mdns_txt_meta.get(ip) {
                                if let Ok(mut meta) = meta_clone.lock() {
                                    let entry = meta.entry(*ip).or_insert_with(HashMap::new);
                                    for (k, v) in txt_meta {
                                        entry.insert(k.clone(), v.clone());
                                    }
                                }
                            }
                        }
                    }
                }

                // Store mDNS TXT metadata into the shared device_metadata store
                if !mdns_txt_meta.is_empty() {
                    if let Ok(mut meta) = meta_clone.lock() {
                        for (ip, txt_meta) in mdns_txt_meta {
                            let entry = meta.entry(ip).or_insert_with(HashMap::new);
                            for (k, v) in txt_meta {
                                entry.insert(k, v);
                            }
                        }
                    }
                }

                // Step 2: Per-IP fallback threads for standard DNS and NetBIOS
                let handles: Vec<(IpAddr, mpsc::Receiver<_>)> = snapshot_clone.iter().map(|&ip| {
                    let (tx, rx) = mpsc::channel();
                    let mdns_ref = Arc::clone(&mdns_clone);

                    thread::spawn(move || {
                        // Resolution chain: mDNS → NetBIOS → PowerShell DNS → System reverse DNS
                        #[cfg(windows)]
                        let result = mdns_ref.get(&ip)
                            .cloned()
                            .or_else(|| resolve_netbios_name(&ip))
                            .or_else(|| resolve_powershell_dns(&ip))
                            .or_else(|| lookup_addr(&ip).ok());

                        #[cfg(not(windows))]
                        let result = mdns_ref.get(&ip)
                            .cloned()
                            .or_else(|| lookup_addr(&ip).ok());

                        let _ = tx.send(result);
                    });
                    (ip, rx)
                }).collect();

                // Drain results with timeout
                for (ip, rx) in handles {
                    let hostname = match rx.recv_timeout(Duration::from_secs(15)) {
                        Ok(Some(name)) => {
                            let name_str = name.trim().to_string();
                            if name_str.is_empty() || name_str == ip.to_string() {
                                None // Could not resolve — don't overwrite existing hostname
                            } else {
                                Some(name_str)
                            }
                        }
                        Ok(None) | Err(_) => None, // Resolution failed — preserve existing
                    };

                    // Only update hostname if we actually resolved a name.
                    // NEVER clear an existing hostname or touch last_seen here —
                    // that would reset the aging timer and mess up the display.
                    if let Some(resolved_name) = hostname {
                        if let Ok(mut map) = devices_clone.lock() {
                            if let Some(entry) = map.get_mut(&ip) {
                                // Only upgrade: don't overwrite a good name with a worse one
                                if entry.hostname == "Resolving..." || entry.hostname == "\u{2014}" || entry.hostname.is_empty() {
                                    entry.hostname = resolved_name;
                                }
                            }
                        }
                    } else {
                        // Resolution failed — if still "Resolving...", set to "—"
                        // so the UI doesn't show a perpetual "Resolving..." state
                        if let Ok(mut map) = devices_clone.lock() {
                            if let Some(entry) = map.get_mut(&ip) {
                                if entry.hostname == "Resolving..." {
                                    entry.hostname = "\u{2014}".to_string();
                                }
                            }
                        }
                    }
                }

                // Save baseline — strip fe80:: duplicates only from the SAVED copy,
                // NOT from the live active_discovery map (removing from live map caused
                // devices to vanish from the UI).
                if let Ok(map) = devices_clone.lock() {
                    let mut baseline_copy = map.clone();
                    let ipv4_macs: std::collections::HashSet<String> = baseline_copy.iter()
                        .filter(|(ip, _)| matches!(ip, IpAddr::V4(_)))
                        .map(|(_, dev)| dev.mac.clone())
                        .collect();
                    let dupes: Vec<IpAddr> = baseline_copy.iter()
                        .filter(|(ip, dev)| {
                            if let IpAddr::V6(v6) = ip {
                                v6.segments()[0] == 0xfe80 && ipv4_macs.contains(&dev.mac)
                            } else {
                                false
                            }
                        })
                        .map(|(ip, _)| *ip)
                        .collect();
                    for ip in &dupes {
                        baseline_copy.remove(ip);
                    }
                    save_baseline(&network_name_clone, &baseline_copy);
                }

                // Step 3: SSDP/UPnP device enumeration (smart TVs, Roku, Sonos, routers)
                let ssdp_results = ssdp_discover(3);
                if !ssdp_results.is_empty() {
                    if let Ok(mut meta) = meta_clone.lock() {
                        for (ip, ssdp_meta) in ssdp_results {
                            let entry = meta.entry(ip).or_insert_with(HashMap::new);
                            for (k, v) in ssdp_meta {
                                entry.insert(k, v);
                            }
                        }
                    }
                }

                // Step 4: WSD probe for Windows devices (printers, PCs, NAS)
                let wsd_results = wsd_discover(3);
                if !wsd_results.is_empty() {
                    if let Ok(mut meta) = meta_clone.lock() {
                        for (ip, wsd_meta) in &wsd_results {
                            let entry = meta.entry(*ip).or_insert_with(HashMap::new);
                            for (k, v) in wsd_meta {
                                entry.insert(k.clone(), v.clone());
                            }
                        }
                    }
                    // Also update hostnames from WSD if we got one
                    for (ip, wsd_meta) in wsd_results {
                        if let Some(hostname) = wsd_meta.get("wsd_hostname") {
                            if let Ok(mut map) = devices_clone.lock() {
                                if let Some(entry) = map.get_mut(&ip) {
                                    if entry.hostname == "\u{2014}" || entry.hostname == "Resolving..." {
                                        entry.hostname = hostname.clone();
                                    }
                                }
                            }
                        }
                    }
                }

                // Step 4.5: Active DHCP Inform Probing for unidentified devices
                // Any device found via ARP but missing OS identification gets a DHCP Inform packet
                // to solicit its Option 55 Parameter Request List without negotiating a lease.
                {
                    let mut unident_ips = Vec::new();
                    if let Ok(map) = devices_clone.lock() {
                        let meta_guard = meta_clone.lock().unwrap();
                        for (ip, dev) in map.iter() {
                            if let IpAddr::V4(v4) = ip {
                                // Only probe if we don't already have a strong OS model/fingerprint
                                let has_model = meta_guard.get(ip).map_or(false, |m| m.contains_key("model"));
                                let is_apple = dev.vendor == "Apple Inc." || dev.vendor == "Apple";
                                // If it's completely unknown, or we know it's Apple but don't know WHICH Apple device
                                if !has_model && (dev.vendor == "Unknown" || dev.vendor == "Randomized MAC" || is_apple) {
                                    unident_ips.push(*v4);
                                }
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
                            if let Ok(mut meta) = meta_clone.lock() {
                                for (ip, fp) in dhcp_fps {
                                    let entry = meta.entry(ip).or_insert_with(HashMap::new);
                                    entry.insert("dhcp_fingerprint".to_string(), fp);
                                }
                            }
                        }
                    }
                }

                // Step 5: Final Enrichment - replace technical junk with friendly names
                if let Ok(mut map) = devices_clone.lock() {
                    if let Ok(meta) = meta_clone.lock() {
                        for (ip, entry) in map.iter_mut() {
                            // If name is cryptic (starts with _, or is a placeholder) try to upgrade it from metadata
                            if entry.hostname.starts_with('_') || entry.hostname == "\u{2014}" || entry.hostname == "Resolving..." {
                                if let Some(dev_meta) = meta.get(ip) {
                                    if let Some(model) = dev_meta.get("model")
                                        .or(dev_meta.get("friendly_name"))
                                        .or(dev_meta.get("model_name")) 
                                    {
                                        entry.hostname = model.clone();
                                    }
                                }
                            }
                            
                            // General cleanup for common cryptic network artifacts
                            let mut clean_name = entry.hostname.trim_start_matches('_').to_string();
                            if let Some(pos) = clean_name.find("._") {
                                clean_name.truncate(pos);
                            }
                            if clean_name.starts_with("I49B8F") { clean_name = "eero Node".to_string(); }
                            if clean_name == "eerogw" { clean_name = "eero Gateway".to_string(); }
                            if clean_name == "trel" { clean_name = "eero Link".to_string(); }
                            if clean_name == "asquic" {
                                // Context-aware: use model from metadata if available
                                if let Some(dev_meta) = meta.get(ip) {
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
                        }
                    }
                }

                // Final save of baseline with enriched names
                if let Ok(map) = devices_clone.lock() {
                    let mut baseline_copy = map.clone();
                    // Strip fe80:: dupes from saved baseline only
                    let ipv4_macs: std::collections::HashSet<String> = baseline_copy.iter()
                        .filter(|(ip, _)| matches!(ip, IpAddr::V4(_)))
                        .map(|(_, dev)| dev.mac.clone())
                        .collect();
                    baseline_copy.retain(|ip, dev| {
                        if let IpAddr::V6(v6) = ip {
                            !(v6.segments()[0] == 0xfe80 && ipv4_macs.contains(&dev.mac))
                        } else {
                            true
                        }
                    });
                    save_baseline(&network_name_clone, &baseline_copy);
                }
            });
        } else {
            let _ = status_tx.send("Error: API failure".to_string());
        }
    }
}

#[cfg(not(windows))]
fn perform_scan(_: &Arc<Mutex<HashMap<IpAddr, (String, String, String)>>>, _: &Arc<Mutex<DeviceMetadata>>, _: &str, _: &str, status_tx: &mpsc::Sender<String>, _: &mpsc::Sender<String>) {
    let _ = status_tx.send("Discovery not supported".to_string());
}
