use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::net::IpAddr;
use std::sync::Arc;
use dashmap::DashMap;

use chrono::{DateTime, Local};
use std::time::Duration;
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::symbols;
use ratatui::widgets::{
    Axis, Bar, BarChart, BarGroup, Block, Chart, Dataset, GraphType, List, ListItem, Paragraph,
};
use ratatui::widgets::canvas::Canvas;
use ratatui::Frame;

use crate::packet::{CapturedPacket, Protocol, ProtocolFilter};

const HOST_ICON_RAW: &str = include_str!("../laptopbraille.txt");
static HOST_ICON: std::sync::OnceLock<Vec<String>> = std::sync::OnceLock::new();

// ---------------------------------------------------------------------------
// Alert types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq)]
pub enum AlertLevel {
    Warn,
    Info,
}

#[derive(Clone, Copy, PartialEq)]
pub enum AlertTier {
    Suspicious,
    Behavioral,
    External,
    Noise,
}

#[derive(Clone, Copy, PartialEq)]
pub enum AlertReason {
    SuspiciousFlags,
    SensitivePort,
    InboundExternal,
    HighVolume,
    OutboundPublic,
    LocalBroadcast,
}

#[derive(Clone)]
#[allow(dead_code)]
pub struct Alert {
    pub timestamp: DateTime<Local>,
    pub message: String,
    pub level: AlertLevel,
    pub tier: AlertTier,
    pub remote_ip: Option<IpAddr>,
    pub process: Option<String>,
    pub reason: AlertReason,
}

#[derive(PartialEq, Clone, Copy)]
pub enum AlertFilter {
    All,
    Suspicious,
    Behavioral,
    External,
    Noise,
}

#[derive(PartialEq, Clone, Copy)]
pub enum DiscoveryFilter {
    All,
    Named,
    Vendors,
    Unknown,
}

// ---------------------------------------------------------------------------
// Application state — owned by main, passed by reference to draw functions
// ---------------------------------------------------------------------------

#[derive(PartialEq, Clone, Copy)]
pub enum Panel {
    Feed,
    Alerts,
    Discovery,
}

#[derive(PartialEq, Clone, Copy)]
pub enum InputMode {
    Normal,
    Exporting,
    Whitelisting,
}

/// Per-IP traffic profile for behavioral device classification.
/// Accumulated over 60-second rolling windows.
pub struct TrafficProfile {
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub tcp_packets: u32,
    pub udp_packets: u32,
    pub unique_dsts: HashSet<IpAddr>,
    pub port_counts: HashMap<u16, u32>,
    pub last_reset: std::time::Instant,
}

impl TrafficProfile {
    pub fn new() -> Self {
        Self {
            upload_bytes: 0,
            download_bytes: 0,
            tcp_packets: 0,
            udp_packets: 0,
            unique_dsts: HashSet::new(),
            port_counts: HashMap::new(),
            last_reset: std::time::Instant::now(),
        }
    }
}

/// Classify a device's likely type based on its 60-second traffic profile.
fn classify_device_type(profile: &TrafficProfile) -> Option<&'static str> {
    let total = profile.tcp_packets + profile.udp_packets;
    if total < 3 { return None; }

    let udp_ratio = profile.udp_packets as f64 / total as f64;

    // Camera: sustained upstream UDP on RTSP ports
    let rtsp = profile.port_counts.get(&554).copied().unwrap_or(0)
        + profile.port_counts.get(&8554).copied().unwrap_or(0);
    if rtsp > 5 && udp_ratio > 0.5 && profile.upload_bytes > 50_000 {
        return Some("CAM");
    }

    // Gaming console: large UDP to gaming ports
    let game: u32 = [3074u16, 3478, 3479, 3480, 9307].iter()
        .filter_map(|p| profile.port_counts.get(p))
        .sum();
    if game > 10 && udp_ratio > 0.4 {
        return Some("GME");
    }

    // Streaming: high sustained download, few destinations
    if profile.download_bytes > 500_000 && profile.unique_dsts.len() <= 5 {
        return Some("STR");
    }

    // IoT sensor: tiny periodic traffic
    if total < 15 && profile.upload_bytes < 5_000 && profile.download_bytes < 5_000
        && profile.unique_dsts.len() <= 2 {
        return Some("IoT");
    }

    None
}

#[allow(clippy::type_complexity)]
pub struct AppState {
    pub interface_name: String,
    pub current_network: String,
    pub feed_tcp: VecDeque<(std::time::Instant, crate::packet::CapturedPacket)>,
    pub feed_udp: VecDeque<(std::time::Instant, crate::packet::CapturedPacket)>,
    pub feed_icmp: VecDeque<(std::time::Instant, crate::packet::CapturedPacket)>,
    pub tcp_count: u64,
    pub udp_count: u64,
    pub icmp_count: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub dest_bytes: HashMap<IpAddr, u64>,
    pub connections: HashMap<(IpAddr, IpAddr, Option<u16>), (u64, u64, Option<String>, std::time::Duration)>,
    pub unique_ips: HashSet<IpAddr>,
    pub src_packet_counts: HashMap<IpAddr, u64>,
    pub pair_packet_counts: HashMap<(IpAddr, IpAddr), u64>,
    pub high_volume_alerted: HashSet<(IpAddr, IpAddr)>,
    pub bytes_history: VecDeque<u64>,
    pub current_second_bytes: u64,
    pub current_second_packets: u64,
    pub packets_per_sec: u64,
    pub start_time: std::time::Instant,
    pub last_tick: std::time::Instant,
    pub paused: bool,
    pub display_filter: ProtocolFilter,
    pub alert_filter: AlertFilter,
    pub discovery_filter: DiscoveryFilter,
    pub limit_reached: bool,
    pub capture_error: Option<String>,
    pub alerts_suspicious: Vec<Alert>,
    pub alerts_behavioral: Vec<Alert>,
    pub alerts_external: Vec<Alert>,
    pub alerts_noise: Vec<Alert>,
    pub total_alerts: u64,
    pub total_alerts_suspicious: u64,
    pub total_alerts_behavioral: u64,
    pub total_alerts_external: u64,
    pub total_alerts_noise: u64,
    // Scrolling and Focus
    pub focused_panel: Panel,
    pub feed_scroll: usize,
    pub feed_paused_scroll: bool,
    pub alert_scroll: usize,
    pub alert_paused_scroll: bool,
    pub discovery_scroll: usize,
    pub discovery_paused_scroll: bool,
    pub discovery_status: String,
    pub last_discovery_time: String,
    pub auto_scan_enabled: bool,
    pub last_auto_scan: std::time::Instant,
    // Input Mode and State
    pub scan_has_run: bool,
    pub ip_compressed: bool,
    pub input_mode: InputMode,
    pub input_buffer: String,
    pub whitelist: HashSet<IpAddr>,
    pub geo_cache: HashMap<IpAddr, crate::geoip::GeoInfo>,
    pub geo_in_flight: usize,
    pub footer_message: Option<(String, std::time::Instant)>,
    pub process_cache: Arc<DashMap<(u16, Protocol), String>>,
    pub passive_discovery: Arc<std::sync::Mutex<HashMap<IpAddr, crate::discovery::DeviceInfo>>>,
    pub active_discovery: Arc<std::sync::Mutex<HashMap<IpAddr, crate::discovery::DeviceInfo>>>,
    // DNS Poisoning Detection
    pub dns_response_counts: HashMap<(IpAddr, IpAddr), (u64, std::time::Instant)>,
    pub dns_poison_alerted: HashSet<String>,
    // Beacon/C2 Detection
    pub connection_intervals: HashMap<(IpAddr, IpAddr), Vec<std::time::Instant>>,
    pub beacon_alerted: HashSet<(IpAddr, IpAddr)>,
    // Port Scan Detection
    pub src_port_targets: HashMap<IpAddr, HashSet<u16>>,
    pub port_scan_alerted: HashSet<IpAddr>,
    // Connection Duration Tracking
    pub connection_first_seen: HashMap<(IpAddr, IpAddr, Option<u16>), std::time::Instant>,
    // Passive OS Fingerprinting: IP → (tag like "[Win]", confidence 0-255)
    pub os_fingerprints: HashMap<IpAddr, (&'static str, u8)>,
    // DNS Cache: resolved IP → domain name (from parsed DNS responses)
    pub dns_cache: HashMap<IpAddr, String>,
    // Graph View
    pub show_graph: bool,
    pub graph_nodes: HashMap<IpAddr, GraphNode>,
    pub graph_tick: u64,
    pub edge_last_seen: HashMap<(IpAddr, IpAddr), std::time::Instant>,
    pub selected_node: Option<IpAddr>,
    pub edge_first_seen: HashMap<(IpAddr, IpAddr), std::time::Instant>,
    pub node_last_seen_details: HashMap<IpAddr, (String, String)>,
    // Radar visual effects
    pub sweep_hit_tick: HashMap<IpAddr, u64>,
    pub ping_rings: Vec<(f64, f64, u64)>,
    pub positioned_nodes: Vec<IpAddr>,
    // Rich device metadata from mDNS TXT records and SSDP/UPnP
    pub device_metadata: Arc<std::sync::Mutex<crate::discovery::DeviceMetadata>>,
    // JA4 TLS fingerprints: local IP → (most common JA4 hash, sample count)
    pub tls_fingerprints: HashMap<IpAddr, (String, u32)>,
    // DHCP Parameter Request List fingerprints: IP → Option 55 string
    pub dhcp_fingerprints: HashMap<IpAddr, String>,
    // Per-IP traffic profiles for behavioral device classification
    pub traffic_profiles: HashMap<IpAddr, TrafficProfile>,
    pub external_alerted: HashSet<IpAddr>,
}

#[derive(Debug, Clone)]
pub struct GraphNode {
    pub x: f64,
    pub y: f64,
    pub last_seen: std::time::Instant,
    pub pinned: bool,
}



impl AppState {
    pub fn new(interface_name: String, current_network: String) -> Self {
        let now = std::time::Instant::now();
        
        let mut host_ip = None;
        for iface in pnet::datalink::interfaces() {
            if iface.name == interface_name {
                for ip_net in iface.ips {
                    if ip_net.ip().is_ipv4() {
                        host_ip = Some(ip_net.ip());
                        break;
                    }
                }
            }
        }
        
        let mut graph_nodes = HashMap::new();
        if let Some(ip) = host_ip {
            graph_nodes.insert(ip, GraphNode {
                x: 0.0,
                y: 0.0,
                last_seen: now,
                pinned: true,
            });
        }
        
        // Parse host icon at startup, crop empty braille space
        HOST_ICON.get_or_init(|| {
            let lines: Vec<String> = HOST_ICON_RAW
                .split('\n')
                .map(|s| s.trim_end_matches('\r').to_string())
                .filter(|s| !s.replace('⠀', "").trim().is_empty())
                .collect();
                
            if lines.is_empty() {
                return vec!["[HOST]".to_string()];
            }

            let min_leading = lines.iter()
                .map(|l| l.chars().take_while(|&c| c == '⠀' || c == ' ').count())
                .min()
                .unwrap_or(0);

            lines.into_iter()
                .map(|l| {
                    let chars: String = l.chars().skip(min_leading).collect();
                    chars.trim_end_matches(|c| c == '⠀' || c == ' ').to_string()
                })
                .collect()
        });

        Self {
            interface_name,
            current_network,
            feed_tcp: VecDeque::with_capacity(2001),
            feed_udp: VecDeque::with_capacity(2001),
            feed_icmp: VecDeque::with_capacity(2001),
            tcp_count: 0,
            udp_count: 0,
            icmp_count: 0,
            total_packets: 0,
            total_bytes: 0,
            dest_bytes: HashMap::new(),
            connections: HashMap::new(),
            unique_ips: HashSet::new(),
            src_packet_counts: HashMap::new(),
            pair_packet_counts: HashMap::new(),
            high_volume_alerted: HashSet::new(),
            bytes_history: VecDeque::with_capacity(31),
            current_second_bytes: 0,
            current_second_packets: 0,
            packets_per_sec: 0,
            start_time: now,
            last_tick: now,
            paused: false,
            display_filter: ProtocolFilter::All,
            alert_filter: AlertFilter::All,
            discovery_filter: DiscoveryFilter::All, // Default to All
            limit_reached: false,
            capture_error: None,
            alerts_suspicious: Vec::new(),
            alerts_behavioral: Vec::new(),
            alerts_external: Vec::new(),
            alerts_noise: Vec::new(),
            total_alerts: 0,
            total_alerts_suspicious: 0,
            total_alerts_behavioral: 0,
            total_alerts_external: 0,
            total_alerts_noise: 0,
            focused_panel: Panel::Feed,
            feed_scroll: 0,
            feed_paused_scroll: false,
            alert_scroll: 0,
            alert_paused_scroll: false,
            discovery_scroll: 0,
            discovery_paused_scroll: false,
            discovery_status: "[ Waiting for Signal ]".to_string(),
            last_discovery_time: "--:--:--".to_string(),
            auto_scan_enabled: true,
            last_auto_scan: now,
            scan_has_run: false,
            ip_compressed: true,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            whitelist: HashSet::new(),
            geo_cache: HashMap::new(),
            geo_in_flight: 0,
            footer_message: None,
            process_cache: Arc::new(DashMap::new()),
            passive_discovery: Arc::new(std::sync::Mutex::new(HashMap::new())),
            active_discovery: Arc::new(std::sync::Mutex::new(HashMap::new())),
            dns_response_counts: HashMap::new(),
            dns_poison_alerted: HashSet::new(),
            connection_intervals: HashMap::new(),
            beacon_alerted: HashSet::new(),
            src_port_targets: HashMap::new(),
            port_scan_alerted: HashSet::new(),
            connection_first_seen: HashMap::new(),
            os_fingerprints: HashMap::new(),
            dns_cache: HashMap::new(),
            show_graph: false,
            graph_nodes,
            graph_tick: 0,
            edge_last_seen: HashMap::new(),
            selected_node: None,
            edge_first_seen: HashMap::new(),
            node_last_seen_details: HashMap::new(),
            sweep_hit_tick: HashMap::new(),
            ping_rings: Vec::new(),
            positioned_nodes: Vec::new(),
            device_metadata: Arc::new(std::sync::Mutex::new(HashMap::new())),
            tls_fingerprints: HashMap::new(),
            dhcp_fingerprints: HashMap::new(),
            traffic_profiles: HashMap::new(),
            external_alerted: HashSet::new(),
        }
    }

fn is_noise_address(ip: &std::net::IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_broadcast()           // 255.255.255.255
            || v4.is_multicast()        // 224.0.0.0/4
            || v4.octets()[0] == 239    // 239.x.x.x SSDP
            || v4.octets()[3] == 255    // directed subnet broadcast (x.x.x.255)
            || v4.octets()[3] == 0      // network address (x.x.x.0)
        }
        IpAddr::V6(v6) => {
            v6.is_multicast()
        }
    }
}

    pub fn ingest_packet(&mut self, pkt: &CapturedPacket) {
        if Self::is_noise_address(&pkt.src_ip) || Self::is_noise_address(&pkt.dst_ip) {
            return;
        }

        match pkt.protocol {
            Protocol::Tcp => self.tcp_count += 1,
            Protocol::Udp => self.udp_count += 1,
            Protocol::Icmp => self.icmp_count += 1,
            Protocol::Unknown(_) => {}
        }
        self.total_packets += 1;
        self.total_bytes += pkt.size as u64;

        self.edge_last_seen.insert((pkt.src_ip, pkt.dst_ip), std::time::Instant::now());
        self.edge_first_seen.entry((pkt.src_ip, pkt.dst_ip)).or_insert_with(std::time::Instant::now);

        let proto_str = match pkt.protocol {
            Protocol::Tcp => "TCP",
            Protocol::Udp => "UDP",
            Protocol::Icmp => "ICMP",
            Protocol::Unknown(_) => "Unknown",
        }.to_string();
        
        let proc_name = if let Some(port) = pkt.src_port.or(pkt.dst_port) {
            self.process_cache.get(&(port, pkt.protocol.clone())).map(|v| v.clone()).unwrap_or_else(|| "--".to_string())
        } else {
            "--".to_string()
        };

        self.node_last_seen_details.insert(pkt.src_ip, (proto_str.clone(), proc_name.clone()));
        self.node_last_seen_details.insert(pkt.dst_ip, (proto_str, proc_name));

        // Passive OS fingerprinting from TTL + TCP window
        self.update_os_fingerprint(pkt);

        // DNS cache: map resolved IPs to their domain name
        if let Some((domain, ips)) = &pkt.dns_answers {
            for ip in ips {
                self.dns_cache.insert(*ip, domain.clone());
            }
        }

        // TLS SNI / HTTP Host: map destination IP to domain
        if let Some(domain) = &pkt.domain_hint {
            self.dns_cache.entry(pkt.dst_ip).or_insert_with(|| domain.clone());
        }

        *self.dest_bytes.entry(pkt.dst_ip).or_insert(0) += pkt.size as u64;
        self.current_second_bytes += pkt.size as u64;
        self.current_second_packets += 1;

        // JA4 TLS fingerprint tracking per local device
        if let Some(ref ja4) = pkt.tls_fingerprint {
            if is_private_ip(&pkt.src_ip) {
                let entry = self.tls_fingerprints.entry(pkt.src_ip)
                    .or_insert_with(|| (ja4.clone(), 0));
                entry.1 += 1;
            }
        }

        // Traffic profile accumulation for behavioral device classification
        if is_private_ip(&pkt.src_ip) {
            let profile = self.traffic_profiles.entry(pkt.src_ip)
                .or_insert_with(TrafficProfile::new);
            if profile.last_reset.elapsed() > std::time::Duration::from_secs(60) {
                *profile = TrafficProfile::new();
            }
            profile.upload_bytes += pkt.size as u64;
            match pkt.protocol {
                Protocol::Tcp => profile.tcp_packets += 1,
                Protocol::Udp => profile.udp_packets += 1,
                _ => {}
            }
            if let Some(port) = pkt.dst_port {
                *profile.port_counts.entry(port).or_insert(0) += 1;
            }
            profile.unique_dsts.insert(pkt.dst_ip);
        }
        if is_private_ip(&pkt.dst_ip) {
            let profile = self.traffic_profiles.entry(pkt.dst_ip)
                .or_insert_with(TrafficProfile::new);
            if profile.last_reset.elapsed() > std::time::Duration::from_secs(60) {
                *profile = TrafficProfile::new();
            }
            profile.download_bytes += pkt.size as u64;
        }

        // Graph view nodes tracking
        let now = std::time::Instant::now();
        for ip in &[pkt.src_ip, pkt.dst_ip] {
            if ip.is_multicast() { continue; }
            if let IpAddr::V4(v4) = ip {
                if v4.is_broadcast() || v4.octets() == [255, 255, 255, 255] { continue; }
            }

            if !self.graph_nodes.contains_key(ip) {
                self.graph_nodes.insert(*ip, GraphNode {
                    x: 0.0,
                    y: 0.0,
                    last_seen: now,
                    pinned: false,
                });
            } else {
                if let Some(node) = self.graph_nodes.get_mut(ip) {
                    node.last_seen = now;
                }
            }
        }

        // Update connection tracker (now includes process name and duration)
        let conn_key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port);

        // Track first-seen time for new connections
        self.connection_first_seen.entry(conn_key).or_insert_with(std::time::Instant::now);

        // Resolve process name from packet or background cache
        let resolved_proc = if let Some(p) = &pkt.process {
            if p == "unknown" {
                let key = (pkt.src_port.unwrap_or(0), pkt.protocol.clone());
                self.process_cache.get(&key).map(|v| v.value().clone()).unwrap_or_else(|| "unknown".to_string())
            } else {
                p.clone()
            }
        } else {
            let key = (pkt.src_port.unwrap_or(0), pkt.protocol.clone());
            self.process_cache.get(&key).map(|v| v.value().clone()).unwrap_or_else(|| "unknown".to_string())
        };

        let packet_count = {
            let entry = self.connections.entry(conn_key).or_insert((0, 0, None, std::time::Duration::ZERO));
            entry.0 += 1;
            entry.1 += pkt.size as u64;
            // Only update if we have a real name or if it was unknown
            if entry.2.is_none() || entry.2.as_deref() == Some("unknown") {
                entry.2 = Some(resolved_proc.clone());
            }
            // Update duration since first seen
            entry.3 = self.connection_first_seen
                .get(&conn_key)
                .map(|t| t.elapsed())
                .unwrap_or_default();
            entry.0
        };

        // Track unique IPs and per-source packet counts
        self.unique_ips.insert(pkt.src_ip);
        self.unique_ips.insert(pkt.dst_ip);
        *self.src_packet_counts.entry(pkt.src_ip).or_insert(0) += 1;

        // Track per-pair packet counts for high-volume alert
        let pair = (pkt.src_ip, pkt.dst_ip);
        let pair_count = {
            let entry = self.pair_packet_counts.entry(pair).or_insert(0);
            *entry += 1;
            *entry
        };

        // --- DNS Poisoning Detection ---
        // Track DNS responses (UDP port 53) for flood detection
        // Skip if source is a private IP (router/gateway) to avoid false positives
        if pkt.protocol == Protocol::Udp && pkt.src_port == Some(53) && !is_private_ip(&pkt.src_ip) {
            let dns_key = (pkt.src_ip, pkt.dst_ip);
            let now_instant = std::time::Instant::now();

            let entry = self.dns_response_counts.entry(dns_key).or_insert((0, now_instant));
            let (count, start_time) = entry;

            // Reset if more than 1 second has passed
            if now_instant.duration_since(*start_time) > Duration::from_secs(1) {
                *count = 1;
                *start_time = now_instant;
            } else {
                *count += 1;
            }

            // Alert if more than 5 responses in under 1 second
            if *count > 5 && !self.dns_poison_alerted.contains(&dns_key.0.to_string()) {
                self.dns_poison_alerted.insert(dns_key.0.to_string());
                self.push_alert(Alert {
                    timestamp: Local::now(),
                    message: format!("DNS FLOOD DETECTED: {} is sending abnormal DNS responses (possible poisoning attempt)", pkt.src_ip),
                    level: AlertLevel::Warn,
                    tier: AlertTier::Suspicious,
                    remote_ip: Some(pkt.src_ip),
                    process: None,
                    reason: AlertReason::SuspiciousFlags,
                });
            }
        }

        // --- Beacon/C2 Detection ---
        // Track connection intervals to public IPs
        if !is_local_or_multicast(&pkt.dst_ip) {
            let beacon_key = (pkt.src_ip, pkt.dst_ip);
            let now_instant = std::time::Instant::now();

            let intervals = self.connection_intervals.entry(beacon_key).or_insert_with(Vec::new);

            // Only record if this is a new connection attempt (first packet or gap > 4s since last)
            let should_record = intervals.last()
                .map(|last| now_instant.duration_since(*last).as_secs_f64() > 4.0)
                .unwrap_or(true); // always record the first packet

            if should_record {
                intervals.push(now_instant);
            }

            // Prune to last 20 entries to prevent unbounded growth
            if intervals.len() > 20 {
                *intervals = intervals.split_off(intervals.len() - 20);
            }

            // Check for beacon pattern if we have 6+ timestamps
            if intervals.len() >= 6 && !self.beacon_alerted.contains(&beacon_key) {
                let last_6: Vec<_> = intervals.iter().copied().skip(intervals.len() - 6).collect();
                let gaps: Vec<f64> = last_6.windows(2)
                    .map(|w| w[1].duration_since(w[0]).as_secs_f64())
                    .collect();

                if gaps.len() == 5 {
                    let mean_gap = gaps.iter().sum::<f64>() / gaps.len() as f64;

                    // Check if mean gap is between 5 seconds and 5 minutes
                    if mean_gap >= 5.0 && mean_gap <= 300.0 {
                        // Calculate standard deviation
                        let variance = gaps.iter()
                            .map(|g| (g - mean_gap).powi(2))
                            .sum::<f64>() / gaps.len() as f64;
                        let std_dev = variance.sqrt();

                        // Alert if std_dev is less than 20% of mean (very regular)
                        if std_dev < mean_gap * 0.2 {
                            // Suppress beacon alerts for known trusted processes
                            let proc_name = self.process_cache
                                .get(&(pkt.src_port.unwrap_or(0), pkt.protocol.clone()))
                                .map(|v| v.clone())
                                .unwrap_or_default()
                                .to_lowercase();

                            let trusted_processes = [
                                "chrome.exe",
                                "antigravity.exe", 
                                "language_server_windows_x64.exe",
                                "vora-recon.exe",
                                "msedge.exe",
                                "firefox.exe",
                                "teams.exe",
                                "slack.exe",
                                "discord.exe",
                                "spotify.exe",
                                "onedrive.exe",
                                "svchost.exe",
                            ];

                            let is_trusted = trusted_processes.iter().any(|t| proc_name.contains(t));
                            if !is_trusted {
                                self.beacon_alerted.insert(beacon_key);
                                self.push_alert(Alert {
                                    timestamp: Local::now(),
                                    message: format!("BEACON DETECTED: {} -> {} — regular interval ~{:.0}s (possible C2 heartbeat)",
                                        pkt.src_ip, pkt.dst_ip, mean_gap),
                                    level: AlertLevel::Warn,
                                    tier: AlertTier::Behavioral,
                                    remote_ip: Some(pkt.dst_ip),
                                    process: None,
                                    reason: AlertReason::SuspiciousFlags,
                                });
                            }
                        }
                    }
                }
            }
        }

        // --- Port Scan Detection ---
        // Track unique destination ports per source IP (TCP/UDP only)
        // Only track external sources probing local ports (not private IPs scanning out)
        if (pkt.protocol == Protocol::Tcp || pkt.protocol == Protocol::Udp)
            && !is_private_ip(&pkt.src_ip)
            && is_private_ip(&pkt.dst_ip)
        {
            if let Some(dst_port) = pkt.dst_port {
                let ports = self.src_port_targets.entry(pkt.src_ip).or_insert_with(HashSet::new);
                ports.insert(dst_port);

                // Alert if source IP has contacted more than 25 unique destination ports
                if ports.len() > 25 && !self.port_scan_alerted.contains(&pkt.src_ip) {
                    self.port_scan_alerted.insert(pkt.src_ip);
                    let port_count = ports.len();
                    let src_ip = pkt.src_ip;
                    // Clear the entry to prevent unbounded growth
                    self.src_port_targets.remove(&pkt.src_ip);
                    self.push_alert(Alert {
                        timestamp: Local::now(),
                        message: format!("PORT SCAN DETECTED: {} is probing {} unique ports (possible reconnaissance)", src_ip, port_count),
                        level: AlertLevel::Warn,
                        tier: AlertTier::Suspicious,
                        remote_ip: Some(src_ip),
                        process: None,
                        reason: AlertReason::SuspiciousFlags,
                    });
                }
            }
        }

        // --- Generate alerts ---
        if self.whitelist.contains(&pkt.src_ip) || self.whitelist.contains(&pkt.dst_ip) {
            return;
        }

        let proc_label = resolved_proc;
        let now = Local::now();
        
        let geo_tag = self.geo_cache.get(&pkt.dst_ip)
            .map(|g| format!(" {}", format_geo_tag(g)))
            .unwrap_or_default();

        let src_geo_tag = self.geo_cache.get(&pkt.src_ip)
            .map(|g| format!(" {}", format_geo_tag(g)))
            .unwrap_or_default();

        // Rule 1 — Suspicious flags (TCP only)
        if pkt.protocol == Protocol::Tcp {
            if let Some(f) = &pkt.flags {
                if f.contains("SYN") && f.contains("FIN") {
                    self.push_alert(Alert {
                        timestamp: now,
                        message: format!("Illegal flags SYN+FIN from {} (possible OS fingerprint) ({})", pkt.src_ip, proc_label),
                        level: AlertLevel::Warn,
                        tier: AlertTier::Suspicious,
                        remote_ip: Some(pkt.src_ip),
                        process: Some(proc_label.clone()),
                        reason: AlertReason::SuspiciousFlags,
                    });
                }
                if f.contains("SYN") && f.contains("PSH") && !f.contains("ACK") {
                    self.push_alert(Alert {
                        timestamp: now,
                        message: format!("Illegal flags SYN+PSH from {} (data before handshake) ({})", pkt.src_ip, proc_label),
                        level: AlertLevel::Warn,
                        tier: AlertTier::Suspicious,
                        remote_ip: Some(pkt.src_ip),
                        process: Some(proc_label.clone()),
                        reason: AlertReason::SuspiciousFlags,
                    });
                }
                if f == "\u{2014}" {
                    self.push_alert(Alert {
                        timestamp: now,
                        message: format!("NULL scan from {} \u{2014} no TCP flags set ({})", pkt.src_ip, proc_label),
                        level: AlertLevel::Warn,
                        tier: AlertTier::Suspicious,
                        remote_ip: Some(pkt.src_ip),
                        process: Some(proc_label.clone()),
                        reason: AlertReason::SuspiciousFlags,
                    });
                }
                if f.contains("FIN") && f.contains("PSH") && f.contains("URG") {
                    self.push_alert(Alert {
                        timestamp: now,
                        message: format!("Xmas scan from {} \u{2014} FIN+PSH+URG ({})", pkt.src_ip, proc_label),
                        level: AlertLevel::Warn,
                        tier: AlertTier::Suspicious,
                        remote_ip: Some(pkt.src_ip),
                        process: Some(proc_label.clone()),
                        reason: AlertReason::SuspiciousFlags,
                    });
                }
            }
        }

        // Rule 2 — Sensitive outbound port
        if let Some(port) = pkt.dst_port {
            if [21, 23, 445, 3389].contains(&port) && !is_local_or_multicast(&pkt.dst_ip) {
                let port_name = match port {
                    21 => "FTP",
                    23 => "Telnet",
                    445 => "SMB",
                    3389 => "RDP",
                    _ => "Unknown",
                };
                self.push_alert(Alert {
                    timestamp: now,
                    message: format!("Outbound {} ({}) \u{2192} {}{} ({})", port_name, port, pkt.dst_ip, geo_tag, proc_label),
                    level: AlertLevel::Warn,
                    tier: AlertTier::Suspicious,
                    remote_ip: Some(pkt.dst_ip),
                    process: Some(proc_label.clone()),
                    reason: AlertReason::SensitivePort,
                });
            }
        }

        // Rule 3 — Inbound external on privileged port
        if let Some(port) = pkt.dst_port {
            if is_private_ip(&pkt.dst_ip) && !is_private_ip(&pkt.src_ip) && port < 1024 {
                self.push_alert(Alert {
                    timestamp: now,
                    message: format!("Inbound on port {} from {}{} ({})", port, pkt.src_ip, src_geo_tag, proc_label),
                    level: AlertLevel::Warn,
                    tier: AlertTier::Suspicious,
                    remote_ip: Some(pkt.src_ip),
                    process: Some(proc_label.clone()),
                    reason: AlertReason::InboundExternal,
                });
            }
        }

        // Rule 4 — High volume
        if pair_count >= 500 && !self.high_volume_alerted.contains(&pair) {
            self.high_volume_alerted.insert(pair);
            self.push_alert(Alert {
                timestamp: now,
                message: format!(
                    "High volume: {} \u{2192} {} exceeded 500 packets",
                    pair.0, pair.1,
                ),
                level: AlertLevel::Warn,
                tier: AlertTier::Behavioral,
                remote_ip: None,
                process: Some(proc_label.clone()),
                reason: AlertReason::HighVolume,
            });
        }

        // Auto-whitelist trusted services to prevent false positives
        let is_geo_lookup = |ip: &std::net::IpAddr| {
            let ip_str = ip.to_string();
            matches!(ip_str.as_str(), "208.95.112.1")
            || self.dns_cache.get(ip)
                .map(|d| d.contains("ip-api.com") || d.contains("malwarebytes"))
                .unwrap_or(false)
        };

        if is_geo_lookup(&pkt.src_ip) || is_geo_lookup(&pkt.dst_ip) {
            return;
        }

        // Rule 5 — Outbound public (External tier)
        if !is_local_or_multicast(&pkt.dst_ip) && packet_count == 1 {
            let port_str = pkt.dst_port.map_or("---".to_string(), |p| p.to_string());

            let trusted_orgs = [
                "Google LLC", "Google Cloud", "Cloudflare", "Amazon",
                "Microsoft", "Akamai", "Fastly", "Meta ", "Apple Inc",
                "Anthropic", "Akamaitech", "AS13335", "AS15169",
            ];
            let is_trusted_org = self.geo_cache.get(&pkt.dst_ip)
                .map(|g| trusted_orgs.iter().any(|o| g.org.contains(o)))
                .unwrap_or(false);

            let alert_tier = if is_trusted_org { AlertTier::Noise } else { AlertTier::External };

            if !self.external_alerted.contains(&pkt.dst_ip) {
                self.external_alerted.insert(pkt.dst_ip);
                self.push_alert(Alert {
                    timestamp: now,
                    message: format!("Outbound \u{2192} {}:{}{} ({})", pkt.dst_ip, port_str, geo_tag, proc_label),
                    level: AlertLevel::Info,
                    tier: alert_tier,
                    remote_ip: Some(pkt.dst_ip),
                    process: Some(proc_label.clone()),
                    reason: AlertReason::OutboundPublic,
                });
            }
        }

        // Rule 6 — Local broadcast/discovery (Noise tier)
        let dst_ip_str = pkt.dst_ip.to_string();
        let is_broadcast_ip = dst_ip_str == "224.0.0.251" || dst_ip_str == "239.255.255.250" || dst_ip_str == "255.255.255.255";
        let discovery_ports = [1900, 3702, 5353, 5355, 67, 68, 137, 138, 139];
        let is_discovery_port = pkt.dst_port.map_or(false, |p| discovery_ports.contains(&p)) || pkt.src_port.map_or(false, |p| discovery_ports.contains(&p));

        if (is_broadcast_ip || is_discovery_port) && packet_count == 1 {
            let port_str = pkt.dst_port.map_or("---".to_string(), |p| p.to_string());
            self.push_alert(Alert {
                timestamp: now,
                message: format!("Local discovery: {} {} \u{2192} {} port {}", pkt.protocol, pkt.src_ip, pkt.dst_ip, port_str),
                level: AlertLevel::Info,
                tier: AlertTier::Noise,
                remote_ip: None,
                process: Some(proc_label.clone()),
                reason: AlertReason::LocalBroadcast,
            });
        }


        // Push to protocol-specific buffer
        let now_instant = std::time::Instant::now();
        match pkt.protocol {
            Protocol::Tcp => {
                self.feed_tcp.push_back((now_instant, pkt.clone()));
                if self.feed_tcp.len() > 2000 {
                    self.feed_tcp.pop_front();
                }
            }
            Protocol::Udp => {
                self.feed_udp.push_back((now_instant, pkt.clone()));
                if self.feed_udp.len() > 2000 {
                    self.feed_udp.pop_front();
                }
            }
            Protocol::Icmp => {
                self.feed_icmp.push_back((now_instant, pkt.clone()));
                if self.feed_icmp.len() > 2000 {
                    self.feed_icmp.pop_front();
                }
            }
            Protocol::Unknown(_) => {}
        }

        if self.feed_paused_scroll {
            self.feed_scroll = self.feed_scroll.saturating_add(1);
        }

        // Ensure exactly one pinned host node exists
        let has_pinned = self.graph_nodes.values().any(|n| n.pinned);
        if !has_pinned && !self.graph_nodes.is_empty() {
            // Most frequent local src IP is the host machine
            let host_candidate = self.src_packet_counts.iter()
                .filter(|(ip, _)| is_private_ip(ip) && self.graph_nodes.contains_key(ip))
                .max_by_key(|(_, count)| *count)
                .map(|(ip, _)| *ip);
            if let Some(host_ip) = host_candidate {
                if let Some(node) = self.graph_nodes.get_mut(&host_ip) {
                    node.pinned = true;
                }
            }
        }
    }

    pub fn push_alert(&mut self, alert: Alert) {
        self.total_alerts += 1;
        let target_vec = match alert.tier {
            AlertTier::Suspicious => {
                self.total_alerts_suspicious += 1;
                &mut self.alerts_suspicious
            }
            AlertTier::Behavioral => {
                self.total_alerts_behavioral += 1;
                &mut self.alerts_behavioral
            }
            AlertTier::External => {
                self.total_alerts_external += 1;
                &mut self.alerts_external
            }
            AlertTier::Noise => {
                self.total_alerts_noise += 1;
                &mut self.alerts_noise
            }
        };

        target_vec.push(alert); // newest at end (matches live feed order)
        if target_vec.len() > 2000 {
            target_vec.remove(0); // trim oldest from front
        }

        if self.alert_paused_scroll {
            self.alert_scroll = self.alert_scroll.saturating_add(1);
        }
    }

    pub fn clear_alerts(&mut self) {
        self.alerts_suspicious.clear();
        self.alerts_behavioral.clear();
        self.alerts_external.clear();
        self.alerts_noise.clear();
    }

    pub fn whitelist_ip(&mut self, ip: IpAddr) {
        self.whitelist.insert(ip);
        let ip_str = ip.to_string();
        self.alerts_suspicious.retain(|a| !a.message.contains(&ip_str));
        self.alerts_behavioral.retain(|a| !a.message.contains(&ip_str));
        self.alerts_external.retain(|a| !a.message.contains(&ip_str));
        self.alerts_noise.retain(|a| !a.message.contains(&ip_str));
    }

    pub fn set_footer_message(&mut self, msg: String) {
        self.footer_message = Some((msg, std::time::Instant::now()));
    }

    /// Gets a cleaned display name for an IP address via an authoritative priority chain.
    pub fn get_display_hostname(&self, ip: &IpAddr) -> String {
        // 1. Check DNS cache first (authoritative external domains or mDNS results)
        if let Some(domain) = self.dns_cache.get(ip) {
            let cleaned = clean_hostname(domain);
            if cleaned != "\u{2014}" && cleaned != "Resolving..." && !cleaned.is_empty() {
                return cleaned;
            }
        }

        // 2. Check local discovery hostname
        let discovery_h;
        if is_private_ip(ip) {
            if let Ok(devices) = self.active_discovery.try_lock() {
                if let Some(dev) = devices.get(ip) {
                    discovery_h = clean_hostname(&dev.hostname);
                    if discovery_h != "\u{2014}" && discovery_h != "Resolving..." && !discovery_h.is_empty() {
                        return discovery_h;
                    }
                }
            }

            // 3. Try rich metadata (mDNS model, SSDP friendly name, etc.)
            if let Ok(meta) = self.device_metadata.try_lock() {
                if let Some(dev_meta) = meta.get(ip) {
                    if let Some(m) = dev_meta.get("model").or(dev_meta.get("friendly_name")).or(dev_meta.get("model_name")) {
                        let cleaned = clean_hostname(m);
                        if cleaned != "\u{2014}" && !cleaned.is_empty() {
                            return cleaned;
                        }
                    }
                }
            }

            // 3b. Try passive_discovery as a hostname source of last resort
            if let Ok(passive) = self.passive_discovery.try_lock() {
                if let Some(dev) = passive.get(ip) {
                    let cleaned = clean_hostname(&dev.hostname);
                    if cleaned != "\u{2014}" && cleaned != "Resolving..." && !cleaned.is_empty() {
                        return cleaned;
                    }
                }
            }

            // 4. Last resort: Behavioral classification
            if let Some(profile) = self.traffic_profiles.get(ip) {
                if let Some(dev_type) = classify_device_type(profile) {
                    return dev_type.to_string();
                }
            }
        }

        // Fallback to IP string
        ip.to_string()
    }

    /// Passive OS fingerprinting from TTL and TCP window size.
    /// Only fingerprints private/local source IPs (the ones that show up in Local Discovery).
    /// Enhanced with MAC-vendor cross-referencing for higher accuracy.
    pub fn update_os_fingerprint(&mut self, pkt: &CapturedPacket) {
        let ttl = match pkt.ttl {
            Some(t) if t > 0 => t,
            _ => return,
        };

        // Only fingerprint private IPs (local subnet devices)
        if !is_private_ip(&pkt.src_ip) {
            return;
        }

        // Round TTL up to the nearest known initial value
        let (_initial_ttl, base_os) = if ttl <= 64 {
            (64u8, "unix")   // Linux, macOS, iOS, Android
        } else if ttl <= 128 {
            (128u8, "windows") // Windows
        } else {
            (255u8, "network") // Cisco, Solaris, FreeBSD routers
        };

        // Determine tag — use TCP window size to disambiguate unix family
        let mut tag: &'static str = match base_os {
            "windows" => "[Win]",
            "network" => "[Net]",
            "unix" => {
                // TCP window size helps distinguish Linux from macOS
                match pkt.tcp_window {
                    Some(65535) => "[Mac]",              // macOS / iOS default
                    Some(64240) => "[Win]",              // Windows 10+ sometimes shows TTL 64 behind NAT
                    Some(w) if w <= 32768 => "[Lin]",    // Linux (29200, 5840, 14600, etc.)
                    Some(_) => "[Lin]",                  // Default to Linux for other unix TTLs
                    None => "[Lin]",                     // UDP/ICMP with TTL ≤64 → likely Linux
                }
            }
            _ => "[?]",
        };

        // MAC-vendor cross-reference: override passive fingerprint using known manufacturer
        // This fixes Apple devices behind eero mesh being labeled [Lin]
        if let Ok(devices) = self.active_discovery.try_lock() {
            if let Some(dev) = devices.get(&pkt.src_ip) {
                let vendor_lower = dev.vendor.to_lowercase();
                if vendor_lower.contains("apple") {
                    tag = "[Mac]";
                } else if vendor_lower.contains("samsung") || vendor_lower.contains("murata") {
                    // Murata makes Wi-Fi chips for many Android devices
                    if tag != "[Win]" { tag = "[And]"; }
                } else if vendor_lower.contains("nintendo") {
                    tag = "[Nin]";
                } else if vendor_lower.contains("sony") && !vendor_lower.contains("ericsson") {
                    tag = "[PS]";
                } else if vendor_lower.contains("microsoft") {
                    tag = "[Win]";
                } else if vendor_lower.contains("google") {
                    if tag == "[Lin]" { tag = "[And]"; }
                } else if vendor_lower.contains("oneplus") || vendor_lower.contains("xiaomi")
                    || vendor_lower.contains("huawei") || vendor_lower.contains("oppo")
                    || vendor_lower.contains("vivo") || vendor_lower.contains("realme") {
                    tag = "[And]";
                } else if vendor_lower.contains("amazon") {
                    tag = "[Amz]";
                } else if vendor_lower.contains("roku") {
                    tag = "[Rok]";
                } else if vendor_lower.contains("sonos") {
                    tag = "[Son]";
                }
            }
        }

        // Update with confidence tracking
        match self.os_fingerprints.get(&pkt.src_ip) {
            Some(&(existing_tag, confidence)) => {
                if existing_tag == tag {
                    // Same guess — increase confidence (capped at 255)
                    self.os_fingerprints.insert(pkt.src_ip, (tag, confidence.saturating_add(1)));
                } else if confidence <= 1 {
                    // Low confidence existing guess — overwrite
                    self.os_fingerprints.insert(pkt.src_ip, (tag, 1));
                }
                // Otherwise keep the higher-confidence existing guess
            }
            None => {
                // First time seeing this IP
                self.os_fingerprints.insert(pkt.src_ip, (tag, 1));
            }
        }
    }

    /// Resolves the final OS tag, applying MAC vendor overrides to correct passive fingerprinting errors
    pub fn get_resolved_os_tag(&self, ip: &IpAddr) -> String {
        // Step 0 — DHCP fingerprint (most reliable passive signal, confidence 200)
        // Only use if we have a match — otherwise fall through to existing logic
        if let Some(fp) = self.dhcp_fingerprints.get(ip) {
            if let Some((tag, _desc)) = crate::dhcp::classify_dhcp(fp) {
                return tag.to_string();
            }
        }
        
        if let Ok(meta) = self.device_metadata.try_lock() {
            if let Some(dev_meta) = meta.get(ip) {
                if let Some(fp) = dev_meta.get("dhcp_fingerprint") {
                    if let Some((tag, _desc)) = crate::dhcp::classify_dhcp(fp) {
                        return tag.to_string();
                    }
                }
            }
        }

        let mut tag = self.os_fingerprints.get(ip).map(|(t, _)| t.to_string()).unwrap_or_else(|| "[?]".to_string());
        
        let mut meta_found = false;
        let mut refined = "[?]".to_string();

        // 1. Primary Resolution: Use deep device metadata (mDNS/SSDP)
        if let Ok(meta) = self.device_metadata.try_lock() {
            if let Some(dev_meta) = meta.get(ip) {
                let model = dev_meta.get("model")
                    .or_else(|| dev_meta.get("friendly_name"))
                    .or_else(|| dev_meta.get("model_name"))
                    .cloned().unwrap_or_default().to_lowercase();
                
                if !model.is_empty() {
                    if model.contains("iphone") || model.contains("ipad") || model.contains("watch") || model.contains("homepod") || model.contains("apple tv") || model.contains("appletv") || model.contains("audioaccessory") {
                        refined = "[iOS]".to_string();
                        meta_found = true;
                    } else if model.contains("mac") || model.contains("book") || model.contains("imac") {
                        refined = "[Mac]".to_string();
                        meta_found = true;
                    } else if model.contains("samsung") || model.contains("galaxy") || model.contains("sm-") || model.contains("gt-") {
                        refined = "[And]".to_string();
                        meta_found = true;
                    } else if model.contains("nintendo") || model.contains("switch") {
                        refined = "[Nin]".to_string();
                        meta_found = true;
                    } else if model.contains("playstation") || model.contains("ps4") || model.contains("ps5") {
                        refined = "[PS]".to_string();
                        meta_found = true;
                    }
                }
            }
        }

        // 2. Secondary Resolution: Use MAC Vendor OUI (if metadata failed or didn't exist)
        if !meta_found {
            if let Ok(devices) = self.active_discovery.try_lock() {
                if let Some(dev) = devices.get(ip) {
                    let vendor_lower = dev.vendor.to_lowercase();
                    let h_lower = dev.hostname.to_lowercase();

                    if vendor_lower.contains("apple") {
                        refined = "[Apl]".to_string();
                        // Refine Apl to iOS/Mac based on hostname
                        if h_lower.contains("iphone") || h_lower.contains("ipad") || h_lower.contains("watch") || h_lower.contains("homepod") || h_lower.contains("apple tv") || h_lower.contains("airpod") {
                            refined = "[iOS]".to_string();
                        } else if h_lower.contains("mac") || h_lower.contains("book") {
                            refined = "[Mac]".to_string();
                        }
                    } else if vendor_lower.contains("nintendo") {
                        refined = "[Nin]".to_string();
                    } else if vendor_lower.contains("sony") {
                        refined = "[PS]".to_string();
                    } else if vendor_lower.contains("samsung") || vendor_lower.contains("murata") {
                        refined = "[And]".to_string();
                    } else if vendor_lower.contains("microsoft") {
                        refined = "[Win]".to_string();
                    }
                }
            }
        }

        // Apply refinement if it's better than current passive tag
        if refined != "[?]" {
            // Overwrite generic Linux or unknown tags with refined ones
            if tag == "[?]" || tag == "[Lin]" || tag == "[Net]" {
                tag = refined;
            } else if (tag == "[Apl]" || tag == "[And]") && refined.len() > 3 {
                // e.g. Upgrade [Apl] to [iOS]
                tag = refined;
            }
        }

        // Vendor-based OS hint fallback
        if tag == "[?]" {
            if let Ok(devices) = self.active_discovery.try_lock() {
                if let Some(dev) = devices.get(ip) {
                    let vendor = dev.vendor.to_lowercase();
                    if vendor.contains("apple") { return "[iOS?]".to_string(); }
                    if vendor.contains("samsung") { return "[And?]".to_string(); }
                    if vendor.contains("google") { return "[Lin?]".to_string(); }
                    if vendor.contains("amazon") { return "[?/IoT]".to_string(); }
                    if vendor.contains("ring") { return "[?/IoT]".to_string(); }
                    if vendor.contains("ecobee") { return "[?/IoT]".to_string(); }
                    if vendor.contains("sonos") { return "[Son]".to_string(); }
                    if vendor.contains("philips") { return "[?/IoT]".to_string(); }
                    if vendor.contains("whirlpool") { return "[?/IoT]".to_string(); }
                    if vendor.contains("leviton") { return "[?/IoT]".to_string(); }
                    if vendor.contains("chamberlain") { return "[?/IoT]".to_string(); }
                    if vendor.contains("texas instruments") { return "[?/IoT]".to_string(); }
                }
            }
        }

        tag
    }

    pub fn update_radar_layout(&mut self) {
        if !self.show_graph { return; }

        self.graph_tick = self.graph_tick.wrapping_add(1);

        let now = std::time::Instant::now();
        
        // Refresh host node last_seen every tick so it never expires
        let host_key = self.graph_nodes.iter()
            .find(|(_, n)| n.pinned)
            .map(|(ip, _)| *ip);
        if let Some(ip) = host_key {
            if let Some(node) = self.graph_nodes.get_mut(&ip) {
                node.last_seen = now;
            }
        }

        // Expire nodes not seen in 30 seconds
        self.graph_nodes.retain(|_, n| now.duration_since(n.last_seen).as_secs() < 30);

        let host_ip = self.graph_nodes.iter()
            .find(|(_, n)| n.pinned)
            .map(|(ip, _)| *ip);

        // Group IPs by label to prevent duplication (multiple IPs for same domain/host)
        let mut local_groups: HashMap<String, (IpAddr, u64)> = HashMap::new();
        let mut external_groups: HashMap<String, (IpAddr, u64)> = HashMap::new();

        for &ip in self.graph_nodes.keys() {
            if Some(ip) == host_ip { continue; }
            let bytes = self.dest_bytes.get(&ip).copied().unwrap_or(0);
            
            // Filter low-volume noise: ignore local devices that only replied to a single ping
            if is_private_ip(&ip) && bytes < 500 {
                continue;
            }

            let label = build_short_label(&ip, self);
            
            let target_map = if is_private_ip(&ip) { &mut local_groups } else { &mut external_groups };
            let entry = target_map.entry(label).or_insert((ip, 0));
            entry.1 += bytes;
            // The "Lead IP" for this label is the one with the most traffic
            if bytes > self.dest_bytes.get(&entry.0).copied().unwrap_or(0) {
                entry.0 = ip;
            }
        }

        let mut local_ips: Vec<IpAddr> = local_groups.into_values().map(|(ip, _)| ip).collect();
        let mut external_ips: Vec<IpAddr> = external_groups.into_values().map(|(ip, _)| ip).collect();

        // Cap local ring at 12 nodes by traffic volume
        local_ips.sort_by_key(|ip| std::cmp::Reverse(self.dest_bytes.get(ip).copied().unwrap_or(0)));
        local_ips.truncate(12);
        local_ips.sort(); 

        // Cap external ring at 16 nodes by traffic volume  
        external_ips.sort_by_key(|ip| std::cmp::Reverse(self.dest_bytes.get(ip).copied().unwrap_or(0)));
        external_ips.truncate(16);
        external_ips.sort();

        // Track which nodes are actually being shown on rings
        self.positioned_nodes.clear();
        self.positioned_nodes.extend(local_ips.iter());
        self.positioned_nodes.extend(external_ips.iter());


        let inner_radius = 110.0_f64;
        let outer_radius = 165.0_f64;

        let place_ring = |ips: &[IpAddr], radius: f64, nodes: &mut HashMap<IpAddr, GraphNode>| {
            let n = ips.len();
            if n == 0 { return; }
            for (i, ip) in ips.iter().enumerate() {
                let angle = (i as f64 / n as f64) * std::f64::consts::TAU
                    - std::f64::consts::FRAC_PI_2; // start from top
                let target_x = angle.cos() * radius;
                let target_y = angle.sin() * radius;
                if let Some(node) = nodes.get_mut(ip) {
                    // Smooth lerp toward target position
                    node.x += (target_x - node.x) * 0.12;
                    node.y += (target_y - node.y) * 0.12;
                }
            }
        };

        place_ring(&local_ips, inner_radius, &mut self.graph_nodes);
        place_ring(&external_ips, outer_radius, &mut self.graph_nodes);

        // Pin host at center
        if let Some(ip) = host_ip {
            if let Some(node) = self.graph_nodes.get_mut(&ip) {
                node.x = 0.0;
                node.y = 0.0;
            }
        }

        // Sweep hit detection for phosphor decay + ping rings
        let sweep_angle = (self.graph_tick as f64 / 120.0) * std::f64::consts::TAU;
        let current_tick = self.graph_tick;
        let mut hits: Vec<(IpAddr, f64, f64)> = Vec::new();
        for (ip, node) in &self.graph_nodes {
            if node.pinned { continue; }
            let node_angle = node.y.atan2(node.x);
            let angle_diff = (sweep_angle - node_angle).rem_euclid(std::f64::consts::TAU);
            if angle_diff < 0.18 {
                hits.push((*ip, node.x, node.y));
            }
        }
        for (ip, x, y) in hits {
            let prev = self.sweep_hit_tick.get(&ip).copied().unwrap_or(0);
            if current_tick.wrapping_sub(prev) > 20 {
                self.ping_rings.push((x, y, current_tick));
            }
            self.sweep_hit_tick.insert(ip, current_tick);
        }
        // Expire old ping rings
        let tick = self.graph_tick;
        self.ping_rings.retain(|&(_, _, birth)| tick.wrapping_sub(birth) < 25);
    }

    pub fn tick(&mut self) {
        self.update_radar_layout();

        if self.last_tick.elapsed() >= std::time::Duration::from_secs(1) {
            self.bytes_history.push_back(self.current_second_bytes);
            if self.bytes_history.len() > 30 {
                self.bytes_history.pop_front();
            }
            self.packets_per_sec = self.current_second_packets;
            self.current_second_bytes = 0;
            self.current_second_packets = 0;
            self.last_tick = std::time::Instant::now();
        }
    }

    pub fn cycle_filter(&mut self) {
        match self.focused_panel {
            Panel::Feed => {
                self.display_filter = match self.display_filter {
                    ProtocolFilter::All => ProtocolFilter::Tcp,
                    ProtocolFilter::Tcp => ProtocolFilter::Udp,
                    ProtocolFilter::Udp => ProtocolFilter::Icmp,
                    ProtocolFilter::Icmp => ProtocolFilter::All,
                };
            }
            Panel::Alerts => {
                self.alert_filter = match self.alert_filter {
                    AlertFilter::All => AlertFilter::Suspicious,
                    AlertFilter::Suspicious => AlertFilter::Behavioral,
                    AlertFilter::Behavioral => AlertFilter::External,
                    AlertFilter::External => AlertFilter::Noise,
                    AlertFilter::Noise => AlertFilter::All,
                };
            }
            Panel::Discovery => {
                self.discovery_filter = match self.discovery_filter {
                    DiscoveryFilter::All => DiscoveryFilter::Named,
                    DiscoveryFilter::Named => DiscoveryFilter::Vendors,
                    DiscoveryFilter::Vendors => DiscoveryFilter::Unknown,
                    DiscoveryFilter::Unknown => DiscoveryFilter::All,
                };
            }
        }
    }

    pub fn switch_panel(&mut self) {
        self.focused_panel = match self.focused_panel {
            Panel::Feed => Panel::Alerts,
            Panel::Alerts => Panel::Discovery,
            Panel::Discovery => Panel::Feed,
        };
    }

    pub fn scroll_up(&mut self) {
        match self.focused_panel {
            Panel::Feed => {
                self.feed_paused_scroll = true;
                self.feed_scroll = self.feed_scroll.saturating_add(1);
            }
            Panel::Alerts => {
                let len = match self.alert_filter {
                    AlertFilter::All => self.alerts_suspicious.len() + self.alerts_behavioral.len() + self.alerts_external.len() + self.alerts_noise.len(),
                    AlertFilter::Suspicious => self.alerts_suspicious.len(),
                    AlertFilter::Behavioral => self.alerts_behavioral.len(),
                    AlertFilter::External => self.alerts_external.len(),
                    AlertFilter::Noise => self.alerts_noise.len(),
                };
                let max = len.saturating_sub(1);
                if self.alert_scroll < max {
                    self.alert_paused_scroll = true;
                    self.alert_scroll = self.alert_scroll.saturating_add(1);
                }
            }
            Panel::Discovery => {
                let len = self.active_discovery.lock().unwrap().len();
                let max = len.saturating_sub(1);
                if self.discovery_scroll < max {
                    self.discovery_paused_scroll = true;
                    self.discovery_scroll = self.discovery_scroll.saturating_add(1);
                }
            }
        }
    }

    pub fn scroll_down(&mut self) {
        match self.focused_panel {
            Panel::Feed => {
                self.feed_scroll = self.feed_scroll.saturating_sub(1);
                self.feed_paused_scroll = self.feed_scroll != 0;
            }
            Panel::Alerts => {
                self.alert_scroll = self.alert_scroll.saturating_sub(1);
                self.alert_paused_scroll = self.alert_scroll != 0;
            }
            Panel::Discovery => {
                self.discovery_scroll = self.discovery_scroll.saturating_sub(1);
                self.discovery_paused_scroll = self.discovery_scroll != 0;
            }
        }
    }

    pub fn resume_scroll(&mut self) {
        match self.focused_panel {
            Panel::Feed => {
                self.feed_paused_scroll = false;
                self.feed_scroll = 0;
            }
            Panel::Alerts => {
                self.alert_paused_scroll = false;
                self.alert_scroll = 0;
            }
            Panel::Discovery => {
                self.discovery_paused_scroll = false;
                self.discovery_scroll = 0;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// IP classification helpers
// ---------------------------------------------------------------------------

pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            matches!(o, [192, 168, _, _] | [10, _, _, _] | [172, 16..=31, _, _])
        }
        _ => false,
    }
}

pub fn is_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            matches!(o,
                [10, ..] |                          // 10.0.0.0/8
                [172, 16..=31, ..] |               // 172.16.0.0/12
                [192, 168, ..] |                   // 192.168.0.0/16
                [169, 254, ..]                      // 169.254.0.0/16 link-local
            ) && o != [0, 0, 0, 0]
        }
        _ => false,
    }
}

fn get_common_prefix_v4(state: &AppState) -> String {
    if !state.ip_compressed { return String::new(); }
    
    let devices_guard = match state.active_discovery.try_lock() {
        Ok(guard) => guard,
        Err(_) => return String::new(),
    };
    
    let mut match_len = 0;
    let mut first_ipv4 = None;
    for ip in devices_guard.keys() {
        if let IpAddr::V4(v4) = ip {
            if !is_private_ip(ip) { continue; }
            if first_ipv4.is_none() {
                first_ipv4 = Some(v4.octets());
                match_len = 4;
            } else if let Some(first) = first_ipv4 {
                let octets = v4.octets();
                for i in 0..match_len {
                    if octets[i] != first[i] {
                        match_len = i;
                        break;
                    }
                }
            }
        }
    }
    
    if match_len > 0 && match_len < 4 {
        if let Some(first) = first_ipv4 {
            let mut prefix = first[..match_len].iter().map(|o| o.to_string()).collect::<Vec<_>>().join(".");
            prefix.push('.');
            return prefix;
        }
    }
    String::new()
}

fn is_local_or_multicast(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            matches!(
                o,
                [192, 168, _, _]
                    | [10, _, _, _]
                    | [172, 16..=31, _, _]
                    | [127, _, _, _]
                    | [224..=239, _, _, _]
                    | [255, 255, 255, 255]
            )
        }
        _ => false,
    }
}



// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_geo_tag(geo: &crate::geoip::GeoInfo) -> String {
    let sc = geo.region.as_deref().unwrap_or(&geo.country_code);
    match (&geo.city, &geo.region) {
        (Some(city), Some(_)) if !city.is_empty() => {
            let city_short = if city.len() > 15 { &city[..15] } else { city.as_str() };
            format!("[{}, {}]", city_short, sc)
        }
        (Some(city), None) if !city.is_empty() => {
            let city_short = if city.len() > 15 { &city[..15] } else { city.as_str() };
            format!("[{}, {}]", city_short, geo.country_code)
        }
        _ => format!("[{}]", geo.country_code),
    }
}

fn format_bytes(n: u64) -> String {
    if n < 1024 {
        format!("{n}B")
    } else if n < 1_048_576 {
        format!("{:.1}KB", n as f64 / 1024.0)
    } else {
        format!("{:.1}MB", n as f64 / 1_048_576.0)
    }
}

fn format_with_commas(n: u64) -> String {
    let s = n.to_string();
    let mut result = String::with_capacity(s.len() + s.len() / 3);
    for (i, c) in s.chars().rev().enumerate() {
        if i > 0 && i % 3 == 0 {
            result.push(',');
        }
        result.push(c);
    }
    result.chars().rev().collect()
}

fn format_uptime(elapsed: std::time::Duration) -> String {
    let secs = elapsed.as_secs();
    let h = secs / 3600;
    let m = (secs % 3600) / 60;
    let s = secs % 60;
    format!("{h:02}:{m:02}:{s:02}")
}

fn format_port(port: u16) -> String {
    match port {
        21 => "FTP".into(),
        22 => "SSH".into(),
        25 => "SMTP".into(),
        53 => "DNS".into(),
        80 => "HTTP".into(),
        110 => "POP3".into(),
        143 => "IMAP".into(),
        443 => "HTTPS".into(),
        1900 => "UPnP".into(),
        3389 => "RDP".into(),
        5353 => "mDNS".into(),
        8009 => "Cast".into(),
        8080 => "HTTP-Alt".into(),
        other => other.to_string(),
    }
}



/// Truncates a string to a maximum width and appends "..." if it was cut off.
fn truncate_str(s: &str, width: usize) -> String {
    let (trunc, len) = unicode_truncate::UnicodeTruncateStr::unicode_truncate(s, width);
    if len < unicode_width::UnicodeWidthStr::width(s) && width > 3 {
        let (t, _) = unicode_truncate::UnicodeTruncateStr::unicode_truncate(s, width.saturating_sub(3));
        format!("{}...", t)
    } else {
        trunc.to_string()
    }
}

fn format_packet_line(pkt: &crate::packet::CapturedPacket, state: &AppState, prefix: &str) -> String {
    let src = format_endpoint(pkt.src_ip, pkt.src_port, state, prefix);
    let dst = format_endpoint_labeled(pkt.dst_ip, pkt.dst_port, state, prefix);

    let dst_label = state.get_display_hostname(&pkt.dst_ip);
    let src_label = state.get_display_hostname(&pkt.src_ip);

    let dst_str = if dst_label != pkt.dst_ip.to_string() && dst_label != "\u{2014}" {
        format!("{} ({})", dst, dst_label)
    } else if let Some(geo) = state.geo_cache.get(&pkt.dst_ip) {
        format!("{} {}", dst, format_geo_tag(geo))
    } else {
        dst
    };

    let src_str = if src_label != pkt.src_ip.to_string() && src_label != "\u{2014}" {
        format!("{} ({})", src, src_label)
    } else if let Some(geo) = state.geo_cache.get(&pkt.src_ip) {
        format!("{} {}", src, format_geo_tag(geo))
    } else {
        src
    };

    let ts = pkt.timestamp.format("%H:%M:%S%.3f");

    // ICMP packets have type/code info in flags field, TCP has flags, UDP/others show dash
    let info = pkt.flags.as_deref().unwrap_or("\u{2014}");

    format!(
        "[{ts}]  {proto:<4} {src_str:<21}  \u{2192}  {dst_str:<26}  {info:<14} {size}B",
        proto = pkt.protocol,
        size = pkt.size,
    )
}

fn format_endpoint(ip: IpAddr, port: Option<u16>, state: &AppState, prefix: &str) -> String {
    let mut ip_str = ip.to_string();
    if state.ip_compressed {
        if !prefix.is_empty() && ip_str.starts_with(prefix) {
            ip_str = ip_str.strip_prefix(prefix).unwrap_or(&ip_str).to_string();
        } else if let IpAddr::V6(v6) = ip {
            if v6.segments()[0] == 0xfe80 {
                ip_str = format!("fe80::{:x}", v6.segments()[7]);
            }
        }
    }

    match port {
        Some(p) => format!("{ip_str}:{p}"),
        None => ip_str,
    }
}

fn format_endpoint_labeled(ip: IpAddr, port: Option<u16>, state: &AppState, prefix: &str) -> String {
    let mut ip_str = ip.to_string();
    if state.ip_compressed {
        if !prefix.is_empty() && ip_str.starts_with(prefix) {
            ip_str = ip_str.strip_prefix(prefix).unwrap_or(&ip_str).to_string();
        } else if let IpAddr::V6(v6) = ip {
            if v6.segments()[0] == 0xfe80 {
                ip_str = format!("fe80::{:x}", v6.segments()[7]);
            }
        }
    }

    match port {
        Some(p) => format!("{ip_str}:{}", format_port(p)),
        None => ip_str,
    }
}

fn filter_label(f: &ProtocolFilter) -> &'static str {
    match f {
        ProtocolFilter::All => "ALL",
        ProtocolFilter::Tcp => "TCP",
        ProtocolFilter::Udp => "UDP",
        ProtocolFilter::Icmp => "ICMP",
    }
}

// ---------------------------------------------------------------------------
// TUI rendering
// ---------------------------------------------------------------------------

pub fn draw_ui(f: &mut Frame, state: &AppState) {
    let prefix = get_common_prefix_v4(state);

    if state.show_graph {
        let chunks = Layout::vertical([
            Constraint::Fill(1),        // 0: Graph
            Constraint::Length(1),      // 1: Footer line 1
            Constraint::Length(1),      // 2: Footer line 2
        ])
        .split(f.area());

        draw_graph(f, chunks[0], state);
        draw_footer(f, chunks[1], chunks[2], state);
        return;
    }

    let main_chunks = Layout::vertical([
        Constraint::Length(13),     // 0: Live Feed + Logo
        Constraint::Length(11),     // 1: Connections + Alerts
        Constraint::Fill(1),        // 2: Bottom analysis row (Fills remaining space)
        Constraint::Length(1),      // 3: Footer line 1
        Constraint::Length(1),      // 4: Footer line 2
    ])
    .split(f.area());

    let top_chunks = Layout::horizontal([
        Constraint::Percentage(70),
        Constraint::Percentage(30),
    ])
    .split(main_chunks[0]);

    draw_feed(f, top_chunks[0], state, &prefix);
    draw_logo(f, top_chunks[1]);

    let middle_chunks = Layout::horizontal([
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ])
    .split(main_chunks[1]);

    draw_connections(f, middle_chunks[0], state);
    draw_alerts(f, middle_chunks[1], state);

    // 3-panel bottom row overhaul
    let bottom_chunks = Layout::horizontal([
        Constraint::Percentage(18), // Protocol Split
        Constraint::Percentage(54), // Local Discovery
        Constraint::Percentage(28), // Bytes/sec
    ])
    .split(main_chunks[2]);

    draw_protocol_split(f, bottom_chunks[0], state);
    draw_local_devices(f, bottom_chunks[1], state, &prefix);
    draw_bytes_per_sec(f, bottom_chunks[2], state);
    
    draw_footer(f, main_chunks[3], main_chunks[4], state);
}

fn draw_feed(f: &mut Frame, area: Rect, state: &AppState, prefix: &str) {
    let tag = filter_label(&state.display_filter);
    let status = if state.paused { " | PAUSED" } else { "" };
    let error_tag = state
        .capture_error
        .as_ref()
        .map_or(String::new(), |e| format!(" | ERR: {e}"));
    let title_left = format!(" Live Feed [{tag}]{status}{error_tag} ");

    let visible_rows = area.height.saturating_sub(2) as usize;
    let width = area.width.saturating_sub(2) as usize;

    // Collect packet references based on display_filter
    let mut pkts: Vec<(std::time::Instant, &crate::packet::CapturedPacket)> = Vec::new();
    match state.display_filter {
        ProtocolFilter::All => {
            pkts.reserve(state.feed_tcp.len() + state.feed_udp.len() + state.feed_icmp.len());
            pkts.extend(state.feed_tcp.iter().map(|(t, p)| (*t, p)));
            pkts.extend(state.feed_udp.iter().map(|(t, p)| (*t, p)));
            pkts.extend(state.feed_icmp.iter().map(|(t, p)| (*t, p)));
            pkts.sort_unstable_by_key(|(t, _)| *t);
        }
        ProtocolFilter::Tcp => pkts.extend(state.feed_tcp.iter().map(|(t, p)| (*t, p))),
        ProtocolFilter::Udp => pkts.extend(state.feed_udp.iter().map(|(t, p)| (*t, p))),
        ProtocolFilter::Icmp => pkts.extend(state.feed_icmp.iter().map(|(t, p)| (*t, p))),
    };

    let total_len = pkts.len();
    let (visible_pkts, show_scroll_msg) = if state.feed_paused_scroll {
        let max_scroll = total_len.saturating_sub(visible_rows);
        let actual_scroll = state.feed_scroll.min(max_scroll);
        let skip = max_scroll.saturating_sub(actual_scroll);
        let take = if actual_scroll > 0 { visible_rows.saturating_sub(1) } else { visible_rows };
        (pkts.into_iter().skip(skip).take(take).collect::<Vec<_>>(), actual_scroll > 0)
    } else {
        let skip = total_len.saturating_sub(visible_rows);
        (pkts.into_iter().skip(skip).collect::<Vec<_>>(), false)
    };

    let mut list_items: Vec<ListItem> = visible_pkts.into_iter().map(|(_, pkt)| {
        let s = format_packet_line(pkt, state, prefix);
        ListItem::new(truncate_str(&s, width))
    }).collect();

    if show_scroll_msg && !list_items.is_empty() {
        list_items.push(ListItem::new(""));
        let last_idx = list_items.len() - 1;
        list_items[last_idx] = ListItem::new("  \u{2193} Press [Space] to resume live scroll")
            .style(Style::default().fg(Color::Yellow));
    }

    let border_color = if state.focused_panel == Panel::Feed { Color::Yellow } else { Color::White };
    let block = Block::bordered()
        .title(title_left)
        .style(Style::default().fg(border_color).bg(Color::Black));

    let list = List::new(list_items)
        .block(block)
        .style(Style::default().fg(Color::White));

    f.render_widget(list, area);
}

fn draw_logo(f: &mut Frame, area: Rect) {
    const LOGO: &str = r#"
 _    ______  ____  ___           
| |  / / __ \/ __ \/   |          
| | / / / / / /_/ / /| |          
| |/ / /_/ / _, _/ ___ |          
|___/\____/_/_|_/_/__|_|__  _   __
   / __ \/ ____/ ____/ __ \/ | / /
  / /_/ / __/ / /   / / / /  |/ / 
 / _, _/ /___/ /___/ /_/ / /|  /  
/_/ |_/_____/\____/\____/_/ |_/   "#;

    let logo_lines: Vec<&str> = LOGO.lines().collect();
    let logo_height = logo_lines.len() as u16;
    let inner_height = area.height.saturating_sub(2);
    // Removed the .saturating_sub(1) to perfectly center vertically
    let pad_top = inner_height.saturating_sub(logo_height) / 2;
    let mut padded = "\n".repeat(pad_top as usize);
    for line in &logo_lines {
        padded.push(' ');
        padded.push_str(line);
        padded.push('\n');
    }

    let block = Block::bordered()
        .style(Style::default().fg(Color::White).bg(Color::Black));

    let paragraph = Paragraph::new(padded)
        .alignment(Alignment::Center)
        .block(block)
        .style(Style::default().fg(Color::White));

    f.render_widget(paragraph, area);
}

fn format_duration(dur: std::time::Duration) -> String {
    let total_secs = dur.as_secs();
    if total_secs < 60 {
        format!("{}s", total_secs)
    } else if total_secs < 3600 {
        let mins = total_secs / 60;
        let secs = total_secs % 60;
        format!("{}m{}s", mins, secs)
    } else {
        let hours = total_secs / 3600;
        let mins = (total_secs % 3600) / 60;
        format!("{}h{}m", hours, mins)
    }
}

fn draw_connections(f: &mut Frame, area: Rect, state: &AppState) {
    let mut sorted: Vec<_> = state.connections.iter().collect();
    sorted.sort_by(|a, b| (b.1).1.cmp(&(a.1).1));
    sorted.truncate(5);

    let items: Vec<ListItem> = sorted
        .iter()
        .map(|((src, dst, _port), (pkts, bytes, proc, duration))| {
            let dst_label = state.get_display_hostname(dst);
            let src_label = state.get_display_hostname(src);
            // Strip full path to just filename
            let mut proc_name = proc.as_deref().unwrap_or("unknown");
            proc_name = std::path::Path::new(proc_name)
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or(proc_name);
                
            let proc_display = if proc_name == "unknown" && !is_private_ip(src) && is_private_ip(dst) {
                "← inbound"
            } else {
                proc_name
            };

            let dur_str = format_duration(*duration);

            let org = if let Some(geo) = state.geo_cache.get(dst) {
                format!(" [{}]", geo.org)
            } else if let Some(geo) = state.geo_cache.get(src) {
                format!(" [{}]", geo.org)
            } else {
                String::new()
            };

            let c = format!(
                " {:<15} \u{2192} {:<21} \u{2014} {}{org} \u{2014} {} pkts, {} ({})",
                src_label, dst_label, proc_display,
                format_with_commas(*pkts),
                format_bytes(*bytes),
                dur_str
            );

            let width = area.width.saturating_sub(2) as usize;
            ListItem::new(truncate_str(&c, width))
        })
        .collect();

    // Summary line
    let n_conns = state.connections.len();
    let n_unique = state.unique_ips.len();
    let most_active = state
        .src_packet_counts
        .iter()
        .max_by_key(|(_, c)| *c)
        .map(|(ip, _)| ip.to_string())
        .unwrap_or_else(|| "---".into());

    let mut final_items = items;
    final_items.push(ListItem::new(""));
    final_items.push(
        ListItem::new(format!(
            " {} active connections  |  {} unique IPs seen  |  most active: {}",
            n_conns, n_unique, most_active,
        ))
        .style(Style::default().fg(Color::DarkGray)),
    );

    let block = Block::bordered()
        .title(" Connections ")
        .title_alignment(Alignment::Left)
        .style(Style::default().fg(Color::White).bg(Color::Black));

    let list = List::new(final_items)
        .block(block)
        .style(Style::default().fg(Color::White));

    f.render_widget(list, area);
}

fn draw_alerts(f: &mut Frame, area: Rect, state: &AppState) {
    let tag = match state.alert_filter {
        AlertFilter::All => "ALL",
        AlertFilter::Suspicious => "SUSPICIOUS",
        AlertFilter::Behavioral => "BEHAVIORAL",
        AlertFilter::External => "EXTERNAL",
        AlertFilter::Noise => "NOISE",
    };
    let count = match state.alert_filter {
        AlertFilter::All => state.total_alerts,
        AlertFilter::Suspicious => state.total_alerts_suspicious,
        AlertFilter::Behavioral => state.total_alerts_behavioral,
        AlertFilter::External => state.total_alerts_external,
        AlertFilter::Noise => state.total_alerts_noise,
    };
    let title = format!(" Alerts [{}] (Total: {}) ", tag, count);

    let mut all_alerts: Vec<&Alert>;
    let filtered_alerts: Vec<&Alert> = match state.alert_filter {
        AlertFilter::Suspicious => state.alerts_suspicious.iter().collect(),
        AlertFilter::Behavioral => state.alerts_behavioral.iter().collect(),
        AlertFilter::External => state.alerts_external.iter().collect(),
        AlertFilter::Noise => state.alerts_noise.iter().collect(),
        AlertFilter::All => {
            all_alerts = state.alerts_suspicious.iter()
                .chain(state.alerts_behavioral.iter())
                .chain(state.alerts_external.iter())
                .chain(state.alerts_noise.iter())
                .collect();
            all_alerts.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
            all_alerts
        }
    };

    let visible_rows = area.height.saturating_sub(2) as usize;

    let mut items: Vec<ListItem> = if filtered_alerts.is_empty() {
        vec![ListItem::new(format!(" No alerts matching filter [{tag}]"))
            .style(Style::default().fg(Color::DarkGray))]
    } else {
        let all_items: Vec<ListItem> = filtered_alerts
            .iter()
            .map(|a| {
                let ts = a.timestamp.format("%H:%M:%S");
                let (prefix, color) = match a.tier {
                    AlertTier::Suspicious => ("[!]", Color::Red),
                    AlertTier::Behavioral => ("[~]", Color::Yellow),
                    AlertTier::External   => ("[→]", Color::Cyan),
                    AlertTier::Noise      => ("[-]", Color::DarkGray),
                };

                let msg = a.message.clone();
                let c = format!(" [{ts}] {prefix} {msg}");
                let width = area.width.saturating_sub(2) as usize;
                ListItem::new(truncate_str(&c, width))
                    .style(Style::default().fg(color))
            })
            .collect();

        if state.alert_paused_scroll {
            // Scrolling back: show from the end minus scroll offset
            let max_scroll = all_items.len().saturating_sub(visible_rows);
            let actual_scroll = state.alert_scroll.min(max_scroll);
            let skip = max_scroll.saturating_sub(actual_scroll);
            all_items.into_iter().skip(skip).take(visible_rows).collect()
        } else {
            // Live: show the newest (tail)
            let skip = all_items.len().saturating_sub(visible_rows);
            all_items.into_iter().skip(skip).collect()
        }
    };

    if state.alert_paused_scroll && !filtered_alerts.is_empty() {
        let last_idx = items.len() - 1;
        items[last_idx] = ListItem::new("  \u{2193} Press [Space] to resume live updates")
            .style(Style::default().fg(Color::Yellow));
    }

    let border_color = if state.focused_panel == Panel::Alerts { Color::Yellow } else { Color::White };
    let block = Block::bordered()
        .title(title)
        .style(Style::default().fg(border_color).bg(Color::Black));

    let list = List::new(items)
        .block(block)
        .style(Style::default().fg(Color::White));

    f.render_widget(list, area);
}

fn draw_protocol_split(f: &mut Frame, area: Rect, state: &AppState) {
    let block = Block::bordered()
        .title(" Protocol Split ")
        .style(Style::default().fg(Color::White).bg(Color::Black));
    let inner = block.inner(area);
    f.render_widget(block, area);

    let chunks = Layout::vertical([
        Constraint::Length(4), // Stats block at the top
        Constraint::Fill(1),   // Bar Chart below
    ])
    .split(inner);

    // 1. Protocol Stats (Top)
    let uptime = format_uptime(state.start_time.elapsed());
    let total_str = format_with_commas(state.total_packets);
    let avg_size = if state.total_packets > 0 {
        format_bytes(state.total_bytes / state.total_packets)
    } else {
        "0B".into()
    };
    let pps = format_with_commas(state.packets_per_sec);

    let stats = format!(
        "Total: {total_str}\nUptime: {uptime}\nAvg Sz: {avg_size}\nPps:   {pps}"
    );
    let paragraph = Paragraph::new(stats).style(Style::default().fg(Color::White));
    f.render_widget(paragraph, chunks[0]);

    // 2. Protocol Bar Chart (Bottom)
    let total = state.total_packets.max(1) as f64;
    let tcp_pct = (state.tcp_count as f64 / total * 100.0) as u64;
    let udp_pct = (state.udp_count as f64 / total * 100.0) as u64;
    let icmp_pct = (state.icmp_count as f64 / total * 100.0) as u64;

    let bar_w = (chunks[1].width.saturating_sub(2) / 3).max(1);
    let bars = BarGroup::default().bars(&[
        Bar::default()
            .value(tcp_pct)
            .label("TCP".into())
            .text_value(format!("{tcp_pct}%")),
        Bar::default()
            .value(udp_pct)
            .label("UDP".into())
            .text_value(format!("{udp_pct}%")),
        Bar::default()
            .value(icmp_pct)
            .label("ICMP".into())
            .text_value(format!("{icmp_pct}%")),
    ]);

    let chart = BarChart::default()
        .data(bars)
        .bar_width(bar_w)
        .bar_gap(1)
        .max(100)
        .bar_style(Style::default().fg(Color::Cyan));
    
    f.render_widget(chart, chunks[1]);
}

pub fn clean_hostname(raw: &str) -> String {
    use std::sync::OnceLock;
    use regex::Regex;

    static RE_VERBOSE: OnceLock<Regex> = OnceLock::new();
    static RE_SHORT: OnceLock<Regex> = OnceLock::new();
    static RE_GOOGLE: OnceLock<Regex> = OnceLock::new();
    static RE_UUID: OnceLock<Regex> = OnceLock::new();
    static RE_MAC_HOST: OnceLock<Regex> = OnceLock::new();
    static RE_NETBIOS: OnceLock<Regex> = OnceLock::new();
    static RE_GENERIC_ID: OnceLock<Regex> = OnceLock::new();
    static RE_AMAZON_ID: OnceLock<Regex> = OnceLock::new();
    static RE_HEX: OnceLock<Regex> = OnceLock::new();
    static RE_HEX_PAIR: OnceLock<Regex> = OnceLock::new();
    static RE_HOMEPOD: OnceLock<Regex> = OnceLock::new();
    static RE_IP_PAREN: OnceLock<Regex> = OnceLock::new();
    static RE_MODEL_PAREN: OnceLock<Regex> = OnceLock::new();
    static RE_SNAKE_PAREN: OnceLock<Regex> = OnceLock::new();
    static RE_ZONE_PAREN: OnceLock<Regex> = OnceLock::new();
    static RE_ZONE_ONLY: OnceLock<Regex> = OnceLock::new();

    let re_verbose = RE_VERBOSE.get_or_init(|| Regex::new(r"^[\d\.]+\s+-\s+(.+?)\s+-\s+RINCON_[0-9A-Fa-f]+$").unwrap());
    let re_short = RE_SHORT.get_or_init(|| Regex::new(r"^sonosRINCON_[0-9A-Fa-f]+$").unwrap());
    let re_google = RE_GOOGLE.get_or_init(|| Regex::new(r"^Google-TV-Streamer-[0-9a-fA-F]{16,}$").unwrap());
    let re_uuid = RE_UUID.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$").unwrap());
    let re_mac_host = RE_MAC_HOST.get_or_init(|| Regex::new(r"(?i)^[a-z][-a-z]*-[0-9a-fA-F]{6,12}$").unwrap());
    let re_netbios = RE_NETBIOS.get_or_init(|| Regex::new(r"^NPI[0-9A-Fa-f]{6}$").unwrap());
    let re_generic_id = RE_GENERIC_ID.get_or_init(|| Regex::new(r"^[A-Z]{2,4}[0-9A-F]{6,8}$").unwrap());
    let re_amazon_id = RE_AMAZON_ID.get_or_init(|| Regex::new(r"(?i)^dp-[0-9a-z]{6,}$").unwrap());
    let re_hex = RE_HEX.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{8,}$").unwrap());
    let re_hex_pair = RE_HEX_PAIR.get_or_init(|| Regex::new(r"^[0-9a-fA-F]{8,}-[0-9a-fA-F]{8,}$").unwrap());
    let re_homepod = RE_HOMEPOD.get_or_init(|| Regex::new(r"^HomePodSensor\s+\d+$").unwrap());
    let re_ip_paren = RE_IP_PAREN.get_or_init(|| Regex::new(r"\s+\(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}[^)]*\)$").unwrap());
    let re_model_paren = RE_MODEL_PAREN.get_or_init(|| Regex::new(r"\s+\([A-Z0-9][A-Z0-9\-]{2,}\)$").unwrap());
    let re_snake_paren = RE_SNAKE_PAREN.get_or_init(|| Regex::new(r"\s+\([a-z][a-z0-9_]*\)$").unwrap());
    let re_zone_paren = RE_ZONE_PAREN.get_or_init(|| Regex::new(r"\s+\(\d+(?:,\s*\d+)*\)$").unwrap());
    let re_zone_only = RE_ZONE_ONLY.get_or_init(|| Regex::new(r"^\d+(?:,\d+)+$").unwrap());

    let mut h = raw.trim().to_string();

    // 1. IPv6 / bracket prefix check
    if h.starts_with('[') || h.starts_with("fe80") || h.contains("::") {
        return "\u{2014}".to_string();
    }

    // 2. RINCON verbose format -> RETURN IMMEDIATELY
    if let Some(caps) = re_verbose.captures(&h) {
        return caps[1].trim().to_string();
    }

    // 3. sonosRINCON_ prefix -> RETURN IMMEDIATELY
    if re_short.is_match(&h) {
        return "Sonos Device".to_string();
    }

    // 4. Google TV hash suffix -> RETURN IMMEDIATELY
    if re_google.is_match(&h) || h.starts_with("Google-TV-Streamer-") {
        return "Google TV Streamer".to_string();
    }

    // 5. Service type list (spotify-connect, airplay, etc.)
    let service_names = ["spotify-connect", "spotifyconnect", "airplay", "sftp-ssh", 
                         "dial", "homekit", "sftp", "ftp", "ssh", "http", "https"];
    if service_names.contains(&h.to_lowercase().as_str()) {
        return "\u{2014}".to_string();
    }

    // 6. Known auto-generated ID patterns
    if re_uuid.is_match(&h) || re_mac_host.is_match(&h) || re_netbios.is_match(&h) || 
       re_generic_id.is_match(&h) || re_amazon_id.is_match(&h) || re_hex.is_match(&h) || 
       re_hex_pair.is_match(&h) || re_homepod.is_match(&h) {
        return "\u{2014}".to_string();
    }

    // 7. Strip IP-in-parentheses (loop until stable)
    loop {
        let prev = h.clone();
        h = re_ip_paren.replace(&h, "").to_string();
        if h == prev { break; }
    }

    // 8. Strip duplicate parenthetical (string comparison method)
    h = strip_duplicate_parens(&h);

    // 9. Strip model-code parenthetical (ECB601, D215R, HPRO-1)
    h = re_model_paren.replace(&h, "").to_string();

    // 10. Strip snake_case parenthetical (floodlight_pro)
    h = re_snake_paren.replace(&h, "").to_string();

    // 11. Strip digit-list zone ID (0,1,2)
    h = re_zone_paren.replace(&h, "").to_string();

    // 12. Final cleanup
    if re_zone_only.is_match(&h) {
        return "\u{2014}".to_string();
    }

    h.trim().to_string()
}

fn strip_duplicate_parens(s: &str) -> String {
    if let Some(idx) = s.rfind(" (") {
        let prefix = s[..idx].trim();
        let suffix = &s[idx + 2..]; // skip " ("
        if suffix.ends_with(')') {
            let inner = &suffix[..suffix.len() - 1].trim();
            if inner.eq_ignore_ascii_case(prefix) {
                return prefix.to_string();
            }
        }
    }
    s.to_string()
}

fn format_last_seen(dev: &crate::discovery::DeviceInfo) -> String {
    if dev.miss_count == 0 {
        // Online — use Instant for precision
        let secs = dev.last_seen.elapsed().as_secs();
        if secs < 10 { "Online".to_string() }
        else if secs < 60 { format!("{}s ago", secs) }
        else { format!("{}m ago", secs / 60) }
    } else {
        // Offline — use Unix timestamp for accuracy across restarts
        let now_unix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        let secs = now_unix.saturating_sub(dev.last_seen_unix);
        if secs < 60 { format!("{}s ago", secs) }
        else if secs < 3600 { format!("{}m ago", secs / 60) }
        else if secs < 86400 { format!("{}h ago", secs / 3600) }
        else { format!("{}d ago", secs / 86400) }
    }
}

fn draw_local_devices(f: &mut Frame, area: Rect, state: &AppState, prefix: &str) {
    let devices_guard = match state.active_discovery.try_lock() {
        Ok(guard) => guard,
        Err(_) => {
            // Lock busy - render panel with scanning indicator instead of blank
            let auto_scan_status = if state.auto_scan_enabled {
                if state.scan_has_run {
                    let elapsed = state.last_auto_scan.elapsed().as_secs();
                    let remaining = 180u64.saturating_sub(elapsed);
                    format!(" (Auto-Rescan in {}s)", remaining)
                } else {
                    " (Auto-Rescanning Enabled)".to_string()
                }
            } else {
                " (Auto-Rescan: PAUSED)".to_string()
            };

            let block = Block::bordered()
                .title(format!(" Local Discovery [{}] (Scanning...){} ", match state.discovery_filter {
                    DiscoveryFilter::All => "ALL",
                    DiscoveryFilter::Named => "NAMED",
                    DiscoveryFilter::Vendors => "VENDORS",
                    DiscoveryFilter::Unknown => "UNKNOWN",
                }, auto_scan_status))
                .style(Style::default().fg(Color::White).bg(Color::Black));
            let list = List::new(vec![
                ListItem::new(format!(" {}", state.discovery_status))
                    .style(Style::default().fg(Color::Yellow))
            ]).block(block);
            f.render_widget(list, area);
            return;
        }
    };
    let devices = &*devices_guard;

    let mut sorted: Vec<_> = devices.iter().filter(|(_, dev)| {
        let clean_name = clean_hostname(&dev.hostname);
        match state.discovery_filter {
            DiscoveryFilter::All => true,
            DiscoveryFilter::Named => clean_name != "\u{2014}" && clean_name != "Resolving...",
            DiscoveryFilter::Vendors => dev.vendor.as_str() != "Unknown",
            DiscoveryFilter::Unknown => dev.vendor.as_str() == "Unknown" && (clean_name == "\u{2014}" || clean_name == "Resolving..."),
        }
    }).collect();
    
    // Sort by IP for consistency (Descending so newest/highest appear at bottom for live tail view)
    sorted.sort_by(|a, b| b.0.cmp(a.0));

    let items: Vec<ListItem> = if !state.scan_has_run {
        let auto_status = if state.auto_scan_enabled { " (Auto-Rescanning Enabled)" } else { " (Auto-Rescan: PAUSED)" };
        vec![
            ListItem::new(format!(" TOTAL: 0 Devices Found{}", auto_status)).style(Style::default().fg(Color::Cyan)),
            ListItem::new(" WARNING: Only scan with explicit permission from admin.").style(Style::default().fg(Color::Yellow)),
            ListItem::new(" Unauthorized scanning may be illegal under computer misuse laws."),
            ListItem::new(""),
            ListItem::new(" Press [Alt+S] to start discovery scan").style(Style::default().fg(Color::Cyan)),
            ListItem::new(" Press [A] to toggle Auto-Rescan").style(Style::default().fg(Color::DarkGray)),
        ]
    } else if sorted.is_empty() {
        let msg = if state.discovery_status == "[ Waiting for Signal ]" {
            " WARNING: Only scan with explicit permission from admin."
        } else {
            &state.discovery_status
        };
        let mut inner_items = vec![ListItem::new(format!(" {msg}")).style(Style::default().fg(Color::Yellow))];
        if state.discovery_status == "[ Waiting for Signal ]" {
            inner_items.push(ListItem::new(" Unauthorized scanning may be illegal under computer misuse laws."));
            inner_items.push(ListItem::new(""));
            inner_items.push(ListItem::new(" Press [Alt+S] to start discovery scan").style(Style::default().fg(Color::Cyan)));
        }
        inner_items
    } else {
        // Precompute display IPs and find max length for column width
        let mut display_ips = Vec::with_capacity(sorted.len());
        let mut max_ip_len = 0;
        for (ip, _) in &sorted {
            let ip_str = ip.to_string();
            let display_ip = if state.ip_compressed {
                if let IpAddr::V4(_) = ip {
                    if !prefix.is_empty() && ip_str.starts_with(prefix) {
                        ip_str.strip_prefix(prefix).unwrap_or(&ip_str).to_string()
                    } else {
                        ip_str
                    }
                } else if let IpAddr::V6(v6) = ip {
                    if v6.segments()[0] == 0xfe80 {
                        format!("fe80::{:x}", v6.segments()[7])
                    } else {
                        ip_str
                    }
                } else {
                    ip_str
                }
            } else {
                ip_str
            };
            max_ip_len = max_ip_len.max(display_ip.len());
            display_ips.push(display_ip);
        }

        let ip_col_width = if state.ip_compressed { max_ip_len + 1 } else { 16 };

        sorted.iter().enumerate().map(|(i, (ip, dev))| {
            let last_seen_str = format_last_seen(dev);
            let os_tag = state.get_resolved_os_tag(ip);
            let is_stale = dev.miss_count > 0;
            
            let hostname = clean_hostname(&dev.hostname);

            // Resolve the best available display name via priority chain (Option A)
            let display_hostname = if hostname != "\u{2014}" && hostname != "Resolving..." && !hostname.is_empty() {
                // 1. Use discovery hostname if it's high quality
                hostname
            } else {
                // 2. Try rich metadata (mDNS model, SSDP friendly name, etc.)
                let metadata_name = if let Ok(meta) = state.device_metadata.try_lock() {
                    meta.get(ip)
                        .and_then(|m| m.get("model").or(m.get("friendly_name")).or(m.get("model_name")))
                        .map(|m| clean_hostname(m))
                } else {
                    None
                };

                if let Some(m) = metadata_name {
                    if m != "\u{2014}" && !m.is_empty() {
                        m
                    } else {
                        // 3. Fallback to behavioral classification if metadata is also poor
                        state.traffic_profiles.get(ip)
                            .and_then(|p| classify_device_type(p))
                            .map(|c| c.to_string())
                            .unwrap_or_else(|| hostname.clone())
                    }
                } else {
                    // 3. Fallback to behavioral classification
                    state.traffic_profiles.get(ip)
                        .and_then(|p| classify_device_type(p))
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| hostname.clone())
                }
            };

            let row = format!(" {:<ip_width$} {:<5} {:<17}  {:<24} {:<10} {}", 
                display_ips[i], 
                os_tag, 
                dev.mac, 
                truncate_str(&display_hostname, 24), 
                last_seen_str,
                dev.vendor,
                ip_width = ip_col_width
            );

            let color = if is_stale { Color::DarkGray } else { Color::White };
            ListItem::new(truncate_str(&row, area.width.saturating_sub(2) as usize))
                .style(Style::default().fg(color))
        }).collect()
    };

    let visible_height = area.height.saturating_sub(2) as usize;
    let items_len = items.len();
    let mut rendered_items = if items_len > visible_height {
        if state.discovery_paused_scroll {
            // Scrolling back: show from the end minus scroll offset
            let max_scroll = items_len.saturating_sub(visible_height);
            let actual_scroll = state.discovery_scroll.min(max_scroll);
            let skip = max_scroll.saturating_sub(actual_scroll);
            items.into_iter().skip(skip).take(visible_height).collect::<Vec<_>>()
        } else {
            // Live: show the newest (tail)
            let skip = items_len.saturating_sub(visible_height);
            items.into_iter().skip(skip).collect::<Vec<_>>()
        }
    } else {
        items
    };

    if state.discovery_paused_scroll && !rendered_items.is_empty() {
        let last_idx = rendered_items.len() - 1;
        rendered_items[last_idx] = ListItem::new("  \u{2193} Press [Space] to resume live scroll")
            .style(Style::default().fg(Color::Yellow));
    }

    let border_color = if state.focused_panel == Panel::Discovery { Color::Yellow } else { Color::White };
    let auto_scan_status = if state.auto_scan_enabled {
        if state.scan_has_run {
            let elapsed = state.last_auto_scan.elapsed().as_secs();
            let remaining = 180u64.saturating_sub(elapsed);
            format!(" (Auto-Rescan in {}s)", remaining)
        } else {
            " (Auto-Rescanning Enabled)".to_string()
        }
    } else {
        " (Auto-Rescan: PAUSED)".to_string()
    };

    let f_tag = match state.discovery_filter {
        DiscoveryFilter::All => "ALL",
        DiscoveryFilter::Named => "NAMED",
        DiscoveryFilter::Vendors => "VENDORS",
        DiscoveryFilter::Unknown => "UNKNOWN",
    };
    
    let block = Block::bordered()
        .title(format!(" Local Discovery [{}] (Total: {}) {}{} ", f_tag, sorted.len(), state.last_discovery_time, auto_scan_status))
        .title_alignment(Alignment::Left)
        .style(Style::default().fg(border_color).bg(Color::Black));

    if state.discovery_status != "[ Waiting for Signal ]" {
        rendered_items.push(ListItem::new(""));
        rendered_items.push(
            ListItem::new(format!(" Last Scan: {}", state.last_discovery_time))
                .style(Style::default().fg(Color::DarkGray))
        );
    }

    let list = List::new(rendered_items)
        .block(block)
        .style(Style::default().fg(Color::White));

    f.render_widget(list, area);
}


fn draw_bytes_per_sec(f: &mut Frame, area: Rect, state: &AppState) {
    let data: Vec<(f64, f64)> = state
        .bytes_history
        .iter()
        .enumerate()
        .map(|(i, &v)| (i as f64, v as f64))
        .collect();

    let max_val = state
        .bytes_history
        .iter()
        .copied()
        .max()
        .unwrap_or(1)
        .max(1);
    let mid_val = max_val / 2;
    let len = state.bytes_history.len().max(1) as f64;

    let block = Block::bordered()
        .title(" Bytes/sec ")
        .style(Style::default().fg(Color::White).bg(Color::Black));

    let dataset = Dataset::default()
        .marker(symbols::Marker::Braille)
        .graph_type(GraphType::Line)
        .style(Style::default().fg(Color::Green))
        .data(&data);

    let y_labels: Vec<String> = vec![
        "0".into(),
        format_bytes(mid_val),
        format_bytes(max_val),
    ];
    let y_axis = Axis::default()
        .style(Style::default().fg(Color::DarkGray))
        .bounds([0.0, max_val as f64])
        .labels(y_labels);

    let x_axis = Axis::default()
        .style(Style::default().fg(Color::DarkGray))
        .bounds([0.0, len - 1.0]);

    let chart = Chart::new(vec![dataset])
        .block(block)
        .x_axis(x_axis)
        .y_axis(y_axis)
        .legend_position(None);

    f.render_widget(chart, area);
}

fn draw_footer(f: &mut Frame, area1: Rect, area2: Rect, state: &AppState) {
    let last_bps = state.bytes_history.back().copied().unwrap_or(0);

    let (status, keys) = match state.input_mode {
        InputMode::Normal => {
            let msg = if let Some((m, t)) = &state.footer_message {
                if t.elapsed() < std::time::Duration::from_secs(2) {
                    format!(" \u{2714} {}", m)
                } else {
                    format!(
                        " Capturing on {}  |  Network: {}  |  {} packets  |  {}/sec",
                        state.interface_name,
                        state.current_network,
                        format_with_commas(state.total_packets),
                        format_bytes(last_bps),
                    )
                }
            } else {
                format!(
                    " Capturing on {}  |  Network: {}  |  {} packets  |  {}/sec",
                    state.interface_name,
                    state.current_network,
                    format_with_commas(state.total_packets),
                    format_bytes(last_bps),
                )
            };
            
            let f_key_text = match state.focused_panel {
                Panel::Feed => {
                    let tag = filter_label(&state.display_filter);
                    format!("[F] Protocol: {}", tag)
                }
                Panel::Alerts => {
                    let tag = match state.alert_filter {
                        AlertFilter::All => "ALL",
                        AlertFilter::Suspicious => "SUSPICIOUS",
                        AlertFilter::Behavioral => "BEHAVIORAL",
                        AlertFilter::External => "EXTERNAL",
                        AlertFilter::Noise => "NOISE",
                    };
                    format!("[F] Alerts: {}", tag)
                }
                Panel::Discovery => {
                    let tag = match state.discovery_filter {
                        DiscoveryFilter::All => "ALL",
                        DiscoveryFilter::Named => "NAMED",
                        DiscoveryFilter::Vendors => "VENDORS",
                        DiscoveryFilter::Unknown => "UNKNOWN",
                    };
                    format!("[F] Discovery: {}", tag)
                }
            };

            let ip_hint = if state.ip_compressed { "[I] Full IPs" } else { "[I] Short IPs" };

            let k = if state.show_graph {
                format!(" [Tab] Switch Panel  [\u{2191}\u{2193}] Scroll  [Alt+S] Scan  [A] Auto-Scan  [G] Graph  [N] Select Node  [Esc] Clear  [E] Export  {}  [W] Whitelist IP  {} ", f_key_text, ip_hint)
            } else {
                format!(" [Tab] Switch Panel  [\u{2191}\u{2193}] Scroll  [Alt+S] Scan  [A] Auto-Scan  [G] Graph  [Space] Resume  [E] Export  {}  [W] Whitelist IP  {} ", f_key_text, ip_hint)
            };
            (msg, k)
        }
        InputMode::Exporting => {
            (format!(" Save report to: {}_", state.input_buffer), " [Enter] Confirm   [Esc] Cancel ".to_string())
        }
        InputMode::Whitelisting => {
            (format!(" Whitelist IP: {}_", state.input_buffer), " [Enter] Confirm   [Esc] Cancel ".to_string())
        }
    };

    let bg1 = if state.input_mode == InputMode::Normal { Color::DarkGray } else { Color::Blue };
    
    let paragraph_status = Paragraph::new(status)
        .style(Style::default().fg(Color::White).bg(bg1));
    f.render_widget(paragraph_status, area1);

    let paragraph_keys = Paragraph::new(keys)
        .style(Style::default().fg(Color::DarkGray).bg(Color::Black));
    f.render_widget(paragraph_keys, area2);
}


fn build_short_label(ip: &IpAddr, state: &AppState) -> String {
    let os_tag = format!(" {}", state.get_resolved_os_tag(ip));
    let name = state.get_display_hostname(ip);

    if is_private_ip(ip) {
        if name != ip.to_string() && name != "\u{2014}" && name != "Resolving..." && !name.is_empty() {
            let name_trunc = if name.len() > 14 { format!("{}..", &name[..12]) } else { name };
            return format!("{}{}", name_trunc, os_tag);
        }
        return format!("{}{}", ip, os_tag);
    } else {
        if name != ip.to_string() && name != "\u{2014}" && name != "Resolving..." && !name.is_empty() {
            let d = name.trim_end_matches('.');
            let d_short = if d.len() > 20 { format!("{}..", &d[..18]) } else { d.to_string() };
            return format!("{}", d_short);
        }
        let cc = state.geo_cache.get(ip).map(|g| format!(" {}", format_geo_tag(g))).unwrap_or_default();
        return format!("{}{}", ip, cc);
    }
}

fn draw_graph(f: &mut Frame, area: Rect, state: &AppState) {
    let units_per_col = 680.0 / (area.width as f64).max(1.0);
    let units_per_row = 360.0 / (area.height as f64).max(1.0);

    let block = Block::bordered()
        .title(" Network Topology [Radar] ")
        .style(Style::default().fg(Color::Rgb(29, 158, 117)).bg(Color::Black));

    let canvas = Canvas::default()
        .block(block)
        .x_bounds([-340.0, 340.0])
        .y_bounds([-180.0, 180.0])
        .background_color(Color::Rgb(4, 12, 8))
        .paint(|ctx| {
            // Layer 1 — Grid crosshairs
            ctx.draw(&ratatui::widgets::canvas::Line {
                x1: 0.0, y1: -178.0, x2: 0.0, y2: 178.0,
                color: Color::Rgb(15, 40, 25),
            });
            ctx.draw(&ratatui::widgets::canvas::Line {
                x1: -338.0, y1: 0.0, x2: 338.0, y2: 0.0,
                color: Color::Rgb(15, 40, 25),
            });

            // Layer 1.5 — Axis markers
            ctx.print(0.0, 172.0, ratatui::text::Span::styled("N", Style::default().fg(Color::Rgb(15, 40, 25))));
            ctx.print(0.0, -178.0, ratatui::text::Span::styled("S", Style::default().fg(Color::Rgb(15, 40, 25))));
            ctx.print(330.0, 2.0, ratatui::text::Span::styled("E", Style::default().fg(Color::Rgb(15, 40, 25))));
            ctx.print(-338.0, 2.0, ratatui::text::Span::styled("W", Style::default().fg(Color::Rgb(15, 40, 25))));

            // Layer 2 — Zone rings + depth rings
            for r in &[60.0, 140.0] {
                ctx.draw(&ratatui::widgets::canvas::Circle { x: 0.0, y: 0.0, radius: *r, color: Color::Rgb(10, 25, 18) });
            }
            for (r, color) in &[(110.0, Color::Rgb(29, 90, 60)), (165.0, Color::Rgb(29, 90, 60))] {
                ctx.draw(&ratatui::widgets::canvas::Circle { x: 0.0, y: 0.0, radius: *r, color: *color });
            }
            ctx.print(-6.0, 112.0, ratatui::text::Span::styled("local", Style::default().fg(Color::Rgb(29, 90, 60))));
            ctx.print(-10.0, 167.0, ratatui::text::Span::styled("internet", Style::default().fg(Color::Rgb(29, 90, 60))));

            // Layer 3 — Sweep line and sector
            let sweep_angle = (state.graph_tick as f64 / 120.0) * std::f64::consts::TAU;
            let sweep_end_x = sweep_angle.cos() * 175.0;
            let sweep_end_y = sweep_angle.sin() * 175.0;
            ctx.draw(&ratatui::widgets::canvas::Line {
                x1: 0.0, y1: 0.0,
                x2: sweep_end_x, y2: sweep_end_y,
                color: Color::Rgb(93, 202, 165),
            });
            // Trailing fade lines (3 ghost lines slightly behind the sweep)
            for i in 1..=3 {
                let trail_angle = sweep_angle - (i as f64 * 0.12);
                let fade = Color::Rgb(
                    (93.0 * (1.0 - i as f64 * 0.28)) as u8,
                    (202.0 * (1.0 - i as f64 * 0.28)) as u8,
                    (165.0 * (1.0 - i as f64 * 0.28)) as u8,
                );
                ctx.draw(&ratatui::widgets::canvas::Line {
                    x1: 0.0, y1: 0.0,
                    x2: trail_angle.cos() * 175.0,
                    y2: trail_angle.sin() * 175.0,
                    color: fade,
                });
            }

            // Collect alert IPs first
            let alerted_ips: HashSet<IpAddr> = state.alerts_suspicious.iter()
                .filter_map(|a| a.remote_ip)
                .collect();

            let host_ip = state.graph_nodes.iter()
                .find(|(_, n)| n.pinned)
                .map(|(ip, _)| *ip);

            // Layer 5 — Nodes (Only draw the positioned ones + host)
            for ip in &state.positioned_nodes {
                let node = match state.graph_nodes.get(ip) {
                    Some(n) => n,
                    None => continue,
                };

                let is_alert = alerted_ips.contains(ip);
                let is_local = is_private_ip(ip);

                // Check recent traffic
                let active_traffic = state.edge_last_seen.iter()
                    .any(|((s, d), t)| (s == ip || d == ip) && t.elapsed().as_secs_f64() < 1.5);

                let node_color = if is_alert {
                    Color::Red
                } else if active_traffic {
                    Color::White
                } else if is_local {
                    Color::Green
                } else {
                    Color::Yellow
                };

                // Use a larger symbol for active traffic
                let mut symbol = if active_traffic { "◉".to_string() } else { "●".to_string() };
                
                // Highlight selected node with prominent arrows
                let mut dot_x = node.x;
                if state.selected_node == Some(*ip) {
                    symbol = format!("►{}◄", symbol);
                    dot_x -= units_per_col * 2.0; // Shift left to center the arrows properly
                    // Make the label pop more for the selected node
                    ctx.print(dot_x, node.y - units_per_row * 2.0, ratatui::text::Span::styled("~~~~~", Style::default().fg(Color::Yellow)));
                }

                // Draw dot
                ctx.print(dot_x, node.y, ratatui::text::Span::styled(symbol, Style::default().fg(node_color)));
                // Label placement
                let label = build_short_label(ip, state);
                let label_color = if is_alert {
                    Color::Red
                } else if active_traffic {
                    Color::White
                } else if is_local {
                    Color::Green
                } else {
                    Color::Gray
                };

                if node.x >= 0.0 {
                    ctx.print(node.x + 3.0, node.y, ratatui::text::Span::styled(
                        format!(" {}", label),
                        Style::default().fg(label_color)
                    ));
                } else {
                    let offset = -(label.chars().count() as f64 * units_per_col + 4.0);
                    ctx.print(node.x + offset, node.y, ratatui::text::Span::styled(
                        label.clone(),
                        Style::default().fg(label_color)
                    ));
                }

            }

            // Layer 6 — Host node (pinned)
            if let Some(host_ip_val) = host_ip {
                if let Some(node) = state.graph_nodes.get(&host_ip_val) {
                    let frame = HOST_ICON.get().unwrap();
                    let line_count = frame.len() as f64;

                    // Fix vertical overlapping with exact row height mapping
                    let line_step = units_per_row;

                    let max_chars = frame.iter().map(|l| l.chars().count()).max().unwrap_or(0) as f64;
                    // Shift right by a larger offset so it appears visually centered
                    let right_nudge = units_per_col * 3.5;
                    let start_x = node.x - (max_chars * units_per_col / 2.0) + right_nudge;

                    for (i, line) in frame.iter().enumerate() {
                        let y = node.y + (line_count / 2.0 - i as f64) * line_step - (line_step / 2.0);
                        ctx.print(start_x, y, ratatui::text::Span::styled(
                            line.clone(),
                            {
                                let pulse = ((state.graph_tick as f64 / 40.0).sin() * 0.5 + 0.5) as f64;
                                let pr = (29.0 + (93.0 - 29.0) * pulse) as u8;
                                let pg = (158.0 + (202.0 - 158.0) * pulse) as u8;
                                let pb = (117.0 + (165.0 - 117.0) * pulse) as u8;
                                Style::default().fg(Color::Rgb(pr, pg, pb))
                            }
                        ));
                    }

                    // Host label — centered relative to the icon
                    let label = format!("{} [HOST]", host_ip_val);
                    let label_y = node.y - (line_count / 2.0) * line_step - (line_step * 1.5);
                    let label_x = node.x - (label.chars().count() as f64 * units_per_col / 2.0) + right_nudge;
                    ctx.print(label_x, label_y, ratatui::text::Span::styled(
                        label,
                        Style::default().fg(Color::Rgb(159, 225, 203))
                    ));
                }
            }

            // Layer 8 — Ping rings (expanding & more visible)
            for &(rx, ry, birth) in &state.ping_rings {
                let age = state.graph_tick.wrapping_sub(birth) as f64;
                let ring_radius = 4.0 + age * 1.5; // Faster expansion
                let fade = (1.0 - age / 30.0).max(0.0); // Slower fade
                let g_val = (220.0 * fade) as u8;
                let b_val = (180.0 * fade) as u8;
                ctx.draw(&ratatui::widgets::canvas::Circle {
                    x: rx, y: ry, radius: ring_radius,
                    color: Color::Rgb(0, g_val, b_val),
                });
            }

            // Layer 9 — Legend (bottom-left) with standard ANSI colors
            let legend_y = -178.0;
            // "LOCAL" entry — green dot + green label
            ctx.print(-330.0, legend_y, ratatui::text::Span::styled(
                "●", Style::default().fg(Color::Green)
            ));
            ctx.print(-320.0, legend_y, ratatui::text::Span::styled(
                "LOCAL", Style::default().fg(Color::Green)
            ));
            // "INTERNET" entry — yellow dot + yellow label
            ctx.print(-268.0, legend_y, ratatui::text::Span::styled(
                "●", Style::default().fg(Color::Yellow)
            ));
            ctx.print(-258.0, legend_y, ratatui::text::Span::styled(
                "INTERNET", Style::default().fg(Color::Yellow)
            ));
            // "ACTIVE" entry — white ring + white label
            ctx.print(-190.0, legend_y, ratatui::text::Span::styled(
                "◉", Style::default().fg(Color::White)
            ));
            ctx.print(-180.0, legend_y, ratatui::text::Span::styled(
                "ACTIVE", Style::default().fg(Color::White)
            ));
            // "ALERT" entry — red dot + red label
            ctx.print(-118.0, legend_y, ratatui::text::Span::styled(
                "●", Style::default().fg(Color::Red)
            ));
            ctx.print(-108.0, legend_y, ratatui::text::Span::styled(
                "ALERT", Style::default().fg(Color::Red)
            ));
        });

    f.render_widget(canvas, area);

    // Draw the detail popup if a node is selected
    if let Some(ip) = state.selected_node {
        let popup_width = 38;

        let mut hostname = state.dns_cache.get(&ip).map(|s| s.clone()).unwrap_or_else(|| "--".to_string());
        if (hostname == "--" || hostname == "Resolving...") && is_private_ip(&ip) {
            if let Ok(devices) = state.active_discovery.try_lock() {
                if let Some(dev) = devices.get(&ip) {
                    let display_host = {
                        let h = clean_hostname(&dev.hostname);
                        if h == "\u{2014}" || h == "Resolving..." { ip.to_string() } else { h }
                    };
                    hostname = display_host;
                }
            }
        }
        let hostname = clean_hostname(&hostname);

        let mut country = "--".to_string();
        let mut org = "--".to_string();
        if let Some(geo) = state.geo_cache.get(&ip) {
            country = geo.country_code.clone();
            org = geo.org.clone();
        }

        let mut in_pkts = 0;
        let mut out_pkts = 0;
        for ((src, dst), count) in &state.pair_packet_counts {
            if *src == ip { out_pkts += count; }
            if *dst == ip { in_pkts += count; }
        }
        let total_pkts = format_with_commas(in_pkts + out_pkts);

        let bytes_val = state.dest_bytes.get(&ip).copied().unwrap_or(0);
        let bytes_str = format_bytes(bytes_val);

        let (protocol, process) = state.node_last_seen_details.get(&ip).cloned().unwrap_or_else(|| ("--".to_string(), "--".to_string()));

        let mut last_seen = "--".to_string();
        let mut first_seen = "--".to_string();

        let mut latest = std::time::Duration::from_secs(999999);
        let mut earliest = std::time::Duration::from_secs(0);
        let mut found = false;

        for ((src, dst), last_t) in &state.edge_last_seen {
            if src == &ip || dst == &ip {
                let e = last_t.elapsed();
                if e < latest { latest = e; }
                found = true;
            }
        }
        for ((src, dst), first_t) in &state.edge_first_seen {
            if src == &ip || dst == &ip {
                let e = first_t.elapsed();
                if e > earliest { earliest = e; }
            }
        }

        if found {
            last_seen = format!("{:.1}s ago", latest.as_secs_f64());
            first_seen = format_duration(earliest);
            first_seen = format!("{} ago", first_seen);
        }

        let details = vec![
            ratatui::widgets::ListItem::new(ratatui::text::Span::styled(hostname, Style::default().fg(Color::Cyan))),
            ratatui::widgets::ListItem::new(ratatui::text::Span::styled(ip.to_string(), Style::default().fg(Color::DarkGray))),
            ratatui::widgets::ListItem::new(""),
            ratatui::widgets::ListItem::new(format!("{:<10} {}", "Country:", country)),
            ratatui::widgets::ListItem::new(format!("{:<10} {}", "Org:", org)),
            ratatui::widgets::ListItem::new(format!("{:<10} {}", "Packets:", total_pkts)),
            ratatui::widgets::ListItem::new(format!("{:<10} {}", "Bytes:", bytes_str)),
            ratatui::widgets::ListItem::new(format!("{:<10} {}", "Protocol:", protocol)),
            ratatui::widgets::ListItem::new(format!("{:<10} {}", "Process:", process)),
            ratatui::widgets::ListItem::new(format!("{:<10} {}", "First seen:", first_seen)),
            ratatui::widgets::ListItem::new(format!("{:<10} {}", "Last seen:", last_seen)),
        ];

        // Enrich with device metadata if available
        let mut enriched_details = details;
        if let Ok(meta) = state.device_metadata.try_lock() {
            if let Some(dev_meta) = meta.get(&ip) {
                enriched_details.push(ratatui::widgets::ListItem::new(
                    ratatui::text::Span::styled("── Device Info ──", Style::default().fg(Color::Rgb(29, 158, 117)))
                ));
                // Show model
                if let Some(model) = dev_meta.get("model") {
                    enriched_details.push(ratatui::widgets::ListItem::new(
                        format!("{:<10} {}", "Model:", model)
                    ));
                } else if let Some(model_name) = dev_meta.get("model_name") {
                    enriched_details.push(ratatui::widgets::ListItem::new(
                        format!("{:<10} {}", "Model:", model_name)
                    ));
                }
                // Friendly name (SSDP / Chromecast)
                if let Some(fname) = dev_meta.get("friendly_name") {
                    enriched_details.push(ratatui::widgets::ListItem::new(
                        format!("{:<10} {}", "Name:", fname)
                    ));
                }
                // Manufacturer (SSDP)
                if let Some(mfr) = dev_meta.get("manufacturer") {
                    enriched_details.push(ratatui::widgets::ListItem::new(
                        format!("{:<10} {}", "Mfr:", mfr)
                    ));
                }
                // Firmware version
                if let Some(fw) = dev_meta.get("firmware") {
                    enriched_details.push(ratatui::widgets::ListItem::new(
                        format!("{:<10} {}", "Firmware:", fw)
                    ));
                }
                // OS version
                if let Some(osv) = dev_meta.get("os_version") {
                    enriched_details.push(ratatui::widgets::ListItem::new(
                        format!("{:<10} {}", "OS:", osv)
                    ));
                }
                // Services
                if let Some(svcs) = dev_meta.get("services") {
                    enriched_details.push(ratatui::widgets::ListItem::new(
                        format!("{:<10} {}", "Services:", truncate_str(svcs, 24))
                    ));
                }
                // Serial (SSDP)
                if let Some(serial) = dev_meta.get("serial") {
                    enriched_details.push(ratatui::widgets::ListItem::new(
                        format!("{:<10} {}", "Serial:", serial)
                    ));
                }
            }
        }

        // JA4 TLS fingerprint
        if let Some((ja4, count)) = state.tls_fingerprints.get(&ip) {
            enriched_details.push(ratatui::widgets::ListItem::new(
                ratatui::text::Span::styled("── TLS Profile ──", Style::default().fg(Color::Rgb(29, 158, 117)))
            ));
            enriched_details.push(ratatui::widgets::ListItem::new(
                format!("{:<10} {}", "JA4:", truncate_str(ja4, 36))
            ));
            enriched_details.push(ratatui::widgets::ListItem::new(
                format!("{:<10} {} samples", "Seen:", count)
            ));
        }

        // DHCP fingerprint
        let mut dhcp_fp = state.dhcp_fingerprints.get(&ip).cloned();
        if dhcp_fp.is_none() {
            if let Ok(meta) = state.device_metadata.try_lock() {
                if let Some(dev_meta) = meta.get(&ip) {
                    dhcp_fp = dev_meta.get("dhcp_fingerprint").cloned();
                }
            }
        }
        if let Some(fp) = dhcp_fp {
            enriched_details.push(ratatui::widgets::ListItem::new(
                ratatui::text::Span::styled("── DHCP Profile ──", Style::default().fg(Color::Rgb(29, 158, 117)))
            ));
            enriched_details.push(ratatui::widgets::ListItem::new(
                format!("{:<10} {}", "PRL:", truncate_str(&fp, 36))
            ));
            if let Some((_tag, desc)) = crate::dhcp::classify_dhcp(&fp) {
                enriched_details.push(ratatui::widgets::ListItem::new(
                    format!("{:<10} {}", "OS Match:", desc)
                ));
            }
        }

        // Behavioral classification
        if let Some(profile) = state.traffic_profiles.get(&ip) {
            if let Some(dev_type) = classify_device_type(profile) {
                enriched_details.push(ratatui::widgets::ListItem::new(
                    format!("{:<10} {}", "Behavior:", dev_type)
                ));
            }
        }

        let popup_height = (enriched_details.len() as u16 + 2).min(area.height);

        let popup_area = ratatui::layout::Rect {
            x: area.x.saturating_add(area.width.saturating_sub(popup_width)),
            y: area.y,
            width: popup_width.min(area.width),
            height: popup_height,
        };

        let popup_block = Block::bordered()
            .title(" Node Detail ")
            .style(Style::default().fg(Color::Rgb(29, 158, 117)).bg(Color::Black));

        let list = ratatui::widgets::List::new(enriched_details)
            .block(popup_block)
            .style(Style::default().fg(Color::White));

        // Use clear to avoid background overlapping
        f.render_widget(ratatui::widgets::Clear, popup_area);
        f.render_widget(list, popup_area);
    }
}
