use std::collections::HashMap;
use std::collections::HashSet;
use std::collections::VecDeque;
use std::net::IpAddr;

use chrono::{DateTime, Local};
use ratatui::layout::{Alignment, Constraint, Layout, Rect};
use ratatui::style::{Color, Style};
use ratatui::symbols;
use ratatui::widgets::{
    Axis, Bar, BarChart, BarGroup, Block, Chart, Dataset, GraphType, List, ListItem, Paragraph,
};
use ratatui::Frame;

use crate::packet::{CapturedPacket, Protocol, ProtocolFilter};

// ---------------------------------------------------------------------------
// Alert types
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub enum AlertLevel {
    Warn,
    Info,
}

#[derive(Clone, Copy, PartialEq)]
pub enum AlertReason {
    UnusualPort,
    UnknownDestination,
    HighVolume,
    InboundExternal,
}

#[derive(Clone)]
pub struct Alert {
    pub timestamp: DateTime<Local>,
    pub message: String,
    pub level: AlertLevel,
    pub remote_ip: Option<IpAddr>,
    pub process: Option<String>,
    pub reason: AlertReason,
}

#[derive(PartialEq, Clone, Copy)]
pub enum AlertFilter {
    All,
    Suspicious,
    External,
    Noise,
}

// ---------------------------------------------------------------------------
// Application state — owned by main, passed by reference to draw functions
// ---------------------------------------------------------------------------

#[derive(PartialEq, Clone, Copy)]
pub enum Panel {
    Feed,
    Alerts,
}

#[derive(PartialEq, Clone, Copy)]
pub enum InputMode {
    Normal,
    Exporting,
    Whitelisting,
}

#[allow(clippy::type_complexity)]
pub struct AppState {
    pub interface_name: String,
    pub feed_entries: VecDeque<(Protocol, String)>,
    pub tcp_count: u64,
    pub udp_count: u64,
    pub icmp_count: u64,
    pub total_packets: u64,
    pub total_bytes: u64,
    pub dest_bytes: HashMap<IpAddr, u64>,
    pub connections: HashMap<(IpAddr, IpAddr, Option<u16>), (u64, u64, Option<String>)>,
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
    pub limit_reached: bool,
    pub capture_error: Option<String>,
    pub alerts: Vec<Alert>,
    // Scrolling and Focus
    pub focused_panel: Panel,
    pub feed_scroll: usize,
    pub feed_paused_scroll: bool,
    pub alert_scroll: usize,
    pub alert_paused_scroll: bool,
    // Input Mode and State
    pub input_mode: InputMode,
    pub input_buffer: String,
    pub whitelist: HashSet<IpAddr>,
    pub geo_cache: HashMap<IpAddr, crate::geoip::GeoInfo>,
    pub geo_in_flight: usize,
    pub footer_message: Option<(String, std::time::Instant)>,
}

const KNOWN_PORTS: [u16; 16] = [
    80, 443, 53, 22, 3389, 5353, 1900, 8009, 8080, 21, 25, 110, 143, 123, 67, 68,
];

impl AppState {
    pub fn new(interface_name: String) -> Self {
        let now = std::time::Instant::now();
        Self {
            interface_name,
            feed_entries: VecDeque::with_capacity(51),
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
            limit_reached: false,
            capture_error: None,
            alerts: Vec::new(),
            focused_panel: Panel::Feed,
            feed_scroll: 0,
            feed_paused_scroll: false,
            alert_scroll: 0,
            alert_paused_scroll: false,
            input_mode: InputMode::Normal,
            input_buffer: String::new(),
            whitelist: HashSet::new(),
            geo_cache: HashMap::new(),
            geo_in_flight: 0,
            footer_message: None,
        }
    }

    pub fn ingest_packet(&mut self, pkt: &CapturedPacket) {
        match pkt.protocol {
            Protocol::Tcp => self.tcp_count += 1,
            Protocol::Udp => self.udp_count += 1,
            Protocol::Icmp => self.icmp_count += 1,
            Protocol::Unknown(_) => {}
        }
        self.total_packets += 1;
        self.total_bytes += pkt.size as u64;

        *self.dest_bytes.entry(pkt.dst_ip).or_insert(0) += pkt.size as u64;
        self.current_second_bytes += pkt.size as u64;
        self.current_second_packets += 1;

        // Update connection tracker (now includes process name)
        let conn_key = (pkt.src_ip, pkt.dst_ip, pkt.dst_port);
        let entry = self.connections.entry(conn_key).or_insert((0, 0, None));
        entry.0 += 1;
        entry.1 += pkt.size as u64;
        if entry.2.is_none() {
            entry.2.clone_from(&pkt.process);
        }

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

        // --- Generate alerts ---
        if self.whitelist.contains(&pkt.src_ip) || self.whitelist.contains(&pkt.dst_ip) {
            return;
        }

        let proc_label = pkt
            .process
            .as_deref()
            .unwrap_or("unknown")
            .to_string();
        let now = Local::now();
        
        let geo_tag = self.geo_cache.get(&pkt.dst_ip)
            .map(|g| format!(" [{}]", g.country_code))
            .unwrap_or_default();

        let src_geo_tag = self.geo_cache.get(&pkt.src_ip)
            .map(|g| format!(" [{}]", g.country_code))
            .unwrap_or_default();

        // 1. Unusual port
        if let Some(port) = pkt.dst_port {
            if !KNOWN_PORTS.contains(&port) && !is_local_or_multicast(&pkt.dst_ip) {
                self.push_alert(Alert {
                    timestamp: now,
                    message: format!(
                        "Unusual port {} \u{2192} {} ({})",
                        port, pkt.dst_ip, proc_label,
                    ),
                    level: AlertLevel::Warn,
                    remote_ip: Some(pkt.dst_ip),
                    process: Some(proc_label.clone()),
                    reason: AlertReason::UnusualPort,
                });
            }
        }

        // 2. Unknown destination
        if !is_known_destination(&pkt.dst_ip) {
            let port_str = pkt
                .dst_port
                .map_or("---".into(), |p| p.to_string());
            self.push_alert(Alert {
                timestamp: now,
                message: format!(
                    "Unknown destination {}:{}{} ({})",
                    pkt.dst_ip, port_str, geo_tag, proc_label,
                ),
                level: AlertLevel::Info,
                remote_ip: Some(pkt.dst_ip),
                process: Some(proc_label.clone()),
                reason: AlertReason::UnknownDestination,
            });
        }

        // 3. High volume (fire once per pair)
        if pair_count >= 500 && !self.high_volume_alerted.contains(&pair) {
            self.high_volume_alerted.insert(pair);
            self.push_alert(Alert {
                timestamp: now,
                message: format!(
                    "High volume: {} \u{2192} {} exceeded 500 packets",
                    pair.0, pair.1,
                ),
                level: AlertLevel::Warn,
                remote_ip: None, // Could be bi-directional pair, skipping explicit remote label
                process: Some(proc_label.clone()),
                reason: AlertReason::HighVolume,
            });
        }

        // 4. Inbound to listening port — external src → private dst on port < 1024 or known ports (excluding ephemeral)
        if let Some(port) = pkt.dst_port {
            if (port < 1024 || KNOWN_PORTS.contains(&port))
                && port < 49152
                && is_private_ip(&pkt.dst_ip)
                && !is_private_ip(&pkt.src_ip)
            {
                self.push_alert(Alert {
                    timestamp: now,
                    message: format!(
                        "Inbound connection on port {} from {}{} ({})",
                        port, pkt.src_ip, src_geo_tag, proc_label,
                    ),
                    level: AlertLevel::Warn,
                    remote_ip: Some(pkt.src_ip),
                    process: Some(proc_label.clone()),
                    reason: AlertReason::InboundExternal,
                });
            }
        }

        let line = format_packet_line(pkt, self);
        self.feed_entries.push_back((pkt.protocol.clone(), line));
        if self.feed_entries.len() > 50 {
            self.feed_entries.pop_front();
        }
        if self.feed_paused_scroll {
            self.feed_scroll = self.feed_scroll.saturating_add(1);
        }
    }

    fn push_alert(&mut self, alert: Alert) {
        self.alerts.insert(0, alert); // newest first
        if self.alerts.len() > 50 {
            self.alerts.pop();
        }
        if self.alert_paused_scroll {
            self.alert_scroll = self.alert_scroll.saturating_add(1);
        }
    }

    pub fn clear_alerts(&mut self) {
        self.alerts.clear();
    }

    pub fn whitelist_ip(&mut self, ip: IpAddr) {
        self.whitelist.insert(ip);
        self.alerts.retain(|a| !a.message.contains(&ip.to_string()));
    }

    pub fn set_footer_message(&mut self, msg: String) {
        self.footer_message = Some((msg, std::time::Instant::now()));
    }

    pub fn tick(&mut self) {
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
        if self.focused_panel == Panel::Feed {
            self.display_filter = match self.display_filter {
                ProtocolFilter::All => ProtocolFilter::Tcp,
                ProtocolFilter::Tcp => ProtocolFilter::Udp,
                ProtocolFilter::Udp => ProtocolFilter::Icmp,
                ProtocolFilter::Icmp => ProtocolFilter::All,
            };
        } else {
            self.alert_filter = match self.alert_filter {
                AlertFilter::All => AlertFilter::Suspicious,
                AlertFilter::Suspicious => AlertFilter::External,
                AlertFilter::External => AlertFilter::Noise,
                AlertFilter::Noise => AlertFilter::All,
            };
        }
    }

    pub fn switch_panel(&mut self) {
        self.focused_panel = match self.focused_panel {
            Panel::Feed => Panel::Alerts,
            Panel::Alerts => Panel::Feed,
        };
    }

    pub fn scroll_up(&mut self) {
        match self.focused_panel {
            Panel::Feed => {
                self.feed_paused_scroll = true;
                self.feed_scroll = self.feed_scroll.saturating_add(1);
            }
            Panel::Alerts => {
                let max = self.alerts.len().saturating_sub(1);
                if self.alert_scroll < max {
                    self.alert_paused_scroll = true;
                    self.alert_scroll = self.alert_scroll.saturating_add(1);
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
        }
    }
}

// ---------------------------------------------------------------------------
// IP classification helpers
// ---------------------------------------------------------------------------

fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            matches!(o, [192, 168, _, _] | [10, _, _, _] | [172, 16..=31, _, _])
        }
        _ => false,
    }
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

fn is_known_destination(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            matches!(
                o,
                // Private / local / multicast
                [192, 168, _, _]
                    | [10, _, _, _]
                    | [172, 16..=31, _, _]
                    | [127, _, _, _]
                    | [224..=239, _, _, _]
                    | [255, 255, 255, 255]
                    // Known services from display_ip()
                    | [8, 8, 8, 8]
                    | [8, 8, 4, 4]
                    | [1, 1, 1, 1]
                    | [1, 0, 0, 1]
                    | [20, 50, 73, 4]
                    | [20, 112, 52, 29]
                    | [142, 250, _, _]
                    | [172, 217, _, _]
                    | [13, 107, _, _]
                    | [52, _, _, _]
                    | [54, _, _, _]
                    | [104, _, _, _]
            )
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

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

fn display_ip(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            match o {
                [255, 255, 255, 255] => "Broadcast".into(),
                [224, 0, 0, 251] => "mDNS".into(),
                [239, 255, 255, 250] => "UPnP".into(),
                [8, 8, 8, 8] | [8, 8, 4, 4] => "Google DNS".into(),
                [1, 1, 1, 1] | [1, 0, 0, 1] => "Cloudflare DNS".into(),
                [20, 50, 73, 4] | [20, 112, 52, 29] => "Microsoft".into(),
                [142, 250, _, _] | [172, 217, _, _] => "Google".into(),
                [13, 107, _, _] => "Microsoft".into(),
                [52, _, _, _] | [54, _, _, _] => "Amazon AWS".into(),
                [104, _, _, _] => "Cloudflare".into(),
                [192, 168, _, _] | [10, _, _, _] | [172, 16..=31, _, _] => v4.to_string(),
                _ => v4.to_string(),
            }
        }
        IpAddr::V6(v6) => v6.to_string(),
    }
}

fn format_packet_line(pkt: &CapturedPacket, state: &AppState) -> String {
    let src = format_endpoint(pkt.src_ip, pkt.src_port);
    let dst = format_endpoint_labeled(pkt.dst_ip, pkt.dst_port);
    let flags = pkt.flags.as_deref().unwrap_or("\u{2014}");
    
    // Check GeoIP cache
    let dst_str = if let Some(geo) = state.geo_cache.get(&pkt.dst_ip) {
        format!("{} [{}]", dst, geo.country_code)
    } else {
        dst
    };

    let src_str = if let Some(geo) = state.geo_cache.get(&pkt.src_ip) {
        format!("{} [{}]", src, geo.country_code)
    } else {
        src
    };

    let ts = pkt.timestamp.format("%H:%M:%S%.3f");
    format!(
        "[{ts}]  {proto:<4} {src_str:<21}  \u{2192}  {dst_str:<26}  {flags:<10} {size}B",
        proto = pkt.protocol,
        size = pkt.size,
    )
}

fn format_endpoint(ip: IpAddr, port: Option<u16>) -> String {
    match port {
        Some(p) => format!("{ip}:{p}"),
        None => ip.to_string(),
    }
}

fn format_endpoint_labeled(ip: IpAddr, port: Option<u16>) -> String {
    match port {
        Some(p) => format!("{ip}:{}", format_port(p)),
        None => ip.to_string(),
    }
}

fn matches_display_filter(proto: &Protocol, filter: &ProtocolFilter) -> bool {
    match filter {
        ProtocolFilter::All => true,
        ProtocolFilter::Tcp => matches!(proto, Protocol::Tcp),
        ProtocolFilter::Udp => matches!(proto, Protocol::Udp),
        ProtocolFilter::Icmp => matches!(proto, Protocol::Icmp),
    }
}

const KNOWN_WINDOWS_PROCESSES: [&str; 12] = [
    "svchost.exe", "SearchHost.exe", "MsMpEng.exe", "WmiPrvSE.exe",
    "RuntimeBroker.exe", "SupportAssistAgent.exe", "lsass.exe",
    "services.exe", "wininit.exe", "csrss.exe", "System", "dasHost.exe"
];

fn matches_alert_filter(alert: &Alert, filter: &AlertFilter) -> bool {
    let process_name = alert.process.as_deref().unwrap_or("unknown");
    let is_known_proc = KNOWN_WINDOWS_PROCESSES.iter().any(|&p| p.eq_ignore_ascii_case(process_name));
    
    let is_remote_external = match alert.remote_ip {
        Some(ip) => !is_local_or_multicast(&ip),
        None => false,
    };

    match filter {
        AlertFilter::All => true,
        AlertFilter::Suspicious => {
            if alert.reason == AlertReason::HighVolume {
                true
            } else if alert.reason == AlertReason::UnusualPort || alert.reason == AlertReason::InboundExternal {
                !is_known_proc
            } else {
                false
            }
        }
        AlertFilter::External => is_remote_external && !is_known_proc,
        AlertFilter::Noise => {
            is_known_proc || !is_remote_external
        }
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
    let main_chunks = Layout::vertical([
        Constraint::Fill(1),        // 0: Live Feed (fills remaining)
        Constraint::Length(11),     // 1: Connections + Alerts
        Constraint::Percentage(28), // 2: Bottom panels row
        Constraint::Length(1),      // 3: Footer line 1 (capturing status)
        Constraint::Length(1),      // 4: Footer line 2 (keybinds)
    ])
    .split(f.area());

    let top_chunks = Layout::horizontal([
        Constraint::Percentage(65),
        Constraint::Percentage(35),
    ])
    .split(main_chunks[0]);

    draw_feed(f, top_chunks[0], state);
    draw_logo(f, top_chunks[1]);

    let middle_chunks = Layout::horizontal([
        Constraint::Percentage(50),
        Constraint::Percentage(50),
    ])
    .split(main_chunks[1]);

    draw_connections(f, middle_chunks[0], state);
    draw_alerts(f, middle_chunks[1], state);

    let bottom_chunks = Layout::horizontal([
        Constraint::Percentage(33),
        Constraint::Percentage(34),
        Constraint::Percentage(33),
    ])
    .split(main_chunks[2]);

    draw_protocol_split(f, bottom_chunks[0], state);
    draw_top_destinations(f, bottom_chunks[1], state);
    draw_bytes_per_sec(f, bottom_chunks[2], state);
    draw_footer(f, main_chunks[3], main_chunks[4], state);
}

fn draw_feed(f: &mut Frame, area: Rect, state: &AppState) {
    let tag = filter_label(&state.display_filter);
    let status = if state.paused { " | PAUSED" } else { "" };
    let error_tag = state
        .capture_error
        .as_ref()
        .map_or(String::new(), |e| format!(" | ERR: {e}"));
    let title_left = format!(" Live Feed [{tag}]{status}{error_tag} ");

    let mut items: Vec<String> = state
        .feed_entries
        .iter()
        .filter(|(proto, _)| matches_display_filter(proto, &state.display_filter))
        .map(|(_, line)| line.clone())
        .collect();

    let visible_rows = area.height.saturating_sub(2) as usize;

    if state.feed_paused_scroll {
        items.push("".to_string());
        let max_scroll = items.len().saturating_sub(visible_rows);
        let actual_scroll = state.feed_scroll.min(max_scroll);
        let skip = max_scroll.saturating_sub(actual_scroll);
        
        let width = area.width.saturating_sub(2) as usize;
        let mut visible: Vec<ListItem> = items.into_iter().skip(skip).take(visible_rows).map(|s| {
            let trunc = unicode_truncate::UnicodeTruncateStr::unicode_truncate(s.as_str(), width).0;
            ListItem::new(trunc.to_string())
        }).collect();
        
        if !visible.is_empty() {
            let last_idx = visible.len() - 1;
            visible[last_idx] = ListItem::new("  \u{2193} Press [Space] to resume live scroll")
                .style(Style::default().fg(Color::Yellow));
        }

        let border_color = if state.focused_panel == Panel::Feed { Color::Yellow } else { Color::White };
        let block = Block::bordered()
            .title(title_left)
            .style(Style::default().fg(border_color).bg(Color::Black));

        let list = List::new(visible)
            .block(block)
            .style(Style::default().fg(Color::White));

        f.render_widget(list, area);
    } else {
        let skip = items.len().saturating_sub(visible_rows);
        let width = area.width.saturating_sub(2) as usize;
        let visible: Vec<ListItem> = items.into_iter().skip(skip).map(|s| {
            let trunc = unicode_truncate::UnicodeTruncateStr::unicode_truncate(s.as_str(), width).0;
            ListItem::new(trunc.to_string())
        }).collect();

        let border_color = if state.focused_panel == Panel::Feed { Color::Yellow } else { Color::White };
        let block = Block::bordered()
            .title(title_left)
            .style(Style::default().fg(border_color).bg(Color::Black));

        let list = List::new(visible)
            .block(block)
            .style(Style::default().fg(Color::White));

        f.render_widget(list, area);
    }
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
    let pad_top = (inner_height.saturating_sub(logo_height) / 2).saturating_sub(1);
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

fn draw_connections(f: &mut Frame, area: Rect, state: &AppState) {
    let mut sorted: Vec<_> = state.connections.iter().collect();
    sorted.sort_by(|a, b| (b.1).1.cmp(&(a.1).1));
    sorted.truncate(7);

    let items: Vec<ListItem> = sorted
        .iter()
        .map(|((src, dst, _port), (pkts, bytes, proc))| {
            let dst_label = display_ip(dst);
            let proc_name = proc.as_deref().unwrap_or("unknown");
                
                let org = if let Some(geo) = state.geo_cache.get(dst) {
                    format!(" [{}]", geo.org)
                } else if let Some(geo) = state.geo_cache.get(src) {
                    format!(" [{}]", geo.org)
                } else {
                    String::new()
                };

                let c = format!(
                    " {:<15} \u{2192} {:<21} \u{2014} {}{org} \u{2014} {} pkts, {}",
                    src.to_string(), dst_label, proc_name,
                    format_with_commas(*pkts),
                    format_bytes(*bytes)
                );
                
                let width = area.width.saturating_sub(2) as usize;
                let trunc = unicode_truncate::UnicodeTruncateStr::unicode_truncate(c.as_str(), width).0;
                ListItem::new(trunc.to_string())
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
        AlertFilter::External => "EXTERNAL",
        AlertFilter::Noise => "NOISE",
    };
    let title = format!(" Alerts [{tag}] ");
    
    let filtered_alerts: Vec<&Alert> = state
        .alerts
        .iter()
        .filter(|a| matches_alert_filter(a, &state.alert_filter))
        .collect();

    let visible_rows = area.height.saturating_sub(2) as usize;
    
    let mut items: Vec<ListItem> = if filtered_alerts.is_empty() {
        vec![ListItem::new(format!(" No alerts matching filter [{tag}]"))
            .style(Style::default().fg(Color::DarkGray))]
    } else {
        let max_scroll = filtered_alerts.len().saturating_sub(visible_rows);
        let actual_scroll = state.alert_scroll.min(max_scroll);
        let skip = if state.alert_paused_scroll { actual_scroll } else { 0 };
        
        filtered_alerts
            .iter()
            .skip(skip)
            .take(visible_rows)
            .map(|a| {
                let ts = a.timestamp.format("%H:%M:%S");
                let (icon, color) = match a.level {
                    AlertLevel::Warn => ("\u{26A0}", Color::Yellow),
                    AlertLevel::Info => ("\u{2139}", Color::Cyan),
                };
                
                let msg = a.message.clone();
                let c = format!(" [{ts}] {icon}  {msg}");
                let width = area.width.saturating_sub(2) as usize;
                let trunc = unicode_truncate::UnicodeTruncateStr::unicode_truncate(c.as_str(), width).0;
                ListItem::new(trunc.to_string())
                    .style(Style::default().fg(color))
            })
            .collect()
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

    let halves = Layout::horizontal([
        Constraint::Percentage(55),
        Constraint::Percentage(45),
    ])
    .split(inner);

    let total = state.total_packets.max(1) as f64;
    let tcp_pct = (state.tcp_count as f64 / total * 100.0) as u64;
    let udp_pct = (state.udp_count as f64 / total * 100.0) as u64;
    let icmp_pct = (state.icmp_count as f64 / total * 100.0) as u64;

    let bar_w = halves[0].width.saturating_sub(2) / 3;
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
        .bar_width(bar_w.max(1))
        .bar_gap(1)
        .max(100)
        .bar_style(Style::default().fg(Color::Cyan))
        .value_style(Style::default().fg(Color::White))
        .label_style(Style::default().fg(Color::White));

    f.render_widget(chart, halves[0]);

    let uptime = format_uptime(state.start_time.elapsed());
    let total_str = format_with_commas(state.total_packets);
    let avg_size = if state.total_packets > 0 {
        format_bytes(state.total_bytes / state.total_packets)
    } else {
        "0B".into()
    };
    let pps = format_with_commas(state.packets_per_sec);

    let stats = format!(
        " Total:    {total_str}\n Uptime:   {uptime}\n Avg Size: {avg_size}\n Pkts/sec: {pps}"
    );

    let paragraph = Paragraph::new(stats)
        .style(Style::default().fg(Color::White));
    f.render_widget(paragraph, halves[1]);
}

fn draw_top_destinations(f: &mut Frame, area: Rect, state: &AppState) {
    let mut sorted: Vec<_> = state.dest_bytes.iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(a.1));
    sorted.truncate(5);

    let items: Vec<ListItem> = sorted
        .iter()
        .enumerate()
        .map(|(i, (ip, bytes))| {
            let label = display_ip(ip);
            ListItem::new(format!(
                " {}. {:<21} {:>8}",
                i + 1,
                label,
                format_bytes(**bytes),
            ))
        })
        .collect();

    let block = Block::bordered()
        .title(" Top Destinations ")
        .style(Style::default().fg(Color::White).bg(Color::Black));

    let list = List::new(items)
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
                        " Capturing on {}  |  {} packets  |  {}/sec",
                        state.interface_name,
                        format_with_commas(state.total_packets),
                        format_bytes(last_bps),
                    )
                }
            } else {
                format!(
                    " Capturing on {}  |  {} packets  |  {}/sec",
                    state.interface_name,
                    format_with_commas(state.total_packets),
                    format_bytes(last_bps),
                )
            };
            
            let f_key_text = if state.focused_panel == Panel::Feed {
                let tag = filter_label(&state.display_filter);
                format!("[F] Protocol: {}", tag)
            } else {
                let tag = match state.alert_filter {
                    AlertFilter::All => "ALL",
                    AlertFilter::Suspicious => "SUSPICIOUS",
                    AlertFilter::External => "EXTERNAL",
                    AlertFilter::Noise => "NOISE",
                };
                format!("[F] Alerts: {}", tag)
            };

            let k = format!(" [Tab] Switch Panel  [\u{2191}\u{2193}] Scroll  [Space] Resume  [E] Export  {}  [W] Whitelist IP  [Q] Quit ", f_key_text);
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
