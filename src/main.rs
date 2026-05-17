mod capture;
mod display;
mod logger;
mod packet;
mod geoip;
#[cfg(target_os = "windows")]
mod process;
mod discovery;
mod oui;
mod dhcp;
mod dhcp_probe;

use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use clap::Parser;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, DisableMouseCapture, EnableMouseCapture, MouseEventKind};
use ratatui::crossterm::execute;

use display::{AppState, InputMode};
use packet::ProtocolFilter;

pub const APP_VERSION: &str = "2.0.0";

#[derive(Parser, Debug)]
#[command(name = "vora-recon", about = "CLI packet sniffer with TUI dashboard")]
struct Args {
    /// Network interface name to capture on
    #[arg(short, long)]
    interface: Option<String>,

    /// Stop after n packets
    #[arg(short, long)]
    limit: Option<u64>,

    /// Write packets to a JSONL file
    #[arg(short, long)]
    output: Option<String>,
}



fn main() -> Result<(), Box<dyn std::error::Error>> {
    eprintln!("DEBUG: Sonos RINCON Regex Pattern: ^[\\d\\.]+\\s+-\\s+(.+?)\\s+-\\s+RINCON_[0-9A-Fa-f]+$");
    let args = Args::parse();
    
    let (iface_name, resolved_iface_name) = match args.interface.clone() {
        Some(name) => {
            let mut resolved = name.clone();
            for iface in pnet::datalink::interfaces() {
                if iface.name == name || name.contains(&iface.name) {
                    resolved = iface.description.clone();
                    if resolved.is_empty() {
                        resolved = iface.name.clone();
                    }
                    break;
                }
            }
            (name, resolved)
        }
        None => {
            let mut fallback_iface = None;
            let mut best_iface = None;
            
            for iface in pnet::datalink::interfaces() {
                if iface.is_loopback() || iface.name.contains("Loopback") || !iface.name.starts_with("\\Device\\NPF_") {
                    continue;
                }
                
                if fallback_iface.is_none() {
                    fallback_iface = Some(iface.clone());
                }

                let desc_lower = iface.description.to_lowercase();
                let is_wifi = desc_lower.contains("wi-fi") || desc_lower.contains("wireless");
                let has_ip = !iface.ips.is_empty();

                if is_wifi && has_ip {
                    best_iface = Some(iface);
                    break;
                }
            }

            let selected = best_iface.or(fallback_iface);

            if let Some(iface) = selected {
                eprintln!("Auto-selected interface: {}", iface.name);
                let resolved = if iface.description.is_empty() {
                    iface.name.clone()
                } else {
                    iface.description.clone()
                };
                (iface.name.clone(), resolved)
            } else {
                eprintln!("No active network interface found. Use --interface to specify one manually.");
                std::process::exit(1);
            }
        }
    };

    let (tx, rx) = mpsc::channel();
    let (passive_tx, passive_rx) = mpsc::channel();
    let iface = iface_name;
    thread::spawn(move || {
        capture::start_capture(&iface, &ProtocolFilter::All, tx, Some(passive_tx));
    });

    let mut log = args.output.as_ref().map(|path| {
        logger::Logger::new(path).expect("Failed to open log file")
    });

    // Terminal setup
    ratatui::crossterm::terminal::enable_raw_mode()?;
    let mut stdout = std::io::stdout();
    execute!(stdout, ratatui::crossterm::terminal::EnterAlternateScreen, EnableMouseCapture)?;
    let backend = ratatui::backend::CrosstermBackend::new(stdout);
    let mut terminal = ratatui::Terminal::new(backend)?;

    let result = run_app(&mut terminal, &args, rx, passive_rx, &mut log, resolved_iface_name);
    execute!(std::io::stdout(), DisableMouseCapture).ok();
    ratatui::restore();
    result
}

fn run_app(
    terminal: &mut ratatui::Terminal<ratatui::backend::CrosstermBackend<std::io::Stdout>>,
    args: &Args,
    rx: mpsc::Receiver<packet::CapturedPacket>,
    passive_rx: mpsc::Receiver<(String, std::net::IpAddr)>,
    log: &mut Option<logger::Logger>,
    interface_name_label: String,
) -> Result<(), Box<dyn std::error::Error>> {
    // Detect current network (WiFi SSID) for baseline storage
    let current_network = {
        #[cfg(windows)]
        {
            std::process::Command::new("powershell")
                .args(["-NoProfile", "-Command", "(Get-NetConnectionProfile).Name"])
                .output()
                .ok()
                .and_then(|out| {
                    let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    if stdout.is_empty() { None } else { Some(stdout) }
                })
                .unwrap_or_else(|| interface_name_label.clone())
        }
        #[cfg(not(windows))]
        {
            interface_name_label.clone()
        }
    };

    let mut state = AppState::new(interface_name_label.clone(), current_network.clone());

    // Load device baseline from previous session so devices persist across restarts
    {
        let baseline = discovery::load_baseline(&current_network);
        if !baseline.is_empty() {
            if let Ok(mut active) = state.active_discovery.lock() {
                *active = baseline;
            }
            state.scan_has_run = true;
        }
    }
    
    // Warm up OUI database to prevent lag during first discovery scan
    let _ = crate::oui::get_vendor("00:00:00:00:00:00");
    
    // GeoIP setup
    let (geo_tx, geo_rx) = mpsc::channel();
    let (geo_res_tx, geo_res_rx) = mpsc::channel();
    geoip::start_geo_thread(geo_rx, geo_res_tx);
    
    // Process enrichment setup
    let process_cache = state.process_cache.clone();
    std::thread::spawn(move || {
        loop {
            crate::process::refresh_process_cache(process_cache.clone());
            std::thread::sleep(std::time::Duration::from_millis(1000));
        }
    });

    // Device Discovery setup
    let active_discovery = state.active_discovery.clone();
    let passive_discovery = state.passive_discovery.clone();
    let discovery_metadata = state.device_metadata.clone();
    let (disco_tx, disco_rx) = mpsc::channel();
    let (disco_status_tx, disco_status_rx) = mpsc::channel();
    let (disco_alert_tx, disco_alert_rx) = mpsc::channel();
    discovery::start_discovery_thread(passive_discovery, active_discovery, discovery_metadata, disco_rx, disco_status_tx, disco_alert_tx, interface_name_label.clone(), current_network);
        
    let mut count: u64 = 0;
    let mut channel_alive = true;
    let mut last_render = Instant::now();

    loop {
        state.tick();

        // Auto-Scan Logic (every 180s) - Only runs if user has initiated a scan once
        if state.auto_scan_enabled && state.scan_has_run && state.last_auto_scan.elapsed() >= Duration::from_secs(180) {
            state.last_auto_scan = Instant::now();
            let _ = disco_tx.send(discovery::DiscoverySignal::ScanNow);
        }

        // Drain GeoIP results
        while let Ok((ip, geo_opt)) = geo_res_rx.try_recv() {
            state.geo_in_flight = state.geo_in_flight.saturating_sub(1);
            if let Some(geo) = geo_opt {
                state.geo_cache.insert(ip, geo);
            } else {
                // Insert a dummy to skip re-querying failed IPs
                state.geo_cache.insert(ip, geoip::GeoInfo {
                    country_code: "??".into(),
                    city: None,
                    region: None,
                    org: "Unknown".into(),
                });
            }
        }

        // Drain Discovery status updates
        while let Ok(status) = disco_status_rx.try_recv() {
            state.discovery_status = status;
            state.last_discovery_time = chrono::Local::now().format("%H:%M:%S").to_string();
        }

        // Drain Passive Discovery from Capture thread (silently enrichment passive_discovery)
        while let Ok((mac, ip)) = passive_rx.try_recv() {
            // Filter: only local/private IPs allowed in discovery maps
            if !display::is_local_ip(&ip) { continue; }

            if let Ok(mut passive) = state.passive_discovery.lock() {
                if !passive.contains_key(&ip) {
                    let vendor = crate::oui::get_vendor(&mac);
                    passive.insert(ip, discovery::DeviceInfo {
                        mac,
                        vendor,
                        hostname: "—".to_string(),
                        miss_count: 0,
                        last_seen: std::time::Instant::now(),
                        last_seen_unix: crate::discovery::default_unix_now(),
                    });
                } else if let Some(entry) = passive.get_mut(&ip) {
                    // Reset aging counter and update last seen
                    entry.miss_count = 0;
                    entry.last_seen = std::time::Instant::now();
                    entry.last_seen_unix = crate::discovery::default_unix_now();
                }
            }
        }

        // Drain Discovery alerts
        while let Ok(alert_msg) = disco_alert_rx.try_recv() {
            state.push_alert(display::Alert {
                timestamp: chrono::Local::now(),
                message: alert_msg,
                level: display::AlertLevel::Warn,
                tier: display::AlertTier::Suspicious,
                remote_ip: None,
                process: None,
                reason: display::AlertReason::SuspiciousFlags,
            });
        }

        // Drain pending packets from the channel
        if channel_alive && !state.limit_reached {
            let mut packets_this_tick = 0;
            loop {
                // Limit the number of packets we process "at once" to ensure 
                // the UI remains prioritized under extreme load.
                if packets_this_tick >= 1000 {
                    break;
                }

                match rx.try_recv() {
                    Ok(pkt) => {
                        // Resolve process name from source port (with caching)
                        // Logger always writes regardless of pause/filter
                        if let Some(ref mut logger) = log {
                            let _ = logger.log_packet(&pkt);
                        }

                        if !state.paused {
                            // Forward to Geo IP if unseen and public
                            for ip in &[pkt.dst_ip, pkt.src_ip] {
                                if !state.geo_cache.contains_key(ip) 
                                   && state.geo_in_flight < 5 
                                   && is_public_ip_heuristic(ip) {
                                    state.geo_in_flight += 1;
                                    // we pre-insert a dummy so we don't spam the thread with the same IP while it's parsing
                                    state.geo_cache.insert(*ip, geoip::GeoInfo {
                                        country_code: "...".into(),
                                        city: None,
                                        region: None,
                                        org: "Looking up...".into(),
                                    });
                                    let _ = geo_tx.send(*ip);
                                }
                            }

                            state.ingest_packet(&pkt);

                // DHCP fingerprint ingestion — runs after ingest_packet
                if let Some(ref fp) = pkt.dhcp_fingerprint {
                    // DHCP Discover uses src_ip=0.0.0.0 — skip those, we can't attribute them.
                    // DHCP Request uses the client's actual IP — use those.
                    if let std::net::IpAddr::V4(v4) = pkt.src_ip {
                        if v4.octets() != [0, 0, 0, 0] {
                            // Store raw fingerprint for display in node detail popup
                            state.dhcp_fingerprints.insert(pkt.src_ip, fp.clone());

                            // Immediately classify and insert OS tag at confidence 200
                            // (higher than passive TTL/window which caps at 255 but starts at 1)
                            if let Some((tag, _desc)) = crate::dhcp::classify_dhcp(fp) {
                                // Only overwrite if existing confidence is below 200
                                let existing_conf = state.os_fingerprints
                                    .get(&pkt.src_ip)
                                    .map(|(_, c)| *c)
                                    .unwrap_or(0);
                                if existing_conf < 200 {
                                    state.os_fingerprints.insert(pkt.src_ip, (tag, 200));
                                }
                            }
                        }
                    }
                }
                        }

                        count += 1;
                        packets_this_tick += 1;
                        if let Some(limit) = args.limit {
                            if count >= limit {
                                state.limit_reached = true;
                                break;
                            }
                        }
                    }
                    Err(mpsc::TryRecvError::Empty) => break,
                    Err(mpsc::TryRecvError::Disconnected) => {
                        channel_alive = false;
                        state.capture_error =
                            Some("Capture thread exited (check interface name / admin privileges)".into());
                        break;
                    }
                }
            }
        }

        // --- Throttled Rendering ---
        // Render at most 20 times per second (50ms interval)
        if last_render.elapsed() >= Duration::from_millis(50) {
            terminal.draw(|f| display::draw_ui(f, &state))?;
            last_render = Instant::now();
        }

        // --- Event Draining ---
        // Drain *all* pending events
        while event::poll(Duration::from_millis(0))? {
            match event::read()? {
                Event::Key(key) => {
                    if key.kind == KeyEventKind::Press {
                        match state.input_mode {
                            InputMode::Normal => match key.code {

                                KeyCode::Char('p') | KeyCode::Char('P') => {
                                    state.paused = !state.paused;
                                }
                                KeyCode::Char('f') | KeyCode::Char('F') => {
                                    state.cycle_filter();
                                }
                                KeyCode::Char('c') | KeyCode::Char('C') => {
                                    state.clear_alerts();
                                }
                                KeyCode::Char('g') | KeyCode::Char('G') => {
                                    state.show_graph = !state.show_graph;
                                }
                                KeyCode::Char('e') | KeyCode::Char('E') => {
                                    let base_path = std::env::current_exe()
                                        .ok()
                                        .and_then(|p| p.parent().map(|p| p.to_path_buf()))
                                        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| std::path::PathBuf::from(".")));
                                    let dir = base_path.join("Session Reports");
                                    let _ = std::fs::create_dir_all(&dir);
                                    let dir_str = dir.to_string_lossy();
                                    let date_str = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
                                    state.input_buffer = format!("{}\\VORA_Session_Report_{}.txt", dir_str, date_str);
                                    state.input_mode = InputMode::Exporting;
                                }
                                KeyCode::Char('w') | KeyCode::Char('W') => {
                                    state.input_buffer.clear();
                                    state.input_mode = InputMode::Whitelisting;
                                }
                                KeyCode::Char('i') | KeyCode::Char('I') => {
                                    state.ip_compressed = !state.ip_compressed;
                                    let msg = if state.ip_compressed { "IP Compression: ON" } else { "IP Compression: OFF" };
                                    state.set_footer_message(msg.into());
                                }
                                KeyCode::Char(' ') => state.resume_scroll(),
                                KeyCode::Tab => state.switch_panel(),
                                KeyCode::Up => state.scroll_up(),
                                KeyCode::Down => state.scroll_down(),
                                KeyCode::Char('a') | KeyCode::Char('A') => {
                                    state.auto_scan_enabled = !state.auto_scan_enabled;
                                    let msg = if state.auto_scan_enabled { "Auto-Rescan: ENABLED (3m)" } else { "Auto-Rescan: PAUSED" };
                                    state.set_footer_message(msg.into());
                                }
                                KeyCode::Char('s') | KeyCode::Char('S') if key.modifiers.contains(event::KeyModifiers::ALT) => {
                                    state.scan_has_run = true;
                                    state.last_auto_scan = std::time::Instant::now();
                                    let _ = disco_tx.send(discovery::DiscoverySignal::ScanNow);
                                    state.set_footer_message("Manual Scan Triggered...".into());
                                }
                                KeyCode::Char('n') | KeyCode::Char('N') => {
                                    if state.show_graph {
                                        let mut ips: Vec<_> = state.graph_nodes.keys().copied().collect();
                                        ips.sort();
                                        if !ips.is_empty() {
                                            if let Some(current) = state.selected_node {
                                                if let Some(idx) = ips.iter().position(|&ip| ip == current) {
                                                    state.selected_node = Some(ips[(idx + 1) % ips.len()]);
                                                } else {
                                                    state.selected_node = Some(ips[0]);
                                                }
                                            } else {
                                                state.selected_node = Some(ips[0]);
                                            }
                                        }
                                    }
                                }
                                KeyCode::Esc => {
                                    if state.show_graph {
                                        state.selected_node = None;
                                    }
                                }
                                _ => {}
                            },
                            InputMode::Exporting | InputMode::Whitelisting => match key.code {
                                KeyCode::Esc => {
                                    state.input_mode = InputMode::Normal;
                                    state.input_buffer.clear();
                                }
                                KeyCode::Enter => {
                                    if state.input_mode == InputMode::Exporting {
                                        let mut path = state.input_buffer.clone();
                                        if std::path::Path::new(&path).is_dir() {
                                            let date_str = chrono::Local::now().format("%Y-%m-%d_%H-%M-%S").to_string();
                                            let file_name = format!("VORA_Session_Report_{}.txt", date_str);
                                            path = std::path::Path::new(&path).join(file_name).to_string_lossy().to_string();
                                        }
                                        match export_report(&state, &path) {
                                            Ok(_) => {
                                                state.set_footer_message(format!("Report saved to {}", path));
                                                
                                                // Automatically open the file location (Windows only)
                                                #[cfg(windows)]
                                                {
                                                    if let Some(parent) = std::path::Path::new(&path).parent() {
                                                        let folder = parent.to_string_lossy().replace("\\\\?\\", "");
                                                        let _ = std::process::Command::new("explorer.exe")
                                                            .arg(&folder)
                                                            .spawn();
                                                    }
                                                }
                                            },
                                            Err(e) => state.set_footer_message(format!("Failed to save report: {}", e)),
                                        }
                                    } else {
                                        if let Ok(ip) = state.input_buffer.parse::<std::net::IpAddr>() {
                                            state.whitelist_ip(ip);
                                            state.set_footer_message(format!("Whitelisted IP: {}", ip));
                                        } else {
                                            state.set_footer_message("Invalid IP address format".to_string());
                                        }
                                    }
                                    state.input_mode = InputMode::Normal;
                                    state.input_buffer.clear();
                                }
                                KeyCode::Char('a') | KeyCode::Char('A') | 
                                KeyCode::Char('u') | KeyCode::Char('U') | 
                                KeyCode::Char('w') | KeyCode::Char('W') | 
                                KeyCode::Char('x') | KeyCode::Char('X') 
                                if key.modifiers.contains(event::KeyModifiers::CONTROL) => {
                                    state.input_buffer.clear();
                                }
                                KeyCode::Backspace => {
                                    state.input_buffer.pop();
                                }
                                KeyCode::Char(c) => {
                                    state.input_buffer.push(c);
                                }
                                _ => {}
                            },
                        }
                    }
                }
                Event::Mouse(mouse) => match mouse.kind {
                    MouseEventKind::ScrollUp => state.scroll_up(),
                    MouseEventKind::ScrollDown => state.scroll_down(),
                    _ => {}
                },
                _ => {}
            }
        }
        
        // Brief sleep to avoid 100% CPU on a single core during low traffic
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn is_public_ip_heuristic(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            let o = v4.octets();
            !matches!(
                o,
                [192, 168, _, _]
                    | [10, _, _, _]
                    | [172, 16..=31, _, _]
                    | [127, _, _, _]
                    | [224..=239, _, _, _]
                    | [255, 255, 255, 255]
            )
        }
        _ => false, // Simplification for V6 for now
    }
}

fn export_report(state: &AppState, path: &str) -> std::io::Result<()> {
    use std::io::Write;
    let mut file = std::fs::File::create(path)?;

    let duration = state.start_time.elapsed().as_secs();
    let duration_fmt = if duration > 3600 {
        format!("{}h {}m {}s", duration / 3600, (duration % 3600) / 60, duration % 60)
    } else if duration > 60 {
        format!("{}m {}s", duration / 60, duration % 60)
    } else {
        format!("{}s", duration)
    };

    writeln!(file, "================================================================")?;
    writeln!(file, "                VORA-RECON SESSION REPORT")?;
    writeln!(file, "================================================================")?;
    writeln!(file, "Version:      {}", crate::APP_VERSION)?;
    writeln!(file, "Timestamp:    {}", chrono::Local::now().format("%Y-%m-%d %H:%M:%S"))?;
    writeln!(file, "Interface:    {}", state.interface_name)?;
    writeln!(file, "Network:      {}", state.current_network)?;
    writeln!(file, "Duration:     {}", duration_fmt)?;
    writeln!(file, "----------------------------------------------------------------")?;

    // --- 1. Security Summary ---
    writeln!(file, "\n[ SECURITY POSTURE SUMMARY ]")?;
    writeln!(file, "Total Alerts:      {}", state.total_alerts)?;
    writeln!(file, "  - Suspicious:    {}", state.total_alerts_suspicious)?;
    writeln!(file, "  - Behavioral:    {}", state.total_alerts_behavioral)?;
    writeln!(file, "  - External:      {}", state.total_alerts_external)?;
    writeln!(file, "  - Noise/Misc:    {}", state.total_alerts_noise)?;
    
    // OS Distribution
    use std::collections::HashMap;
    let mut os_counts: HashMap<String, usize> = HashMap::new();
    for ip in state.unique_ips.iter().filter(|ip| display::is_private_ip(ip)) {
        let tag = state.get_resolved_os_tag(ip);
        if tag != "[?]" {
            *os_counts.entry(tag).or_insert(0) += 1;
        }
    }
    if !os_counts.is_empty() {
        write!(file, "OS Distribution:  ")?;
        for (tag, count) in os_counts {
            write!(file, "{} ({})  ", tag, count)?;
        }
        writeln!(file)?;
    }

    // --- 2. Traffic Summary ---
    writeln!(file, "\n[ TRAFFIC STATISTICS ]")?;
    writeln!(file, "Total Packets:     {}", state.total_packets)?;
    writeln!(file, "Total Data:        {}", format_size(state.total_bytes))?;
    let avg_pps = if duration > 0 { state.total_packets / duration } else { 0 };
    let avg_bps = if duration > 0 { state.total_bytes / duration } else { 0 };
    writeln!(file, "Average Throughput: {} pkts/s | {}/s", avg_pps, format_size(avg_bps))?;
    
    writeln!(file, "\nProtocol Breakdown:")?;
    let tcp_pct = if state.total_packets > 0 { (state.tcp_count as f64 / state.total_packets as f64) * 100.0 } else { 0.0 };
    let udp_pct = if state.total_packets > 0 { (state.udp_count as f64 / state.total_packets as f64) * 100.0 } else { 0.0 };
    let icmp_pct = if state.total_packets > 0 { (state.icmp_count as f64 / state.total_packets as f64) * 100.0 } else { 0.0 };
    writeln!(file, "  - TCP:           {} ({:.1}%)", state.tcp_count, tcp_pct)?;
    writeln!(file, "  - UDP:           {} ({:.1}%)", state.udp_count, udp_pct)?;
    writeln!(file, "  - ICMP:          {} ({:.1}%)", state.icmp_count, icmp_pct)?;

    let devices = state.active_discovery.lock().unwrap();
    if !devices.is_empty() {
        writeln!(file, "\n[ LOCAL NETWORK INVENTORY ]")?;
        writeln!(file, "{:<16} | {:<30} | {:<25} | {:<18} | {:<8}", "IP Address", "Hostname", "OUI Vendor", "MAC Address", "OS")?;
        writeln!(file, "-----------------|--------------------------------|---------------------------|--------------------|---------")?;
        let mut dev_vec: Vec<_> = devices.iter().collect();
        dev_vec.sort_by_key(|(ip, _)| *ip);
        let meta_guard = state.device_metadata.lock().ok();
        for (ip, dev) in &dev_vec {
            let os_tag = state.get_resolved_os_tag(ip);
            
            // Priority chain for report hostname:
            // 1. Cleaned discovery hostname
            // 2. Metadata model/friendly_name (using already-locked meta_guard)
            // 3. —
            let display_host = {
                let from_discovery = display::clean_hostname(&dev.hostname);
                if from_discovery != "\u{2014}" && from_discovery != "Resolving..." && !from_discovery.is_empty() {
                    from_discovery
                } else if let Some(ref meta) = meta_guard {
                    // meta_guard is already locked — no try_lock needed
                    meta.get(ip)
                        .and_then(|m| {
                            m.get("model")
                             .or_else(|| m.get("friendly_name"))
                             .or_else(|| m.get("model_name"))
                        })
                        .map(|s| display::clean_hostname(s))
                        .filter(|s| s != "\u{2014}" && !s.is_empty())
                        .unwrap_or_else(|| "\u{2014}".to_string())
                } else {
                    "\u{2014}".to_string()
                }
            };
            
            writeln!(file, "{:<16} | {:<30} | {:<25} | {:<18} | {:<8}", 
                ip.to_string(), 
                display_host,
                dev.vendor, 
                dev.mac, 
                os_tag
            )?;
        }

        // Device Metadata section (mDNS TXT + SSDP/UPnP enrichment)
        if let Some(ref meta) = meta_guard {
            let enriched: Vec<_> = dev_vec.iter()
                .filter_map(|(ip, _)| meta.get(ip).map(|m| (*ip, m)))
                .collect();
            if !enriched.is_empty() {
                writeln!(file, "\n[ DEVICE METADATA (mDNS/SSDP) ]")?;
                writeln!(file, "{:<16} | {:<28} | {:<20} | {:<20} | {}", "IP Address", "Model", "Firmware", "Services", "Extra")?;
                writeln!(file, "-----------------|------------------------------|----------------------|----------------------|------")?;
                for (ip, dev_meta) in enriched {
                    let model = dev_meta.get("model")
                        .or_else(|| dev_meta.get("friendly_name"))
                        .or_else(|| dev_meta.get("model_name"))
                        .cloned().unwrap_or_else(|| "—".to_string());
                    let firmware = dev_meta.get("firmware")
                        .or_else(|| dev_meta.get("os_version"))
                        .cloned().unwrap_or_else(|| "—".to_string());
                    let services = dev_meta.get("services")
                        .cloned().unwrap_or_else(|| "—".to_string());
                    let extra = dev_meta.get("manufacturer")
                        .or_else(|| dev_meta.get("serial"))
                        .or_else(|| dev_meta.get("homekit_category"))
                        .cloned().unwrap_or_else(|| "—".to_string());
                    writeln!(file, "{:<16} | {:<28} | {:<20} | {:<20} | {}", 
                        ip.to_string(), model, firmware, services, extra)?;
                }
            }
        }
    }
    drop(devices);

    // --- 4. Top External Destinations ---
    writeln!(file, "\n[ TOP EXTERNAL DESTINATIONS ]")?;
    let mut dest_vec: Vec<_> = state.dest_bytes.iter()
        .filter(|(ip, _)| !is_private_ip(ip))
        .collect();
    dest_vec.sort_by(|a, b| b.1.cmp(a.1));
    
    if dest_vec.is_empty() {
        writeln!(file, "No external traffic recorded.")?;
    } else {
        writeln!(file, "{:<16} | {:<40} | {:<10} | {:<40}", "IP Address", "Organization", "Bytes", "Domain/Hint")?;
        writeln!(file, "-----------------|------------------------------------------|------------|-----------------------------------------")?;
        for (ip, bytes) in dest_vec.into_iter().take(10) {
            let geo = state.geo_cache.get(ip);
            let org = geo.map(|g| g.org.as_str()).unwrap_or("Unknown");
            let domain = state.dns_cache.get(ip).cloned().unwrap_or_else(|| "---".to_string());
            writeln!(file, "{:<16} | {:<40} | {:<10} | {:<40}", 
                ip.to_string(), 
                org, 
                format_size(*bytes),
                domain
            )?;
        }
    }

    // --- 5. Top Connections (Talkers) ---
    writeln!(file, "\n[ TOP ACTIVE CONNECTIONS ]")?;
    let mut conn_vec: Vec<_> = state.connections.iter().collect();
    conn_vec.sort_by(|a, b| (b.1).1.cmp(&(a.1).1));
    
    writeln!(file, "{:<15} -> {:<15} | {:<50} | {:<15} | {:<10}", "Source", "Destination", "Process", "Data", "Duration")?;
    writeln!(file, "----------------|-----------------|----------------------------------------------------|-----------------|-----------")?;
    for ((src, dst, _), (pkts, bytes, proc_name, duration)) in conn_vec.into_iter().take(15) {
        let p_name = proc_name.as_deref().unwrap_or("unknown");
        let dur_fmt = format!("{:.1}s", duration.as_secs_f32());
        writeln!(file, "{:<15} -> {:<15} | {:<50} | {:<15} | {:<10}", 
            src.to_string(), 
            dst.to_string(), 
            p_name, 
            format!("{} ({}p)", format_size(*bytes), pkts),
            dur_fmt
        )?;
    }

    // --- 6. Top Resolved Domains ---
    let mut domains: HashMap<String, usize> = HashMap::new();
    for domain in state.dns_cache.values() {
        *domains.entry(domain.clone()).or_insert(0) += 1;
    }
    if !domains.is_empty() {
        writeln!(file, "\n[ TOP RESOLVED DOMAINS ]")?;
        let mut dom_vec: Vec<_> = domains.into_iter().collect();
        dom_vec.sort_by(|a, b| b.1.cmp(&a.1));
        for (domain, count) in dom_vec.into_iter().take(10) {
            writeln!(file, "{:<40} ({} hits)", domain, count)?;
        }
    }

    // --- 7. Security Alert Log (Top 50) ---
    writeln!(file, "\n[ SECURITY ALERT LOG (RECENT 50) ]")?;
    let mut all_alerts: Vec<&display::Alert> = state.alerts_suspicious.iter()
        .chain(state.alerts_behavioral.iter())
        .chain(state.alerts_external.iter())
        .collect();
    all_alerts.sort_by(|a, b| b.timestamp.cmp(&a.timestamp));

    if all_alerts.is_empty() {
        writeln!(file, "No security alerts generated.")?;
    } else {
        for alert in all_alerts.iter().take(50) {
            let prefix = match alert.tier {
                display::AlertTier::Suspicious => "!!",
                display::AlertTier::Behavioral => "* ",
                display::AlertTier::External   => "> ",
                display::AlertTier::Noise      => ". ",
            };
            writeln!(file, "{} [{}] {}", prefix, alert.timestamp.format("%H:%M:%S"), alert.message)?;
        }
    }

    if !state.whitelist.is_empty() {
        writeln!(file, "\n[ WHITELISTED ADDRESSES ]")?;
        for ip in &state.whitelist {
            writeln!(file, "  - {}", ip)?;
        }
    }

    Ok(())
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1024 * 1024 * 1024 {
        format!("{:.2} GB", bytes as f64 / (1024.0 * 1024.0 * 1024.0))
    } else if bytes >= 1024 * 1024 {
        format!("{:.2} MB", bytes as f64 / (1024.0 * 1024.0))
    } else if bytes >= 1024 {
        format!("{:.2} KB", bytes as f64 / 1024.0)
    } else {
        format!("{} B", bytes)
    }
}

fn is_private_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => {
            v4.is_private() || v4.is_loopback() || v4.is_link_local() || v4.is_multicast() || v4.is_broadcast()
        }
        std::net::IpAddr::V6(v6) => v6.is_loopback() || v6.is_multicast(),
    }
}

