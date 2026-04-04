mod capture;
mod display;
mod logger;
mod packet;
mod geoip;
#[cfg(target_os = "windows")]
mod process;

use std::sync::mpsc;
use std::thread;
use std::time::Duration;

use clap::Parser;
use ratatui::crossterm::event::{self, Event, KeyCode, KeyEventKind, DisableMouseCapture};
use ratatui::crossterm::execute;

use display::{AppState, InputMode};
use packet::ProtocolFilter;

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

#[cfg(target_os = "windows")]
unsafe extern "system" fn console_ctrl_handler(ctrl_type: u32) -> winapi::shared::minwindef::BOOL {
    if ctrl_type == winapi::um::wincon::CTRL_CLOSE_EVENT || ctrl_type == winapi::um::wincon::CTRL_C_EVENT {
        execute!(std::io::stdout(), DisableMouseCapture).ok();
        use winapi::um::winuser::{SetCursor, LoadCursorW, IDC_ARROW};
        use std::ptr::null_mut;
        SetCursor(LoadCursorW(null_mut(), IDC_ARROW));
        ratatui::restore();
        std::process::exit(0);
    }
    winapi::shared::minwindef::FALSE
}

#[cfg(target_os = "windows")]
fn setup_console_handler() {
    unsafe {
        winapi::um::consoleapi::SetConsoleCtrlHandler(Some(console_ctrl_handler), winapi::shared::minwindef::TRUE);
    }
}

#[cfg(target_os = "windows")]
fn maximize_console() {
    std::thread::spawn(|| {
        std::thread::sleep(std::time::Duration::from_millis(100));
        unsafe {
            use winapi::um::winuser::{SetCursor, LoadCursorW, IDC_ARROW};
            use std::ptr::null_mut;
            SetCursor(LoadCursorW(null_mut(), IDC_ARROW));

            let hwnd = winapi::um::wincon::GetConsoleWindow();
            if !hwnd.is_null() {
                winapi::um::winuser::ShowWindow(hwnd, winapi::um::winuser::SW_MAXIMIZE);
                winapi::um::winuser::UpdateWindow(hwnd);
            }
        }
    });
}

#[cfg(target_os = "windows")]
fn fix_console_mode() {
    unsafe {
        let handle = winapi::um::processenv::GetStdHandle(winapi::um::winbase::STD_INPUT_HANDLE);
        if handle != winapi::um::handleapi::INVALID_HANDLE_VALUE {
            let mut mode: u32 = 0;
            if winapi::um::consoleapi::GetConsoleMode(handle, &mut mode) != 0 {
                mode &= !winapi::um::wincon::ENABLE_QUICK_EDIT_MODE;
                mode |= winapi::um::wincon::ENABLE_EXTENDED_FLAGS;
                mode &= !winapi::um::wincon::ENABLE_WINDOW_INPUT;
                winapi::um::consoleapi::SetConsoleMode(handle, mode);
            }
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
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
    let iface = iface_name;
    thread::spawn(move || {
        capture::start_capture(&iface, &ProtocolFilter::All, tx);
    });

    let mut log = args.output.as_ref().map(|path| {
        logger::Logger::new(path).expect("Failed to open log file")
    });

    let mut terminal = ratatui::init();
    execute!(std::io::stdout(), DisableMouseCapture).ok();

    #[cfg(target_os = "windows")]
    unsafe {
        use winapi::um::winuser::{SetCursor, LoadCursorW, IDC_ARROW};
        use std::ptr::null_mut;
        SetCursor(LoadCursorW(null_mut(), IDC_ARROW));
    }

    #[cfg(target_os = "windows")]
    {
        setup_console_handler();
        maximize_console();
        fix_console_mode();
    }

    let result = run_app(&mut terminal, &args, rx, &mut log, resolved_iface_name);
    execute!(std::io::stdout(), DisableMouseCapture).ok();
    ratatui::restore();
    result
}

fn run_app(
    terminal: &mut ratatui::DefaultTerminal,
    args: &Args,
    rx: mpsc::Receiver<packet::CapturedPacket>,
    log: &mut Option<logger::Logger>,
    interface_name_label: String,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut state = AppState::new(interface_name_label);
    
    // GeoIP setup
    let (geo_tx, geo_rx) = mpsc::channel();
    let (geo_res_tx, geo_res_rx) = mpsc::channel();
    geoip::start_geo_thread(geo_rx, geo_res_tx);
    
    let mut count: u64 = 0;
    let mut channel_alive = true;

    loop {
        state.tick();

        // Drain GeoIP results
        while let Ok((ip, geo_opt)) = geo_res_rx.try_recv() {
            state.geo_in_flight = state.geo_in_flight.saturating_sub(1);
            if let Some(geo) = geo_opt {
                state.geo_cache.insert(ip, geo);
            } else {
                // Insert a dummy to skip re-querying failed IPs
                state.geo_cache.insert(ip, geoip::GeoInfo {
                    country_code: "??".into(),
                    org: "Unknown".into(),
                });
            }
        }

        // Drain ALL pending packets from the channel before drawing
        if channel_alive && !state.limit_reached {
            loop {
                match rx.try_recv() {
                    Ok(mut pkt) => {
                        // Resolve process name from source port
                        #[cfg(target_os = "windows")]
                        {
                            pkt.process = pkt
                                .src_port
                                .and_then(|p| process::lookup_process(p, &pkt.protocol));
                        }

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
                                        org: "Looking up...".into(),
                                    });
                                    let _ = geo_tx.send(*ip);
                                }
                            }

                            state.ingest_packet(&pkt);
                        }

                        count += 1;
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

        // Render once after draining
        terminal.draw(|f| display::draw_ui(f, &state))?;

        // Handle keyboard input
        if event::poll(Duration::from_millis(50))? {
            if let Event::Key(key) = event::read()? {
                if key.kind == KeyEventKind::Press {
                    match state.input_mode {
                        InputMode::Normal => match key.code {
                            KeyCode::Char('q') | KeyCode::Char('Q') => break,
                            KeyCode::Char('p') | KeyCode::Char('P') => {
                                state.paused = !state.paused;
                            }
                            KeyCode::Char('f') | KeyCode::Char('F') => {
                                state.cycle_filter();
                            }
                            KeyCode::Char('c') | KeyCode::Char('C') => {
                                state.clear_alerts();
                            }
                            KeyCode::Char('e') | KeyCode::Char('E') => {
                                state.input_buffer = r"C:\Users\SamRo\Documents\vora_report.txt".to_string();
                                state.input_mode = InputMode::Exporting;
                            }
                            KeyCode::Char('w') | KeyCode::Char('W') => {
                                state.input_buffer.clear();
                                state.input_mode = InputMode::Whitelisting;
                            }
                            KeyCode::Char(' ') => state.resume_scroll(),
                            KeyCode::Tab => state.switch_panel(),
                            KeyCode::Up => state.scroll_up(),
                            KeyCode::Down => state.scroll_down(),
                            _ => {}
                        },
                        InputMode::Exporting | InputMode::Whitelisting => match key.code {
                            KeyCode::Esc => {
                                state.input_mode = InputMode::Normal;
                                state.input_buffer.clear();
                            }
                            KeyCode::Enter => {
                                if state.input_mode == InputMode::Exporting {
                                    match export_report(&state, &state.input_buffer) {
                                        Ok(_) => state.set_footer_message(format!("Report saved to {}", state.input_buffer)),
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
        }
    }

    Ok(())
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
    
    writeln!(file, "================================================")?;
    writeln!(file, " VORA-RECON SESSION REPORT")?;
    writeln!(file, "================================================")?;
    writeln!(file, "Duration: {}s", duration)?;
    writeln!(file, "Total Packets: {}", state.total_packets)?;
    writeln!(file, "Total Bytes: {}", state.total_bytes)?;
    writeln!(file, "Unique IPs: {}", state.unique_ips.len())?;
    
    writeln!(file, "\n--- Protocol Breakdown ---")?;
    let tcp_pct = if state.total_packets > 0 { (state.tcp_count as f64 / state.total_packets as f64) * 100.0 } else { 0.0 };
    let udp_pct = if state.total_packets > 0 { (state.udp_count as f64 / state.total_packets as f64) * 100.0 } else { 0.0 };
    let icmp_pct = if state.total_packets > 0 { (state.icmp_count as f64 / state.total_packets as f64) * 100.0 } else { 0.0 };
    writeln!(file, "TCP:  {} ({:.1}%)", state.tcp_count, tcp_pct)?;
    writeln!(file, "UDP:  {} ({:.1}%)", state.udp_count, udp_pct)?;
    writeln!(file, "ICMP: {} ({:.1}%)", state.icmp_count, icmp_pct)?;

    writeln!(file, "\n--- Top 10 Destinations by Bytes ---")?;
    let mut dest_vec: Vec<_> = state.dest_bytes.iter().collect();
    dest_vec.sort_by(|a, b| b.1.cmp(a.1));
    for (ip, bytes) in dest_vec.into_iter().take(10) {
        let org = state.geo_cache.get(ip).map(|g| format!(" [{}]", g.org)).unwrap_or_default();
        writeln!(file, "{:<15}{} - {} bytes", ip.to_string(), org, bytes)?;
    }

    writeln!(file, "\n--- Top 10 Connections ---")?;
    let mut conn_vec: Vec<_> = state.connections.iter().collect();
    conn_vec.sort_by(|a, b| (b.1).1.cmp(&(a.1).1));
    for ((src, dst, _), (pkts, bytes, proc_name)) in conn_vec.into_iter().take(10) {
        let org = state.geo_cache.get(dst).map(|g| format!(" [{}]", g.org)).unwrap_or_default();
        let p_name = proc_name.as_deref().unwrap_or("unknown");
        writeln!(file, "{:<15} -> {:<15}{} | Process: {:<15} | {} pkts / {} bytes", 
            src.to_string(), dst.to_string(), org, p_name, pkts, bytes)?;
    }

    writeln!(file, "\n--- Alerts ---")?;
    if state.alerts.is_empty() {
        writeln!(file, "No alerts generated.")?;
    } else {
        for alert in &state.alerts {
            writeln!(file, "[{}] {}", alert.timestamp.format("%H:%M:%S"), alert.message)?;
        }
    }

    Ok(())
}
