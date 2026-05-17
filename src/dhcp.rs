// src/dhcp.rs
// DHCP Parameter Request List (Option 55) fingerprint database.
// Returns (os_tag, description) matching the existing tag format.

pub fn classify_dhcp(fingerprint: &str) -> Option<(&'static str, &'static str)> {
    let fp = fingerprint.trim();

    // --- Exact matches (highest confidence) ---

    // Windows 10/11
    match fp {
        "1,3,6,15,31,33,43,44,46,47,119,121,249,252" |
        "1,15,3,6,44,46,47,31,33,121,249,43,252"     |
        "1,3,6,15,31,33,43,44,46,47,119,121,249"     => return Some(("[Win]", "Windows 10/11")),
        "1,15,3,6,44,46,47,31,33,121,249,43"         => return Some(("[Win]", "Windows 7/8")),
        _ => {}
    }

    // macOS
    match fp {
        "1,121,3,6,15,119,252"      => return Some(("[Mac]", "macOS")),
        "1,121,3,6,15,119,252,95"   => return Some(("[Mac]", "macOS Ventura/Sonoma")),
        "1,3,6,15,119,252"          => return Some(("[Mac]", "macOS (older)")),
        _ => {}
    }

    // iOS / iPadOS
    match fp {
        "1,121,3,6,15,119,252,95,44,46,47" |
        "1,121,3,6,15,119,252,95,44"        |
        "1,121,3,6,15,119,252,44,46,47"     |
        "1,3,6,15,119,252,44,46,47"         |
        "1,121,3,6,15,119,252,95"           |   // iOS 16+ minimal
        "1,121,3,6,15,119,252,95,44,46"     |   // iOS variant
        "1,3,6,15,119,252,95,44,46,47"      => return Some(("[iOS]", "iOS/iPadOS")),   // iOS (no option 121)
        _ => {}
    }

    // Android
    match fp {
        "1,3,6,15,26,28,51,58,59,43"     |
        "1,3,6,15,26,28,51,58,59"         |
        "1,3,6,15,26,28,51,58,59,43,114" => return Some(("[And]", "Android")),
        _ => {}
    }

    // Linux
    match fp {
        "1,28,2,3,15,6,119,12,44,47,26,121,42" => return Some(("[Lin]", "Linux (dhclient)")),
        "1,3,6,12,15,17,23,28,29,31,33,40,41,42,119" |
        "1,3,6,12,15,17,28,42,119"               => return Some(("[Lin]", "Linux (dhcpcd)")),
        _ => {}
    }

    // Network/embedded
    match fp {
        "1,3,6,15,44,46,47" => return Some(("[Net]", "Network Device")),
        "1,3,6"              => return Some(("[Net]", "Embedded/Router")),
        _ => {}
    }

    // --- Prefix-based fallback (handles firmware-appended extra options) ---
    // These cover devices that add vendor-specific options after a known base pattern.
    let prefix_rules: &[(&str, &str, &str)] = &[
        ("1,3,6,15,31,33,43,44,46,47", "[Win]", "Windows"),
        ("1,15,3,6,44,46,47",          "[Win]", "Windows"),
        ("1,121,3,6,15,119,252,95",    "[iOS]", "iOS (modern)"),  // iOS 16+ — must be before macOS/iOS
        ("1,121,3,6,15,119",           "[Mac]", "macOS/iOS"),  // distinguishes by option 121 position
        ("1,3,6,15,26,28",             "[And]", "Android"),
        ("1,28,2,3,15,6",              "[Lin]", "Linux (dhclient)"),
        ("1,3,6,12,15,17",             "[Lin]", "Linux (dhcpcd)"),
    ];

    for (prefix, tag, desc) in prefix_rules {
        if fp.starts_with(prefix) {
            return Some((tag, desc));
        }
    }

    None
}
