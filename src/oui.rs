use std::collections::HashMap;
use std::sync::OnceLock;

// Singleton database instance, embedded at compile time
static DB: OnceLock<HashMap<String, String>> = OnceLock::new();

pub fn get_vendor(mac: &str) -> String {
    let db = DB.get_or_init(|| {
        let mut map = HashMap::new();
        // Embed the OUI database into the binary for high-speed, offline lookups
        let data = include_str!("../oui.txt");
        
        // Fast line-by-line parser for the IEEE OUI text format
        for line in data.lines() {
            if line.contains("(hex)") {
                // Format: "XX-XX-XX   (hex)		Company Name"
                let parts: Vec<&str> = line.split("(hex)").collect();
                if parts.len() >= 2 {
                    let oui = parts[0].trim().replace("-", "").to_uppercase();
                    let vendor = parts[1].trim();
                    if !oui.is_empty() && !vendor.is_empty() {
                        map.insert(oui, vendor.to_string());
                    }
                }
            }
        }
        map
    });

    // Clean up input MAC: take first 6 chars, remove hex separators, uppercase
    let clean_mac = mac.replace(":", "").replace("-", "").to_uppercase();
    if clean_mac.len() < 6 {
        return "Unknown".to_string();
    }
    
    let prefix = &clean_mac[..6];
    
    // Check for standard Broadcast/Multicast MACs
    if clean_mac == "FFFFFFFFFFFF" {
        return "Broadcast".to_string();
    }
    if prefix == "01005E" {
        return "IPv4 Multicast".to_string();
    }
    if prefix.starts_with("3333") {
        return "IPv6 Multicast".to_string();
    }
    
    // Check for randomized MAC (locally administered bit)
    if let Ok(first_byte) = u8::from_str_radix(&clean_mac[..2], 16) {
        if (first_byte & 2) == 2 {
            return "Randomized MAC".to_string();
        }
    }
    
    let prefix = &clean_mac[..6];
    db.get(prefix)
        .cloned()
        .unwrap_or_else(|| "Unknown".to_string())
}
