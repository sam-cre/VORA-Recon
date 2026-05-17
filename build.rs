fn main() {
    if std::env::var("CARGO_CFG_TARGET_OS").unwrap() == "windows" {
        let mut res = winres::WindowsResource::new();
        res.set_icon("assets/logo.ico");
        res.compile().expect("Failed to compile Windows resource");

        // Link Npcap SDK - using the path found on this system
        println!("cargo:rustc-link-search=native=C:\\Users\\SRJ\\Downloads\\npcap-sdk-1.16\\Lib\\x64");
    }
}
