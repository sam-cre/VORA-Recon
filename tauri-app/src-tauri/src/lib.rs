use std::process::{Command, Stdio};
use std::io::Read;
use tauri::{Emitter, Window};

#[tauri::command]
fn start_vora(window: Window) {
    std::thread::spawn(move || {
        let mut vora_path = std::env::current_exe().expect("Failed to get current executable path");
        vora_path.pop(); // Remove the tauri executable name
        vora_path.push("vora-recon.exe");

        let mut child = Command::new(vora_path)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("Failed to start vora-recon.exe");

        if let Some(mut stdout) = child.stdout.take() {
            let mut buffer = [0; 256];
            while let Ok(bytes_read) = stdout.read(&mut buffer) {
                if bytes_read == 0 {
                    break;
                }
                let chunk = String::from_utf8_lossy(&buffer[..bytes_read]);
                let _ = window.emit("vora-output", chunk.to_string());
            }
        }
        
        let _ = child.wait();
    });
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .invoke_handler(tauri::generate_handler![start_vora])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
