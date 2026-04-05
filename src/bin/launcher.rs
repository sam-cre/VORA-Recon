#![windows_subsystem = "windows"]

use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::ptr::null_mut;
use winapi::um::shellapi::ShellExecuteW;
use winapi::um::winuser::SW_SHOW;
use winapi::um::wincon::FreeConsole;
use winapi::um::processthreadsapi::ExitProcess;

fn main() {
    let mut exe_path = std::env::current_exe().expect("Failed to get current executable path");
    exe_path.pop(); // Remove launcher.exe
    let vora_path = exe_path.join("vora-recon.exe");
    
    let verb: Vec<u16> = OsStr::new("runas").encode_wide().chain(std::iter::once(0)).collect();
    let file: Vec<u16> = OsStr::new("wt.exe").encode_wide().chain(std::iter::once(0)).collect();
    
    // Wrap the path in quotes for ShellExecute parameters
    let params_str = format!("\"{}\"", vora_path.to_string_lossy());
    let params: Vec<u16> = OsStr::new(&params_str).encode_wide().chain(std::iter::once(0)).collect();
    
    unsafe {
        // Detach from parent console if any exists
        FreeConsole();
        
        ShellExecuteW(
            null_mut(),
            verb.as_ptr(),
            file.as_ptr(),
            params.as_ptr(),
            null_mut(),
            SW_SHOW,
        );
        
        // OS-level exit to ensure the process disappears instantly
        ExitProcess(0);
    }
}
