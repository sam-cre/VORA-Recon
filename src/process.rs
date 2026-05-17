use crate::packet::Protocol;
use std::sync::Arc;
use dashmap::DashMap;

use winapi::shared::tcpmib::MIB_TCPTABLE_OWNER_PID;
use winapi::shared::udpmib::MIB_UDPTABLE_OWNER_PID;
use winapi::shared::ws2def::AF_INET;
use winapi::um::handleapi::CloseHandle;
use winapi::um::iphlpapi::{GetExtendedTcpTable, GetExtendedUdpTable};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::GetModuleFileNameExW;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
const UDP_TABLE_OWNER_PID: u32 = 1;

/// Batch refresh the process cache by scanning all active TCP/UDP owners.
pub fn refresh_process_cache(cache: Arc<DashMap<(u16, Protocol), String>>) {
    // Refresh TCP
    if let Some(tcp_map) = get_all_tcp_pids() {
        for (port, pid) in tcp_map {
            if !cache.contains_key(&(port, Protocol::Tcp)) {
                if let Some(path) = resolve_pid(pid) {
                    cache.insert((port, Protocol::Tcp), path);
                }
            }
        }
    }

    // Refresh UDP
    if let Some(udp_map) = get_all_udp_pids() {
        for (port, pid) in udp_map {
            if !cache.contains_key(&(port, Protocol::Udp)) {
                if let Some(path) = resolve_pid(pid) {
                    cache.insert((port, Protocol::Udp), path);
                }
            }
        }
    }
}

fn get_all_tcp_pids() -> Option<Vec<(u16, u32)>> {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedTcpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0);

        let mut buf = vec![0u8; size as usize];
        if GetExtendedTcpTable(buf.as_mut_ptr().cast(), &mut size, 0, AF_INET as u32, TCP_TABLE_OWNER_PID_ALL, 0) != 0 {
            return None;
        }

        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);
        
        Some(rows.iter().map(|r| (u16::from_be(r.dwLocalPort as u16), r.dwOwningPid)).collect())
    }
}

fn get_all_udp_pids() -> Option<Vec<(u16, u32)>> {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(std::ptr::null_mut(), &mut size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0);

        let mut buf = vec![0u8; size as usize];
        if GetExtendedUdpTable(buf.as_mut_ptr().cast(), &mut size, 0, AF_INET as u32, UDP_TABLE_OWNER_PID, 0) != 0 {
            return None;
        }

        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(table.table.as_ptr(), table.dwNumEntries as usize);

        Some(rows.iter().map(|r| (u16::from_be(r.dwLocalPort as u16), r.dwOwningPid)).collect())
    }
}

fn resolve_pid(pid: u32) -> Option<String> {
    if pid == 0 || pid == 4 { return Some("System".to_string()); }
    
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() { return None; }

        let mut buf = [0u16; 260];
        let len = GetModuleFileNameExW(handle, std::ptr::null_mut(), buf.as_mut_ptr(), 260);
        CloseHandle(handle);

        if len == 0 { return None; }
        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}
