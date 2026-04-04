//! Process lookup — maps local source ports to owning process name.
//! Uses Windows iphlpapi (GetExtendedTcpTable / GetExtendedUdpTable) to find
//! the PID bound to a port, then psapi (GetModuleBaseNameW) to resolve the
//! executable filename.

#![cfg(target_os = "windows")]

use crate::packet::Protocol;

use winapi::shared::tcpmib::MIB_TCPTABLE_OWNER_PID;

/// TCP_TABLE_OWNER_PID_ALL = 5 (not exported by winapi 0.3)
const TCP_TABLE_OWNER_PID_ALL: u32 = 5;
use winapi::shared::udpmib::MIB_UDPTABLE_OWNER_PID;

/// UDP_TABLE_OWNER_PID = 1 (not exported by winapi 0.3)
const UDP_TABLE_OWNER_PID: u32 = 1;
use winapi::shared::ws2def::AF_INET;
use winapi::um::handleapi::CloseHandle;
use winapi::um::iphlpapi::{GetExtendedTcpTable, GetExtendedUdpTable};
use winapi::um::processthreadsapi::OpenProcess;
use winapi::um::psapi::GetModuleBaseNameW;
use winapi::um::winnt::{PROCESS_QUERY_INFORMATION, PROCESS_VM_READ};

/// Attempt to resolve the process name that owns `src_port` for the given protocol.
pub fn lookup_process(src_port: u16, protocol: &Protocol) -> Option<String> {
    let pid = match protocol {
        Protocol::Tcp => find_tcp_pid(src_port),
        Protocol::Udp => find_udp_pid(src_port),
        _ => None,
    }?;

    resolve_pid(pid)
}

fn find_tcp_pid(port: u16) -> Option<u32> {
    unsafe {
        let mut size: u32 = 0;
        // First call — get required buffer size
        GetExtendedTcpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedTcpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET as u32,
            TCP_TABLE_OWNER_PID_ALL,
            0,
        );
        if ret != 0 {
            return None;
        }

        let table = &*(buf.as_ptr() as *const MIB_TCPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr(),
            table.dwNumEntries as usize,
        );

        for row in rows {
            let local_port = u16::from_be(row.dwLocalPort as u16);
            if local_port == port {
                return Some(row.dwOwningPid);
            }
        }
        None
    }
}

fn find_udp_pid(port: u16) -> Option<u32> {
    unsafe {
        let mut size: u32 = 0;
        GetExtendedUdpTable(
            std::ptr::null_mut(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );

        let mut buf = vec![0u8; size as usize];
        let ret = GetExtendedUdpTable(
            buf.as_mut_ptr().cast(),
            &mut size,
            0,
            AF_INET as u32,
            UDP_TABLE_OWNER_PID,
            0,
        );
        if ret != 0 {
            return None;
        }

        let table = &*(buf.as_ptr() as *const MIB_UDPTABLE_OWNER_PID);
        let rows = std::slice::from_raw_parts(
            table.table.as_ptr(),
            table.dwNumEntries as usize,
        );

        for row in rows {
            let local_port = u16::from_be(row.dwLocalPort as u16);
            if local_port == port {
                return Some(row.dwOwningPid);
            }
        }
        None
    }
}

fn resolve_pid(pid: u32) -> Option<String> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, 0, pid);
        if handle.is_null() {
            return None;
        }

        let mut buf = [0u16; 260];
        let len = GetModuleBaseNameW(handle, std::ptr::null_mut(), buf.as_mut_ptr(), 260);
        CloseHandle(handle);

        if len == 0 {
            return None;
        }

        Some(String::from_utf16_lossy(&buf[..len as usize]))
    }
}
