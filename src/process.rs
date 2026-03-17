//! Process information module
//!
//! Provides cross-platform process information gathering.

use crate::error::{Result, SysInfoError};
use crate::types::{ChildProcessEvent, ProcessInfo, ProcessState};
use std::collections::HashSet;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

/// List all processes
pub fn list_processes() -> Result<Vec<ProcessInfo>> {
    #[cfg(target_os = "linux")]
    return linux::list_processes();

    #[cfg(target_os = "macos")]
    return macos::list_processes();

    #[cfg(target_os = "windows")]
    return innerWindows::list_processes();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

/// Process tracker handle
pub struct ProcessTracker {
    handle: Arc<Mutex<TrackerState>>,
}

struct TrackerState {
    root_pid: u32,
    running: bool,
    known_pids: HashSet<u32>,
    callback: Box<dyn Fn(ChildProcessEvent) + Send + 'static>,
}

/// Start tracking child processes of a given PID
pub fn start_tracking_children<F>(pid: u32, callback: F) -> Result<ProcessTracker>
where
    F: Fn(ChildProcessEvent) + Send + 'static,
{
    let state = Arc::new(Mutex::new(TrackerState {
        root_pid: pid,
        running: true,
        known_pids: HashSet::new(),
        callback: Box::new(callback),
    }));

    let state_clone = Arc::clone(&state);
    thread::spawn(move || {
        track_loop(state_clone);
    });

    Ok(ProcessTracker { handle: state })
}

impl ProcessTracker {
    /// Stop tracking child processes
    pub fn stop(&self) {
        if let Ok(mut state) = self.handle.lock() {
            state.running = false;
        }
    }
}

fn track_loop(state: Arc<Mutex<TrackerState>>) {
    loop {
        let (root_pid, running) = {
            let s = state.lock().unwrap();
            (s.root_pid, s.running)
        };

        if !running {
            break;
        }

        if let Ok(children) = find_all_children(root_pid) {
            let mut state_lock = state.lock().unwrap();
            for child in children {
                if !state_lock.known_pids.contains(&child.pid) {
                    state_lock.known_pids.insert(child.pid);
                    (state_lock.callback)(child);
                }
            }
        }

        thread::sleep(Duration::from_millis(500));
    }
}

fn find_all_children(root_pid: u32) -> Result<Vec<ChildProcessEvent>> {
    let mut result = Vec::new();
    let mut to_check = vec![root_pid];
    let mut checked = HashSet::new();

    while let Some(pid) = to_check.pop() {
        if checked.contains(&pid) {
            continue;
        }
        checked.insert(pid);

        if let Ok(processes) = list_processes() {
            for proc in processes {
                if proc.ppid == pid && proc.pid != root_pid {
                    result.push(ChildProcessEvent {
                        pid: proc.pid,
                        ppid: proc.ppid,
                        name: proc.name.clone(),
                        cmdline: proc.cmdline.clone(),
                        exe_path: proc.exe_path.clone(),
                        start_time: proc.start_time,
                    });
                    to_check.push(proc.pid);
                }
            }
        }
    }

    Ok(result)
}

/// Kill a process by PID. Sends SIGKILL on Unix, calls TerminateProcess on Windows.
pub fn kill_process(pid: u32) -> Result<()> {
    #[cfg(target_os = "linux")]
    return linux::kill_process(pid);

    #[cfg(target_os = "macos")]
    return macos::kill_process(pid);

    #[cfg(target_os = "windows")]
    return innerWindows::kill_process(pid);

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

/// Get information about a specific process
pub fn get_process_info(pid: u32) -> Result<ProcessInfo> {
    #[cfg(target_os = "linux")]
    return linux::get_process_info(pid);

    #[cfg(target_os = "macos")]
    return macos::get_process_info(pid);

    #[cfg(target_os = "windows")]
    return innerWindows::get_process_info(pid);

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

// ============================================================================
// Linux Implementation
// ============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use std::path::Path;

    pub fn list_processes() -> Result<Vec<ProcessInfo>> {
        let mut processes = Vec::new();

        for entry in fs::read_dir("/proc")? {
            let entry = entry?;
            let file_name = entry.file_name();
            let name = file_name.to_string_lossy();

            // Check if directory name is a number (PID)
            if let Ok(pid) = name.parse::<u32>() {
                if let Ok(info) = get_process_info(pid) {
                    processes.push(info);
                }
            }
        }

        Ok(processes)
    }

    pub fn kill_process(pid: u32) -> Result<()> {
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if ret == 0 {
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ESRCH) => Err(SysInfoError::ProcessNotFound(pid)),
                Some(libc::EPERM) => Err(SysInfoError::PermissionDenied(format!("kill pid {pid}"))),
                _ => Err(SysInfoError::SysCall(format!("kill({pid}) failed: {err}"))),
            }
        }
    }

    pub fn get_process_info(pid: u32) -> Result<ProcessInfo> {
        let proc_path = Path::new("/proc").join(pid.to_string());
        if !proc_path.exists() {
            return Err(SysInfoError::ProcessNotFound(pid));
        }

        let mut info = ProcessInfo {
            pid,
            ..Default::default()
        };

        // Read /proc/[pid]/stat
        if let Ok(stat) = fs::read_to_string(proc_path.join("stat")) {
            parse_stat(&stat, &mut info)?;
        }

        // Read /proc/[pid]/status for additional info
        if let Ok(status) = fs::read_to_string(proc_path.join("status")) {
            parse_status(&status, &mut info);
        }

        // Read /proc/[pid]/cmdline
        if let Ok(cmdline) = fs::read_to_string(proc_path.join("cmdline")) {
            info.cmdline = cmdline
                .split('\0')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect();
        }

        // Read /proc/[pid]/exe
        if let Ok(exe) = fs::read_link(proc_path.join("exe")) {
            info.exe_path = exe.to_string_lossy().to_string();
        }

        Ok(info)
    }

    fn parse_stat(stat: &str, info: &mut ProcessInfo) -> Result<()> {
        // Format: pid (comm) state ppid pgrp session tty_nr tpgid flags
        //         minflt cminflt majflt cmajflt utime stime cutime cstime priority nice
        //         num_threads itrealvalue starttime vsize rss ...

        // Find the comm field (enclosed in parentheses)
        let start = stat
            .find('(')
            .ok_or_else(|| SysInfoError::Parse("Invalid stat format".to_string()))?;
        let end = stat
            .rfind(')')
            .ok_or_else(|| SysInfoError::Parse("Invalid stat format".to_string()))?;

        info.name = stat[start + 1..end].to_string();

        // Parse fields after the comm field
        let rest = &stat[end + 2..];
        let fields: Vec<&str> = rest.split_whitespace().collect();

        if fields.len() >= 22 {
            // State is first field after (comm)
            info.state = match fields[0] {
                "R" => ProcessState::Running,
                "S" => ProcessState::Sleeping,
                "D" => ProcessState::Sleeping, // Disk sleep
                "Z" => ProcessState::Zombie,
                "T" => ProcessState::Stopped,
                "I" => ProcessState::Idle,
                _ => ProcessState::Unknown,
            };

            // ppid is second field
            info.ppid = fields[1].parse().unwrap_or(0);

            // num_threads is at index 17 (0-indexed)
            info.threads = fields[17].parse().unwrap_or(0);

            // starttime is at index 19
            info.start_time = fields[19].parse().unwrap_or(0);

            // vsize (virtual memory) is at index 20
            info.virtual_memory = fields[20].parse().unwrap_or(0);

            // rss (resident set size) is at index 21 (in pages)
            let rss_pages: u64 = fields[21].parse().unwrap_or(0);
            let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) as u64 };
            info.memory_bytes = rss_pages * page_size;
        }

        Ok(())
    }

    fn parse_status(status: &str, info: &mut ProcessInfo) {
        for line in status.lines() {
            let parts: Vec<&str> = line.splitn(2, ':').collect();
            if parts.len() != 2 {
                continue;
            }

            let key = parts[0].trim();
            let value = parts[1].trim();

            match key {
                "Uid" => {
                    if let Some(uid_str) = value.split_whitespace().next() {
                        info.uid = uid_str.parse().unwrap_or(0);
                    }
                }
                "VmRSS" => {
                    // Override memory_bytes with more accurate value
                    if let Some(mem_str) = value.split_whitespace().next() {
                        if let Ok(mem_kb) = mem_str.parse::<u64>() {
                            info.memory_bytes = mem_kb * 1024;
                        }
                    }
                }
                "VmSize" => {
                    if let Some(mem_str) = value.split_whitespace().next() {
                        if let Ok(mem_kb) = mem_str.parse::<u64>() {
                            info.virtual_memory = mem_kb * 1024;
                        }
                    }
                }
                _ => {}
            }
        }
    }
}

// ============================================================================
// macOS Implementation
// ============================================================================

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use libc::{
        c_int, c_void, sysctl, CTL_KERN, KERN_PROC, KERN_PROCARGS2, KERN_PROC_ALL, KERN_PROC_PID,
    };
    use std::mem;
    use std::ptr;

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct KinfoProc {
        kp_proc: ExternProc,
        kp_eproc: Eproc,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct ExternProc {
        p_starttime: libc::timeval,
        p_vmspace: *mut c_void,
        p_sigacts: *mut c_void,
        p_flag: c_int,
        p_stat: u8,
        p_pid: i32,
        p_oppid: i32,
        p_dupfd: c_int,
        user_stack: *mut c_void,
        exit_thread: *mut c_void,
        p_debugger: c_int,
        sigwait: c_int,
        p_estcpu: u32,
        p_cpticks: c_int,
        p_pctcpu: u32,
        p_wchan: *mut c_void,
        p_wmesg: *mut i8,
        p_swtime: u32,
        p_slptime: u32,
        p_realtimer: libc::itimerval,
        p_rtime: libc::timeval,
        p_uticks: u64,
        p_sticks: u64,
        p_iticks: u64,
        p_traceflag: c_int,
        p_tracep: *mut c_void,
        p_siglist: c_int,
        p_textvp: *mut c_void,
        p_holdcnt: c_int,
        p_sigmask: u32,
        p_sigignore: u32,
        p_sigcatch: u32,
        p_priority: u8,
        p_usrpri: u8,
        p_nice: i8,
        p_comm: [i8; 17],
        p_pgrp: *mut c_void,
        p_addr: *mut c_void,
        p_xstat: u16,
        p_acflag: u16,
        p_ru: *mut c_void,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Eproc {
        e_paddr: *mut c_void,
        e_sess: *mut c_void,
        e_pcred: Pcred,
        e_ucred: Ucred,
        e_vm: Vmspace,
        e_ppid: i32,
        e_pgid: i32,
        e_jobc: i16,
        e_tdev: i32,
        e_tpgid: i32,
        e_tsess: *mut c_void,
        e_wmesg: [i8; 8],
        e_xsize: i32,
        e_xrssize: i16,
        e_xccount: i16,
        e_xswrss: i16,
        e_flag: i32,
        e_login: [i8; 12],
        e_spare: [i32; 4],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Pcred {
        pc_lock: [i8; 72],
        pc_ucred: *mut c_void,
        p_ruid: u32,
        p_svuid: u32,
        p_rgid: u32,
        p_svgid: u32,
        p_refcnt: c_int,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Ucred {
        cr_ref: i32,
        cr_uid: u32,
        cr_ngroups: i16,
        cr_groups: [u32; 16],
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Vmspace {
        dummy: c_int,
        dummy2: *mut c_void,
        dummy3: [i32; 5],
        dummy4: [*mut c_void; 3],
    }

    pub fn list_processes() -> Result<Vec<ProcessInfo>> {
        let mut mib: [c_int; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_ALL, 0];
        let entry_size = mem::size_of::<KinfoProc>();

        // Query the kernel for the current byte size of the process table.
        let mut size: usize = 0;
        unsafe {
            if sysctl(
                mib.as_mut_ptr(),
                3,
                ptr::null_mut(),
                &mut size,
                ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(SysInfoError::SysCall(
                    "sysctl KERN_PROC_ALL size failed".to_string(),
                ));
            }
        }

        // Add headroom up front to reduce the gap between the size probe and
        // the actual fetch. If new processes appear meanwhile and the kernel
        // returns ENOMEM, keep doubling until the buffer is large enough.
        let mut buf_size = (size + size / 5).max(entry_size);

        loop {
            let count = buf_size.div_ceil(entry_size);
            let mut procs: Vec<KinfoProc> = vec![unsafe { mem::zeroed() }; count];
            let mut actual_size = buf_size;

            let ret = unsafe {
                sysctl(
                    mib.as_mut_ptr(),
                    3,
                    procs.as_mut_ptr() as *mut c_void,
                    &mut actual_size,
                    ptr::null_mut(),
                    0,
                )
            };

            if ret == 0 {
                let actual_count = actual_size / entry_size;
                let mut processes = Vec::with_capacity(actual_count);
                for proc in procs.into_iter().take(actual_count) {
                    processes.push(kinfo_to_process_info(&proc));
                }
                return Ok(processes);
            }

            let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
            if errno != libc::ENOMEM {
                return Err(SysInfoError::SysCall(format!(
                    "sysctl KERN_PROC_ALL failed (errno {errno})"
                )));
            }

            // The process table grew between the size probe and the fetch.
            // Grow aggressively to avoid repeated retries under churn.
            buf_size = buf_size.checked_mul(2).ok_or_else(|| {
                SysInfoError::SysCall("sysctl KERN_PROC_ALL buffer size overflow".to_string())
            })?;
        }
    }

    pub fn kill_process(pid: u32) -> Result<()> {
        let ret = unsafe { libc::kill(pid as libc::pid_t, libc::SIGKILL) };
        if ret == 0 {
            Ok(())
        } else {
            let err = std::io::Error::last_os_error();
            match err.raw_os_error() {
                Some(libc::ESRCH) => Err(SysInfoError::ProcessNotFound(pid)),
                Some(libc::EPERM) => Err(SysInfoError::PermissionDenied(format!("kill pid {pid}"))),
                _ => Err(SysInfoError::SysCall(format!("kill({pid}) failed: {err}"))),
            }
        }
    }

    pub fn get_process_info(pid: u32) -> Result<ProcessInfo> {
        let mut mib: [c_int; 4] = [CTL_KERN, KERN_PROC, KERN_PROC_PID, pid as c_int];
        let mut kp: KinfoProc = unsafe { mem::zeroed() };
        let mut size = mem::size_of::<KinfoProc>();

        unsafe {
            if sysctl(
                mib.as_mut_ptr(),
                4,
                &mut kp as *mut KinfoProc as *mut c_void,
                &mut size,
                ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(SysInfoError::ProcessNotFound(pid));
            }
        }

        if size == 0 {
            return Err(SysInfoError::ProcessNotFound(pid));
        }

        Ok(kinfo_to_process_info(&kp))
    }

    fn kinfo_to_process_info(kp: &KinfoProc) -> ProcessInfo {
        let name = unsafe {
            std::ffi::CStr::from_ptr(kp.kp_proc.p_comm.as_ptr())
                .to_string_lossy()
                .to_string()
        };

        let state = match kp.kp_proc.p_stat {
            1 => ProcessState::Idle,     // SIDL
            2 => ProcessState::Running,  // SRUN
            3 => ProcessState::Sleeping, // SSLEEP
            4 => ProcessState::Stopped,  // SSTOP
            5 => ProcessState::Zombie,   // SZOMB
            _ => ProcessState::Unknown,
        };

        let pid = kp.kp_proc.p_pid as u32;
        let (exe_path, cmdline) = get_process_args(pid);

        ProcessInfo {
            pid,
            ppid: kp.kp_eproc.e_ppid as u32,
            name,
            exe_path,
            cmdline,
            state,
            memory_bytes: 0,
            virtual_memory: 0,
            cpu_percent: 0.0,
            threads: 0,
            start_time: kp.kp_proc.p_starttime.tv_sec as u64,
            uid: kp.kp_eproc.e_ucred.cr_uid,
            username: String::new(),
        }
    }

    fn get_process_args(pid: u32) -> (String, Vec<String>) {
        let mut mib = [CTL_KERN, KERN_PROCARGS2, pid as c_int];
        let mut size: usize = 0;

        unsafe {
            if sysctl(
                mib.as_mut_ptr(),
                3,
                ptr::null_mut(),
                &mut size,
                ptr::null_mut(),
                0,
            ) != 0
            {
                return (String::new(), Vec::new());
            }

            let mut buf = vec![0u8; size];
            if sysctl(
                mib.as_mut_ptr(),
                3,
                buf.as_mut_ptr() as *mut c_void,
                &mut size,
                ptr::null_mut(),
                0,
            ) != 0
            {
                return (String::new(), Vec::new());
            }

            if size < 4 {
                return (String::new(), Vec::new());
            }

            let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
            let mut pos = 4;

            // Skip executable path
            while pos < buf.len() && buf[pos] != 0 {
                pos += 1;
            }
            // Skip trailing nulls
            while pos < buf.len() && buf[pos] == 0 {
                pos += 1;
            }

            let mut args = Vec::new();
            for _ in 0..argc {
                if pos >= buf.len() {
                    break;
                }
                let start = pos;
                while pos < buf.len() && buf[pos] != 0 {
                    pos += 1;
                }
                if pos > start {
                    if let Ok(arg) = String::from_utf8(buf[start..pos].to_vec()) {
                        args.push(arg);
                    }
                }
                pos += 1;
            }

            let exe = args.first().cloned().unwrap_or_default();
            (exe, args)
        }
    }
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
mod innerWindows {
    use super::*;
    use std::mem;
    use windows::core::PWSTR;
    use windows::Wdk::System::Threading::{NtQueryInformationProcess, ProcessBasicInformation};
    use windows::Win32::Foundation::{CloseHandle, HANDLE};
    use windows::Win32::System::ProcessStatus::{
        EnumProcesses, GetProcessMemoryInfo, PROCESS_MEMORY_COUNTERS,
    };
    use windows::Win32::System::Threading::{
        OpenProcess, QueryFullProcessImageNameW, PROCESS_BASIC_INFORMATION, PROCESS_NAME_WIN32,
        PROCESS_QUERY_INFORMATION, PROCESS_VM_READ,
    };

    pub fn list_processes() -> Result<Vec<ProcessInfo>> {
        let mut pids: Vec<u32> = vec![0; 1024];
        let mut bytes_returned: u32 = 0;

        loop {
            unsafe {
                let result = EnumProcesses(
                    pids.as_mut_ptr(),
                    (pids.len() * mem::size_of::<u32>()) as u32,
                    &mut bytes_returned,
                );

                if result.is_err() {
                    return Err(SysInfoError::WindowsApi(format!(
                        "EnumProcesses failed: {}",
                        result.unwrap_err()
                    )));
                }
            }

            let count = bytes_returned as usize / mem::size_of::<u32>();

            if count < pids.len() {
                pids.truncate(count);
                break;
            } else {
                pids.resize(pids.len() * 2, 0);
            }
        }

        let mut processes = Vec::new();

        for pid in pids {
            if pid == 0 {
                continue;
            }

            if let Ok(info) = get_process_info(pid) {
                processes.push(info);
            }
        }

        Ok(processes)
    }

    pub fn kill_process(pid: u32) -> Result<()> {
        use windows::Win32::System::Threading::{OpenProcess, TerminateProcess, PROCESS_TERMINATE};
        unsafe {
            let handle = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|_| {
                SysInfoError::PermissionDenied(format!("Cannot open process {pid} for termination"))
            })?;
            let _guard = HandleGuard(handle);
            TerminateProcess(handle, 1).map_err(|e| {
                SysInfoError::WindowsApi(format!("TerminateProcess({pid}) failed: {e}"))
            })?;
        }
        Ok(())
    }

    pub fn get_process_info(pid: u32) -> Result<ProcessInfo> {
        let mut info = ProcessInfo {
            pid,
            ..Default::default()
        };

        unsafe {
            // Keep PROCESS_QUERY_INFORMATION | PROCESS_VM_READ so that protected/kernel
            // processes (System PID 4, Registry, etc.) continue to be rejected by
            // OpenProcess and skipped — avoiding any risk of SEH exceptions from
            // NtQueryInformationProcess or QueryFullProcessImageNameW on those handles.
            let handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid)
                .map_err(|_| {
                    SysInfoError::PermissionDenied(format!("Cannot open process {}", pid))
                })?;
            let _handle_guard = HandleGuard(handle);

            // Get PPID via NtQueryInformationProcess
            let mut pbi: PROCESS_BASIC_INFORMATION = mem::zeroed();
            let mut return_length: u32 = 0;
            let _ = NtQueryInformationProcess(
                handle,
                ProcessBasicInformation,
                &mut pbi as *mut _ as *mut _,
                mem::size_of::<PROCESS_BASIC_INFORMATION>() as u32,
                &mut return_length,
            );
            info.ppid = pbi.InheritedFromUniqueProcessId as u32;

            // Get exe path and derive the process name from it.
            // QueryFullProcessImageNameW is safe for all user-accessible processes and
            // does not read from the target process's memory, unlike GetModuleBaseNameW
            // which calls ReadProcessMemory internally and causes STATUS_HEAP_CORRUPTION
            // when the target is a WOW64 (32-bit) or partially-initialized process.
            let mut path_buffer: [u16; 260] = [0; 260];
            let mut path_len = path_buffer.len() as u32;
            if QueryFullProcessImageNameW(
                handle,
                PROCESS_NAME_WIN32,
                PWSTR(path_buffer.as_mut_ptr()),
                &mut path_len,
            )
            .is_ok()
                && path_len > 0
            {
                info.exe_path = String::from_utf16_lossy(&path_buffer[..path_len as usize]);
                info.cmdline = vec![info.exe_path.clone()];
                if let Some(name) = std::path::Path::new(&info.exe_path).file_name() {
                    info.name = name.to_string_lossy().to_string();
                }
            }

            // Get memory info using the same handle (already has PROCESS_VM_READ).
            let mut mem_counters: PROCESS_MEMORY_COUNTERS = mem::zeroed();
            mem_counters.cb = mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32;
            if GetProcessMemoryInfo(
                handle,
                &mut mem_counters,
                mem::size_of::<PROCESS_MEMORY_COUNTERS>() as u32,
            )
            .is_ok()
            {
                info.memory_bytes = mem_counters.WorkingSetSize as u64;
                info.virtual_memory = mem_counters.PagefileUsage as u64;
            }
        }

        info.state = ProcessState::Running;

        Ok(info)
    }

    struct HandleGuard(HANDLE);

    impl Drop for HandleGuard {
        fn drop(&mut self) {
            unsafe {
                CloseHandle(self.0).ok();
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_list_processes() {
        let processes = list_processes().expect("Failed to list processes");
        assert!(!processes.is_empty(), "Should find at least one process");
    }

    #[test]
    fn test_get_current_process() {
        let pid = std::process::id();
        let info = get_process_info(pid).expect("Failed to get current process info");
        assert_eq!(info.pid, pid);
    }

    #[test]
    fn test_tracking_api() {
        use std::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Arc;

        let called = Arc::new(AtomicBool::new(false));
        let called_clone = Arc::clone(&called);

        let tracker = start_tracking_children(std::process::id(), move |_event| {
            called_clone.store(true, Ordering::SeqCst);
        })
        .expect("Failed to start tracking");

        thread::sleep(Duration::from_millis(100));
        tracker.stop();
    }
}
