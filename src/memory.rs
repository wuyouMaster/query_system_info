//! Memory information module
//!
//! Provides cross-platform memory information gathering.

use crate::error::{Result, SysInfoError};
use crate::types::MemoryInfo;

/// Get memory information for the current system
pub fn get_memory_info() -> Result<MemoryInfo> {
    #[cfg(target_os = "linux")]
    return linux::get_memory_info();

    #[cfg(target_os = "macos")]
    return macos::get_memory_info();

    #[cfg(target_os = "windows")]
    return innerWindows::get_memory_info();

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

    pub fn get_memory_info() -> Result<MemoryInfo> {
        let contents = fs::read_to_string("/proc/meminfo")?;
        parse_meminfo(&contents)
    }

    fn parse_meminfo(contents: &str) -> Result<MemoryInfo> {
        let mut info = MemoryInfo::default();

        for line in contents.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }

            let key = parts[0].trim_end_matches(':');
            let value: u64 = parts[1]
                .parse()
                .map_err(|_| SysInfoError::Parse(format!("Failed to parse {}", key)))?;

            // Values in /proc/meminfo are in kB, convert to bytes
            let value_bytes = value * 1024;

            match key {
                "MemTotal" => info.total = value_bytes,
                "MemFree" => info.free = value_bytes,
                "MemAvailable" => info.available = value_bytes,
                "Buffers" => info.buffers = value_bytes,
                "Cached" => info.cached = value_bytes,
                "SwapTotal" => info.swap_total = value_bytes,
                "SwapFree" => info.swap_free = value_bytes,
                _ => {}
            }
        }

        info.used = info.total.saturating_sub(info.available);
        info.swap_used = info.swap_total.saturating_sub(info.swap_free);

        if info.total > 0 {
            info.usage_percent = (info.used as f64 / info.total as f64) * 100.0;
        }

        Ok(info)
    }
}

// ============================================================================
// macOS Implementation
// ============================================================================

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    #[allow(deprecated)]
    use libc::{
        c_int, c_void, host_statistics64, mach_host_self, mach_msg_type_number_t, sysctl,
        sysctlbyname, vm_statistics64, CTL_HW, HOST_VM_INFO64, HW_MEMSIZE, KERN_SUCCESS,
    };
    use std::mem;
    use std::ptr;

    const HOST_VM_INFO64_COUNT: mach_msg_type_number_t =
        (mem::size_of::<vm_statistics64>() / mem::size_of::<c_int>()) as mach_msg_type_number_t;

    pub fn get_memory_info() -> Result<MemoryInfo> {
        let mut info = MemoryInfo::default();

        // Get total memory using sysctl
        info.total = get_total_memory()?;

        // Get VM statistics
        let vm_stats = get_vm_statistics()?;
        let page_size = get_page_size()? as u64;

        // Calculate memory values
        info.free = vm_stats.free_count as u64 * page_size;
        info.cached = vm_stats.purgeable_count as u64 * page_size;

        // Available = free + inactive + purgeable (cached)
        info.available = info.free + (vm_stats.inactive_count as u64 * page_size) + info.cached;

        // Used = total - available
        info.used = info.total.saturating_sub(info.available);

        if info.total > 0 {
            info.usage_percent = (info.used as f64 / info.total as f64) * 100.0;
        }

        // Get swap info
        let (swap_total, swap_used) = get_swap_info()?;
        info.swap_total = swap_total;
        info.swap_used = swap_used;
        info.swap_free = swap_total.saturating_sub(swap_used);

        Ok(info)
    }

    fn get_total_memory() -> Result<u64> {
        let mut mem_size: u64 = 0;
        let mut size = mem::size_of::<u64>();
        let mut mib: [c_int; 2] = [CTL_HW, HW_MEMSIZE];

        unsafe {
            if sysctl(
                mib.as_mut_ptr(),
                2,
                &mut mem_size as *mut u64 as *mut c_void,
                &mut size,
                ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(SysInfoError::SysCall(
                    "sysctl HW_MEMSIZE failed".to_string(),
                ));
            }
        }

        Ok(mem_size)
    }

    fn get_page_size() -> Result<usize> {
        unsafe { Ok(libc::sysconf(libc::_SC_PAGESIZE) as usize) }
    }

    fn get_vm_statistics() -> Result<vm_statistics64> {
        let mut vm_stats: vm_statistics64 = unsafe { mem::zeroed() };
        let mut count = HOST_VM_INFO64_COUNT;

        unsafe {
            #[allow(deprecated)]
            let result = host_statistics64(
                mach_host_self(),
                HOST_VM_INFO64 as i32,
                &mut vm_stats as *mut vm_statistics64 as *mut i32,
                &mut count,
            );

            if result != KERN_SUCCESS as i32 {
                return Err(SysInfoError::SysCall(format!(
                    "host_statistics64 failed with error {}",
                    result
                )));
            }
        }

        Ok(vm_stats)
    }

    fn get_swap_info() -> Result<(u64, u64)> {
        #[repr(C)]
        struct XswUsage {
            xsu_total: u64,
            xsu_avail: u64,
            xsu_used: u64,
            xsu_pagesize: u32,
            xsu_encrypted: bool,
        }

        let mut swap: XswUsage = unsafe { mem::zeroed() };
        let mut size = mem::size_of::<XswUsage>();

        unsafe {
            let name = b"vm.swapusage\0";
            if sysctlbyname(
                name.as_ptr() as *const i8,
                &mut swap as *mut XswUsage as *mut c_void,
                &mut size,
                ptr::null_mut(),
                0,
            ) != 0
            {
                // Swap might not be enabled
                return Ok((0, 0));
            }
        }

        Ok((swap.xsu_total, swap.xsu_used))
    }
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
mod innerWindows {
    use super::*;
    use windows::Win32::System::SystemInformation::{GlobalMemoryStatusEx, MEMORYSTATUSEX};

    pub fn get_memory_info() -> Result<MemoryInfo> {
        let mut mem_status = MEMORYSTATUSEX {
            dwLength: std::mem::size_of::<MEMORYSTATUSEX>() as u32,
            ..Default::default()
        };

        unsafe {
            GlobalMemoryStatusEx(&mut mem_status).map_err(|e| {
                SysInfoError::WindowsApi(format!("GlobalMemoryStatusEx failed: {}", e))
            })?;
        }

        Ok(MemoryInfo {
            total: mem_status.ullTotalPhys,
            available: mem_status.ullAvailPhys,
            used: mem_status.ullTotalPhys - mem_status.ullAvailPhys,
            free: mem_status.ullAvailPhys,
            usage_percent: mem_status.dwMemoryLoad as f64,
            swap_total: mem_status.ullTotalPageFile,
            swap_used: mem_status.ullTotalPageFile - mem_status.ullAvailPageFile,
            swap_free: mem_status.ullAvailPageFile,
            cached: 0,  // Not directly available on Windows
            buffers: 0, // Not applicable on Windows
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_memory_info() {
        let info = get_memory_info().expect("Failed to get memory info");
        assert!(info.total > 0, "Total memory should be greater than 0");
        assert!(
            info.used <= info.total,
            "Used memory should not exceed total"
        );
        assert!(
            info.usage_percent >= 0.0 && info.usage_percent <= 100.0,
            "Usage percent should be between 0 and 100"
        );
        println!("Memory info: {:?}", info);
    }
}
