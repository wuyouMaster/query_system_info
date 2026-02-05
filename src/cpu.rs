//! CPU information module
//!
//! Provides cross-platform CPU information gathering.

use crate::error::{Result, SysInfoError};
use crate::types::{CpuInfo, CpuTimes};
use std::thread;
use std::time::Duration;

/// Get CPU information
pub fn get_cpu_info() -> Result<CpuInfo> {
    #[cfg(target_os = "linux")]
    return linux::get_cpu_info();

    #[cfg(target_os = "macos")]
    return macos::get_cpu_info();

    #[cfg(target_os = "windows")]
    return windows::get_cpu_info();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported("Unsupported platform".to_string()))
}

/// Get CPU usage percentage (requires two samples with a delay)
pub fn get_cpu_usage(sample_duration: Duration) -> Result<Vec<f64>> {
    let times1 = get_cpu_times()?;
    thread::sleep(sample_duration);
    let times2 = get_cpu_times()?;

    let mut usages = Vec::new();
    for i in 0..times1.len() {
        let total1 = times1[i].user + times1[i].system + times1[i].idle + times1[i].nice + times1[i].iowait;
        let total2 = times2[i].user + times2[i].system + times2[i].idle + times2[i].nice + times2[i].iowait;
        let total_diff = total2.saturating_sub(total1);
        let idle_diff = times2[i].idle.saturating_sub(times1[i].idle);
        let usage = ((total_diff - idle_diff) as f64 / total_diff as f64) * 100.0;
        usages.push(usage);
    }
    Ok(usages)
}

/// Get raw CPU times
pub fn get_cpu_times() -> Result<Vec<CpuTimes>> {
    #[cfg(target_os = "linux")]
    return linux::get_cpu_times();

    #[cfg(target_os = "macos")]
    return macos::get_cpu_times();

    #[cfg(target_os = "windows")]
    return windows::get_cpu_times();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported("Unsupported platform".to_string()))
}

// ============================================================================
// Linux Implementation
// ============================================================================

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use std::fs;
    use regex::Regex;
    use std::sync::OnceLock;
    static CPU_REGEX: OnceLock<Regex> = OnceLock::new();

    pub fn get_cpu_info() -> Result<CpuInfo> {
        let mut info = CpuInfo::default();

        // Read /proc/cpuinfo
        let cpuinfo = fs::read_to_string("/proc/cpuinfo")?;
        let mut cores_seen = 0u32;
        let mut physical_ids = std::collections::HashSet::new();

        for line in cpuinfo.lines() {
            if line.starts_with("processor") {
                cores_seen += 1;
            } else if line.starts_with("model name") {
                if info.model_name.is_empty() {
                    info.model_name = line.split(':').nth(1).unwrap_or("").trim().to_string();
                }
            } else if line.starts_with("vendor_id") {
                if info.vendor.is_empty() {
                    info.vendor = line.split(':').nth(1).unwrap_or("").trim().to_string();
                }
            } else if line.starts_with("cpu MHz") {
                if info.frequency_mhz == 0 {
                    if let Some(freq_str) = line.split(':').nth(1) {
                        info.frequency_mhz = freq_str.trim().parse::<f64>().unwrap_or(0.0) as u64;
                    }
                }
            } else if line.starts_with("physical id") {
                if let Some(id_str) = line.split(':').nth(1) {
                    if let Ok(id) = id_str.trim().parse::<u32>() {
                        physical_ids.insert(id);
                    }
                }
            }
        }

        info.logical_cores = cores_seen;

        // Get physical core count
        if let Ok(cores) = fs::read_to_string("/sys/devices/system/cpu/cpu0/topology/core_siblings_list") {
            let core_count = cores.split(',').count() + cores.matches('-').count();
            info.physical_cores = (info.logical_cores as usize / core_count.max(1)) as u32;
        } else {
            info.physical_cores = if physical_ids.is_empty() {
                cores_seen
            } else {
                physical_ids.len() as u32
            };
        }

        Ok(info)
    }

    pub fn get_cpu_times() -> Result<Vec<CpuTimes>> {
        let stat = fs::read_to_string("/proc/stat")?;
        let mut times = Vec::new();
        let cpu_regex = CPU_REGEX.get_or_init(|| Regex::new(r"cpu\d+").expect("Failed to create CPU regex"));
        for line in stat.lines() {
            if cpu_regex.is_match(line) {
                let mut time = CpuTimes::default();
                let parts: Vec<&str> = line.split_whitespace().collect();
                time.user = parts[0].parse().unwrap_or(0);
                time.nice = parts[1].parse().unwrap_or(0);
                time.system = parts[2].parse().unwrap_or(0);
                time.idle = parts[3].parse().unwrap_or(0);
                time.iowait = parts[4].parse().unwrap_or(0);
                time.irq = parts[5].parse().unwrap_or(0);
                time.softirq = parts[6].parse().unwrap_or(0);
                times.push(time);
            }
        }
        return Ok(times);
    }
}

// ============================================================================
// macOS Implementation
// ============================================================================

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use libc::{c_int, c_void, sysctlbyname};
    use mach2::mach_types::host_t;
    use std::mem;
    use std::ptr;

    // processor_info types
    const PROCESSOR_CPU_LOAD_INFO: c_int = 2;

    extern "C" {
        fn mach_host_self() -> host_t;
        fn host_processor_info(
            host: host_t,
            flavor: c_int,
            out_processor_count: *mut u32,
            out_processor_info: *mut *mut c_int,
            out_processor_infoCnt: *mut u32,
        ) -> c_int;
    }

    pub fn get_cpu_info() -> Result<CpuInfo> {
        let mut info = CpuInfo::default();

        // Get logical CPU count
        info.logical_cores = get_sysctl_u32("hw.logicalcpu")? as u32;
        info.physical_cores = get_sysctl_u32("hw.physicalcpu")? as u32;

        // Get CPU brand string - try multiple sysctl keys for compatibility
        // On Apple Silicon, machdep.cpu.brand_string doesn't exist, use hw.model instead
        info.model_name = get_sysctl_string("machdep.cpu.brand_string")
            .unwrap_or_else(|_| get_sysctl_string("hw.model").unwrap_or_default());

        // Vendor - try machdep.cpu.vendor, if not available detect from model
        info.vendor = get_sysctl_string("machdep.cpu.vendor").unwrap_or_else(|_| {
            if info.model_name.contains("Apple") || info.model_name.starts_with("Mac") {
                "Apple".to_string()
            } else {
                "Unknown".to_string()
            }
        });

        // Get CPU frequency (in Hz, convert to MHz)
        // On Apple Silicon, hw.cpufrequency might not be available
        info.frequency_mhz = get_sysctl_u64("hw.cpufrequency").unwrap_or(0) / 1_000_000;

        Ok(info)
    }

    pub fn get_cpu_times() -> Result<Vec<CpuTimes>> {
        let mut processor_count: u32 = 0;
        let mut processor_info: *mut c_int = ptr::null_mut();
        let mut processor_info_count: u32 = 0;

        unsafe {
            let result = host_processor_info(
                mach_host_self(),
                PROCESSOR_CPU_LOAD_INFO,
                &mut processor_count,
                &mut processor_info,
                &mut processor_info_count,
            );

            if result != 0 {
                return Err(SysInfoError::SysCall(format!(
                    "host_processor_info failed with error {}",
                    result
                )));
            }

            let mut times = Vec::new();

            // Sum up all CPU ticks
            for i in 0..processor_count as isize {
                let mut time = CpuTimes::default();
                let info_ptr = processor_info.offset(i * 4);
                time.user += *info_ptr as u64;
                time.system += *info_ptr.offset(1) as u64;
                time.idle += *info_ptr.offset(2) as u64;
                time.nice += *info_ptr.offset(3) as u64;
                times.push(time);
            }

            // Free the processor info
            #[allow(deprecated)]
            libc::vm_deallocate(
                libc::mach_task_self(),
                processor_info as usize,
                (processor_info_count * mem::size_of::<c_int>() as u32) as usize,
            );

            Ok(times)
        }
    }

    fn get_sysctl_u32(name: &str) -> Result<u32> {
        let mut value: u32 = 0;
        let mut size = mem::size_of::<u32>();
        let name_cstr = std::ffi::CString::new(name).unwrap();

        unsafe {
            if sysctlbyname(
                name_cstr.as_ptr(),
                &mut value as *mut u32 as *mut c_void,
                &mut size,
                ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(SysInfoError::SysCall(format!("sysctlbyname {} failed", name)));
            }
        }

        Ok(value)
    }

    fn get_sysctl_u64(name: &str) -> Result<u64> {
        let mut value: u64 = 0;
        let mut size = mem::size_of::<u64>();
        let name_cstr = std::ffi::CString::new(name).unwrap();

        unsafe {
            if sysctlbyname(
                name_cstr.as_ptr(),
                &mut value as *mut u64 as *mut c_void,
                &mut size,
                ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(SysInfoError::SysCall(format!("sysctlbyname {} failed", name)));
            }
        }

        Ok(value)
    }

    fn get_sysctl_string(name: &str) -> Result<String> {
        let name_cstr = std::ffi::CString::new(name).unwrap();
        let mut size: usize = 0;

        // First call to get size
        unsafe {
            if sysctlbyname(
                name_cstr.as_ptr(),
                ptr::null_mut(),
                &mut size,
                ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(SysInfoError::SysCall(format!("sysctlbyname {} failed", name)));
            }
        }

        let mut buffer: Vec<u8> = vec![0; size];

        unsafe {
            if sysctlbyname(
                name_cstr.as_ptr(),
                buffer.as_mut_ptr() as *mut c_void,
                &mut size,
                ptr::null_mut(),
                0,
            ) != 0
            {
                return Err(SysInfoError::SysCall(format!("sysctlbyname {} failed", name)));
            }
        }

        // Remove null terminator if present
        if let Some(pos) = buffer.iter().position(|&b| b == 0) {
            buffer.truncate(pos);
        }

        String::from_utf8(buffer)
            .map_err(|_| SysInfoError::Parse("Invalid UTF-8 in sysctl string".to_string()))
    }
}

// ============================================================================
// Windows Implementation
// ============================================================================

#[cfg(target_os = "windows")]
mod windows {
    use super::*;
    use windows::Win32::System::SystemInformation::{
        GetSystemInfo, SYSTEM_INFO,
    };
    use windows::Win32::System::Threading::{
        GetCurrentProcess,
    };
    use windows::Win32::System::ProcessStatus::{
        GetProcessTimes,
    };
    use std::mem;

    pub fn get_cpu_info() -> Result<CpuInfo> {
        let mut info = CpuInfo::default();

        unsafe {
            let mut system_info: SYSTEM_INFO = mem::zeroed();
            GetSystemInfo(&mut system_info);

            info.logical_cores = system_info.dwNumberOfProcessors;
            info.physical_cores = system_info.dwNumberOfProcessors; // Simplified

            // Get processor name from registry
            info.model_name = get_cpu_name_from_registry().unwrap_or_else(|_| "Unknown".to_string());
        }

        Ok(info)
    }

    pub fn get_cpu_times() -> Result<Vec<CpuTimes>> {
        use windows::Win32::System::SystemInformation::{GetSystemProcessorPerformanceInformation, SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION};
        let mut performance_info_count: u32 = 0;
        let mut performance_info: Vec<SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION> = Vec::new();
        let mut times = Vec::new();
        unsafe {
            GetSystemProcessorPerformanceInformation(&mut performance_info, &mut performance_info_count)?;
            for i in 0..performance_info_count {
                let time = CpuTimes::default();
                time.user = performance_info[i].UserTime.QuadPart;
                time.system = performance_info[i].KernelTime.QuadPart;
                time.idle = performance_info[i].IdleTime.QuadPart;
                times.push(time);
            }
            Ok(times)
        }
    }

    fn filetime_to_u64(ft: &windows::Win32::Foundation::FILETIME) -> u64 {
        ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
    }

    fn get_cpu_name_from_registry() -> Result<String> {
        use std::process::Command;

        // Use wmic to get CPU name (simpler than registry access)
        let output = Command::new("wmic")
            .args(["cpu", "get", "name"])
            .output()
            .map_err(|e| SysInfoError::SysCall(format!("Failed to run wmic: {}", e)))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let name = output_str
            .lines()
            .skip(1) // Skip header
            .next()
            .unwrap_or("Unknown")
            .trim()
            .to_string();

        Ok(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cpu_info() {
        let info = get_cpu_info().expect("Failed to get CPU info");
        assert!(info.logical_cores > 0, "Should have at least 1 logical core");
        assert!(info.physical_cores > 0, "Should have at least 1 physical core");
    }

    #[test]
    fn test_get_cpu_times() {
        let times = get_cpu_times().expect("Failed to get CPU times");
        // At least one of these should be non-zero
        assert!(
            times.len() > 0 && (times[0].user > 0 || times[0].system > 0 || times[0].idle > 0),
            "CPU times should have some activity"
        );
        println!("CPU times: {:?}", times);
    }
}
