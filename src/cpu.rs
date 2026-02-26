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
    return innerWindows::get_cpu_info();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

/// Get CPU usage percentage (requires two samples with a delay)
pub fn get_cpu_usage(sample_duration: Duration) -> Result<Vec<f64>> {
    let times1 = get_cpu_times()?;
    thread::sleep(sample_duration);
    let times2 = get_cpu_times()?;

    let mut usages = Vec::new();
    for i in 0..times1.len() {
        let total1 =
            times1[i].user + times1[i].system + times1[i].idle + times1[i].nice + times1[i].iowait;
        let total2 =
            times2[i].user + times2[i].system + times2[i].idle + times2[i].nice + times2[i].iowait;
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
    return innerWindows::get_cpu_times();

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
    use regex::Regex;
    use std::fs;
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
        if let Ok(cores) =
            fs::read_to_string("/sys/devices/system/cpu/cpu0/topology/core_siblings_list")
        {
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
        let cpu_regex =
            CPU_REGEX.get_or_init(|| Regex::new(r"cpu\d+").expect("Failed to create CPU regex"));
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
                return Err(SysInfoError::SysCall(format!(
                    "sysctlbyname {} failed",
                    name
                )));
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
                return Err(SysInfoError::SysCall(format!(
                    "sysctlbyname {} failed",
                    name
                )));
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
                return Err(SysInfoError::SysCall(format!(
                    "sysctlbyname {} failed",
                    name
                )));
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
                return Err(SysInfoError::SysCall(format!(
                    "sysctlbyname {} failed",
                    name
                )));
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
mod innerWindows {
    use super::*;
    use std::mem;
    use windows::Win32::System::Performance::*;
    #[cfg(target_arch = "x86_64", target_arch = "x86")]
    pub fn get_cpu_vendor() -> String {
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::__cpuid;

        #[cfg(target_arch = "x86")]
        use std::arch::x86::__cpuid;
        let res = unsafe { __cpuid(0) };

        // leaf 0 的 ebx/edx/ecx 拼成 12 字节厂商字符串
        // 注意顺序是 ebx -> edx -> ecx，不是 ebx -> ecx -> edx
        let mut raw = Vec::with_capacity(12);
        raw.extend_from_slice(&res.ebx.to_le_bytes());
        raw.extend_from_slice(&res.edx.to_le_bytes());
        raw.extend_from_slice(&res.ecx.to_le_bytes());

        let raw = match std::str::from_utf8(&raw) {
            Ok(s) => s.trim_matches('\0').to_owned(),
            Err(_) => return String::from("Unknown"),
        };

        match raw.as_str() {
            "GenuineIntel"   => "Intel".to_string(),
            "AuthenticAMD"   => "AMD".to_string(),
            "HygonGenuine"   => "Hygon".to_string(),      // 海光（AMD 授权国产）
            "GenuineTMx86"   => "Transmeta".to_string(),
            "CyrixInstead"   => "Cyrix".to_string(),
            "CentaurHauls"   => "VIA".to_string(),         // VIA / Centaur
            "VIA VIA VIA "   => "VIA".to_string(),
            "SiS SiS SiS "   => "SiS".to_string(),
            "NexGenDriven"   => "NexGen".to_string(),
            "UMC UMC UMC "   => "UMC".to_string(),
            "RiseRiseRise"   => "Rise".to_string(),
            "Geode by NSC"   => "National Semiconductor".to_string(),
            // 虚拟机 Hypervisor
            "KVMKVMKVM\0\0\0" => "KVM".to_string(),
            "VMwareVMware"   => "VMware".to_string(),
            "Microsoft Hv"   => "Hyper-V".to_string(),
            "XenVMMXenVMM"   => "Xen".to_string(),
            "VBoxVBoxVBox"   => "VirtualBox".to_string(),
            "TCGTCGTCGTCG"   => "QEMU".to_string(),
            other            => other.to_string(),          // 保底返回原始值
        }
    }

    #[cfg(target_arch = "x86_64", target_arch = "x86")]
    pub fn get_cpu_model_name() -> String {
        #[cfg(target_arch = "x86")]
        use std::arch::x86::__cpuid;
        #[cfg(target_arch = "x86_64")]
        use std::arch::x86_64::__cpuid;

        // 查询最大支持的扩展 leaf
        let res = unsafe {__cpuid(0x80000000)};
        if res.eax < 0x80000004 {
            return String::new(); // CPU 太老，不支持品牌字符串
        }

        let mut out: Vec<u8> = Vec::with_capacity(48);
        // 0x80000002, 0x80000003, 0x80000004 各给 16 字节，共 48 字节
        for leaf in 0x80000002..=0x80000004 {
            let res = unsafe { __cpuid(leaf) };
            for reg in [res.eax, res.ebx, res.ecx, res.edx] {
                out.extend_from_slice(&reg.to_le_bytes());
            }
        }

        // 截断到第一个 null 字节
        let end = out.iter().position(|&b| b == 0).unwrap_or(out.len());
        match std::str::from_utf8(&out[..end]) {
            Ok(s) => s.trim().to_owned(),
            Err(_) => String::new(),
        }
    }

    pub fn get_cpu_cores() -> (u32, u32) {
        let mut len = 0;
        // First call to get required buffer size
        unsafe {
            GetLogicalProcessorInformation(None, &mut len);
        }

        let mut buffer = Vec::with_capacity((len as usize) / mem::size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>() + 1);
        
        // Second call to get actual data
        unsafe {
            GetLogicalProcessorInformation(Some(buffer.as_mut_ptr()), &mut len).expect("Failed to get processor info");
            buffer.set_len((len as usize) / mem::size_of::<SYSTEM_LOGICAL_PROCESSOR_INFORMATION>());
        }

        let mut phys_cores = 0;
        let mut log_cores = 0;

        for info in buffer {
            if info.Relationship == RelationProcessorCore {
                phys_cores += 1;
                // Count set bits in the mask to get logical cores per physical
                log_cores += info.ProcessorMask.count_ones() as usize;
            }
        }

        (phys_cores as u32, log_cores as u32)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn get_cpu_model_name() -> String {
        use windows::Win32::System::Registry::{RegOpenKeyExW, RegQueryValueExW, RegCloseKey};
        use windows::Win32::System::Registry::{HKEY, KEY_READ, REG_VALUE_TYPE};
        unsafe {
            let subkey = windows::core::w!(
                "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
            );
            
            let mut hkey = HKEY::default();
            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey,
                0,
                KEY_READ,
                &mut hkey,
            ).is_err() {
                return String::new();
            }
    
            let value_name = windows::core::w!("ProcessorNameString");
            let mut data_type = REG_VALUE_TYPE::default();
            let mut buf = vec![0u8; 256];
            let mut buf_len = buf.len() as u32;
    
            let result = RegQueryValueExW(
                hkey,
                value_name,
                None,
                Some(&mut data_type),
                Some(buf.as_mut_ptr()),
                Some(&mut buf_len),
            );
    
            RegCloseKey(hkey);
    
            if result.is_err() {
                return String::new();
            }
    
            // buf 是 UTF-16LE，转成 Rust String
            let words: Vec<u16> = buf[..buf_len as usize]
                .chunks_exact(2)
                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                .take_while(|&w| w != 0)
                .collect();
    
            String::from_utf16_lossy(&words)
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn get_cpu_vendor() -> String {
        use windows::Win32::System::Registry::{RegOpenKeyExW, RegQueryValueExW, RegCloseKey};
        use windows::Win32::System::Registry::{HKEY, KEY_READ, REG_VALUE_TYPE};
        unsafe {
            let subkey = windows::core::w!(
                "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0"
            );
            
            let mut hkey = HKEY::default();
            if RegOpenKeyExW(
                HKEY_LOCAL_MACHINE,
                subkey,
                0,
                KEY_READ,
                &mut hkey,
            ).is_err() {
                return String::new();
            }
        }
        let value_name = windows::core::w!("VendorIdentifier");
        let mut data_type = REG_VALUE_TYPE::default();
        let mut buf = vec![0u8; 256];
        let mut buf_len = buf.len() as u32;
        let result = RegQueryValueExW(
            hkey,
            value_name,
        );
        RegCloseKey(hkey);
        if result.is_err() {
            return String::new();
        }
        let words: Vec<u16> = buf[..buf_len as usize]
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .take_while(|&w| w != 0)
            .collect();
        String::from_utf16_lossy(&words)
    }

    pub fn get_cpu_info() -> Result<CpuInfo> {
        let mut info = CpuInfo::default();

        unsafe {
            let (physical_cores, logical_cores) = get_cpu_cores();
            info.logical_cores = logical_cores;
            info.physical_cores = physical_cores;
            info.model_name = get_cpu_model_name();
            info.vendor = get_cpu_vendor();
        }

        Ok(info)
    }
    
    unsafe fn collect_counter_array(counter: PDH_HCOUNTER) -> Vec<f64> {
        let mut buf_size = 0u32;
        let mut item_count = 0u32;
        let _ = PdhGetFormattedCounterArrayW(
            counter, PDH_FMT_DOUBLE,
            &mut buf_size, &mut item_count, None,
        );
        let mut items = vec![
            PDH_FMT_COUNTERVALUE_ITEM_W::default();
            buf_size as usize / std::mem::size_of::<PDH_FMT_COUNTERVALUE_ITEM_W>()
        ];
        PdhGetFormattedCounterArrayW(
            counter, PDH_FMT_DOUBLE,
            &mut buf_size, &mut item_count,
            Some(items.as_mut_ptr()),
        ).unwrap();
        items[..item_count as usize]
            .iter()
            .map(|item| item.FmtValue.Anonymous.doubleValue)
            .collect()
    }

    pub fn get_cpu_times() -> Result<Vec<CpuTimes>> {
        unsafe {
            let mut query = PDH_HQUERY::default();
            PdhOpenQueryW(None, 0, &mut query).unwrap();
    
            // 同时注册多个计数器
            let mut c_user     = PDH_HCOUNTER::default();
            let mut c_system   = PDH_HCOUNTER::default();
            let mut c_idle     = PDH_HCOUNTER::default();
            let mut c_irq      = PDH_HCOUNTER::default();
            let mut c_dpc      = PDH_HCOUNTER::default();
    
            PdhAddCounterW(query, windows::core::w!(r"\Processor(*)\% User Time"),        0, &mut c_user).unwrap();
            PdhAddCounterW(query, windows::core::w!(r"\Processor(*)\% Privileged Time"),  0, &mut c_system).unwrap();
            PdhAddCounterW(query, windows::core::w!(r"\Processor(*)\% Idle Time"),        0, &mut c_idle).unwrap();
            PdhAddCounterW(query, windows::core::w!(r"\Processor(*)\% Interrupt Time"),   0, &mut c_irq).unwrap();
            PdhAddCounterW(query, windows::core::w!(r"\Processor(*)\% DPC Time"),         0, &mut c_dpc).unwrap();
    
            // 两次采样
            PdhCollectQueryData(query).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1000));
            PdhCollectQueryData(query).unwrap();
    
            // 读取每个计数器的数组
            let user_vals   = collect_counter_array(c_user);
            let system_vals = collect_counter_array(c_system);
            let idle_vals   = collect_counter_array(c_idle);
            let irq_vals    = collect_counter_array(c_irq);
            let dpc_vals    = collect_counter_array(c_dpc);
    
            PdhCloseQuery(query).unwrap();
    
            // 最后一项是 _Total，跳过
            let core_count = user_vals.len().saturating_sub(1);
            let times = (0..core_count).map(|i| CpuTimes {
                user:      user_vals[i],
                system:    system_vals[i],
                idle:      idle_vals[i],
                interrupt: irq_vals[i],
                dpc:       dpc_vals[i],
            }).collect();

        }
    }

    fn filetime_to_u64(ft: &windows::Win32::Foundation::FILETIME) -> u64 {
        ((ft.dwHighDateTime as u64) << 32) | (ft.dwLowDateTime as u64)
    }

}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_cpu_info() {
        let info = get_cpu_info().expect("Failed to get CPU info");
        println!("CPU info: {:?}", info);
        assert!(
            info.logical_cores > 0,
            "Should have at least 1 logical core"
        );
        assert!(
            info.physical_cores > 0,
            "Should have at least 1 physical core"
        );
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
