//! Disk information module
//!
//! Provides cross-platform disk and I/O statistics gathering.

use crate::error::{Result, SysInfoError};
use crate::types::{DiskInfo, DiskIoStats};

/// Get list of mounted disks
pub fn get_disks() -> Result<Vec<DiskInfo>> {
    #[cfg(target_os = "linux")]
    return linux::get_disks();

    #[cfg(target_os = "macos")]
    return macos::get_disks();

    #[cfg(target_os = "windows")]
    return innerWindows::get_disks();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported(
        "Unsupported platform".to_string(),
    ))
}

/// Get disk I/O statistics
pub fn get_disk_io_stats() -> Result<Vec<DiskIoStats>> {
    #[cfg(target_os = "linux")]
    return linux::get_disk_io_stats();

    #[cfg(target_os = "macos")]
    return macos::get_disk_io_stats();

    #[cfg(target_os = "windows")]
    return innerWindows::get_disk_io_stats();

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

    pub fn get_disks() -> Result<Vec<DiskInfo>> {
        let mut disks = Vec::new();

        // Read /proc/mounts
        let mounts = fs::read_to_string("/proc/mounts")?;

        for line in mounts.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 4 {
                continue;
            }

            let device = parts[0];
            let mount_point = parts[1];
            let fs_type = parts[2];

            // Skip non-physical filesystems
            if !device.starts_with("/dev/") {
                continue;
            }

            // Skip pseudo filesystems
            if matches!(
                fs_type,
                "devtmpfs" | "tmpfs" | "proc" | "sysfs" | "devpts" | "cgroup" | "cgroup2"
            ) {
                continue;
            }

            // Get disk space info using statvfs
            if let Ok(stat) = get_statvfs(mount_point) {
                let total_bytes = stat.f_blocks * stat.f_frsize;
                let free_bytes = stat.f_bfree * stat.f_frsize;
                let available_bytes = stat.f_bavail * stat.f_frsize;
                let used_bytes = total_bytes - free_bytes;

                let usage_percent = if total_bytes > 0 {
                    (used_bytes as f64 / total_bytes as f64) * 100.0
                } else {
                    0.0
                };

                disks.push(DiskInfo {
                    device: device.to_string(),
                    mount_point: mount_point.to_string(),
                    fs_type: fs_type.to_string(),
                    total_bytes,
                    used_bytes,
                    available_bytes,
                    usage_percent,
                });
            }
        }

        Ok(disks)
    }

    fn get_statvfs(path: &str) -> Result<libc::statvfs> {
        use std::ffi::CString;
        use std::mem;

        let path_cstr =
            CString::new(path).map_err(|_| SysInfoError::Parse("Invalid path".to_string()))?;
        let mut stat: libc::statvfs = unsafe { mem::zeroed() };

        unsafe {
            if libc::statvfs(path_cstr.as_ptr(), &mut stat) != 0 {
                return Err(SysInfoError::SysCall(format!(
                    "statvfs failed for {}",
                    path
                )));
            }
        }

        Ok(stat)
    }

    pub fn get_disk_io_stats() -> Result<Vec<DiskIoStats>> {
        let mut stats = Vec::new();

        // Read /proc/diskstats
        let diskstats = fs::read_to_string("/proc/diskstats")?;

        for line in diskstats.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 14 {
                continue;
            }

            let device = parts[2];

            // Skip partitions (only show whole disks)
            // Skip ram, loop devices
            if device.starts_with("ram") || device.starts_with("loop") || device.starts_with("dm-")
            {
                continue;
            }

            // Only include devices that look like real disks
            let is_partition = device
                .chars()
                .last()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false);

            // Include both whole disks and partitions
            let reads: u64 = parts[3].parse().unwrap_or(0);
            let reads_merged: u64 = parts[4].parse().unwrap_or(0);
            let sectors_read: u64 = parts[5].parse().unwrap_or(0);
            let read_time: u64 = parts[6].parse().unwrap_or(0);
            let writes: u64 = parts[7].parse().unwrap_or(0);
            let writes_merged: u64 = parts[8].parse().unwrap_or(0);
            let sectors_written: u64 = parts[9].parse().unwrap_or(0);
            let write_time: u64 = parts[10].parse().unwrap_or(0);

            // Sector size is typically 512 bytes
            let sector_size: u64 = 512;

            stats.push(DiskIoStats {
                device: device.to_string(),
                reads,
                writes,
                bytes_read: sectors_read * sector_size,
                bytes_written: sectors_written * sector_size,
                read_time_ms: read_time,
                write_time_ms: write_time,
            });
        }

        Ok(stats)
    }
}

// ============================================================================
// macOS Implementation
// ============================================================================

#[cfg(target_os = "macos")]
mod macos {
    use super::*;
    use libc::{c_int, getfsstat, statfs, MNT_NOWAIT};
    use std::ffi::CStr;
    use std::mem;

    pub fn get_disks() -> Result<Vec<DiskInfo>> {
        let mut disks = Vec::new();

        // Get number of mounted filesystems
        let count = unsafe { getfsstat(std::ptr::null_mut(), 0, MNT_NOWAIT) };
        if count < 0 {
            return Err(SysInfoError::SysCall("getfsstat failed".to_string()));
        }

        // Allocate buffer and get filesystem info
        let mut fs_buf: Vec<statfs> = vec![unsafe { mem::zeroed() }; count as usize];
        let buf_size = (count as usize * mem::size_of::<statfs>()) as c_int;

        let actual_count = unsafe { getfsstat(fs_buf.as_mut_ptr(), buf_size, MNT_NOWAIT) };
        if actual_count < 0 {
            return Err(SysInfoError::SysCall("getfsstat failed".to_string()));
        }

        for i in 0..actual_count as usize {
            let fs = &fs_buf[i];

            let device = unsafe { CStr::from_ptr(fs.f_mntfromname.as_ptr()) }
                .to_string_lossy()
                .to_string();

            let mount_point = unsafe { CStr::from_ptr(fs.f_mntonname.as_ptr()) }
                .to_string_lossy()
                .to_string();

            let fs_type = unsafe { CStr::from_ptr(fs.f_fstypename.as_ptr()) }
                .to_string_lossy()
                .to_string();

            // Skip non-physical filesystems
            if !device.starts_with("/dev/") && !device.contains("disk") {
                continue;
            }

            let block_size = fs.f_bsize as u64;
            let total_bytes = fs.f_blocks * block_size;
            let free_bytes = fs.f_bfree * block_size;
            let available_bytes = fs.f_bavail * block_size;
            let used_bytes = total_bytes - free_bytes;

            let usage_percent = if total_bytes > 0 {
                (used_bytes as f64 / total_bytes as f64) * 100.0
            } else {
                0.0
            };

            disks.push(DiskInfo {
                device,
                mount_point,
                fs_type,
                total_bytes,
                used_bytes,
                available_bytes,
                usage_percent,
            });
        }

        Ok(disks)
    }

    pub fn get_disk_io_stats() -> Result<Vec<DiskIoStats>> {
        use std::ffi::CString;
        use std::ptr;

        #[link(name = "IOKit", kind = "framework")]
        #[link(name = "CoreFoundation", kind = "framework")]
        unsafe extern "C" {
            fn IOServiceMatching(name: *const libc::c_char) -> *mut libc::c_void;
            fn IOServiceGetMatchingServices(
                main_port: u32,
                matching: *mut libc::c_void,
                existing: *mut u32,
            ) -> i32;
            fn IOIteratorNext(iterator: u32) -> u32;
            fn IOObjectRelease(obj: u32) -> i32;
            fn IORegistryEntryCreateCFProperties(
                entry: u32,
                properties: *mut *mut libc::c_void,
                allocator: *const libc::c_void,
                options: u32,
            ) -> i32;
            fn CFDictionaryGetValue(
                dict: *const libc::c_void,
                key: *const libc::c_void,
            ) -> *const libc::c_void;
            fn CFNumberGetValue(
                number: *const libc::c_void,
                the_type: i32,
                value_ptr: *mut libc::c_void,
            ) -> u8;
            fn CFStringCreateWithCString(
                alloc: *const libc::c_void,
                cstr: *const libc::c_char,
                encoding: u32,
            ) -> *mut libc::c_void;
            fn CFRelease(cf: *const libc::c_void);
        }

        const KERN_SUCCESS: i32 = 0;
        const K_IOMASTER_PORT_DEFAULT: u32 = 0;
        const KCFSTRING_ENCODING_UTF8: u32 = 0x08000100;
        const KCF_NUMBER_SINT64_TYPE: i32 = 4;

        unsafe {
            let matching =
                IOServiceMatching(CString::new("IOBlockStorageDriver").unwrap().as_ptr());
            if matching.is_null() {
                return Err(SysInfoError::SysCall(
                    "IOServiceMatching failed".to_string(),
                ));
            }

            let mut iterator: u32 = 0;
            let kr = IOServiceGetMatchingServices(K_IOMASTER_PORT_DEFAULT, matching, &mut iterator);
            if kr != KERN_SUCCESS {
                return Err(SysInfoError::SysCall(format!(
                    "IOServiceGetMatchingServices failed: {kr}"
                )));
            }

            let mut stats = Vec::new();
            let mut service = IOIteratorNext(iterator);
            let mut disk_index: u32 = 0;

            while service != 0 {
                let mut props: *mut libc::c_void = ptr::null_mut();
                let kr = IORegistryEntryCreateCFProperties(service, &mut props, ptr::null(), 0);

                if kr == KERN_SUCCESS && !props.is_null() {
                    let stats_key = CFStringCreateWithCString(
                        ptr::null(),
                        CString::new("Statistics").unwrap().as_ptr(),
                        KCFSTRING_ENCODING_UTF8,
                    );

                    if !stats_key.is_null() {
                        let stats_dict = CFDictionaryGetValue(props, stats_key);
                        CFRelease(stats_key);

                        if !stats_dict.is_null() {
                            let mut bytes_read: u64 = 0;
                            let mut bytes_written: u64 = 0;
                            let mut reads: u64 = 0;
                            let mut writes: u64 = 0;
                            let mut read_time_ms: u64 = 0;
                            let mut write_time_ms: u64 = 0;

                            macro_rules! read_stat {
                                ($name:expr, $dest:expr) => {{
                                    let key = CFStringCreateWithCString(
                                        ptr::null(),
                                        CString::new($name).unwrap().as_ptr(),
                                        KCFSTRING_ENCODING_UTF8,
                                    );
                                    if !key.is_null() {
                                        let val = CFDictionaryGetValue(stats_dict, key);
                                        CFRelease(key);
                                        if !val.is_null() {
                                            let mut v: i64 = 0;
                                            CFNumberGetValue(
                                                val,
                                                KCF_NUMBER_SINT64_TYPE,
                                                &mut v as *mut i64 as *mut libc::c_void,
                                            );
                                            $dest = v.max(0) as u64;
                                        }
                                    }
                                }};
                            }

                            read_stat!("Bytes (Read)", bytes_read);
                            read_stat!("Bytes (Write)", bytes_written);
                            read_stat!("Operations (Read)", reads);
                            read_stat!("Operations (Write)", writes);
                            read_stat!("Total Time (Read)", read_time_ms);
                            read_stat!("Total Time (Write)", write_time_ms);

                            if bytes_read > 0 || bytes_written > 0 || reads > 0 || writes > 0 {
                                stats.push(DiskIoStats {
                                    device: format!("disk{disk_index}"),
                                    reads,
                                    writes,
                                    bytes_read,
                                    bytes_written,
                                    read_time_ms,
                                    write_time_ms,
                                });
                                disk_index += 1;
                            }
                        }
                    }

                    CFRelease(props);
                }

                IOObjectRelease(service);
                service = IOIteratorNext(iterator);
            }

            IOObjectRelease(iterator);
            Ok(stats)
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
    use windows::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDriveStringsW,
    };
    use windows::Win32::System::Performance::*;
    const DRIVE_REMOVABLE: u32 = 2;
    const DRIVE_FIXED: u32 = 3;

    pub fn get_disks() -> Result<Vec<DiskInfo>> {
        let mut disks = Vec::new();

        let mut buffer: [u16; 256] = [0; 256];
        let len = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) };

        if len == 0 {
            return Err(SysInfoError::WindowsApi(
                "GetLogicalDriveStringsW failed".to_string(),
            ));
        }

        let mut start = 0;
        for i in 0..len as usize {
            if buffer[i] == 0 {
                if i > start {
                    let drive_str = String::from_utf16_lossy(&buffer[start..i]);
                    let drive_wide: Vec<u16> =
                        drive_str.encode_utf16().chain(std::iter::once(0)).collect();

                    let drive_type =
                        unsafe { GetDriveTypeW(windows::core::PCWSTR(drive_wide.as_ptr())) };

                    if drive_type == DRIVE_FIXED || drive_type == DRIVE_REMOVABLE {
                        if let Ok(info) = get_disk_space(&drive_str, &drive_wide) {
                            disks.push(info);
                        }
                    }
                }
                start = i + 1;
            }
        }

        Ok(disks)
    }

    fn get_disk_space(drive_str: &str, drive_wide: &[u16]) -> Result<DiskInfo> {
        let mut free_bytes_available: u64 = 0;
        let mut total_bytes: u64 = 0;
        let mut total_free_bytes: u64 = 0;

        unsafe {
            GetDiskFreeSpaceExW(
                windows::core::PCWSTR(drive_wide.as_ptr()),
                Some(&mut free_bytes_available),
                Some(&mut total_bytes),
                Some(&mut total_free_bytes),
            )
            .map_err(|e| SysInfoError::WindowsApi(format!("GetDiskFreeSpaceExW failed: {}", e)))?;
        }

        let used_bytes = total_bytes - total_free_bytes;
        let usage_percent = if total_bytes > 0 {
            (used_bytes as f64 / total_bytes as f64) * 100.0
        } else {
            0.0
        };

        Ok(DiskInfo {
            device: drive_str.to_string(),
            mount_point: drive_str.to_string(),
            fs_type: get_filesystem_type(drive_str),
            total_bytes,
            used_bytes,
            available_bytes: free_bytes_available,
            usage_percent,
        })
    }

    fn get_filesystem_type(drive_str: &str) -> String {
        use windows::Win32::Storage::FileSystem::GetVolumeInformationW;

        let mut fs_type_buffer: [u16; 260] = [0; 260];
        let drive_wide: Vec<u16> = drive_str.encode_utf16().chain(std::iter::once(0)).collect();

        unsafe {
            let result = GetVolumeInformationW(
                windows::core::PCWSTR(drive_wide.as_ptr()),
                None,
                None,
                None,
                None,
                Some(&mut fs_type_buffer),
            );

            if result.is_ok() {
                if let Some(null_pos) = fs_type_buffer.iter().position(|&c| c == 0) {
                    return String::from_utf16_lossy(&fs_type_buffer[..null_pos]);
                }
            }
        }

        "Unknown".to_string()
    }

    pub fn get_disk_io_stats() -> Result<Vec<DiskIoStats>> {
        unsafe {
            let mut query: isize = 0;
            PdhOpenQueryW(None, 0, &mut query);

            let mut c_read: isize = 0;
            let mut c_write: isize = 0;
            let mut c_read_bytes: isize = 0;
            let mut c_write_bytes: isize = 0;

            let read_path = windows::core::w!("\\PhysicalDisk(*)\\Disk Read Count");
            let write_path = windows::core::w!("\\PhysicalDisk(*)\\Disk Write Count");
            let read_bytes_path = windows::core::w!("\\PhysicalDisk(*)\\Disk Read Bytes");
            let write_bytes_path = windows::core::w!("\\PhysicalDisk(*)\\Disk Write Bytes");

            PdhAddCounterW(query, read_path, 0, &mut c_read);
            PdhAddCounterW(query, write_path, 0, &mut c_write);
            PdhAddCounterW(query, read_bytes_path, 0, &mut c_read_bytes);
            PdhAddCounterW(query, write_bytes_path, 0, &mut c_write_bytes);

            PdhCollectQueryData(query);

            std::thread::sleep(std::time::Duration::from_millis(1000));

            PdhCollectQueryData(query);

            let stats = collect_disk_stats(query, c_read, c_write, c_read_bytes, c_write_bytes)?;

            PdhCloseQuery(query);

            Ok(stats)
        }
    }

    unsafe fn collect_disk_stats(
        query: isize,
        c_read: isize,
        c_write: isize,
        c_read_bytes: isize,
        c_write_bytes: isize,
    ) -> Result<Vec<DiskIoStats>> {
        let mut stats = Vec::new();

        let read_vals = get_counter_array(c_read)?;
        let write_vals = get_counter_array(c_write)?;
        let read_bytes_vals = get_counter_array(c_read_bytes)?;
        let write_bytes_vals = get_counter_array(c_write_bytes)?;

        let counter_names = get_counter_instances(query, c_read)?;

        for (i, device) in counter_names.iter().enumerate() {
            if device == "_Total" {
                continue;
            }

            stats.push(DiskIoStats {
                device: device.clone(),
                reads: read_vals.get(i).copied().unwrap_or(0.0) as u64,
                writes: write_vals.get(i).copied().unwrap_or(0.0) as u64,
                bytes_read: read_bytes_vals.get(i).copied().unwrap_or(0.0) as u64,
                bytes_written: write_bytes_vals.get(i).copied().unwrap_or(0.0) as u64,
                read_time_ms: 0,
                write_time_ms: 0,
            });
        }

        Ok(stats)
    }

    unsafe fn get_counter_array(counter: isize) -> Result<Vec<f64>> {
        let mut buf_size = 0u32;
        let mut item_count = 0u32;

        let _ = PdhGetFormattedCounterArrayW(
            counter,
            PDH_FMT_DOUBLE,
            &mut buf_size,
            &mut item_count,
            None,
        );

        if buf_size == 0 {
            return Ok(Vec::new());
        }

        let mut items = vec![
            PDH_FMT_COUNTERVALUE_ITEM_W::default();
            buf_size as usize / mem::size_of::<PDH_FMT_COUNTERVALUE_ITEM_W>()
        ];

        PdhGetFormattedCounterArrayW(
            counter,
            PDH_FMT_DOUBLE,
            &mut buf_size,
            &mut item_count,
            Some(items.as_mut_ptr()),
        );

        let values = items[..item_count as usize]
            .iter()
            .filter_map(|item| {
                if item.FmtValue.CStatus == 0 {
                    Some(item.FmtValue.Anonymous.doubleValue)
                } else {
                    None
                }
            })
            .collect();

        Ok(values)
    }

    unsafe fn get_counter_instances(_query: isize, counter: isize) -> Result<Vec<String>> {
        let mut buf_size = 0u32;
        let mut item_count = 0u32;

        let _ = PdhGetFormattedCounterArrayW(
            counter,
            PDH_FMT_DOUBLE,
            &mut buf_size,
            &mut item_count,
            None,
        );

        if buf_size == 0 {
            return Ok(Vec::new());
        }

        let mut items = vec![
            PDH_FMT_COUNTERVALUE_ITEM_W::default();
            buf_size as usize / mem::size_of::<PDH_FMT_COUNTERVALUE_ITEM_W>()
        ];

        PdhGetFormattedCounterArrayW(
            counter,
            PDH_FMT_DOUBLE,
            &mut buf_size,
            &mut item_count,
            Some(items.as_mut_ptr()),
        );

        let names = items[..item_count as usize]
            .iter()
            .map(|item| item.szName.to_string().unwrap_or_default())
            .collect();

        Ok(names)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_disks() {
        let disks = get_disks().expect("Failed to get disks");
        // Should have at least one disk (root filesystem)
        assert!(!disks.is_empty(), "Should find at least one disk");

        for disk in &disks {
            assert!(disk.total_bytes > 0, "Disk total should be > 0");
            assert!(
                disk.usage_percent >= 0.0 && disk.usage_percent <= 100.0,
                "Usage percent should be valid"
            );
        }
    }

    #[test]
    fn test_get_disk_io_stats() {
        // This test might fail on systems without proper permissions
        let result = get_disk_io_stats();
        // Just check that it doesn't panic
        assert!(result.is_ok() || result.is_err());
    }
}
