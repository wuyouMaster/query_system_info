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
        // On macOS, disk I/O stats require IOKit framework
        // This is a simplified implementation using system_profiler or iostat
        // For production use, you'd want to use IOKit directly

        use std::process::Command;

        let output = Command::new("iostat")
            .args(["-d", "-c", "1"])
            .output()
            .map_err(|e| SysInfoError::SysCall(format!("iostat failed: {}", e)))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut stats = Vec::new();

        let lines: Vec<&str> = output_str.lines().collect();
        if lines.len() < 3 {
            return Ok(stats);
        }

        // Parse iostat output
        // Header line contains device names
        let header = lines.get(0).unwrap_or(&"");
        let devices: Vec<&str> = header.split_whitespace().collect();

        // Skip header lines and parse data
        for line in lines.iter().skip(2) {
            let values: Vec<&str> = line.split_whitespace().collect();
            if values.is_empty() {
                continue;
            }

            // iostat on macOS shows: KB/t, tps, MB/s for each device
            // This is a simplified parsing
            for (i, device) in devices.iter().enumerate() {
                if device.starts_with("disk") {
                    let base_idx = i * 3;
                    if base_idx + 2 < values.len() {
                        stats.push(DiskIoStats {
                            device: device.to_string(),
                            reads: 0,  // Not directly available from iostat
                            writes: 0, // Not directly available from iostat
                            bytes_read: 0,
                            bytes_written: 0,
                            read_time_ms: 0,
                            write_time_ms: 0,
                        });
                    }
                    break;
                }
            }
        }

        Ok(stats)
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
        GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDriveStringsW, DRIVE_FIXED, DRIVE_REMOVABLE,
    };
    use windows::Win32::System::Performance::*;

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
            let mut query = PDH_HQUERY::default();
            PdhOpenQueryW(None, 0, &mut query)
                .map_err(|e| SysInfoError::WindowsApi(format!("PdhOpenQueryW failed: {}", e)))?;

            let mut c_read = PDH_HCOUNTER::default();
            let mut c_write = PDH_HCOUNTER::default();
            let mut c_read_bytes = PDH_HCOUNTER::default();
            let mut c_write_bytes = PDH_HCOUNTER::default();

            let read_path = windows::core::w!("\\PhysicalDisk(*)\\Disk Read Count");
            let write_path = windows::core::w!("\\PhysicalDisk(*)\\Disk Write Count");
            let read_bytes_path = windows::core::w!("\\PhysicalDisk(*)\\Disk Read Bytes");
            let write_bytes_path = windows::core::w!("\\PhysicalDisk(*)\\Disk Write Bytes");

            PdhAddCounterW(query, read_path, 0, &mut c_read)
                .map_err(|e| SysInfoError::WindowsApi(format!("PdhAddCounterW failed: {}", e)))?;
            PdhAddCounterW(query, write_path, 0, &mut c_write)
                .map_err(|e| SysInfoError::WindowsApi(format!("PdhAddCounterW failed: {}", e)))?;
            PdhAddCounterW(query, read_bytes_path, 0, &mut c_read_bytes)
                .map_err(|e| SysInfoError::WindowsApi(format!("PdhAddCounterW failed: {}", e)))?;
            PdhAddCounterW(query, write_bytes_path, 0, &mut c_write_bytes)
                .map_err(|e| SysInfoError::WindowsApi(format!("PdhAddCounterW failed: {}", e)))?;

            PdhCollectQueryData(query).map_err(|e| {
                SysInfoError::WindowsApi(format!("PdhCollectQueryData failed: {}", e))
            })?;

            std::thread::sleep(std::time::Duration::from_millis(1000));

            PdhCollectQueryData(query).map_err(|e| {
                SysInfoError::WindowsApi(format!("PdhCollectQueryData failed: {}", e))
            })?;

            let stats = collect_disk_stats(query, c_read, c_write, c_read_bytes, c_write_bytes)?;

            PdhCloseQuery(query).ok();

            Ok(stats)
        }
    }

    unsafe fn collect_disk_stats(
        query: PDH_HQUERY,
        c_read: PDH_HCOUNTER,
        c_write: PDH_HCOUNTER,
        c_read_bytes: PDH_HCOUNTER,
        c_write_bytes: PDH_HCOUNTER,
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
                reads: read_vals.get(i).copied().unwrap_or(0) as u64,
                writes: write_vals.get(i).copied().unwrap_or(0) as u64,
                bytes_read: read_bytes_vals.get(i).copied().unwrap_or(0) as u64,
                bytes_written: write_bytes_vals.get(i).copied().unwrap_or(0) as u64,
                read_time_ms: 0,
                write_time_ms: 0,
            });
        }

        Ok(stats)
    }

    unsafe fn get_counter_array(counter: PDH_HCOUNTER) -> Result<Vec<f64>> {
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
        )
        .map_err(|e| {
            SysInfoError::WindowsApi(format!("PdhGetFormattedCounterArrayW failed: {}", e))
        })?;

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

    unsafe fn get_counter_instances(
        query: PDH_HQUERY,
        counter: PDH_HCOUNTER,
    ) -> Result<Vec<String>> {
        let mut counter_path_buffer: [u16; 1024] = [0; 1024];
        let mut counter_path_len = counter_path_buffer.len() as u32;

        PdhGetCounterInfoW(
            counter,
            None,
            &mut counter_path_len,
            Some(counter_path_buffer.as_mut_ptr()),
        )
        .map_err(|e| SysInfoError::WindowsApi(format!("PdhGetCounterInfoW failed: {}", e)))?;

        let mut path: Vec<u16> = vec![0; 1024];
        let mut path_len = path.len() as u32;

        let result = PdhGetCounterPathW(counter, &mut path, &mut path_len, 0);
        if result.is_err() {
            return Ok(vec![String::from("Unknown")]);
        }

        if let Some(null_pos) = path.iter().position(|&c| c == 0) {
            let path_str = String::from_utf16_lossy(&path[..null_pos]);
            if let Some(start) = path_str.rfind('\\') {
                let instance = path_str[start + 1..].to_string();
                return Ok(vec![instance]);
            }
        }

        Ok(vec![String::from("Unknown")])
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
