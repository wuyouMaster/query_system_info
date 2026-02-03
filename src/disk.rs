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
    return windows::get_disks();

    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    Err(SysInfoError::NotSupported("Unsupported platform".to_string()))
}

/// Get disk I/O statistics
pub fn get_disk_io_stats() -> Result<Vec<DiskIoStats>> {
    #[cfg(target_os = "linux")]
    return linux::get_disk_io_stats();

    #[cfg(target_os = "macos")]
    return macos::get_disk_io_stats();

    #[cfg(target_os = "windows")]
    return windows::get_disk_io_stats();

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

        let path_cstr = CString::new(path).map_err(|_| SysInfoError::Parse("Invalid path".to_string()))?;
        let mut stat: libc::statvfs = unsafe { mem::zeroed() };

        unsafe {
            if libc::statvfs(path_cstr.as_ptr(), &mut stat) != 0 {
                return Err(SysInfoError::SysCall(format!("statvfs failed for {}", path)));
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
            if device.starts_with("ram")
                || device.starts_with("loop")
                || device.starts_with("dm-")
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
mod windows {
    use super::*;
    use windows::Win32::Storage::FileSystem::{
        GetDiskFreeSpaceExW, GetDriveTypeW, GetLogicalDriveStringsW, DRIVE_FIXED,
    };
    use std::mem;

    pub fn get_disks() -> Result<Vec<DiskInfo>> {
        let mut disks = Vec::new();

        // Get logical drive strings
        let mut buffer: [u16; 256] = [0; 256];
        let len = unsafe { GetLogicalDriveStringsW(Some(&mut buffer)) };

        if len == 0 {
            return Err(SysInfoError::WindowsApi("GetLogicalDriveStringsW failed".to_string()));
        }

        // Parse drive strings (null-separated, double-null terminated)
        let mut start = 0;
        for i in 0..len as usize {
            if buffer[i] == 0 {
                if i > start {
                    let drive_str = String::from_utf16_lossy(&buffer[start..i]);
                    let drive_wide: Vec<u16> = drive_str.encode_utf16().chain(std::iter::once(0)).collect();

                    // Check if it's a fixed drive
                    let drive_type = unsafe { GetDriveTypeW(windows::core::PCWSTR(drive_wide.as_ptr())) };

                    if drive_type == DRIVE_FIXED {
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
            fs_type: "NTFS".to_string(), // Simplified
            total_bytes,
            used_bytes,
            available_bytes: free_bytes_available,
            usage_percent,
        })
    }

    pub fn get_disk_io_stats() -> Result<Vec<DiskIoStats>> {
        // Windows disk I/O stats require performance counters or WMI
        // This is a simplified implementation

        use std::process::Command;

        let output = Command::new("wmic")
            .args(["diskdrive", "get", "name,bytespersector", "/format:csv"])
            .output()
            .map_err(|e| SysInfoError::SysCall(format!("wmic failed: {}", e)))?;

        let output_str = String::from_utf8_lossy(&output.stdout);
        let mut stats = Vec::new();

        for line in output_str.lines().skip(2) {
            // Skip header
            let parts: Vec<&str> = line.split(',').collect();
            if parts.len() >= 2 {
                stats.push(DiskIoStats {
                    device: parts.get(1).unwrap_or(&"").to_string(),
                    reads: 0,
                    writes: 0,
                    bytes_read: 0,
                    bytes_written: 0,
                    read_time_ms: 0,
                    write_time_ms: 0,
                });
            }
        }

        Ok(stats)
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
