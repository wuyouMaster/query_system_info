// 从字节流中安全读取 u32
pub fn read_u32(data: &[u8], offset: usize) -> Option<u32> {
    if offset + 4 <= data.len() {
        Some(u32::from_ne_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]))
    } else {
        None
    }
}

pub fn read_u32_as_usize(data: &[u8], offset: usize) -> Option<usize> {
    if offset + 4 <= data.len() {
        Some(u32::from_ne_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize)
    } else {
        None
    }
}

// 从字节流中安全读取 i32
pub fn read_i32(data: &[u8], offset: usize) -> Option<i32> {
    if offset + 4 <= data.len() {
        Some(i32::from_ne_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]))
    } else {
        None
    }
}
