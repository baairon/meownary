//! Minimal PE image for tests that require a validated layout.

pub fn pe_bytes() -> Vec<u8> {
    let mut b = vec![0; 512];
    b[..2].copy_from_slice(b"MZ");
    b[0x3c..0x40].copy_from_slice(&64u32.to_le_bytes());
    b[64..68].copy_from_slice(b"PE\0\0");
    b[68..70].copy_from_slice(&0x14cu16.to_le_bytes());
    b[70..72].copy_from_slice(&1u16.to_le_bytes());
    b[84..86].copy_from_slice(&96u16.to_le_bytes());
    b[88..90].copy_from_slice(&0x10bu16.to_le_bytes());
    b[148..152].copy_from_slice(&256u32.to_le_bytes());
    b[184..189].copy_from_slice(b".data");
    b[192..196].copy_from_slice(&256u32.to_le_bytes());
    b[196..200].copy_from_slice(&0x1000u32.to_le_bytes());
    b[200..204].copy_from_slice(&256u32.to_le_bytes());
    b[204..208].copy_from_slice(&256u32.to_le_bytes());
    b[220..224].copy_from_slice(&0x40000040u32.to_le_bytes());
    b
}
