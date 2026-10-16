//! A minimal TIFF/EXIF reader: just enough of IFD0 to name the camera and the
//! software that last wrote the file, and to notice a GPS block. Shared by the
//! JPEG APP1, PNG eXIf and WebP EXIF paths.

use crate::util::bytes::{cstr, slice, u16_be, u16_le, u32_be, u32_le};

const TAG_MAKE: u16 = 0x010F;
const TAG_MODEL: u16 = 0x0110;
const TAG_SOFTWARE: u16 = 0x0131;
const TAG_DATETIME: u16 = 0x0132;
const TAG_GPS_IFD: u16 = 0x8825;
const TYPE_ASCII: u16 = 2;
/// Most IFD0 entries examined.
const MAX_IFD_ENTRIES: usize = 512;
/// Longest ASCII value kept.
const MAX_ASCII: usize = 256;

/// What IFD0 says about where the image came from.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct ExifSummary {
    pub make: Option<String>,
    pub model: Option<String>,
    /// The Software tag value and its byte offset within the TIFF block.
    pub software: Option<(String, usize)>,
    pub datetime: Option<String>,
    pub gps: bool,
}

impl ExifSummary {
    /// "Canon EOS R5" style camera label, if either part is known.
    pub fn camera(&self) -> Option<String> {
        match (&self.make, &self.model) {
            (Some(make), Some(model)) if model.starts_with(make.as_str()) => Some(model.clone()),
            (Some(make), Some(model)) => Some(format!("{make} {model}")),
            (Some(one), None) | (None, Some(one)) => Some(one.clone()),
            (None, None) => None,
        }
    }

    /// A comma-separated description for a note, or `None` when empty.
    pub fn describe(&self) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(cam) = self.camera() {
            parts.push(format!("camera {cam}"));
        }
        if let Some((sw, _)) = &self.software {
            parts.push(format!("software {sw}"));
        }
        if let Some(dt) = &self.datetime {
            parts.push(format!("modified {dt}"));
        }
        if self.gps {
            parts.push("GPS position".to_string());
        }
        (!parts.is_empty()).then(|| parts.join(", "))
    }
}

/// Parse IFD0 of the TIFF block `tiff`. `None` when the TIFF header is invalid.
pub(crate) fn parse_tiff(tiff: &[u8]) -> Option<ExifSummary> {
    let le = match slice(tiff, 0, 2)? {
        b"II" => true,
        b"MM" => false,
        _ => return None,
    };
    let r16 = |o: usize| {
        if le { u16_le(tiff, o) } else { u16_be(tiff, o) }
    };
    let r32 = |o: usize| {
        if le { u32_le(tiff, o) } else { u32_be(tiff, o) }
    };
    if r16(2)? != 42 {
        return None;
    }
    let ifd = r32(4)? as usize;
    let count = (r16(ifd)? as usize).min(MAX_IFD_ENTRIES);
    let mut out = ExifSummary::default();
    for i in 0..count {
        let e = ifd + 2 + i * 12;
        let (Some(tag), Some(ty), Some(n)) = (r16(e), r16(e + 2), r32(e + 4)) else {
            break;
        };
        if tag == TAG_GPS_IFD {
            out.gps = true;
            continue;
        }
        if ty != TYPE_ASCII || !matches!(tag, TAG_MAKE | TAG_MODEL | TAG_SOFTWARE | TAG_DATETIME) {
            continue;
        }
        let n = n as usize;
        let at = if n <= 4 {
            e + 8
        } else {
            match r32(e + 8) {
                Some(o) => o as usize,
                None => continue,
            }
        };
        let Some(raw) = cstr(tiff, at, n.min(MAX_ASCII)) else {
            continue;
        };
        if slice(tiff, at, raw.len()).is_none() {
            continue;
        }
        let value = String::from_utf8_lossy(raw).trim().to_string();
        if value.is_empty() {
            continue;
        }
        match tag {
            TAG_MAKE => out.make = Some(value),
            TAG_MODEL => out.model = Some(value),
            TAG_SOFTWARE => out.software = Some((value, at)),
            _ => out.datetime = Some(value),
        }
    }
    Some(out)
}

/// Test builder: a little-endian TIFF block with ASCII IFD0 entries and an
/// optional GPS pointer.
#[cfg(test)]
pub(crate) fn build_tiff(ascii: &[(u16, &str)], gps: bool) -> Vec<u8> {
    let count = ascii.len() + usize::from(gps);
    let data_start = 8 + 2 + count * 12 + 4;
    let mut ifd = Vec::new();
    let mut data = Vec::new();
    ifd.extend_from_slice(&(count as u16).to_le_bytes());
    for (tag, value) in ascii {
        let mut v = value.as_bytes().to_vec();
        v.push(0);
        ifd.extend_from_slice(&tag.to_le_bytes());
        ifd.extend_from_slice(&TYPE_ASCII.to_le_bytes());
        ifd.extend_from_slice(&(v.len() as u32).to_le_bytes());
        if v.len() <= 4 {
            v.resize(4, 0);
            ifd.extend_from_slice(&v);
        } else {
            ifd.extend_from_slice(&((data_start + data.len()) as u32).to_le_bytes());
            data.extend_from_slice(&v);
        }
    }
    if gps {
        ifd.extend_from_slice(&TAG_GPS_IFD.to_le_bytes());
        ifd.extend_from_slice(&4u16.to_le_bytes());
        ifd.extend_from_slice(&1u32.to_le_bytes());
        ifd.extend_from_slice(&0u32.to_le_bytes());
    }
    ifd.extend_from_slice(&0u32.to_le_bytes());
    let mut out = b"II\x2a\x00\x08\x00\x00\x00".to_vec();
    out.extend_from_slice(&ifd);
    out.extend_from_slice(&data);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_ifd0() {
        let t = build_tiff(
            &[
                (TAG_MAKE, "Canon"),
                (TAG_MODEL, "Canon EOS R5"),
                (TAG_SOFTWARE, "GIMP 2.10"),
            ],
            true,
        );
        let s = parse_tiff(&t).unwrap();
        assert_eq!(s.camera().as_deref(), Some("Canon EOS R5"));
        let (sw, at) = s.software.clone().unwrap();
        assert_eq!(sw, "GIMP 2.10");
        assert_eq!(&t[at..at + 9], b"GIMP 2.10");
        assert!(s.gps);
        assert!(s.describe().unwrap().contains("GPS"));
    }

    #[test]
    fn rejects_bad_headers_and_survives_truncation() {
        assert!(parse_tiff(b"XX\x2a\x00").is_none());
        assert!(parse_tiff(&[0; 16]).is_none());
        let t = build_tiff(
            &[(TAG_SOFTWARE, "x"), (TAG_MAKE, "Nikon Corporation")],
            false,
        );
        for cut in 0..t.len() {
            let _ = parse_tiff(&t[..cut]);
        }
    }
}
