//! FLAC: walk the metadata blocks after `fLaC` and report the Vorbis comment
//! vendor string (the encoder), the comment fields, and embedded pictures.
//!
//! The first block must be a 34-byte STREAMINFO, which is the structural
//! corroboration behind the Strong vendor finding. Fields that steer playback
//! (ReplayGain, R128 gain, the WAVE channel mask) are not reported as tags,
//! so a bulk junk clean never changes how loud or where a track plays.

use super::{Draft, evidence, is_blank, push, read, show, text_marker};
use crate::model::{BrandKind, Category, Confidence, ContainerKind, Finding, JunkKind, Severity};
use crate::scan::FileView;
use crate::util::bytes::{slice, u32_be, u32_le};

/// Most metadata blocks walked.
const MAX_BLOCKS: usize = 128;
/// Most bytes of one VORBIS_COMMENT block read.
const MAX_COMMENT: usize = 1024 * 1024;
/// Most comment fields walked in one comment header.
const MAX_FIELDS: usize = 256;
/// Most pictures reported.
const MAX_PICTURES: usize = 8;

const STREAMINFO: u8 = 0;
const VORBIS_COMMENT: u8 = 4;
const PICTURE: u8 = 6;
const INVALID: u8 = 127;

/// A parsed Vorbis comment header. Offsets are relative to the buffer the
/// header was parsed from (the byte after any codec magic).
pub(super) struct Comments {
    /// Offset and length of the vendor string.
    pub vendor: (usize, usize),
    pub fields: Vec<Field>,
}

/// One `KEY=value` comment field.
pub(super) struct Field {
    /// Offset of the key (just past the 4-byte length).
    pub start: usize,
    /// Length of the key, not counting the `=`.
    pub key_len: usize,
    /// Length of the whole `KEY=value` string.
    pub len: usize,
}

impl Field {
    pub fn key<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        buf.get(self.start..self.start + self.key_len)
            .unwrap_or_default()
    }

    /// Offset and length of the value (after the `=`).
    pub fn value_range(&self) -> (usize, usize) {
        let start = self.start + self.key_len + 1;
        (start, self.len.saturating_sub(self.key_len + 1))
    }

    pub fn value<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let (start, len) = self.value_range();
        buf.get(start..start + len).unwrap_or_default()
    }

    /// Whether the field is a descriptive tag worth reporting: a non-empty
    /// value and not one of the fields that steer playback.
    pub fn is_tag(&self, buf: &[u8]) -> bool {
        let key = self.key(buf).to_ascii_uppercase();
        let playback = key.starts_with(b"REPLAYGAIN_")
            || key.starts_with(b"R128_")
            || key == b"WAVEFORMATEXTENSIBLE_CHANNEL_MASK";
        !playback && !is_blank(self.value(buf))
    }
}

/// Parse a Vorbis comment header (vendor length, vendor, field count, then
/// length-prefixed `KEY=value` fields, all lengths little-endian) from the
/// start of `b`. Fields past the end of `b`, or without an `=`, end the walk.
pub(super) fn parse_comments(b: &[u8]) -> Option<Comments> {
    let vlen = usize::try_from(u32_le(b, 0)?).ok()?;
    slice(b, 4, vlen)?;
    let mut fields = Vec::new();
    let mut pos = 4usize.checked_add(vlen)?;
    let count = u32_le(b, pos).unwrap_or(0) as usize;
    pos += 4;
    for _ in 0..count.min(MAX_FIELDS) {
        let Some(flen) = u32_le(b, pos).and_then(|n| usize::try_from(n).ok()) else {
            break;
        };
        let start = pos + 4;
        let Some(text) = slice(b, start, flen) else {
            break;
        };
        let Some(key_len) = text.iter().position(|&c| c == b'=') else {
            break;
        };
        fields.push(Field {
            start,
            key_len,
            len: flen,
        });
        pos = start + flen;
    }
    Some(Comments {
        vendor: (4, vlen),
        fields,
    })
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    if slice(view.header(), 0, 4) != Some(b"fLaC") {
        return;
    }
    let size = view.size();
    let mut off = 4u64;
    let mut pictures = 0usize;
    for i in 0..MAX_BLOCKS {
        let Some(hb) = read(view, off, 4) else {
            return;
        };
        let Some(&[flags, a, b, c]) = slice(&hb, 0, 4) else {
            return;
        };
        let kind = flags & 0x7f;
        let len = u64::from(u32::from_be_bytes([0, a, b, c]));
        if kind == INVALID || (i == 0 && (kind != STREAMINFO || len != 34)) {
            return;
        }
        let data = off + 4;
        let end = data + len;
        if end > size {
            return;
        }
        match kind {
            VORBIS_COMMENT => comment_block(view, data, len, out),
            PICTURE if pictures < MAX_PICTURES => {
                pictures += 1;
                picture(view, data, len, out);
            }
            _ => {}
        }
        if flags & 0x80 != 0 {
            return;
        }
        off = end;
    }
}

fn comment_block(view: &dyn FileView, data: u64, len: u64, out: &mut Vec<Finding>) {
    let want = usize::try_from(len).unwrap_or(usize::MAX).min(MAX_COMMENT);
    let Some(buf) = read(view, data, want) else {
        return;
    };
    let Some(c) = parse_comments(&buf) else {
        return;
    };
    let (vstart, vlen) = c.vendor;
    let vendor = buf.get(vstart..vstart + vlen).unwrap_or_default();
    if !is_blank(vendor) {
        let v = show(vendor, 60);
        let abs = data + vstart as u64;
        push(
            out,
            Draft {
                category: Category::Brand(BrandKind::MediaEncoder),
                confidence: Confidence::Strong,
                severity: Severity::Info,
                id: "flac.vendor",
                title: format!("FLAC encoder {v}"),
                evidence: evidence(
                    abs,
                    vendor,
                    format!(
                        "VORBIS_COMMENT vendor string = \"{v}\"; scrubbing fills it with spaces and keeps its length"
                    ),
                ),
                marker: text_marker(abs, vlen as u64, ContainerKind::Raw),
            },
        );
    }
    for f in c.fields.iter().filter(|f| f.is_tag(&buf)) {
        let key = show(f.key(&buf), 32);
        let value = f.value(&buf);
        let v = show(value, 40);
        let (vs, vl) = f.value_range();
        let abs = data + vs as u64;
        push(
            out,
            Draft {
                category: Category::Junk(JunkKind::Comment),
                confidence: Confidence::Moderate,
                severity: Severity::Notice,
                id: "flac.tags",
                title: format!("FLAC {key} tag"),
                evidence: evidence(
                    abs,
                    value,
                    format!(
                        "Vorbis comment {key}=\"{v}\"; scrubbing fills the value with spaces and keeps the key and length"
                    ),
                ),
                marker: text_marker(abs, vl as u64, ContainerKind::Raw),
            },
        );
    }
}

fn picture_kind(code: u32) -> &'static str {
    match code {
        1 | 2 => "file icon",
        3 => "front cover",
        4 => "back cover",
        5 => "leaflet page",
        6 => "media label",
        7 => "lead artist",
        8 => "artist",
        13 => "recording location",
        _ => "picture",
    }
}

fn picture(view: &dyn FileView, data: u64, len: u64, out: &mut Vec<Finding>) {
    let Some(b) = read(view, data, len.min(1024) as usize) else {
        return;
    };
    let Some(code) = u32_be(&b, 0) else {
        return;
    };
    let Some(mlen) = u32_be(&b, 4).and_then(|n| usize::try_from(n).ok()) else {
        return;
    };
    let Some(mime) = slice(&b, 8, mlen) else {
        return;
    };
    let Some(dlen) = u32_be(&b, 8 + mlen).and_then(|n| usize::try_from(n).ok()) else {
        return;
    };
    let dims = 12 + mlen + dlen;
    let (Some(w), Some(h), Some(bytes)) = (
        u32_be(&b, dims),
        u32_be(&b, dims + 4),
        u32_be(&b, dims + 16),
    ) else {
        return;
    };
    let mime_s = show(mime, 32);
    let note = format!(
        "PICTURE block: {} ({code}), {mime_s}, {w}x{h}, {bytes} bytes of image data; removing it means rewriting the metadata block chain, so no marker is offered",
        picture_kind(code)
    );
    push(
        out,
        Draft {
            category: Category::Junk(JunkKind::Comment),
            confidence: Confidence::Moderate,
            severity: Severity::Notice,
            id: "flac.picture",
            title: format!("FLAC embedded {}", picture_kind(code)),
            evidence: evidence(data + 8, mime, note),
            marker: None,
        },
    );
}

#[cfg(test)]
pub(crate) mod tests_support {
    /// A Vorbis comment header body (no codec magic, no framing bit).
    pub fn comments(vendor: &[u8], fields: &[&[u8]]) -> Vec<u8> {
        let mut b = (vendor.len() as u32).to_le_bytes().to_vec();
        b.extend_from_slice(vendor);
        b.extend_from_slice(&(fields.len() as u32).to_le_bytes());
        for f in fields {
            b.extend_from_slice(&(f.len() as u32).to_le_bytes());
            b.extend_from_slice(f);
        }
        b
    }

    pub fn block(kind: u8, last: bool, body: &[u8]) -> Vec<u8> {
        let n = body.len() as u32;
        let mut b = vec![kind | if last { 0x80 } else { 0 }];
        b.extend_from_slice(&n.to_be_bytes()[1..]);
        b.extend_from_slice(body);
        b
    }

    pub fn picture(mime: &[u8], data_len: usize) -> Vec<u8> {
        let mut b = 3u32.to_be_bytes().to_vec();
        b.extend_from_slice(&(mime.len() as u32).to_be_bytes());
        b.extend_from_slice(mime);
        b.extend_from_slice(&4u32.to_be_bytes());
        b.extend_from_slice(b"Here");
        for v in [600u32, 600, 24, 0, data_len as u32] {
            b.extend_from_slice(&v.to_be_bytes());
        }
        b.extend(std::iter::repeat_n(0xabu8, data_len));
        b
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::{apply, find, format_of, fuzz, ids, run};
    use super::tests_support::{block, comments, picture};
    use super::*;
    use crate::model::RemovalStrategy;

    fn song(fields: &[&[u8]]) -> Vec<u8> {
        let mut d = b"fLaC".to_vec();
        d.extend(block(STREAMINFO, false, &[0x11; 34]));
        d.extend(block(1, false, &[0u8; 20]));
        d.extend(block(
            VORBIS_COMMENT,
            false,
            &comments(b"reference libFLAC 1.4.3 20230623", fields),
        ));
        d.extend(block(PICTURE, true, &picture(b"image/jpeg", 200)));
        d.extend_from_slice(&[0xff, 0xf8, 0x69, 0x08, 0, 0, 0, 0]);
        d
    }

    fn tagged() -> Vec<u8> {
        song(&[
            b"TITLE=Night Drive",
            b"ARTIST=Someone",
            b"REPLAYGAIN_TRACK_GAIN=-6.5 dB",
            b"DATE=2021",
            b"COMMENT=",
        ])
    }

    #[test]
    fn vendor_tags_and_picture() {
        let data = tagged();
        assert_eq!(format_of("a.flac", &data), Some("flac"));
        let f = run("a.flac", "flac", &data);
        assert_eq!(
            ids(&f),
            [
                "flac.vendor",
                "flac.tags",
                "flac.tags",
                "flac.tags",
                "flac.picture"
            ]
        );
        let v = find(&f, "flac.vendor");
        assert_eq!(v.category, Category::Brand(BrandKind::MediaEncoder));
        assert_eq!(v.confidence, Confidence::Strong);
        assert_eq!(v.severity, Severity::Info);
        assert_eq!(v.title, "FLAC encoder reference libFLAC 1.4.3 20230623");
        let m = v.marker.as_ref().unwrap();
        assert_eq!(m.container, ContainerKind::Raw);
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0x20 });
        let at = m.region.offset as usize;
        assert_eq!(
            &data[at..at + m.region.len as usize],
            b"reference libFLAC 1.4.3 20230623"
        );
        assert_eq!(v.evidence.offset, m.region.offset);

        let t = find(&f, "flac.tags");
        assert_eq!(t.category, Category::Junk(JunkKind::Comment));
        assert_eq!(t.confidence, Confidence::Moderate);
        assert_eq!(t.severity, Severity::Notice);
        assert_eq!(t.title, "FLAC TITLE tag");
        let m = t.marker.as_ref().unwrap();
        let at = m.region.offset as usize;
        assert_eq!(
            &data[at - 6..at + m.region.len as usize],
            b"TITLE=Night Drive"
        );
        let titles: Vec<&str> = f
            .iter()
            .filter(|f| f.signature_id == "flac.tags")
            .map(|f| f.title.as_str())
            .collect();
        assert_eq!(
            titles,
            ["FLAC TITLE tag", "FLAC ARTIST tag", "FLAC DATE tag"]
        );

        let p = find(&f, "flac.picture");
        assert!(p.marker.is_none());
        let note = p.evidence.note.as_deref().unwrap();
        assert!(note.contains("front cover"), "{note}");
        assert!(note.contains("image/jpeg"), "{note}");
        assert!(note.contains("600x600"), "{note}");
        assert!(note.contains("200 bytes"), "{note}");
        assert_eq!(p.evidence.matched, b"image/jpeg");
    }

    #[test]
    fn every_marker_scrubs_and_the_file_still_parses() {
        let mut data = tagged();
        let before = data.clone();
        let f = run("a.flac", "flac", &data);
        let markers: Vec<_> = f.iter().filter_map(|f| f.marker.clone()).collect();
        assert_eq!(markers.len(), 4);
        for m in &markers {
            apply(&mut data, m);
        }
        assert_eq!(data.len(), before.len());
        assert_eq!(ids(&run("a.flac", "flac", &data)), ["flac.picture"]);
        assert_eq!(format_of("a.flac", &data), Some("flac"));
        // Keys, lengths and the playback field survive.
        // fLaC (4), STREAMINFO (4 + 34), PADDING (4 + 20), comment header (4).
        let block = &data[70..];
        let c = parse_comments(block).unwrap();
        assert_eq!(c.fields.len(), 5);
        assert_eq!(c.fields[0].key(block), b"TITLE");
        assert_eq!(c.fields[2].value(block), b"-6.5 dB");
    }

    #[test]
    fn structure_is_required() {
        // No STREAMINFO first: nothing.
        let mut d = b"fLaC".to_vec();
        d.extend(block(
            VORBIS_COMMENT,
            true,
            &comments(b"x264", &[b"TITLE=a"]),
        ));
        assert!(run("a.flac", "flac", &d).is_empty());
        // A block that runs past EOF ends the walk.
        let mut d = song(&[b"TITLE=a"]);
        d.truncate(4 + 38 + 24 + 10);
        assert!(run("a.flac", "flac", &d).is_empty());
        // A field without '=' ends the field walk, the vendor still counts.
        let d = song(&[b"NOEQUALS", b"TITLE=x"]);
        assert_eq!(
            ids(&run("a.flac", "flac", &d)),
            ["flac.vendor", "flac.picture"]
        );
        // Blank vendor, no fields, no picture: nothing.
        let mut d = b"fLaC".to_vec();
        d.extend(block(STREAMINFO, false, &[0x11; 34]));
        d.extend(block(VORBIS_COMMENT, true, &comments(b"", &[])));
        assert!(run("a.flac", "flac", &d).is_empty());
    }

    #[test]
    fn parse_comments_bounds() {
        assert!(parse_comments(&[]).is_none());
        assert!(parse_comments(&[9, 0, 0, 0, b'a']).is_none());
        let c = parse_comments(&comments(b"v", &[])).unwrap();
        assert_eq!(c.vendor, (4, 1));
        assert!(c.fields.is_empty());
        let mut huge = comments(b"v", &[b"A=b"]);
        huge[9..13].copy_from_slice(&u32::MAX.to_le_bytes());
        assert!(parse_comments(&huge).unwrap().fields.is_empty());
    }

    #[test]
    fn truncated_and_corrupt_inputs() {
        fuzz("a.flac", "flac", &tagged());
    }
}
