//! MP3: the ID3v2 tag at the front, the ID3v1 trailer at the back, and the
//! encoder tag (Xing, Info, VBRI, LAME, Lavc) inside the first audio frame.

use super::{Draft, evidence, push, read, show};
use crate::model::{
    BrandKind, Category, Confidence, ContainerKind, Finding, JunkKind, Marker, Region, Severity,
};
use crate::scan::FileView;
use crate::util::bytes::{find, slice, u8_at, u32_be};

/// Most frames walked in one ID3v2 tag.
const MAX_FRAMES: usize = 64;
/// Frames listed in the note.
const NOTE_FRAMES: usize = 8;

/// A parsed ID3v2 header.
pub(crate) struct Id3v2 {
    major: u8,
    flags: u8,
    /// Size of everything after the 10-byte header, footer excluded.
    size: usize,
    /// Offset of the first frame (after any extended header).
    frames_start: usize,
    /// Offset just past the tag, footer included.
    end: usize,
}

fn syncsafe(b: &[u8]) -> Option<usize> {
    if b.len() != 4 || b.iter().any(|&x| x & 0x80 != 0) {
        return None;
    }
    Some(b.iter().fold(0usize, |acc, &x| (acc << 7) | usize::from(x)))
}

/// Parse the ID3v2 header at the start of `h`.
pub(crate) fn parse_v2_header(h: &[u8]) -> Option<Id3v2> {
    let hdr = slice(h, 0, 10)?;
    let major = *hdr.get(3)?;
    if !hdr.starts_with(b"ID3") || !(2..=4).contains(&major) || hdr.get(4) == Some(&0xff) {
        return None;
    }
    let flags = *hdr.get(5)?;
    let size = syncsafe(hdr.get(6..10)?)?;
    let footer = if major == 4 && flags & 0x10 != 0 {
        10
    } else {
        0
    };
    let mut frames_start: usize = 10;
    if flags & 0x40 != 0 && major >= 3 {
        let ext = if major == 3 {
            usize::try_from(u32_be(h, 10)?).ok()?.checked_add(4)?
        } else {
            syncsafe(slice(h, 10, 4)?)?
        };
        frames_start = frames_start.checked_add(ext)?;
    }
    Some(Id3v2 {
        major,
        flags,
        size,
        frames_start,
        end: 10 + size + footer,
    })
}

/// The byte length of a leading ID3v2 tag in `data`, clamped to `data`.
pub(crate) fn id3v2_extent(data: &[u8]) -> Option<usize> {
    parse_v2_header(data).map(|t| t.end.min(data.len()))
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let mut audio_start = 0u64;
    if let Some(tag) = parse_v2_header(view.header()) {
        id3v2(view, &tag, out);
        audio_start = tag.end as u64;
    }
    encoder(view, audio_start, out);
    id3v1(view, out);
}

struct Frame {
    id: String,
    size: usize,
    value: Option<String>,
}

fn frames(view: &dyn FileView, tag: &Id3v2) -> Vec<Frame> {
    let mut found = Vec::new();
    let body_end = 10 + tag.size;
    let (id_len, hdr_len) = if tag.major == 2 { (3, 6) } else { (4, 10) };
    let mut off = tag.frames_start;
    for _ in 0..MAX_FRAMES {
        if off + hdr_len > body_end {
            break;
        }
        let Some(hb) = read(view, off as u64, hdr_len) else {
            break;
        };
        let Some(id) = slice(&hb, 0, id_len) else {
            break;
        };
        if id.first() == Some(&0) {
            break;
        }
        if !id
            .iter()
            .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            break;
        }
        let size = match tag.major {
            2 => slice(&hb, 3, 3)
                .map(|s| s.iter().fold(0usize, |acc, &x| (acc << 8) | usize::from(x))),
            3 => u32_be(&hb, 4).map(|s| s as usize),
            _ => slice(&hb, 4, 4)
                .and_then(syncsafe)
                .or_else(|| u32_be(&hb, 4).map(|s| s as usize)),
        };
        let Some(size) = size else {
            break;
        };
        let data_off = off + hdr_len;
        let avail = body_end.saturating_sub(data_off);
        let id = String::from_utf8_lossy(id).into_owned();
        let value = frame_value(view, &id, data_off as u64, size.min(avail));
        found.push(Frame { id, size, value });
        if size == 0 || size > avail {
            break;
        }
        off = data_off + size;
    }
    found
}

/// A short value for text and comment frames.
fn frame_value(view: &dyn FileView, id: &str, off: u64, size: usize) -> Option<String> {
    let text_frame = id.starts_with('T') && id != "TXXX" && id != "TXX";
    let comment = id == "COMM" || id == "COM";
    if !text_frame && !comment {
        return None;
    }
    let data = read(view, off, size.min(256))?;
    let text = if comment {
        // encoding, language (3), description, NUL, text
        let enc = *data.first()?;
        let rest = data.get(4..)?;
        let skip = if enc == 1 || enc == 2 {
            rest.as_chunks::<2>()
                .0
                .iter()
                .position(|c| *c == [0, 0])
                .map(|p| p * 2 + 2)
        } else {
            rest.iter().position(|&b| b == 0).map(|p| p + 1)
        };
        let mut joined = vec![enc];
        joined.extend_from_slice(rest.get(skip.unwrap_or(0)..).unwrap_or_default());
        decode_text(&joined)
    } else {
        decode_text(&data)
    };
    (!text.is_empty()).then_some(text)
}

/// Decode an ID3v2 text payload (encoding byte first) to a short string.
fn decode_text(data: &[u8]) -> String {
    let Some((&enc, rest)) = data.split_first() else {
        return String::new();
    };
    let text = match enc {
        0 => rest.iter().map(|&b| char::from(b)).collect::<String>(),
        1 | 2 => {
            let (be, body) = match rest {
                [0xff, 0xfe, tail @ ..] => (false, tail),
                [0xfe, 0xff, tail @ ..] => (true, tail),
                _ => (enc == 2, rest),
            };
            let units: Vec<u16> = body
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| {
                    if be {
                        u16::from_be_bytes(c)
                    } else {
                        u16::from_le_bytes(c)
                    }
                })
                .take_while(|&u| u != 0)
                .collect();
            String::from_utf16_lossy(&units)
        }
        3 => String::from_utf8_lossy(rest).into_owned(),
        _ => return String::new(),
    };
    let first = text.split('\0').next().unwrap_or_default();
    show(first.as_bytes(), 32)
}

fn id3v2(view: &dyn FileView, tag: &Id3v2, out: &mut Vec<Finding>) {
    let list = frames(view, tag);
    if list.is_empty() {
        return;
    }
    let shown: Vec<String> = list
        .iter()
        .take(NOTE_FRAMES)
        .map(|f| match (&f.value, f.id.as_str()) {
            (Some(v), _) => format!("{} \"{v}\"", f.id),
            (None, "APIC" | "PIC") => format!("{} ({} bytes)", f.id, f.size),
            (None, _) => f.id.clone(),
        })
        .collect();
    let mut flags = Vec::new();
    if tag.flags & 0x80 != 0 {
        flags.push("unsynchronised");
    }
    if tag.flags & 0x40 != 0 {
        flags.push("extended header");
    }
    if tag.end > 10 + tag.size {
        flags.push("footer");
    }
    let more = if list.len() > NOTE_FRAMES {
        format!(" and {} more", list.len() - NOTE_FRAMES)
    } else {
        String::new()
    };
    let flag_note = if flags.is_empty() {
        String::new()
    } else {
        format!(" ({})", flags.join(", "))
    };
    let note = format!(
        "ID3v2.{} tag of {} bytes{flag_note}: {}{more}; scrubbing zeroes the frames and keeps the 10-byte header, leaving a valid empty tag",
        tag.major,
        tag.end,
        shown.join(", "),
    );
    let size = view.size();
    let start = tag.frames_start as u64;
    let end = ((10 + tag.size) as u64).min(size);
    let marker = (end > start && start > 0)
        .then(|| Marker::blank(Region::new(start, end - start), ContainerKind::Id3v2));
    let header = slice(view.header(), 0, 10).unwrap_or_default();
    push(
        out,
        Draft {
            category: Category::Junk(JunkKind::Id3),
            confidence: Confidence::Strong,
            severity: Severity::Notice,
            id: "mp3.id3v2",
            title: format!("ID3v2.{} tag with {} frame(s)", tag.major, list.len()),
            evidence: evidence(0, header, note),
            marker,
        },
    );
}

fn id3v1(view: &dyn FileView, out: &mut Vec<Finding>) {
    let size = view.size();
    if size < 128 {
        return;
    }
    let at = size - 128;
    let Some(t) = read(view, at, 128) else {
        return;
    };
    if t.len() < 128 || !t.starts_with(b"TAG") {
        return;
    }
    let field = |a: usize, b: usize| show(t.get(a..b).unwrap_or_default(), 30);
    let mut parts = Vec::new();
    for (name, a, b) in [
        ("title", 3, 33),
        ("artist", 33, 63),
        ("album", 63, 93),
        ("year", 93, 97),
    ] {
        let v = field(a, b);
        if !v.is_empty() {
            parts.push(format!("{name} \"{v}\""));
        }
    }
    if u8_at(&t, 125) == Some(0) && u8_at(&t, 126).is_some_and(|n| n != 0) {
        parts.push(format!("track {}", t[126]));
    }
    let summary = if parts.is_empty() {
        "no text fields".to_string()
    } else {
        parts.join(", ")
    };
    let note = format!(
        "ID3v1 trailer in the last 128 bytes: {summary}; cleaning truncates the file at {at}"
    );
    let marker = (at > 0).then(|| Marker::truncate_at(at, ContainerKind::Id3v1));
    push(
        out,
        Draft {
            category: Category::Junk(JunkKind::Id3),
            confidence: Confidence::Strong,
            severity: Severity::Notice,
            id: "mp3.id3v1",
            title: "ID3v1 trailer".to_string(),
            evidence: evidence(at, &t[..3], note),
            marker,
        },
    );
}

/// Frame length and side-information size of a Layer III frame header.
struct FrameHdr {
    frame_len: usize,
    side_info: usize,
}

fn layer3(b: &[u8], i: usize) -> Option<FrameHdr> {
    const BR_V1: [u32; 15] = [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    ];
    const BR_V2: [u32; 15] = [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160];
    const SR: [u32; 3] = [44100, 48000, 32000];
    let h = slice(b, i, 4)?;
    if h[0] != 0xff || h[1] & 0xe0 != 0xe0 {
        return None;
    }
    let version = (h[1] >> 3) & 3;
    let layer = (h[1] >> 1) & 3;
    if version == 1 || layer != 1 {
        return None;
    }
    let br = usize::from(h[2] >> 4);
    let sr = *SR.get(usize::from((h[2] >> 2) & 3))?;
    let pad = u32::from((h[2] >> 1) & 1);
    if br == 0 {
        return None;
    }
    let mono = h[3] >> 6 == 3;
    let (sr, kbps, coef, side) = match version {
        3 => (sr, *BR_V1.get(br)?, 144, if mono { 17 } else { 32 }),
        2 => (sr / 2, *BR_V2.get(br)?, 72, if mono { 9 } else { 17 }),
        _ => (sr / 4, *BR_V2.get(br)?, 72, if mono { 9 } else { 17 }),
    };
    let frame_len = (coef * kbps * 1000 / sr + pad) as usize;
    Some(FrameHdr {
        frame_len,
        side_info: side,
    })
}

fn encoder(view: &dyn FileView, audio_start: u64, out: &mut Vec<Finding>) {
    let Some(buf) = read(view, audio_start, 4096) else {
        return;
    };
    let Some((i, hdr)) = (0..buf.len().min(2048)).find_map(|i| layer3(&buf, i).map(|h| (i, h)))
    else {
        return;
    };
    let frame = buf
        .get(i..(i + hdr.frame_len).min(buf.len()))
        .unwrap_or_default();
    let mut tags: Vec<String> = Vec::new();
    let mut first: Option<(usize, usize)> = None;
    let note_at = |pos: usize, len: usize, first: &mut Option<(usize, usize)>| {
        if first.is_none_or(|(p, _)| pos < p) {
            *first = Some((pos, len));
        }
    };
    let xing = i + 4 + hdr.side_info;
    if let Some(tag @ (b"Xing" | b"Info")) = slice(&buf, xing, 4) {
        tags.push(format!("{} header", String::from_utf8_lossy(tag)));
        note_at(xing, 4, &mut first);
    }
    if slice(&buf, i + 4 + 32, 4) == Some(b"VBRI") {
        tags.push("VBRI header".to_string());
        note_at(i + 36, 4, &mut first);
    }
    let mut version = None;
    for name in [&b"LAME"[..], b"Lavc", b"Lavf"] {
        if let Some(p) = find(frame, name) {
            let run: Vec<u8> = frame[p..]
                .iter()
                .take(9)
                .take_while(|b| b.is_ascii_graphic())
                .copied()
                .collect();
            let text = String::from_utf8_lossy(&run).into_owned();
            note_at(i + p, run.len(), &mut first);
            if version.is_none() {
                version = Some(text.clone());
            }
            tags.push(text);
        }
    }
    let Some((pos, len)) = first else {
        return;
    };
    let title = match &version {
        Some(v) => format!("MP3 encoder tag {v}"),
        None => format!(
            "MP3 {}",
            tags.first().map_or("encoder header", String::as_str)
        ),
    };
    let bytes = buf.get(pos..pos + len).unwrap_or_default();
    push(
        out,
        Draft {
            category: Category::Brand(BrandKind::MediaEncoder),
            confidence: Confidence::Moderate,
            severity: Severity::Info,
            id: "mp3.encoder",
            title,
            evidence: evidence(
                audio_start + pos as u64,
                bytes,
                format!("first audio frame carries: {}", tags.join(", ")),
            ),
            marker: None,
        },
    );
}

#[cfg(test)]
pub(crate) mod tests_support {
    /// An ID3v2.3 tag with the given frames (plain 32-bit sizes) and padding.
    pub fn id3v2(frames: &[(&str, &[u8])]) -> Vec<u8> {
        let mut body = Vec::new();
        for (id, data) in frames {
            body.extend_from_slice(id.as_bytes());
            body.extend_from_slice(&(data.len() as u32).to_be_bytes());
            body.extend_from_slice(&[0, 0]);
            body.extend_from_slice(data);
        }
        body.extend_from_slice(&[0u8; 16]);
        let mut tag = b"ID3\x03\x00\x00".to_vec();
        tag.extend_from_slice(&syncsafe_bytes(body.len()));
        tag.extend_from_slice(&body);
        tag
    }

    pub fn syncsafe_bytes(n: usize) -> [u8; 4] {
        [
            ((n >> 21) & 0x7f) as u8,
            ((n >> 14) & 0x7f) as u8,
            ((n >> 7) & 0x7f) as u8,
            (n & 0x7f) as u8,
        ]
    }

    /// A 128-byte ID3v1 trailer.
    pub fn id3v1(title: &str, artist: &str) -> Vec<u8> {
        let mut t = vec![0u8; 128];
        t[..3].copy_from_slice(b"TAG");
        t[3..3 + title.len()].copy_from_slice(title.as_bytes());
        t[33..33 + artist.len()].copy_from_slice(artist.as_bytes());
        t[93..97].copy_from_slice(b"2001");
        t[126] = 7;
        t
    }

    /// One MPEG-1 Layer III frame (128 kbps, 44.1 kHz, joint stereo) with an
    /// optional Info tag and encoder string.
    pub fn frame(tag: Option<&[u8]>, enc: Option<&[u8]>) -> Vec<u8> {
        let mut f = vec![0u8; 417];
        f[..4].copy_from_slice(&[0xff, 0xfb, 0x90, 0x64]);
        if let Some(t) = tag {
            f[36..40].copy_from_slice(t);
        }
        if let Some(e) = enc {
            f[156..156 + e.len()].copy_from_slice(e);
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::super::testutil::*;
    use super::tests_support::*;
    use crate::model::{
        BrandKind, Category, Confidence, ContainerKind, JunkKind, RemovalStrategy, Severity,
    };

    fn song() -> Vec<u8> {
        let mut d = id3v2(&[
            ("TIT2", b"\x03Night Drive"),
            ("TPE1", b"\x01\xff\xfeA\0b\0c\0"),
            ("TALB", b"\x00Album"),
            ("TSSE", b"\x03Lavf60.3.100"),
            ("COMM", b"\x03engdesc\0hello there"),
            ("APIC", &[0u8; 300]),
        ]);
        d.extend(frame(Some(b"Info"), Some(b"LAME3.100")));
        d.extend(frame(None, None));
        d.extend(id3v1("Night Drive", "Abc"));
        d
    }

    #[test]
    fn id3v2_frames_are_listed_and_blanked() {
        let mut data = song();
        let f = run("a.mp3", "mp3", &data);
        assert_eq!(ids(&f), ["mp3.id3v2", "mp3.encoder", "mp3.id3v1"]);
        let tag = find(&f, "mp3.id3v2");
        assert_eq!(tag.category, Category::Junk(JunkKind::Id3));
        assert_eq!(tag.confidence, Confidence::Strong);
        assert_eq!(tag.severity, Severity::Notice);
        let note = tag.evidence.note.as_deref().unwrap();
        assert!(note.contains("TIT2 \"Night Drive\""), "{note}");
        assert!(note.contains("TPE1 \"Abc\""), "{note}");
        assert!(note.contains("TALB \"Album\""), "{note}");
        assert!(note.contains("TSSE \"Lavf60.3.100\""), "{note}");
        assert!(note.contains("COMM \"hello there\""), "{note}");
        assert!(note.contains("APIC (300 bytes)"), "{note}");
        let m = tag.marker.clone().unwrap();
        assert_eq!(m.container, ContainerKind::Id3v2);
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0 });
        assert_eq!(m.region.offset, 10);
        let tag_len = super::id3v2_extent(&data).unwrap();
        assert_eq!(m.region.end(), tag_len as u64);

        apply(&mut data, &m);
        let after = run("a.mp3", "mp3", &data);
        assert_eq!(ids(&after), ["mp3.encoder", "mp3.id3v1"]);
        assert_eq!(format_of("a.mp3", &data), Some("mp3"));
        assert_eq!(super::id3v2_extent(&data), Some(tag_len));
    }

    #[test]
    fn id3v1_truncates_cleanly() {
        let mut data = song();
        let f = run("a.mp3", "mp3", &data);
        let v1 = find(&f, "mp3.id3v1");
        let at = (data.len() - 128) as u64;
        assert_eq!(v1.evidence.offset, at);
        assert!(
            v1.evidence
                .note
                .as_deref()
                .unwrap()
                .contains("title \"Night Drive\"")
        );
        let m = v1.marker.clone().unwrap();
        assert_eq!(m.removal, RemovalStrategy::Truncate { from: at });
        assert_eq!(m.container, ContainerKind::Id3v1);
        apply(&mut data, &m);
        let after = run("a.mp3", "mp3", &data);
        assert!(after.iter().all(|f| f.signature_id != "mp3.id3v1"));
        assert_eq!(format_of("a.mp3", &data), Some("mp3"));
        // A file that is nothing but a trailer keeps the finding, no marker.
        let only = id3v1("t", "a");
        let f = run("a.mp3", "mp3", &only);
        assert!(find(&f, "mp3.id3v1").marker.is_none());
    }

    #[test]
    fn encoder_tags() {
        let f = run("a.mp3", "mp3", &song());
        let e = find(&f, "mp3.encoder");
        assert_eq!(e.category, Category::Brand(BrandKind::MediaEncoder));
        assert_eq!(e.confidence, Confidence::Moderate);
        assert_eq!(e.title, "MP3 encoder tag LAME3.100");
        let tag_len = super::id3v2_extent(&song()).unwrap() as u64;
        assert_eq!(e.evidence.offset, tag_len + 36);
        assert_eq!(e.evidence.matched, b"Info");

        let bare = frame(Some(b"Xing"), None);
        let f = run("a.mp3", "mp3", &bare);
        assert_eq!(find(&f, "mp3.encoder").title, "MP3 Xing header");

        let lavc = frame(None, Some(b"Lavc61.19"));
        let f = run("a.mp3", "mp3", &lavc);
        assert_eq!(find(&f, "mp3.encoder").title, "MP3 encoder tag Lavc61.19");
        assert_eq!(find(&f, "mp3.encoder").evidence.offset, 156);

        assert!(run("a.mp3", "mp3", &frame(None, None)).is_empty());
    }

    #[test]
    fn other_versions_and_flags() {
        // ID3v2.2 with three-character frame ids.
        let mut v22 = b"ID3\x02\x00\x00".to_vec();
        let body = [b"TT2\x00\x00\x05\x00Song".as_slice(), &[0u8; 8]].concat();
        v22.extend_from_slice(&syncsafe_bytes(body.len()));
        v22.extend_from_slice(&body);
        let f = run("a.mp3", "mp3", &v22);
        assert!(
            find(&f, "mp3.id3v2")
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("TT2 \"Song\"")
        );

        // ID3v2.4 with syncsafe frame sizes, an extended header and a footer.
        let mut body = vec![0, 0, 0, 6, 1, 0];
        body.extend_from_slice(b"TIT2");
        body.extend_from_slice(&syncsafe_bytes(5));
        body.extend_from_slice(&[0, 0]);
        body.extend_from_slice(b"\x03Tune");
        body.extend_from_slice(&[0u8; 4]);
        let mut v24 = b"ID3\x04\x00\x50".to_vec();
        v24.extend_from_slice(&syncsafe_bytes(body.len()));
        v24.extend_from_slice(&body);
        v24.extend_from_slice(b"3DI\x04\x00\x50");
        v24.extend_from_slice(&syncsafe_bytes(body.len()));
        let f = run("a.mp3", "mp3", &v24);
        let t = find(&f, "mp3.id3v2");
        let note = t.evidence.note.as_deref().unwrap();
        assert!(note.contains("TIT2 \"Tune\""), "{note}");
        assert!(note.contains("extended header"), "{note}");
        assert!(note.contains("footer"), "{note}");
        let m = t.marker.as_ref().unwrap();
        assert_eq!(m.region.offset, 16);
        assert_eq!(m.region.end(), (10 + body.len()) as u64);

        // An empty tag (padding only) is not reported.
        let empty = id3v2(&[]);
        assert!(run("a.mp3", "mp3", &empty).is_empty());
    }

    #[test]
    fn truncated_and_corrupt_inputs() {
        fuzz("a.mp3", "mp3", &song());
        let mut huge = id3v2(&[("TIT2", b"\x03x")]);
        huge[6..10].copy_from_slice(&[0x7f; 4]);
        let f = run("a.mp3", "mp3", &huge);
        let m = find(&f, "mp3.id3v2").marker.clone().unwrap();
        assert!(m.region.end() <= huge.len() as u64);
    }
}
