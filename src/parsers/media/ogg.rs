//! Ogg: reassemble the first packets of each logical stream from the leading
//! pages and report the comment header of Vorbis (`\x03vorbis`), Opus
//! (`OpusTags`), Theora (`\x81theora`) and Ogg FLAC streams. The vendor string
//! names the encoder; the fields are tags.
//!
//! Every Ogg page carries a CRC-32 over its bytes, so a length-preserving
//! blank would leave pages a player rejects. No markers are offered; the notes
//! say so.

use super::flac::parse_comments;
use super::{Draft, evidence, is_blank, push, read, show};
use crate::model::{BrandKind, Category, Confidence, Finding, JunkKind, Severity};
use crate::scan::FileView;
use crate::util::bytes::{slice, u8_at, u32_le};

/// Most pages walked from the start of the file.
const MAX_PAGES: usize = 64;
/// Most logical streams followed (beginning-of-stream pages come first).
const MAX_STREAMS: usize = 4;
/// Most bytes of one packet kept; a longer comment header is parsed from
/// its first bytes.
const MAX_PACKET: usize = 1024 * 1024;
/// The comment header is the second packet; look no further than the third.
const HEADER_PACKETS: usize = 3;
/// Fields listed in the tags note.
const NOTE_FIELDS: usize = 8;

const CRC_NOTE: &str = "Ogg pages carry a CRC-32 over these bytes, so a blank would break the checksum and no marker is offered; a tag editor that rewrites the pages can remove them";

/// Packet reassembly state for one logical stream.
struct Stream {
    serial: u32,
    /// Packets completed so far.
    packets: usize,
    /// Whether the last page ended in the middle of a packet.
    partial: bool,
    /// Whether the first packet was an Ogg FLAC identification header.
    flac: bool,
    done: bool,
    buf: Vec<u8>,
    /// Contiguous file runs of `buf`: packet offset, absolute offset, length.
    runs: Vec<(usize, u64, usize)>,
}

impl Stream {
    fn new(serial: u32) -> Self {
        Self {
            serial,
            packets: 0,
            partial: false,
            flac: false,
            done: false,
            buf: Vec::new(),
            runs: Vec::new(),
        }
    }

    fn append(&mut self, bytes: &[u8], abs: u64) {
        let room = MAX_PACKET.saturating_sub(self.buf.len());
        let take = bytes.get(..bytes.len().min(room)).unwrap_or_default();
        if take.is_empty() {
            return;
        }
        let at = self.buf.len();
        match self.runs.last_mut() {
            Some((p, a, n)) if *p + *n == at && *a + *n as u64 == abs => *n += take.len(),
            _ => self.runs.push((at, abs, take.len())),
        }
        self.buf.extend_from_slice(take);
    }

    /// The absolute offset of packet byte `pos` and how many bytes from
    /// there on are contiguous in the file.
    fn abs(&self, pos: usize) -> Option<(u64, usize)> {
        self.runs
            .iter()
            .find(|(p, _, n)| (*p..*p + *n).contains(&pos))
            .map(|&(p, a, n)| (a + (pos - p) as u64, p + n - pos))
    }

    /// One packet is complete (or as complete as it will get).
    fn finish(&mut self, out: &mut Vec<Finding>) {
        let pkt = std::mem::take(&mut self.buf);
        if self.packets == 0 && pkt.starts_with(b"\x7fFLAC") {
            self.flac = true;
        }
        let codec = if pkt.starts_with(b"\x03vorbis") {
            Some(("Vorbis", 7))
        } else if pkt.starts_with(b"OpusTags") {
            Some(("Opus", 8))
        } else if pkt.starts_with(b"\x81theora") {
            Some(("Theora", 7))
        } else if self.flac && self.packets > 0 && pkt.first().is_some_and(|b| b & 0x7f == 4) {
            Some(("FLAC", 4))
        } else {
            None
        };
        if let Some((name, skip)) = codec {
            report(self, name, &pkt, skip, out);
            self.done = true;
        }
        self.packets += 1;
        if self.packets >= HEADER_PACKETS || pkt.len() >= MAX_PACKET {
            self.done = true;
        }
        self.runs.clear();
        self.partial = false;
    }
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    if slice(view.header(), 0, 4) != Some(b"OggS") {
        return;
    }
    let size = view.size();
    let mut streams: Vec<Stream> = Vec::new();
    let mut off = 0u64;
    for _ in 0..MAX_PAGES {
        if off.saturating_add(27) > size {
            break;
        }
        let Some(hdr) = read(view, off, 27 + 255) else {
            break;
        };
        if slice(&hdr, 0, 4) != Some(b"OggS") || u8_at(&hdr, 4) != Some(0) {
            break;
        }
        let (Some(flags), Some(serial), Some(nseg)) =
            (u8_at(&hdr, 5), u32_le(&hdr, 14), u8_at(&hdr, 26))
        else {
            break;
        };
        let Some(lacing) = slice(&hdr, 27, usize::from(nseg)) else {
            break;
        };
        let body_len: usize = lacing.iter().map(|&l| usize::from(l)).sum();
        let body_off = off + 27 + u64::from(nseg);
        let Some(body) = read(view, body_off, body_len) else {
            break;
        };
        if body.len() < body_len {
            break;
        }
        let bos = flags & 0x02 != 0;
        let idx = match streams.iter().position(|s| s.serial == serial) {
            Some(i) => Some(i),
            None if bos && streams.len() < MAX_STREAMS => {
                streams.push(Stream::new(serial));
                Some(streams.len() - 1)
            }
            None => None,
        };
        if let Some(s) = idx.and_then(|i| streams.get_mut(i)) {
            page(s, flags, lacing, &body, body_off, out);
        }
        if !bos && streams.iter().all(|s| s.done) {
            break;
        }
        off = body_off + body_len as u64;
    }
    // A comment header cut short by the page cap still has its vendor and
    // first fields up front.
    for s in streams.iter_mut().filter(|s| !s.done && !s.buf.is_empty()) {
        s.finish(out);
    }
}

/// Feed one page's segments to its stream.
fn page(
    s: &mut Stream,
    flags: u8,
    lacing: &[u8],
    body: &[u8],
    body_off: u64,
    out: &mut Vec<Finding>,
) {
    if s.done {
        return;
    }
    let continued = flags & 0x01 != 0;
    if !continued && s.partial {
        // The previous packet never finished; drop it.
        s.buf.clear();
        s.runs.clear();
        s.partial = false;
    }
    // A continuation of a packet we never saw the start of is skipped.
    let mut skipping = continued && !s.partial;
    let mut pos = 0usize;
    for &l in lacing {
        let l = usize::from(l);
        if !skipping && let Some(seg) = body.get(pos..pos + l) {
            s.append(seg, body_off + pos as u64);
        }
        pos += l;
        if l < 255 {
            if skipping {
                skipping = false;
            } else {
                s.finish(out);
                if s.done {
                    return;
                }
            }
        } else if !skipping {
            s.partial = true;
        }
    }
}

fn report(s: &Stream, codec: &str, pkt: &[u8], skip: usize, out: &mut Vec<Finding>) {
    let Some(body) = pkt.get(skip..) else {
        return;
    };
    let Some(c) = parse_comments(body) else {
        return;
    };
    // Evidence bytes stop where the packet leaves a contiguous file run.
    let at = |pos: usize, bytes: &[u8]| -> Option<(u64, Vec<u8>)> {
        let (abs, run) = s.abs(skip + pos)?;
        Some((
            abs,
            bytes
                .get(..bytes.len().min(run))
                .unwrap_or_default()
                .to_vec(),
        ))
    };
    let (vs, vl) = c.vendor;
    let vendor = body.get(vs..vs + vl).unwrap_or_default();
    if !is_blank(vendor)
        && let Some((abs, bytes)) = at(vs, vendor)
    {
        let v = show(vendor, 60);
        push(
            out,
            Draft {
                category: Category::Brand(BrandKind::MediaEncoder),
                confidence: Confidence::Strong,
                severity: Severity::Info,
                id: "ogg.vendor",
                title: format!("Ogg {codec} encoder {v}"),
                evidence: evidence(
                    abs,
                    &bytes,
                    format!("{codec} comment header vendor string = \"{v}\"; {CRC_NOTE}"),
                ),
                marker: None,
            },
        );
    }
    let tags: Vec<_> = c.fields.iter().filter(|f| f.is_tag(body)).collect();
    let Some(first) = tags.first() else {
        return;
    };
    let Some((abs, bytes)) = at(
        first.start,
        body.get(first.start..first.start + first.len)
            .unwrap_or_default(),
    ) else {
        return;
    };
    let shown: Vec<String> = tags
        .iter()
        .take(NOTE_FIELDS)
        .map(|f| format!("{}=\"{}\"", show(f.key(body), 32), show(f.value(body), 32)))
        .collect();
    let more = if tags.len() > NOTE_FIELDS {
        format!(" and {} more", tags.len() - NOTE_FIELDS)
    } else {
        String::new()
    };
    push(
        out,
        Draft {
            category: Category::Junk(JunkKind::Comment),
            confidence: Confidence::Moderate,
            severity: Severity::Notice,
            id: "ogg.tags",
            title: format!("Ogg {codec} tags ({} field(s))", tags.len()),
            evidence: evidence(
                abs,
                &bytes,
                format!(
                    "{codec} comment fields: {}{more}; {CRC_NOTE}",
                    shown.join(", ")
                ),
            ),
            marker: None,
        },
    );
}

#[cfg(test)]
mod tests {
    use super::super::flac::tests_support::comments;
    use super::super::testutil::{find, format_of, fuzz, ids, run};
    use super::*;

    /// One page. Each part is packet bytes plus whether the packet ends on
    /// this page (an unfinished part must be a multiple of 255 bytes).
    fn page(flags: u8, serial: u32, parts: &[(&[u8], bool)]) -> Vec<u8> {
        let mut lacing = Vec::new();
        let mut body = Vec::new();
        for (p, complete) in parts {
            let mut n = p.len();
            while n >= 255 {
                lacing.push(255u8);
                n -= 255;
            }
            if *complete {
                lacing.push(n as u8);
            } else {
                assert_eq!(n, 0);
            }
            body.extend_from_slice(p);
        }
        let mut pg = b"OggS\0".to_vec();
        pg.push(flags);
        pg.extend_from_slice(&[0u8; 8]);
        pg.extend_from_slice(&serial.to_le_bytes());
        pg.extend_from_slice(&[0u8; 8]);
        pg.push(lacing.len() as u8);
        pg.extend(lacing);
        pg.extend(body);
        pg
    }

    fn vorbis_comment(vendor: &[u8], fields: &[&[u8]]) -> Vec<u8> {
        let mut p = b"\x03vorbis".to_vec();
        p.extend(comments(vendor, fields));
        p.push(1);
        p
    }

    fn vorbis(fields: &[&[u8]]) -> Vec<u8> {
        let ident = [b"\x01vorbis".as_slice(), &[0u8; 23]].concat();
        let comment = vorbis_comment(
            b"Xiph.Org libVorbis I 20200704 (Reducing Environment)",
            fields,
        );
        let setup = [b"\x05vorbis".as_slice(), &[0u8; 40]].concat();
        [
            page(0x02, 7, &[(&ident, true)]),
            page(0, 7, &[(&comment, true), (&setup, true)]),
            page(0, 7, &[(&[0u8; 100], true)]),
        ]
        .concat()
    }

    #[test]
    fn vorbis_vendor_and_tags() {
        let data = vorbis(&[
            b"TITLE=Night Drive",
            b"ARTIST=Someone",
            b"REPLAYGAIN_TRACK_GAIN=-3 dB",
        ]);
        assert_eq!(format_of("a.ogg", &data), Some("ogg"));
        let f = run("a.ogg", "ogg", &data);
        assert_eq!(ids(&f), ["ogg.vendor", "ogg.tags"]);
        let v = find(&f, "ogg.vendor");
        assert_eq!(v.category, Category::Brand(BrandKind::MediaEncoder));
        assert_eq!(v.confidence, Confidence::Strong);
        assert_eq!(v.severity, Severity::Info);
        assert!(v.marker.is_none());
        assert!(
            v.title
                .starts_with("Ogg Vorbis encoder Xiph.Org libVorbis I")
        );
        let at = v.evidence.offset as usize;
        assert!(data[at..].starts_with(b"Xiph.Org libVorbis"));
        assert_eq!(v.evidence.matched, &data[at..at + v.evidence.matched.len()]);
        assert!(v.evidence.note.as_deref().unwrap().contains("CRC-32"));

        let t = find(&f, "ogg.tags");
        assert_eq!(t.category, Category::Junk(JunkKind::Comment));
        assert_eq!(t.confidence, Confidence::Moderate);
        assert_eq!(t.severity, Severity::Notice);
        assert!(t.marker.is_none());
        assert_eq!(t.title, "Ogg Vorbis tags (2 field(s))");
        let note = t.evidence.note.as_deref().unwrap();
        assert!(
            note.contains("TITLE=\"Night Drive\", ARTIST=\"Someone\";"),
            "{note}"
        );
        assert!(!note.contains("REPLAYGAIN"), "{note}");
        let at = t.evidence.offset as usize;
        assert!(data[at..].starts_with(b"TITLE=Night Drive"));
    }

    #[test]
    fn opus_tags_and_a_header_spanning_pages() {
        let head = [b"OpusHead\x01\x02".as_slice(), &[0u8; 9]].concat();
        let big = [b"R128_TRACK_GAIN=".as_slice(), &[b'1'; 600]].concat();
        let mut tags = b"OpusTags".to_vec();
        tags.extend(comments(
            b"libopus 1.4",
            &[&big, b"TITLE=Late", b"ENCODER=opusenc"],
        ));
        let (a, b) = tags.split_at(510);
        let data = [
            page(0x02, 3, &[(&head, true)]),
            page(0, 3, &[(a, false)]),
            page(0x01, 3, &[(b, true)]),
            page(0, 3, &[(&[0u8; 50], true)]),
        ]
        .concat();
        let f = run("a.opus", "ogg", &data);
        assert_eq!(ids(&f), ["ogg.vendor", "ogg.tags"]);
        assert_eq!(find(&f, "ogg.vendor").title, "Ogg Opus encoder libopus 1.4");
        let t = find(&f, "ogg.tags");
        let at = t.evidence.offset as usize;
        assert!(data[at..].starts_with(b"TITLE=Late"), "{at}");
        assert!(
            t.evidence
                .note
                .as_deref()
                .unwrap()
                .contains("ENCODER=\"opusenc\"")
        );
        // The packet left the first page mid-field: offsets past the break
        // map into the second page's body.
        assert!(at > 27 + 1 + head.len() + 27 + 2 + 510);
    }

    #[test]
    fn theora_and_vorbis_streams_and_ogg_flac() {
        let th_ident = [b"\x80theora".as_slice(), &[0u8; 35]].concat();
        let th_comment = [
            b"\x81theora".as_slice(),
            &comments(b"Xiph.Org libtheora 1.1 20090822 (Thusnelda)", &[]),
        ]
        .concat();
        let vb_ident = [b"\x01vorbis".as_slice(), &[0u8; 23]].concat();
        let vb_comment = vorbis_comment(b"Lavf60.3.100", &[b"TITLE=x"]);
        let data = [
            page(0x02, 1, &[(&th_ident, true)]),
            page(0x02, 2, &[(&vb_ident, true)]),
            page(0, 1, &[(&th_comment, true)]),
            page(0, 2, &[(&vb_comment, true)]),
        ]
        .concat();
        let f = run("a.ogv", "ogg", &data);
        let titles: Vec<&str> = f.iter().map(|f| f.title.as_str()).collect();
        assert_eq!(
            titles,
            [
                "Ogg Theora encoder Xiph.Org libtheora 1.1 20090822 (Thusnelda)",
                "Ogg Vorbis encoder Lavf60.3.100",
                "Ogg Vorbis tags (1 field(s))"
            ]
        );

        let ident = [b"\x7fFLAC\x01\x00\x00\x01fLaC".as_slice(), &[0u8; 38]].concat();
        let body = comments(b"reference libFLAC 1.4.3", &[b"ALBUM=A"]);
        let mut block = vec![0x84];
        block.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
        block.extend(body);
        let data = [
            page(0x02, 5, &[(&ident, true)]),
            page(0, 5, &[(&block, true)]),
        ]
        .concat();
        let f = run("a.oga", "ogg", &data);
        assert_eq!(ids(&f), ["ogg.vendor", "ogg.tags"]);
        assert_eq!(
            find(&f, "ogg.vendor").title,
            "Ogg FLAC encoder reference libFLAC 1.4.3"
        );
    }

    #[test]
    fn quiet_cases() {
        // No comment header at all.
        let ident = [b"\x01vorbis".as_slice(), &[0u8; 23]].concat();
        let data = [
            page(0x02, 7, &[(&ident, true)]),
            page(0, 7, &[(&[9u8; 80], true)]),
        ]
        .concat();
        assert!(run("a.ogg", "ogg", &data).is_empty());
        // Blank vendor, no fields.
        assert!(
            run(
                "a.ogg",
                "ogg",
                &[
                    page(0x02, 7, &[(&ident, true)]),
                    page(0, 7, &[(&vorbis_comment(b"", &[]), true)])
                ]
                .concat()
            )
            .is_empty()
        );
        // A comment page from a stream with no BOS page is ignored.
        let data = page(0, 7, &[(&vorbis_comment(b"enc", &[b"A=b"]), true)]);
        assert!(run("a.ogg", "ogg", &data).is_empty());
        // A continued first packet is skipped, not misread.
        let data = [
            page(0x02, 7, &[(&ident, true)]),
            page(0x01, 7, &[(&vorbis_comment(b"enc", &[]), true)]),
        ]
        .concat();
        assert!(run("a.ogg", "ogg", &data).is_empty());
    }

    #[test]
    fn truncated_and_corrupt_inputs() {
        fuzz(
            "a.ogg",
            "ogg",
            &vorbis(&[b"TITLE=Night Drive", b"ARTIST=Someone"]),
        );
    }
}
