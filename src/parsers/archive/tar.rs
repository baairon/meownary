//! tar: the owner fields (uname, gname, uid, gid) of up to the first 64
//! headers, each with a structural marker that blanks the names and fixes
//! that header's checksum.

use crate::model::{
    Category, Confidence, ContainerKind, Evidence, Finding, JunkKind, Marker, Region,
    RemovalStrategy, Severity,
};
use crate::scan::FileView;
use crate::util::bytes::{cstr, slice};

use crate::parsers::image::shared::{
    NOTE_CHARS, TITLE_CHARS, clip, fetch, finding, is_blank, latin1,
};

const BLOCK: u64 = 512;
const MAX_HEADERS: usize = 64;
const UNAME: usize = 265;
const OWNER_LEN: usize = 64;
const CHKSUM: usize = 148;

/// Parse a numeric header field: octal digits (leading spaces or NULs, ended by
/// a space or NUL), or the GNU base-256 form when the high bit is set.
fn number(field: &[u8]) -> Option<u64> {
    let first = *field.first()?;
    if first & 0x80 != 0 {
        let mut v = (first & 0x7F) as u64;
        for &b in &field[1..] {
            v = v.checked_mul(256)?.checked_add(b as u64)?;
        }
        return Some(v);
    }
    let digits: Vec<u8> = field
        .iter()
        .copied()
        .skip_while(|&b| b == b' ' || b == 0)
        .take_while(|&b| b != b' ' && b != 0)
        .collect();
    if digits.is_empty() {
        return Some(0);
    }
    let mut v = 0u64;
    for d in digits {
        if !(b'0'..=b'7').contains(&d) {
            return None;
        }
        v = v.checked_mul(8)?.checked_add((d - b'0') as u64)?;
    }
    Some(v)
}

/// The header checksum computed with the checksum field read as spaces.
fn checksum(h: &[u8]) -> u64 {
    h.iter()
        .enumerate()
        .map(|(i, &b)| {
            if (CHKSUM..CHKSUM + 8).contains(&i) {
                b' ' as u64
            } else {
                b as u64
            }
        })
        .sum()
}

/// Whether `h` is a 512-byte header whose stored checksum matches.
fn header_ok(h: &[u8]) -> bool {
    h.len() == BLOCK as usize
        && slice(h, CHKSUM, 8)
            .and_then(number)
            .is_some_and(|c| c == checksum(h))
}

/// One parsed header.
struct Header {
    off: u64,
    bytes: Vec<u8>,
}

impl Header {
    fn field(&self, at: usize, len: usize) -> &[u8] {
        cstr(&self.bytes, at, len).unwrap_or_default()
    }
}

/// Walk headers from offset 0, stopping at the end-of-archive zero block, a bad
/// checksum, or `limit` headers.
fn walk(view: &dyn FileView, limit: usize) -> Vec<Header> {
    let size = view.size();
    let mut out = Vec::new();
    let mut off = 0u64;
    while out.len() < limit {
        let Some(h) = fetch(view, off, BLOCK as usize) else {
            break;
        };
        if !header_ok(&h) {
            break;
        }
        let Some(len) = slice(&h, 124, 12).and_then(number) else {
            break;
        };
        out.push(Header { off, bytes: h });
        let Some(next) = len
            .checked_add(BLOCK - 1)
            .map(|l| l / BLOCK * BLOCK)
            .and_then(|l| off.checked_add(BLOCK + l))
        else {
            break;
        };
        if next >= size {
            break;
        }
        off = next;
    }
    out
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    for h in walk(view, MAX_HEADERS) {
        let owner = &h.bytes[UNAME..UNAME + OWNER_LEN];
        if is_blank(owner) {
            continue;
        }
        let uname = latin1(h.field(UNAME, 32));
        let gname = latin1(h.field(UNAME + 32, 32));
        let uid = slice(&h.bytes, 108, 8).and_then(number).unwrap_or(0);
        let gid = slice(&h.bytes, 116, 8).and_then(number).unwrap_or(0);
        let name = latin1(h.field(0, 100));
        out.push(finding(
            "tar.owner",
            Category::Junk(JunkKind::Comment),
            Confidence::Moderate,
            Severity::Notice,
            format!(
                "tar entry owner \"{}\"",
                clip(&format!("{}/{}", uname.trim(), gname.trim()), TITLE_CHARS)
            ),
            Evidence::at(h.off + UNAME as u64)
                .with_bytes(owner.to_vec())
                .with_note(format!(
                    "entry \"{}\": uname \"{}\" (uid {uid}), gname \"{}\" (gid {gid})",
                    clip(&name, NOTE_CHARS),
                    clip(&uname, NOTE_CHARS),
                    clip(&gname, NOTE_CHARS)
                )),
            Some(Marker {
                region: Region::new(h.off + UNAME as u64, OWNER_LEN as u64),
                removal: RemovalStrategy::StructuralRemove,
                container: ContainerKind::TarHeader,
                reversible: true,
            }),
        ));
    }
}

/// Structural scrub of one tar header's owner names ([`ContainerKind::TarHeader`]).
///
/// `region` must be exactly the 64 bytes of `uname` and `gname` (offsets 265 to
/// 328) of a header with a valid checksum that a walk from offset 0 reaches.
/// The result is the same length: both names are set to NUL and that header's
/// checksum is recomputed (six octal digits, NUL, space), so the archive stays
/// valid. Numeric uid and gid are left as they are.
pub(super) fn remove_owner(data: &[u8], region: Region) -> Option<Vec<u8>> {
    if region.len != OWNER_LEN as u64 {
        return None;
    }
    let hdr = region.offset.checked_sub(UNAME as u64)?;
    if hdr % BLOCK != 0 {
        return None;
    }
    let view = crate::scan::MemView::new("", data.to_vec());
    let limit = usize::try_from(hdr / BLOCK).ok()?.saturating_add(1);
    walk(&view, limit).iter().find(|h| h.off == hdr)?;
    let s = usize::try_from(hdr).ok()?;
    let mut out = data.to_vec();
    let header = out.get_mut(s..s + BLOCK as usize)?;
    header[UNAME..UNAME + OWNER_LEN].fill(0);
    let sum = checksum(header);
    let field = format!("{sum:06o}\0 ");
    header[CHKSUM..CHKSUM + 8].copy_from_slice(field.as_bytes().get(..8)?);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::archive::probes;
    use crate::parsers::image::shared::testkit::{apply, garbage, run, with_id};

    fn header(name: &str, size: usize, uname: &str, gname: &str) -> Vec<u8> {
        let mut h = vec![0u8; 512];
        h[..name.len()].copy_from_slice(name.as_bytes());
        h[100..108].copy_from_slice(b"0000644\0");
        h[108..116].copy_from_slice(b"0001750\0");
        h[116..124].copy_from_slice(b"0000024\0");
        h[124..136].copy_from_slice(format!("{size:011o}\0").as_bytes());
        h[136..148].copy_from_slice(b"14533000000\0");
        h[156] = b'0';
        h[257..263].copy_from_slice(b"ustar\0");
        h[263..265].copy_from_slice(b"00");
        h[265..265 + uname.len()].copy_from_slice(uname.as_bytes());
        h[297..297 + gname.len()].copy_from_slice(gname.as_bytes());
        let sum = checksum(&h);
        h[148..156].copy_from_slice(format!("{sum:06o}\0 ").as_bytes());
        h
    }

    fn build() -> Vec<u8> {
        let mut v = header("a.txt", 5, "alice", "staff");
        let mut data = b"hello".to_vec();
        data.resize(512, 0);
        v.extend(data);
        v.extend(header("dir/", 0, "", ""));
        v.extend(header("b.txt", 0, "bob", "wheel"));
        v.extend(vec![0u8; 1024]);
        v
    }

    fn scan(data: &[u8]) -> Vec<Finding> {
        run(probes(), "a.tar", data, "tar")
    }

    #[test]
    fn owners_found_and_scrubbed() {
        let data = build();
        let fs = scan(&data);
        let owners = with_id(&fs, "tar.owner");
        assert_eq!(owners.len(), 2);
        assert_eq!(owners[0].title, "tar entry owner \"alice/staff\"");
        let note = owners[0].evidence.note.clone().unwrap();
        assert!(note.contains("uid 1000") && note.contains("gid 20") && note.contains("a.txt"));
        assert_eq!(owners[1].evidence.offset, 1536 + 265);

        let mut cur = data.clone();
        for f in &owners {
            cur = apply(&cur, f);
            assert_eq!(cur.len(), data.len());
        }
        assert!(scan(&cur).is_empty());
        let v = crate::scan::MemView::new("", cur.clone());
        let hs = walk(&v, 64);
        assert_eq!(hs.len(), 3);
        assert!(hs.iter().all(|h| header_ok(&h.bytes)));
    }

    #[test]
    fn remover_refuses_misaligned_regions() {
        let data = build();
        assert!(remove_owner(&data, Region::new(265, 64)).is_some());
        assert!(remove_owner(&data, Region::new(266, 64)).is_none());
        assert!(remove_owner(&data, Region::new(265, 32)).is_none());
        // Offset 512 is file data, not a header.
        assert!(remove_owner(&data, Region::new(512 + 265, 64)).is_none());
        let mut bad = data.clone();
        bad[0] ^= 1;
        assert!(remove_owner(&bad, Region::new(265, 64)).is_none());
    }

    #[test]
    fn numbers() {
        assert_eq!(number(b"0000644\0"), Some(0o644));
        assert_eq!(number(b"   17 \0\0"), Some(0o17));
        assert_eq!(number(b"\x80\0\0\0\0\0\x01\x00"), Some(256));
        assert_eq!(number(b"12a"), None);
        assert_eq!(number(b"\0\0"), Some(0));
    }

    #[test]
    fn garbage_and_truncation_are_safe() {
        let data = build();
        for cut in (0..data.len()).step_by(7) {
            let _ = scan(&data[..cut]);
        }
        for seed in 0..32 {
            assert!(scan(&garbage(seed, 2048)).is_empty());
        }
        let mut g = garbage(3, 1024);
        g[257..263].copy_from_slice(b"ustar\0");
        assert!(scan(&g).is_empty());
    }
}
