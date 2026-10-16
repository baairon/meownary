//! 7z: the signature header (format version, start-header CRC) and the first
//! bytes of the next header, which say whether the header is plain, packed,
//! or encrypted with 7zAES.

use crate::model::{BrandKind, Category, Confidence, DeceptionKind, Evidence, Finding, Severity};
use crate::scan::FileView;
use crate::util::bytes::{u32_le, u64_le};

use crate::parsers::image::shared::{
    NOTE_CHARS, crc32, excerpt, fetch, finding, pw_in_name, quote,
};

const SIG: &[u8] = b"7z\xbc\xaf\x27\x1c";
/// The 7zAES coder id.
const AES_ID: &[u8] = &[0x06, 0xF1, 0x07, 0x01];
/// Most next-header bytes examined.
const MAX_PEEK: u64 = 4096;

/// Whether `buf` names the 7zAES coder: its 4-byte id preceded by a coder
/// flag byte whose low nibble is the id size.
fn has_aes(buf: &[u8]) -> bool {
    buf.windows(5)
        .any(|w| w[0] & 0x0F == 4 && w[0] & 0xC0 == 0 && &w[1..] == AES_ID)
}

pub(super) fn run(view: &dyn FileView, out: &mut Vec<Finding>) {
    let Some(h) = fetch(view, 0, 32) else {
        return;
    };
    if &h[..6] != SIG || u32_le(&h, 8) != Some(crc32(&h[12..32])) {
        return;
    }
    let (major, minor) = (h[6], h[7]);
    let (Some(next_off), Some(next_size)) = (u64_le(&h, 12), u64_le(&h, 20)) else {
        return;
    };
    let mut state = "an empty archive";
    let mut encrypted = false;
    if next_size > 0 {
        let Some(abs) = next_off.checked_add(32) else {
            return;
        };
        let Some(peek) = fetch(view, abs, next_size.min(MAX_PEEK) as usize) else {
            return;
        };
        let aes = has_aes(&peek);
        encrypted = aes;
        state = match (peek[0], aes) {
            (0x17, true) => "an encrypted header (7zAES), which hides the file names",
            (0x17, false) => "a packed (compressed) header",
            (0x01, true) => "a plain header and 7zAES-encrypted file data",
            (0x01, false) => "a plain header",
            _ => return,
        };
    }
    if let (true, Some(name)) = (encrypted, pw_in_name(view)) {
        out.push(finding(
            "7z.encrypted",
            Category::Deception(DeceptionKind::PwInFilename),
            Confidence::Strong,
            Severity::Warn,
            "Encrypted 7z with a password in its file name",
            Evidence::at(0).with_bytes(excerpt(&h)).with_note(format!(
                "the archive uses 7zAES and the file name \"{}\" appears to carry the password",
                quote(name.as_bytes(), NOTE_CHARS)
            )),
            None,
        ));
    }
    out.push(finding(
        "7z.info",
        Category::Brand(BrandKind::Toolchain),
        Confidence::Moderate,
        Severity::Info,
        format!("7-Zip archive v{major}.{minor}"),
        Evidence::at(6)
            .with_bytes(vec![major, minor])
            .with_note(format!("format version {major}.{minor} with {state}")),
        None,
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parsers::archive::probes;
    use crate::parsers::image::shared::testkit::{garbage, run, with_id};

    fn build(next: &[u8]) -> Vec<u8> {
        let mut tail = 0u64.to_le_bytes().to_vec();
        tail.extend_from_slice(&(next.len() as u64).to_le_bytes());
        tail.extend_from_slice(&crc32(next).to_le_bytes());
        let mut v = SIG.to_vec();
        v.extend_from_slice(&[0, 4]);
        v.extend_from_slice(&crc32(&tail).to_le_bytes());
        v.extend(tail);
        v.extend_from_slice(next);
        v
    }

    fn scan(name: &str, data: &[u8]) -> Vec<Finding> {
        run(probes(), name, data, "7z")
    }

    #[test]
    fn version_and_header_state() {
        let fs = scan("a.7z", &build(&[0x01, 0x04, 0x00]));
        assert_eq!(fs.len(), 1);
        assert_eq!(fs[0].title, "7-Zip archive v0.4");
        assert!(
            fs[0]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("a plain header")
        );
        let packed = [
            0x17, 0x06, 0x80, 0x01, 0x09, 0x10, 0x0B, 0x01, 0x00, 0x01, 0x21, 0x03,
        ];
        let fs = scan("a.7z", &build(&packed));
        assert!(fs[0].evidence.note.as_deref().unwrap().contains("packed"));
    }

    #[test]
    fn encrypted_header_with_password_name() {
        let enc = [
            0x17, 0x06, 0x0B, 0x01, 0x00, 0x02, 0x24, 0x06, 0xF1, 0x07, 0x01, 0x0A,
        ];
        let data = build(&enc);
        let fs = scan("files_pass_hunter2.7z", &data);
        assert_eq!(with_id(&fs, "7z.encrypted").len(), 1);
        let fs = scan("files.7z", &data);
        assert!(with_id(&fs, "7z.encrypted").is_empty());
        assert!(
            fs[0]
                .evidence
                .note
                .as_deref()
                .unwrap()
                .contains("hides the file names")
        );
    }

    #[test]
    fn garbage_and_truncation_are_safe() {
        let data = build(&[0x01, 0x04, 0x00]);
        for cut in 0..data.len() {
            assert!(scan("a.7z", &data[..cut]).is_empty());
        }
        let mut bad = data.clone();
        bad[9] ^= 1;
        assert!(scan("a.7z", &bad).is_empty());
        for seed in 0..32 {
            assert!(scan("g.7z", &garbage(seed, 256)).is_empty());
        }
    }
}
