use super::*;
use crate::edit::deattribute::Mode;
use crate::edit::deattribute::mem::{SliceView, deattribute_bytes_mode};
use crate::parsers::pe::image::PeImage;

fn put_u16(b: &mut [u8], at: usize, v: u16) {
    b[at..at + 2].copy_from_slice(&v.to_le_bytes());
}
fn put_u32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_le_bytes());
}
fn put_u64(b: &mut [u8], at: usize, v: u64) {
    b[at..at + 8].copy_from_slice(&v.to_le_bytes());
}
fn put(b: &mut [u8], at: usize, v: &[u8]) {
    b[at..at + v.len()].copy_from_slice(v);
}
fn u32_of(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().unwrap())
}
fn has(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

const OPT: usize = 0x98;

/// A PE32+ with an `.rdata` data section (file 0x200, RVA 0x1000) and an
/// executable `.text` (file 0xa00, RVA 0x2000). The export table names the
/// module `NovaFlow_64.AEX` and exports `NovaFlowRender`; the import table
/// pulls `NovaFlowActivate` from `NovaFlowCore.dll`. All names invented.
fn pe_fixture(checksum: u32) -> Vec<u8> {
    let mut b = vec![0u8; 0xc00];
    put(&mut b, 0, b"MZ");
    put_u32(&mut b, 0x3c, 0x80);
    put(&mut b, 0x80, b"PE\0\0");
    put_u16(&mut b, 0x84, 0x8664);
    put_u16(&mut b, 0x86, 2);
    put_u32(&mut b, 0x88, 0x5abc_1234);
    put_u16(&mut b, 0x94, 0xf0);
    put_u16(&mut b, OPT, 0x20b);
    put_u32(&mut b, OPT + 60, 0x200);
    put_u32(&mut b, OPT + 64, checksum);
    put_u32(&mut b, OPT + 108, 16);
    // Export directory (index 0) and import directory (index 1).
    put_u32(&mut b, OPT + 112, 0x1000);
    put_u32(&mut b, OPT + 116, 0x28);
    put_u32(&mut b, OPT + 120, 0x1600);
    put_u32(&mut b, OPT + 124, 40);
    let sec = OPT + 0xf0;
    put(&mut b, sec, b".rdata");
    put_u32(&mut b, sec + 8, 0x800);
    put_u32(&mut b, sec + 12, 0x1000);
    put_u32(&mut b, sec + 16, 0x800);
    put_u32(&mut b, sec + 20, 0x200);
    put_u32(&mut b, sec + 36, 0x4000_0040);
    let text = sec + 40;
    put(&mut b, text, b".text");
    put_u32(&mut b, text + 8, 0x200);
    put_u32(&mut b, text + 12, 0x2000);
    put_u32(&mut b, text + 16, 0x200);
    put_u32(&mut b, text + 20, 0xa00);
    put_u32(&mut b, text + 36, 0x6000_0020);

    // Export directory at 0x200.
    put_u32(&mut b, 0x200 + 4, 0x1111_2222);
    put_u32(&mut b, 0x200 + 12, 0x1100);
    put_u32(&mut b, 0x200 + 20, 1);
    put_u32(&mut b, 0x200 + 24, 1);
    put_u32(&mut b, 0x200 + 28, 0x1040);
    put_u32(&mut b, 0x200 + 32, 0x1050);
    put_u32(&mut b, 0x200 + 36, 0x1060);
    put_u32(&mut b, 0x240, 0x2000);
    put_u32(&mut b, 0x250, 0x1120);
    put(&mut b, 0x300, b"NovaFlow_64.AEX\0");
    put(&mut b, 0x320, b"NovaFlowRender\0");

    // Strings in data.
    put(&mut b, 0x350, b"Copyright 2000-2026 V:Studio Effects\0");
    put(&mut b, 0x390, b"(V:Studio LIB)\0");
    put(&mut b, 0x3b0, b"NovaFlow GUI\0");
    put(&mut b, 0x3d0, b"NovaFlow Render-only\0");
    put(&mut b, 0x400, b".?AVNovaFlowInternal@@\0");
    put(&mut b, 0x440, b"VFXQ Regular GUI\0");
    put(&mut b, 0x470, b"VFXQ Regular GUI\0");
    put(&mut b, 0x4a0, b".?AVVFXQObject@@\0");
    put(&mut b, 0x500, b"https://example.org/activation\0");
    put(&mut b, 0x540, b"dispatched by the scheduler\0");
    put(&mut b, 0x580, b"Patched by Nobody Group\0");

    // Import descriptor at 0x800, thunks at 0x840 and 0x860.
    put_u32(&mut b, 0x800, 0x1640);
    put_u32(&mut b, 0x800 + 12, 0x1680);
    put_u32(&mut b, 0x800 + 16, 0x1660);
    put_u64(&mut b, 0x840, 0x16a0);
    put_u64(&mut b, 0x860, 0x16a0);
    put(&mut b, 0x880, b"NovaFlowCore.dll\0");
    put(&mut b, 0x8a2, b"NovaFlowActivate\0");

    // Code: a string that looks like a credit must survive.
    put(&mut b, 0xa40, b"\0NovaFlow GUI\0");
    b
}

fn utf16z(text: &str) -> Vec<u8> {
    text.encode_utf16()
        .chain([0])
        .flat_map(u16::to_le_bytes)
        .collect()
}

fn vblock(key: &str, value: &[u8], value_len: u16, text: bool, children: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0u8; 6];
    b.extend(utf16z(key));
    while !b.len().is_multiple_of(4) {
        b.push(0);
    }
    b.extend(value);
    for child in children {
        while !b.len().is_multiple_of(4) {
            b.push(0);
        }
        b.extend(child);
    }
    let len = b.len() as u16;
    put_u16(&mut b, 0, len);
    put_u16(&mut b, 2, value_len);
    put_u16(&mut b, 4, u16::from(text));
    b
}

fn version_blob(company: &str) -> Vec<u8> {
    let value = utf16z(company);
    let company = vblock("CompanyName", &value, (value.len() / 2) as u16, true, &[]);
    let table = vblock("040904B0", &[], 0, true, &[company]);
    let sfi = vblock("StringFileInfo", &[], 0, true, &[table]);
    vblock("VS_VERSION_INFO", &[0; 52], 52, false, &[sfi])
}

fn resource_pe(company: &str, manifest_name: &str) -> Vec<u8> {
    let mut b = pe_fixture(0x1234);
    b.resize(0x1c00, 0);
    put_u16(&mut b, 0x86, 3);
    let section = OPT + 0xf0 + 80;
    put(&mut b, section, b".rsrc");
    put_u32(&mut b, section + 8, 0x1000);
    put_u32(&mut b, section + 12, 0x3000);
    put_u32(&mut b, section + 16, 0x1000);
    put_u32(&mut b, section + 20, 0xc00);
    put_u32(&mut b, section + 36, 0x4000_0040);
    put_u32(&mut b, OPT + 112 + 2 * 8, 0x3000);
    put_u32(&mut b, OPT + 116 + 2 * 8, 0x1000);

    let base = 0xc00;
    put_u16(&mut b, base + 14, 3);
    for (i, (kind, rel, leaf)) in [(6, 0x40, 0x300), (16, 0xc0, 0x500), (24, 0x140, 0x900)]
        .into_iter()
        .enumerate()
    {
        put_u32(&mut b, base + 0x10 + i * 8, kind);
        put_u32(&mut b, base + 0x14 + i * 8, 0x8000_0000 | rel);
        put_u16(&mut b, base + rel as usize + 14, 1);
        put_u32(&mut b, base + rel as usize + 16, 1);
        put_u32(&mut b, base + rel as usize + 20, 0x8000_0000 | (rel + 0x20));
        put_u16(&mut b, base + rel as usize + 0x20 + 14, 1);
        put_u32(&mut b, base + rel as usize + 0x30, 0x409);
        put_u32(&mut b, base + rel as usize + 0x34, rel + 0x40);
        let entry = base + rel as usize + 0x40;
        put_u32(&mut b, entry, 0x3000 + leaf);
        let body = match kind {
            6 => {
                let value = "\u{1f680} Glimmer license expired; retry later";
                let mut body = (value.encode_utf16().count() as u16).to_le_bytes().to_vec();
                body.extend(value.encode_utf16().flat_map(u16::to_le_bytes));
                body.extend([0u8; 30]);
                body
            }
            16 => version_blob(company),
            24 => format!("<assembly><assemblyIdentity name=\"{manifest_name}.Plugin\" version=\"1.0.0.0\"/></assembly>").into_bytes(),
            _ => unreachable!(),
        };
        put_u32(&mut b, entry + 4, body.len() as u32);
        put(&mut b, base + leaf as usize, &body);
    }
    b
}

fn deep(name: &str, data: &[u8]) -> Vec<u8> {
    deattribute_bytes_mode(name, data, Mode::Deep)
        .bytes
        .expect("the deep pass changed something")
}

#[test]
fn deep_pe_blanks_correlated_strings_and_rewrites_build_fields() {
    let source = pe_fixture(0x1234);
    let out = deep("NovaFlow_64.aex", &source);
    assert_eq!(out.len(), source.len());
    for gone in [
        &b"V:Studio"[..],
        b"NovaFlow GUI\0\0",
        b"VFXQ Regular",
        b"Nobody Group",
    ] {
        assert!(
            !has(&out[0x200..0xa00], gone),
            "{}",
            String::from_utf8_lossy(gone)
        );
    }
    assert!(has(&out, b"Render-only"), "useful message kept");
    assert!(
        has(&out, b"https://example.org/activation"),
        "functional URL kept"
    );
    assert!(has(&out, b"module_____.AEX\0"), "neutral export name");
    assert_eq!(u32_of(&out, 0x88), 0, "COFF stamp cleared");
    assert_eq!(u32_of(&out, 0x204), 0, "export stamp cleared");
    let view = SliceView::new("x", &out);
    let img = PeImage::parse(&view).expect("still a PE");
    assert_eq!(
        Some(img.checksum),
        crate::parsers::pe::pe_checksum(&view, img.checksum_off),
        "checksum matches the copy"
    );
}

#[test]
fn deep_pe_never_touches_code_imports_exports_or_rtti() {
    let source = pe_fixture(0x1234);
    let out = deep("x.dll", &source);
    assert_eq!(&out[0xa00..0xc00], &source[0xa00..0xc00], "code section");
    assert_eq!(&out[0x800..0x8c0], &source[0x800..0x8c0], "import tables");
    assert_eq!(&out[0x320..0x330], &source[0x320..0x330], "exported name");
    assert_eq!(&out[0x240..0x264], &source[0x240..0x264], "export arrays");
    assert!(has(&out, b".?AVNovaFlowInternal@@"));
    assert!(has(&out, b".?AVVFXQObject@@"));
    assert!(
        has(&out, b"dispatched by the scheduler"),
        "word-bounded match"
    );
}

#[test]
fn version_identity_cleans_length_prefixed_resource_text_without_erasing_message() {
    let mut source = resource_pe("Glimmer Labs", "Neutral");
    put(&mut source, 0x700, b"Glimmer startup failed; retry later\0");
    let string_len = &source[0xf00..0xf02];
    let out = deep("other.exe", &source);
    assert_eq!(out.len(), source.len());
    assert_eq!(&out[0xf00..0xf02], string_len, "RT_STRING length kept");
    assert!(!has(&out[0xf02..0xf90], &utf16z("Glimmer")[..14]));
    assert!(has(
        &out[0xf02..0xf90],
        &utf16z("license expired; retry later")[..56]
    ));
    assert!(!has(&out[0x700..0x740], b"Glimmer startup"));
    assert!(has(&out[0x700..0x740], b"startup failed; retry later"));
    assert!(has(&out, b"Neutral.Plugin"), "manifest identity kept");
    let view = SliceView::new("x", &out);
    assert!(PeImage::parse(&view).is_some());
    assert!(
        deattribute_bytes_mode("x.exe", &out, Mode::Deep)
            .bytes
            .is_none()
    );
}

#[test]
fn manifest_url_and_registry_correlate_without_rewriting_functional_values() {
    let mut source = resource_pe("Microsoft", "Glimmer");
    let url = b"https://license.glimmer.example/activate\0";
    let key = b"HKCU\\Software\\Glimmer\\Settings\0";
    put(&mut source, 0x6c0, url);
    put(&mut source, 0x700, key);
    put(
        &mut source,
        0x750,
        b"Glimmer license invalid; retry later\0",
    );
    let out = deep("x.exe", &source);
    assert!(has(&out, url), "URL kept byte-exact");
    assert!(has(&out, key), "registry key kept byte-exact");
    assert!(has(&out, b"Glimmer.Plugin"), "manifest identity kept");
    assert!(!has(&out[0x750..0x790], b"Glimmer license invalid"));
    assert!(has(&out[0x750..0x790], b"license invalid; retry later"));
    assert!(
        deattribute_bytes_mode("x.exe", &out, Mode::Deep)
            .bytes
            .is_none()
    );
}

#[test]
fn one_weak_source_does_not_establish_a_root_and_mixed_messages_keep_endpoints() {
    let mut found = Vec::new();
    strings(
        b"\0https://license.glimmer.example/activate\0",
        0,
        true,
        &mut found,
    );
    assert!(!roots(&found, None, &Vec::new()).contains("glimmer"));
    found.push(Hit {
        off: 100,
        len: 31,
        text: "HKCU\\Software\\Glimmer\\Settings".into(),
        encoding: Encoding::Utf8,
    });
    let roots = roots(&found, None, &Vec::new());
    assert!(roots.contains("glimmer"));
    let text = "Glimmer license invalid; see https://glimmer.example/activate;vendor=Glimmer HKCU\\Software\\Glimmer\\Settings;mode=Glimmer";
    let mut edited = text.as_bytes().to_vec();
    for (start, end, _) in redaction_spans(text, &roots) {
        edited[start..end].fill(b' ');
    }
    let edited = String::from_utf8(edited).unwrap();
    assert!(!edited.starts_with("Glimmer"));
    assert!(edited.contains("license invalid; see"));
    assert!(edited.contains("https://glimmer.example/activate;vendor=Glimmer"));
    assert!(edited.contains("HKCU\\Software\\Glimmer\\Settings;mode=Glimmer"));
}

#[test]
fn a_resource_leaf_pointing_into_code_is_never_swept() {
    let mut source = resource_pe("Glimmer Labs", "Neutral");
    put_u32(&mut source, 0xc80, 0x2020);
    put_u32(&mut source, 0xc84, 80);
    let code = &source[0xa00..0xc00];
    let out = deep("x.exe", &source);
    assert_eq!(&out[0xa00..0xc00], code);
}

#[test]
fn pdb_and_certificate_mine_a_name_then_clear_the_detached_certificate() {
    let mut source = pe_fixture(0x1234);
    put(&mut source, 0x700, b"Glimmer startup ready\0");
    put_u32(&mut source, OPT + 112 + 6 * 8, 0x1400);
    put_u32(&mut source, OPT + 116 + 6 * 8, 28);
    put_u32(&mut source, 0x600 + 12, 2);
    let pdb = b"C:\\Build\\Glimmer.pdb\0";
    put_u32(&mut source, 0x600 + 16, (24 + pdb.len()) as u32);
    put_u32(&mut source, 0x600 + 24, 0x650);
    put(&mut source, 0x650, b"RSDS");
    put(&mut source, 0x650 + 24, pdb);
    source.resize(0xc80, 0);
    put_u32(&mut source, OPT + 112 + 4 * 8, 0xc00);
    put_u32(&mut source, OPT + 116 + 4 * 8, 0x80);
    put_u32(&mut source, 0xc00, 0x80);
    put_u16(&mut source, 0xc04, 0x200);
    put_u16(&mut source, 0xc06, 2);
    put(&mut source, 0xc08, b"\x06\x03\x55\x04\x0a\x0c\x07Glimmer");
    let out = deep("x.exe", &source);
    assert!(!has(&out[0x700..0x740], b"Glimmer"));
    assert!(has(&out[0x700..0x740], b"startup ready"));
    assert!(!has(&out, pdb));
    assert_eq!(&out[0xc00..0xc80], &[0; 0x80]);
    assert_eq!(u32_of(&out, OPT + 112 + 4 * 8), 0);
    let view = SliceView::new("x", &out);
    let img = PeImage::parse(&view).unwrap();
    assert_eq!(
        Some(img.checksum),
        crate::parsers::pe::pe_checksum(&view, img.checksum_off)
    );
    assert!(
        deattribute_bytes_mode("x.exe", &out, Mode::Deep)
            .bytes
            .is_none()
    );
}

#[test]
fn deep_is_idempotent_name_independent_and_deterministic() {
    let source = pe_fixture(0x1234);
    let first = deep("NovaFlow_64.aex", &source);
    for _ in 0..10 {
        assert_eq!(deep("NovaFlow_64.aex", &source), first);
    }
    assert_eq!(deep("dir/other-name.dll", &source), first);
    let again = deattribute_bytes_mode("NovaFlow_64.deattributed.aex", &first, Mode::Deep);
    assert!(again.bytes.is_none(), "a deep copy plans nothing more");
}

#[test]
fn a_zero_checksum_stays_zero() {
    let out = deep("x.dll", &pe_fixture(0));
    assert_eq!(u32_of(&out, OPT + 64), 0);
}

#[test]
fn basic_mode_refreshes_a_nonzero_checksum() {
    let source = pe_fixture(0x1234);
    let Some(out) = deattribute_bytes_mode("x.dll", &source, Mode::Basic).bytes else {
        return;
    };
    let view = SliceView::new("x", &out);
    let img = PeImage::parse(&view).unwrap();
    assert_eq!(
        Some(img.checksum),
        crate::parsers::pe::pe_checksum(&view, img.checksum_off)
    );
}

#[test]
fn a_signed_pe_is_left_cleanly_unsigned_with_a_caveat() {
    let mut source = pe_fixture(0x1234);
    // Security directory (index 4): a file offset and size into an overlay.
    put_u32(&mut source, OPT + 112 + 32, 0xb80);
    put_u32(&mut source, OPT + 116 + 32, 0x40);
    let view = SliceView::new("x.dll", &source);
    let found = sweep(
        &crate::model::FileReport {
            format: Some("pe".into()),
            ..crate::model::FileReport::new("x.dll".into(), source.len() as u64)
        },
        &view,
    );
    assert!(found.caveats.contains(&Caveat::SignatureInvalidated));
    let out = deep("x.dll", &source);
    assert_eq!(u32_of(&out, OPT + 144), 0);
    assert_eq!(u32_of(&out, OPT + 148), 0);
}

/// An ELF64 with `.rodata`, executable `.text`, `.dynstr` and `.shstrtab`,
/// each holding the same copyright line.
fn elf_fixture() -> Vec<u8> {
    let line = b"Copyright 2024 Glimmer Labs\0";
    let mut b = vec![0u8; 0x280];
    put(&mut b, 0, b"\x7fELF\x02\x01\x01");
    put_u16(&mut b, 16, 3);
    put_u16(&mut b, 18, 0x3e);
    put_u32(&mut b, 20, 1);
    put_u64(&mut b, 40, 0x140);
    put_u16(&mut b, 52, 64);
    put_u16(&mut b, 54, 56);
    put_u16(&mut b, 58, 64);
    put_u16(&mut b, 60, 5);
    put_u16(&mut b, 62, 4);
    put(&mut b, 0x41, line);
    put(&mut b, 0x81, line);
    put(&mut b, 0xc1, line);
    let names = b"\0.rodata\0.text\0.dynstr\0.shstrtab\0";
    put(&mut b, 0x100, names);
    // (name, type, flags, offset, size)
    let shdrs: [(u32, u32, u64, u64, u64); 5] = [
        (0, 0, 0, 0, 0),
        (1, 1, 0x2, 0x40, 0x40),
        (9, 1, 0x6, 0x80, 0x40),
        (15, 3, 0x2, 0xc0, 0x40),
        (23, 3, 0, 0x100, names.len() as u64),
    ];
    for (i, (name, kind, flags, off, size)) in shdrs.into_iter().enumerate() {
        let at = 0x140 + i * 64;
        put_u32(&mut b, at, name);
        put_u32(&mut b, at + 4, kind);
        put_u64(&mut b, at + 8, flags);
        put_u64(&mut b, at + 24, off);
        put_u64(&mut b, at + 32, size);
    }
    b
}

#[test]
fn deep_elf_sweeps_rodata_only() {
    let source = elf_fixture();
    let out = deep("glimmer", &source);
    assert!(!has(&out[0x40..0x80], b"Glimmer"), ".rodata swept");
    assert_eq!(
        &out[0x80..0x140],
        &source[0x80..0x140],
        ".text and .dynstr kept"
    );
    assert!(
        deattribute_bytes_mode("glimmer", &out, Mode::Deep)
            .bytes
            .is_none(),
        "idempotent"
    );
}

/// A thin 64-bit Mach-O whose `__TEXT,__cstring` holds a copyright line at
/// 0x100, with the same line again at 0x180 outside any listed section.
fn macho_fixture() -> Vec<u8> {
    let line = b"Copyright 2024 Glimmer Labs\0";
    let mut b = vec![0u8; 0x200];
    put(&mut b, 0, &[0xcf, 0xfa, 0xed, 0xfe]);
    put_u32(&mut b, 4, 0x0100_0007);
    put_u32(&mut b, 8, 3);
    put_u32(&mut b, 12, 2);
    put_u32(&mut b, 16, 1);
    put_u32(&mut b, 20, 152);
    let lc = 32;
    put_u32(&mut b, lc, 0x19);
    put_u32(&mut b, lc + 4, 152);
    put(&mut b, lc + 8, b"__TEXT");
    put_u64(&mut b, lc + 48, 0x200);
    put_u32(&mut b, lc + 64, 1);
    let s = lc + 72;
    put(&mut b, s, b"__cstring");
    put(&mut b, s + 16, b"__TEXT");
    put_u64(&mut b, s + 40, 0x40);
    put_u32(&mut b, s + 48, 0x100);
    put_u32(&mut b, s + 64, 2);
    put(&mut b, 0x101, line);
    put(&mut b, 0x181, line);
    b
}

#[test]
fn deep_macho_sweeps_listed_sections_only() {
    let source = macho_fixture();
    let out = deep("glimmer", &source);
    assert!(!has(&out[0x100..0x140], b"Glimmer"));
    assert_eq!(&out[0x180..], &source[0x180..]);
}

#[test]
fn deep_text_keeps_json_valid() {
    let source =
        br#"{"name": "tool", "author": "Patched by Nobody Group", "note": "Copyright 2024 Someone"}"#
            .to_vec();
    let out = deep("package.json", &source);
    assert_eq!(out.len(), source.len());
    let text = std::str::from_utf8(&out).unwrap();
    assert!(!text.contains("Nobody") && !text.contains("Someone"));
    assert!(text.contains(r#""name": "tool""#));
    assert_eq!(text.matches('"').count(), 12, "quotes untouched");
    assert!(
        deattribute_bytes_mode("package.json", &out, Mode::Deep)
            .bytes
            .is_none()
    );
}

fn noise(len: usize) -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[test]
fn fallback_skips_compressed_looking_bytes() {
    let credit = b"\0Patched by Nobody Group\0";
    let mut plain = vec![0u8; 0x4000];
    put(&mut plain, 0x2000, credit);
    let out = deep("blob.bin", &plain);
    assert!(!has(&out, b"Nobody"));

    let mut packed = noise(0x4000);
    packed[0] = 0;
    put(&mut packed, 0x2000, credit);
    assert!(
        deattribute_bytes_mode("blob.bin", &packed, Mode::Deep)
            .bytes
            .is_none()
    );
}

#[test]
fn strings_need_nul_bounds() {
    let mut found = Vec::new();
    strings(
        b"xxCopyright Vendor\0\0Copyright Vendor\0",
        0,
        true,
        &mut found,
    );
    assert_eq!(found.len(), 2);
    let inner: Vec<_> = found.iter().filter(|h| h.off == 20).collect();
    assert_eq!(inner.len(), 1);
    found.clear();
    strings(b"a\x01Copyright Vendor\0", 0, false, &mut found);
    assert!(found.is_empty(), "not preceded by NUL");
}

#[test]
fn copyright_vendor_and_word_bounds() {
    assert_eq!(
        copyright_vendor("Copyright (c) 2001-2026 Glimmer Labs, Inc.").as_deref(),
        Some("glimmer")
    );
    assert_eq!(copyright_vendor("Copyright Microsoft Corporation"), None);
    assert!(has_word("patched by x", "patched by"));
    assert!(!has_word("dispatched by x", "patched by"));
    assert!(!has_word("unpatched by x", "patched by"));
}
