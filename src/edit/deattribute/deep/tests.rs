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
pub(crate) fn pe_fixture(checksum: u32) -> Vec<u8> {
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
fn deep_pe_scrubs_readable_identity_in_code_linkage_and_rtti() {
    let source = pe_fixture(0x1234);
    let out = deep("x.dll", &source);
    assert!(!has(&out[0xa00..0xc00], b"NovaFlow"), "code string");
    assert_eq!(
        &out[0x800..0x8c0],
        &source[0x800..0x8c0],
        "import descriptors, thunks, DLL name and function name"
    );
    assert!(!has(&out[0x320..0x330], b"NovaFlow"), "exported name");
    assert_eq!(&out[0x240..0x264], &source[0x240..0x264], "export arrays");
    assert!(!has(&out, b".?AVNovaFlowInternal@@"));
    assert!(!has(&out, b".?AVVFXQObject@@"));
    assert!(
        has(&out, b"dispatched by the scheduler"),
        "word-bounded match"
    );
}

#[test]
fn deep_pe_scrubs_correlated_vendor_initials_in_identifiers() {
    let mut source = pe_fixture(0x1234);
    put(&mut source, 0x5c0, b"NFL_HOME_DIR\0");
    put(&mut source, 0x600, b"NFL_SERVER\0");
    put(&mut source, 0x620, b"failed to reach nflserver\n\0");
    put(&mut source, 0x650, b"..\\OpenCL\\NFOpenCLMultiDevs.cpp\0");
    put(&mut source, 0x690, b".?AVNFallocator@nf@@\0");
    put(&mut source, 0xa60, b"NFL_QUIT_LIC_FAIL\0");
    let out = deep("x.aex", &source);
    for identity in [
        b"NFL_HOME_DIR".as_slice(),
        b"NFL_SERVER",
        b"nflserver",
        b"NFOpenCLMultiDevs",
        b"NFallocator",
        b"@nf@@",
        b"NFL_QUIT_LIC_FAIL",
    ] {
        assert!(
            !has(&out, identity),
            "{}",
            String::from_utf8_lossy(identity)
        );
    }
    let terms = pe::sweep(&SliceView::new("x", &source)).audit_terms;
    assert_eq!(
        pe::residual_category(&SliceView::new("x", &out), &terms),
        Some("PE data")
    );
}

#[test]
fn deep_pe_preserves_import_module_names_during_raw_identity_scrub() {
    let mut source = pe_fixture(0x1234);
    put(&mut source, 0x350, b"Copyright 2024 Basehost\0");
    put(&mut source, 0x5c0, b"Basehost settings\0");
    put(&mut source, 0x880, b"BASEHOST32.dll\0");

    let out = deep("x.aex", &source);

    assert_eq!(&out[0x880..0x880 + 15], b"BASEHOST32.dll\0");
    assert!(!has(&out[0x5c0..0x5c0 + 17], b"Basehost"));
    let terms = pe::sweep(&SliceView::new("x", &source)).audit_terms;
    assert_eq!(
        pe::residual_category(&SliceView::new("x", &out), &terms),
        Some("PE data")
    );
}

#[test]
fn deep_pe_learns_repeated_third_party_labels_and_license_symbols() {
    let mut source = pe_fixture(0x1234);
    put(&mut source, 0x5c0, b"SilverSix Debug\0");
    put(&mut source, 0x600, b"SilverSix License Report\0");
    put(&mut source, 0x650, b"SSLS_CLIENT_OPEN\0");
    put(&mut source, 0x690, b"SSLS_SERVER_CLOSE\0");
    let out = deep("x.aex", &source);
    for term in [
        b"SilverSix".as_slice(),
        b"SSLS_CLIENT_OPEN",
        b"SSLS_SERVER_CLOSE",
    ] {
        assert!(!has(&out, term), "{}", String::from_utf8_lossy(term));
    }
}

#[test]
fn import_verification_detects_a_damaged_system_dll_name() {
    let source = pe_fixture(0x1234);
    let mut copy = source.clone();
    copy[0x880..0x890].copy_from_slice(b"CRYPT32.dll\0    ");
    assert!(!pe::imports_unchanged(
        &SliceView::new("before", &source),
        &SliceView::new("after", &copy)
    ));
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
fn manifest_url_and_registry_names_are_scrubbed_in_deep_mode() {
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
    assert!(!has(&out, url), "URL identity removed");
    assert!(!has(&out, key), "registry identity removed");
    assert!(!has(&out, b"Glimmer.Plugin"), "manifest identity removed");
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
fn a_resource_leaf_pointing_into_code_does_not_block_code_string_scrubbing() {
    let mut source = resource_pe("Glimmer Labs", "Neutral");
    put_u32(&mut source, 0xc80, 0x2020);
    put_u32(&mut source, 0xc84, 80);
    let out = deep("x.exe", &source);
    assert!(!has(&out[0xa00..0xc00], b"NovaFlow"));
    assert!(PeImage::parse(&SliceView::new("x", &out)).is_some());
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
    let mut source = pe_fixture(0x1234);
    // The catalog needle is lowercase, so the fixture's own credit does not
    // match it.
    put(&mut source, 0x5c0, b"patched by Nobody Group\0");
    let out = deattribute_bytes_mode("x.dll", &source, Mode::Basic)
        .bytes
        .expect("the patch credit is blanked");
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
    assert_eq!(
        copyright_vendor("Copyright 2024 Corvid Labs").as_deref(),
        Some("corvid"),
        "a vendor starting with C keeps its first letter"
    );
    assert_eq!(
        copyright_vendor("(C) Cobalt Forge 2019").as_deref(),
        Some("cobalt")
    );
    assert!(has_word("patched by x", "patched by"));
    assert!(!has_word("dispatched by x", "patched by"));
    assert!(!has_word("unpatched by x", "patched by"));
}

fn put_be32(b: &mut [u8], at: usize, v: u32) {
    b[at..at + 4].copy_from_slice(&v.to_be_bytes());
}
fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle)
        .expect("needle present")
}
fn spaces(n: usize) -> String {
    " ".repeat(n)
}
fn pstr(text: &[u8]) -> Vec<u8> {
    let mut v = vec![text.len() as u8];
    v.extend_from_slice(text);
    v
}

fn sweep_as(format: &str, name: &str, data: &[u8]) -> Deep {
    let view = SliceView::new(name, data);
    sweep(
        &crate::model::FileReport {
            format: Some(format.into()),
            ..crate::model::FileReport::new(name.into(), data.len() as u64)
        },
        &view,
    )
}

#[test]
fn protected_ranges_keep_every_byte_they_were_given() {
    let mut p = Protected::default();
    p.add(0, 0x200);
    p.add(0x100, 0x10);
    p.add(0x1f0, 0x20);
    p.add(0x400, 0x10);
    p.add(0x300, 0x20);
    p.add(0x320, 0xe0);
    for (start, end, want) in [
        (0, 1, true),
        (0xff, 0x100, true),
        (0x20f, 0x210, true),
        (0x210, 0x300, false),
        (0x300, 0x301, true),
        (0x3ff, 0x400, true),
        (0x40f, 0x410, true),
        (0x410, 0x500, false),
    ] {
        assert_eq!(p.overlaps(start, end), want, "{start:#x}..{end:#x}");
    }
}

#[test]
fn identity_boundary_takes_whole_words_and_case_joins() {
    let at = |text: &str| {
        let start = text.to_ascii_lowercase().find("glimmer").unwrap();
        needle::identity_boundary(text, start, start + "glimmer".len())
    };
    for text in ["Glimmer Labs", "(Glimmer)", "GlimmerRender", "useGlimmer"] {
        assert!(at(text), "{text}");
    }
    for text in [
        "glimmerrender",
        "Glimmered",
        "GLIMMERX",
        "lib_glimmer",
        "glimmer2",
    ] {
        assert!(!at(text), "{text}");
    }
}

#[test]
fn pascal_and_windows_ansi_strings_are_read_and_blanked_in_place() {
    let mut found = Vec::new();
    strings(
        b"\x01\x0cGlimmer Labs\x01\0\xa9 2024 Glimmer Labs\0",
        0,
        false,
        &mut found,
    );
    assert_eq!(
        found,
        [
            Hit {
                off: 2,
                len: 12,
                text: "Glimmer Labs".into(),
                encoding: Encoding::Utf8,
            },
            Hit {
                off: 16,
                len: 19,
                text: "\u{a9} 2024 Glimmer Labs".into(),
                encoding: Encoding::SingleByte,
            },
        ]
    );
    let roots = roots(&found, None, &Vec::new());
    assert!(roots.contains("glimmer"));
    assert_eq!(
        redact_hits(&found, &roots, &Protected::default()),
        [
            (Kind::Brand, 2, vec![b' '; 7]),
            (Kind::Brand, 16, vec![b' '; 19]),
        ],
        "one byte per character"
    );
}

#[test]
fn the_longest_string_across_a_window_edge_is_read_once_and_whole() {
    let edge = (WINDOW - (MAX_STRING as u64 + 1) * 2 - 2) as usize;
    let text = "A".repeat(MAX_STRING);
    let wide = utf16z(&text);
    // The last start the first window owns, so the terminator ends exactly
    // where that window's read does.
    let at = edge - 1;
    let mut data = vec![0u8; at + wide.len() + 0x1000];
    put(&mut data, at, &wide);
    let view = SliceView::new("blob.bin", &data);
    let mut skipped = Vec::new();
    let hits = region_strings(&view, &[(0, data.len() as u64)], &mut skipped);
    assert_eq!(
        hits,
        [Hit {
            off: at as u64,
            len: MAX_STRING * 2,
            text,
            encoding: Encoding::Utf16,
        }]
    );
    assert!(skipped.is_empty());
}

#[test]
fn read_full_refuses_ranges_past_the_file_before_allocating() {
    let data = [7u8; 64];
    let view = SliceView::new("x", &data);
    assert_eq!(read_full(&view, 60, 4), Some(vec![7; 4]));
    assert_eq!(read_full(&view, 61, 4), None);
    assert_eq!(read_full(&view, 0, usize::MAX), None);
    assert_eq!(read_full(&view, u64::MAX, 2), None);
}

#[test]
fn identities_in_code_linkage_and_rtti_are_removed() {
    let out = deattribute_bytes_mode("x.dll", &pe_fixture(0x1234), Mode::Deep);
    let bytes = out.bytes.expect("deep copy");
    assert!(!has(&bytes[0x300..0x800], b"NovaFlow"));
    assert!(!has(&bytes[0xa00..0xc00], b"NovaFlow"));
    assert!(!out.skipped.contains(&Reason::IdentityInCode));
    assert!(!out.skipped.contains(&Reason::FunctionalName));

    // With the identity only in display strings there is nothing to report.
    let mut quiet = pe_fixture(0x1234);
    quiet[0xa40..0xa50].fill(0);
    put(&mut quiet, 0x320, b"RenderMain\0\0\0\0\0");
    put(&mut quiet, 0x400, b".?AVInternalThing@@\0\0\0\0");
    put(&mut quiet, 0x880, b"core.dll\0\0\0\0\0\0\0\0\0");
    put(&mut quiet, 0x8a2, b"Activate\0\0\0\0\0\0\0\0\0");
    let out = deattribute_bytes_mode("x.dll", &quiet, Mode::Deep);
    assert!(out.bytes.is_some());
    for reason in [
        Reason::IdentityInCode,
        Reason::FunctionalName,
        Reason::FunctionalValue,
    ] {
        assert!(!out.skipped.contains(&reason), "{reason:?}");
    }

    // A class named after the vendor is edited on the next source too.
    put(&mut quiet, 0x400, b".?AVNovaFlowInternal@@\0");
    let out = deattribute_bytes_mode("x.dll", &quiet, Mode::Deep);
    assert!(!has(
        &out.bytes.expect("deep copy")[0x400..0x420],
        b"NovaFlow"
    ));
    assert!(!out.skipped.contains(&Reason::FunctionalName));
}

#[test]
fn export_forwarders_lose_the_identity_but_keep_their_framing() {
    let mut source = pe_fixture(0x1234);
    // The directory's range covers its arrays, names and one forwarder.
    put_u32(&mut source, OPT + 116, 0x140);
    put_u32(&mut source, 0x240, 0x10c0);
    let forwarder = b"NovaFlowCore.NovaFlowActivate\0";
    put(&mut source, 0x2c0, forwarder);
    let out = deep("x.dll", &source);
    assert!(!has(&out[0x2c0..0x2c0 + forwarder.len()], b"NovaFlow"));
    assert_eq!(out[0x2c0 + forwarder.len() - 1], 0);
    assert!(has(&out, b"module_____.AEX\0"));
}

/// A resource type: numbered, such as RT_DIALOG, or named, such as `PiPL`.
enum Res {
    Id(u32),
    Named(&'static str),
}

/// [`pe_fixture`] with a `.rsrc` section (file 0xc00, RVA 0x3000) holding each
/// leaf under name 1 and language 0x409, from file 0x1000 on. Returns the image
/// and each leaf's file offset.
fn rsrc_pe(leaves: &[(Res, Vec<u8>)]) -> (Vec<u8>, Vec<usize>) {
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
    let named = leaves
        .iter()
        .filter(|(res, _)| matches!(res, Res::Named(_)))
        .count();
    put_u16(&mut b, base + 12, named as u16);
    put_u16(&mut b, base + 14, (leaves.len() - named) as u16);
    // Named entries come first in a directory.
    let (mut next_named, mut next_id) = (0, named);
    let mut body = 0x400;
    let mut offs = Vec::new();
    for (res, leaf) in leaves {
        let (slot, name) = match res {
            Res::Named(text) => {
                let at = 0x100 + next_named * 0x20;
                put_u16(&mut b, base + at, text.len() as u16);
                put(&mut b, base + at + 2, &utf16z(text)[..text.len() * 2]);
                next_named += 1;
                (next_named - 1, 0x8000_0000 | at as u32)
            }
            Res::Id(id) => {
                next_id += 1;
                (next_id - 1, *id)
            }
        };
        let dir = 0x200 + slot * 0x60;
        put_u32(&mut b, base + 0x10 + slot * 8, name);
        put_u32(&mut b, base + 0x14 + slot * 8, 0x8000_0000 | dir as u32);
        put_u16(&mut b, base + dir + 14, 1);
        put_u32(&mut b, base + dir + 16, 1);
        put_u32(&mut b, base + dir + 20, 0x8000_0000 | (dir + 0x20) as u32);
        put_u16(&mut b, base + dir + 0x20 + 14, 1);
        put_u32(&mut b, base + dir + 0x30, 0x409);
        put_u32(&mut b, base + dir + 0x34, (dir + 0x40) as u32);
        put_u32(&mut b, base + dir + 0x40, 0x3000 + body as u32);
        put_u32(&mut b, base + dir + 0x44, leaf.len() as u32);
        put(&mut b, base + body, leaf);
        offs.push(base + body);
        body = (body + leaf.len() + 15) & !15;
    }
    (b, offs)
}

/// A DLGTEMPLATE with a font, a static label and an OK button.
fn dialog(title: &str, label: &str) -> Vec<u8> {
    let mut d = Vec::new();
    d.extend(0x8000_0040u32.to_le_bytes());
    d.extend([0u8; 4]);
    d.extend(2u16.to_le_bytes());
    d.extend([0u8; 8]);
    // No menu, the default class.
    d.extend([0u8; 4]);
    d.extend(utf16z(title));
    d.extend(8u16.to_le_bytes());
    d.extend(utf16z("MS Shell Dlg"));
    for (class, text) in [(0x82u16, label), (0x80, "OK")] {
        while !d.len().is_multiple_of(4) {
            d.push(0);
        }
        d.extend(0x5000_0000u32.to_le_bytes());
        d.extend([0u8; 12]);
        d.extend(1u16.to_le_bytes());
        d.extend([0xff, 0xff]);
        d.extend(class.to_le_bytes());
        d.extend(utf16z(text));
        d.extend([0u8; 2]);
    }
    d
}

/// A message table of one block: an ANSI entry, then a UTF-16 one.
fn messages(ansi: &str, wide: &str) -> Vec<u8> {
    let mut m = Vec::new();
    for v in [1u32, 1, 2, 16] {
        m.extend(v.to_le_bytes());
    }
    let mut ansi = ansi.as_bytes().to_vec();
    ansi.push(0);
    for (flags, mut text) in [(0u16, ansi), (1, utf16z(wide))] {
        while !(text.len() + 4).is_multiple_of(4) {
            text.push(0);
        }
        m.extend(((text.len() + 4) as u16).to_le_bytes());
        m.extend(flags.to_le_bytes());
        m.extend(text);
    }
    m
}

#[test]
fn dialog_and_message_text_is_cleaned_without_moving_a_field() {
    let (source, at) = rsrc_pe(&[
        (Res::Id(16), version_blob("Glimmer Labs")),
        (
            Res::Id(5),
            dialog("Glimmer NovaFlow Setup", "Copyright 2024 Glimmer Labs"),
        ),
        (
            Res::Id(11),
            messages(
                "Glimmer license expired.\r\n",
                "Copyright 2024 Glimmer Labs\r\n",
            ),
        ),
    ]);
    let out = deep("x.dll", &source);
    let want = dialog(&format!("{} Setup", spaces(16)), &spaces(27));
    assert_eq!(&out[at[1]..at[1] + want.len()], &want[..]);
    let want = messages(
        &format!("{} license expired.\r\n", spaces(7)),
        &format!("{}\r\n", spaces(27)),
    );
    assert_eq!(&out[at[2]..at[2] + want.len()], &want[..]);
    assert!(
        deattribute_bytes_mode("x.dll", &out, Mode::Deep)
            .bytes
            .is_none()
    );
}

/// A PiPL property list. Windows lists open with `1, 0` and store integers
/// little-endian with every four-character code reversed; Mac lists are
/// big-endian. Each value is padded to four bytes.
fn pipl_list(windows: bool, props: &[(&[u8; 4], Vec<u8>)]) -> Vec<u8> {
    let code = |c: &[u8; 4]| {
        let mut c = *c;
        if windows {
            c.reverse();
        }
        c
    };
    let int = |v: u32| {
        if windows {
            v.to_le_bytes()
        } else {
            v.to_be_bytes()
        }
    };
    let mut b = if windows { vec![1, 0] } else { Vec::new() };
    let start = b.len();
    b.extend(int(0));
    b.extend(int(props.len() as u32));
    for (key, value) in props {
        b.extend(code(b"8BIM"));
        b.extend(code(key));
        b.extend(int(0));
        b.extend(int(value.len() as u32));
        b.extend_from_slice(value);
        while !(b.len() - start).is_multiple_of(4) {
            b.push(0);
        }
    }
    b
}

#[test]
fn pipl_lists_parse_in_both_byte_orders_and_keep_entry_points() {
    for (windows, entry) in [(true, b"8664"), (false, b"mi64")] {
        let raw = pipl_list(
            windows,
            &[
                (b"kind", b"eFKT".to_vec()),
                (b"name", pstr(b"NovaFlow Glow")),
                (b"catg", pstr(b"Glimmer")),
                (b"eMNA", pstr(b"Glimmer NovaFlow Glow")),
                (entry, b"GlimmerMain\0".to_vec()),
            ],
        );
        let list = pipl::Pipl::parse(&raw, 0x1000).expect("parses");
        assert_eq!(
            list.evidence(),
            [
                ("NovaFlow Glow".to_string(), Source::Product),
                ("Glimmer".to_string(), Source::Product),
                ("Glimmer NovaFlow Glow".to_string(), Source::MatchName),
            ]
        );
        let (rewrites, skipped) = list.rewrites(&BTreeSet::from(["glimmer".to_string()]));
        assert_eq!(skipped, [Reason::FunctionalName], "entry point kept");
        let off = |needle: &[u8]| 0x1000 + find(&raw, needle) as u64 + 1;
        assert_eq!(rewrites.len(), 3);
        assert_eq!(
            rewrites[0],
            (
                Kind::Brand,
                off(b"\x0dNovaFlow Glow"),
                b"Effect       ".to_vec()
            )
        );
        assert_eq!(
            rewrites[1],
            (Kind::Brand, off(b"\x07Glimmer"), b"Effects".to_vec())
        );
        let (kind, at, id) = &rewrites[2];
        assert_eq!(
            (*kind, *at),
            (Kind::Brand, off(b"\x15Glimmer NovaFlow Glow"))
        );
        assert!(id.len() == 21 && id.starts_with(b"de"));
        assert!(id[2..].iter().all(u8::is_ascii_hexdigit));
    }
}

#[test]
fn a_pipl_resource_gets_neutral_names_and_a_derived_match_name() {
    let raw = pipl_list(
        true,
        &[
            (b"kind", b"eFKT".to_vec()),
            (b"name", pstr(b"NovaFlow Glow")),
            (b"catg", pstr(b"Glimmer")),
            (b"eMNA", pstr(b"Glimmer NovaFlow Glow")),
            (b"8664", b"EffectMain\0\0".to_vec()),
        ],
    );
    let (source, at) = rsrc_pe(&[(Res::Named("PiPL"), raw.clone())]);
    let first = deep("x.aex", &source);
    let leaf = &first[at[0]..at[0] + raw.len()];
    let mut want = raw.clone();
    let edits: [(&[u8], &[u8]); 2] = [
        (b"\x0dNovaFlow Glow", b"Effect       "),
        (b"\x07Glimmer", b"Effects"),
    ];
    for (old, new) in edits {
        let at = find(&raw, old) + 1;
        want[at..at + new.len()].copy_from_slice(new);
    }
    let id = find(&raw, b"\x15Glimmer NovaFlow Glow") + 1;
    assert!(leaf[id..].starts_with(b"de"));
    assert!(leaf[id + 2..id + 21].iter().all(u8::is_ascii_hexdigit));
    want[id..id + 21].copy_from_slice(&leaf[id..id + 21]);
    assert_eq!(leaf, &want[..]);
    assert_eq!(deep("other.aex", &source), first, "same bytes, same copy");
    assert!(
        deattribute_bytes_mode("x.aex", &first, Mode::Deep)
            .bytes
            .is_none()
    );
}

#[test]
fn uppercase_pipl_and_short_match_name_are_scrubbed() {
    let raw = pipl_list(
        true,
        &[
            (b"kind", b"eFKT".to_vec()),
            (b"name", pstr(b"NovaFlow")),
            (b"eMNA", pstr(b"Nova")),
            (b"8664", b"NovaFlowMain\0".to_vec()),
        ],
    );
    let (mut source, at) = rsrc_pe(&[(Res::Named("PIPL"), raw.clone())]);
    put(&mut source, 0x5c0, b"Software\\Glimmer\0");
    put(&mut source, 0x600, b"C:\\Program Files\\GlimmerEffects\\\0");
    put(&mut source, 0x680, b"https://wyday.example/limelm/api/\0");
    put(&mut source, 0x720, &utf16z("Glimmer license"));
    let out = deep("x.aex", &source);
    let leaf = &out[at[0]..at[0] + raw.len()];
    assert!(has(leaf, b"\x08Effect  "));
    let id = find(&raw, b"\x04Nova") + 1;
    assert!(leaf[id..id + 4].starts_with(b"de"));
    assert!(!has(leaf, b"NovaFlow"));
    assert!(!has(&out, b"Glimmer"));
    assert!(!has(&out, b"wyday"));
    assert!(!has(&out, b"limelm"));
    assert!(!has(&out, &utf16z("Glimmer")[..14]));
    assert!(PeImage::parse(&SliceView::new("x", &out)).is_some());
    let terms = pe::sweep(&SliceView::new("x", &source)).audit_terms;
    assert_eq!(
        pe::residual_category(&SliceView::new("x", &out), &terms),
        Some("PE data")
    );
    assert!(
        deattribute_bytes_mode("x.aex", &out, Mode::Deep)
            .bytes
            .is_none()
    );
}

#[test]
fn class_and_display_strings_establish_a_product_missing_from_pipl() {
    let raw = pipl_list(
        true,
        &[
            (b"name", pstr(b"Motion Vectors: Create")),
            (b"eMNA", pstr(b"Create Motion Vectors 3.x")),
        ],
    );
    let (mut source, at) = rsrc_pe(&[(Res::Named("PIPL"), raw)]);
    put(&mut source, 0x4f0, b".?AVRVTwixtor4@@\0");
    put(&mut source, 0x5c0, b"Twixtor Pro GUI\0");
    let out = deep("x.aex", &source);
    assert!(!has(&out, b"Twixtor"));
    assert!(!has(&out[at[0]..], b"Motion Vectors: Create"));
    assert!(
        deattribute_bytes_mode("x.aex", &out, Mode::Deep)
            .bytes
            .is_none()
    );
}

#[test]
fn malformed_uppercase_pipl_is_reported_and_overlay_identity_is_scrubbed() {
    let (mut source, _) = rsrc_pe(&[(Res::Named("PIPL"), vec![1, 0, 0, 0, 0])]);
    let result = deattribute_bytes_mode("x.aex", &source, Mode::Deep);
    assert!(result.skipped.contains(&Reason::MalformedMetadata));
    source.extend_from_slice(b"NovaFlow private build\0");
    let out = deep("x.aex", &source);
    assert!(
        !has(&out[0xc00..], b"NovaFlow"),
        "overlay identity scrubbed"
    );
    let terms = pe::sweep(&SliceView::new("x", &source)).audit_terms;
    assert_eq!(
        pe::residual_category(&SliceView::new("x", &out), &terms),
        Some("PE data")
    );
}

#[test]
fn copy_verification_reports_identity_left_in_a_protected_import_name() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("example.aex");
    let mut source = pe_fixture(0x1234);
    source.extend_from_slice(b"NovaFlow private build\0");
    std::fs::write(&path, &source).unwrap();
    let report = crate::scan::scan_file_detailed(&path, &crate::parsers::registry()).report;
    let view = crate::scan::WindowedFile::open(&path).unwrap();
    let plan = crate::edit::deattribute::plan_mode(&report, &view, Mode::Deep);
    drop(view);
    let output = crate::edit::deattribute::write_deattributed(
        &path,
        report.format.as_deref(),
        report.size,
        &plan.targets,
    )
    .unwrap();
    let verified = crate::edit::deattribute::verify_copy(
        &path,
        &output,
        report.format.as_deref(),
        &plan.targets,
        Mode::Deep,
    );
    assert!(!verified.ok(), "{verified:?}");
    assert_eq!(verified.residual, Some("PE data"));
    let bytes = std::fs::read(&output).unwrap();
    assert!(!has(&bytes[0xc00..], b"NovaFlow"));
    assert!(has(&bytes[0x880..0x8c0], b"NovaFlowCore.dll"));
}

/// CLR metadata whose assembly carries Company, Product and FileVersion
/// attributes, with one `#US` message. Every heap index is two bytes.
fn clr_metadata(company: &str, product: &str, message: &str) -> Vec<u8> {
    fn push(heap: &mut Vec<u8>, bytes: &[u8]) -> u16 {
        let at = heap.len() as u16;
        heap.extend_from_slice(bytes);
        at
    }
    fn pad(mut heap: Vec<u8>) -> Vec<u8> {
        while !heap.len().is_multiple_of(4) {
            heap.push(0);
        }
        heap
    }
    let mut names = vec![0u8];
    let ns = push(&mut names, b"System.Reflection\0");
    let ctor = push(&mut names, b".ctor\0");
    let types = [
        b"AssemblyCompanyAttribute\0".as_slice(),
        b"AssemblyProductAttribute\0",
        b"AssemblyFileVersionAttribute\0",
    ]
    .map(|name| push(&mut names, name));
    let mut blobs = vec![0u8];
    let sig = push(&mut blobs, &[4, 0x20, 1, 1, 0x0e]);
    // Prolog, a counted string, no named arguments.
    let values = [company, product, "1.2.3.4"].map(|text| {
        let mut blob = vec![text.len() as u8 + 5, 1, 0, text.len() as u8];
        blob.extend_from_slice(text.as_bytes());
        blob.extend([0, 0]);
        push(&mut blobs, &blob)
    });
    let mut us = vec![0, message.len() as u8 * 2 + 1];
    us.extend(message.encode_utf16().flat_map(u16::to_le_bytes));
    us.push(0);

    let mut tables = vec![0, 0, 0, 0, 2, 0, 0, 1];
    // TypeRef, MemberRef, CustomAttribute and Assembly.
    tables.extend(((1u64 << 1) | (1 << 10) | (1 << 12) | (1 << 32)).to_le_bytes());
    tables.extend(0u64.to_le_bytes());
    for rows in [3u32, 3, 3, 1] {
        tables.extend(rows.to_le_bytes());
    }
    for name in types {
        tables.extend([6, name, ns].map(u16::to_le_bytes).concat());
    }
    for row in 1..=3u16 {
        tables.extend([(row << 3) | 1, ctor, sig].map(u16::to_le_bytes).concat());
    }
    for (row, value) in (1..=3u16).zip(values) {
        tables.extend(
            [(1 << 5) | 14, (row << 3) | 3, value]
                .map(u16::to_le_bytes)
                .concat(),
        );
    }
    tables.extend([0u8; 22]);

    let streams: [(&[u8], Vec<u8>); 4] = [
        (b"#~\0\0", pad(tables)),
        (b"#Strings\0\0\0\0", pad(names)),
        (b"#US\0", pad(us)),
        (b"#Blob\0\0\0", pad(blobs)),
    ];
    let mut md = b"BSJB".to_vec();
    md.extend([1, 0, 1, 0, 0, 0, 0, 0, 12, 0, 0, 0]);
    md.extend(b"v4.0.30319\0\0");
    md.extend([0, 0, 4, 0]);
    let mut at = md.len()
        + streams
            .iter()
            .map(|(name, _)| 8 + name.len())
            .sum::<usize>();
    for (name, body) in &streams {
        md.extend((at as u32).to_le_bytes());
        md.extend((body.len() as u32).to_le_bytes());
        md.extend_from_slice(name);
        at += body.len();
    }
    for (_, body) in streams {
        md.extend(body);
    }
    md
}

/// [`pe_fixture`] with a `.cormeta` data section (file 0xc00, RVA 0x3000)
/// holding a strong-name signed CLR header and `md` at file 0xc50.
fn dotnet_pe(md: &[u8]) -> Vec<u8> {
    let mut b = pe_fixture(0x1234);
    b.resize(0x1400, 0);
    put_u16(&mut b, 0x86, 3);
    let section = OPT + 0xf0 + 80;
    put(&mut b, section, b".cormeta");
    put_u32(&mut b, section + 8, 0x800);
    put_u32(&mut b, section + 12, 0x3000);
    put_u32(&mut b, section + 16, 0x800);
    put_u32(&mut b, section + 20, 0xc00);
    put_u32(&mut b, section + 36, 0x4000_0040);
    put_u32(&mut b, OPT + 112 + 14 * 8, 0x3000);
    put_u32(&mut b, OPT + 116 + 14 * 8, 72);
    put_u32(&mut b, 0xc00, 72);
    put_u32(&mut b, 0xc04, 0x0005_0002);
    put_u32(&mut b, 0xc08, 0x3050);
    put_u32(&mut b, 0xc0c, md.len() as u32);
    put_u32(&mut b, 0xc10, 0x9);
    put(&mut b, 0xc50, md);
    b
}

#[test]
fn assembly_attributes_and_user_strings_are_rewritten_in_place() {
    let md = clr_metadata(
        "Glimmer Labs",
        "NovaFlow Suite",
        "Glimmer license check failed",
    );
    let source = dotnet_pe(&md);
    assert!(
        sweep_as("pe", "x.dll", &source)
            .caveats
            .contains(&Caveat::SignatureInvalidated)
    );
    let out = deep("x.dll", &source);
    let mut want = md.clone();
    for (old, new) in [
        (b"Glimmer Labs".to_vec(), b"Company     ".to_vec()),
        (b"NovaFlow Suite".to_vec(), b"Product       ".to_vec()),
        (
            utf16z("Glimmer license")[..30].to_vec(),
            utf16z(&format!("{} license", spaces(7)))[..30].to_vec(),
        ),
    ] {
        let at = find(&md, &old);
        want[at..at + new.len()].copy_from_slice(&new);
    }
    assert_eq!(
        &out[0xc50..0xc50 + md.len()],
        &want[..],
        "only the attribute values and the message change"
    );
    assert!(
        deattribute_bytes_mode("x.dll", &out, Mode::Deep)
            .bytes
            .is_none()
    );
}

/// [`pe_fixture`] with a debug directory at file 0x600 listing `records` as
/// (type, body) from 0x640 on, a message naming Glimmer at 0x5c0 and a help
/// URL on a Glimmer host at 0x8c0. Returns the image and each body's offset.
fn debug_pe(records: &[(u32, Vec<u8>)]) -> (Vec<u8>, Vec<usize>) {
    let mut b = pe_fixture(0x1234);
    put(&mut b, 0x5c0, b"Glimmer startup ready\0");
    put(&mut b, 0x8c0, b"https://glimmer.example/help\0");
    put_u32(&mut b, OPT + 112 + 6 * 8, 0x1400);
    put_u32(&mut b, OPT + 116 + 6 * 8, 28 * records.len() as u32);
    let mut body = 0x640;
    let mut offs = Vec::new();
    for (i, (kind, data)) in records.iter().enumerate() {
        let entry = 0x600 + i * 28;
        put_u32(&mut b, entry + 4, 0x5abc_1234);
        put_u32(&mut b, entry + 12, *kind);
        put_u32(&mut b, entry + 16, data.len() as u32);
        put_u32(&mut b, entry + 20, 0x1000 + body as u32 - 0x200);
        put_u32(&mut b, entry + 24, body as u32);
        put(&mut b, body, data);
        offs.push(body);
        body = (body + data.len() + 15) & !15;
    }
    (b, offs)
}

fn misc_record(name: &str) -> Vec<u8> {
    let mut r = vec![0u8; 0x20];
    put_u32(&mut r, 0, 1);
    put_u32(&mut r, 4, 0x20);
    put(&mut r, 12, name.as_bytes());
    r
}

fn embedded_pdb(payload: &[u8]) -> Vec<u8> {
    let mut r = b"MPDB".to_vec();
    r.extend((payload.len() as u32).to_le_bytes());
    r.extend(miniz_oxide::deflate::compress_to_vec(payload, 6));
    r
}

#[test]
fn misc_and_embedded_pdb_records_name_the_build_and_are_cleared() {
    let pdb = embedded_pdb(b"\0\0D:\\a\\_work\\Glimmer.pdb\0\0\0\0");
    // IMAGE_DEBUG_TYPE_MISC and IMAGE_DEBUG_TYPE_EMBEDDED_PORTABLE_PDB.
    for (kind, record) in [(4, misc_record("Glimmer.dbg")), (17, pdb)] {
        let (source, at) = debug_pe(&[(kind, record.clone())]);
        let out = deep("x.dll", &source);
        assert_eq!(u32_of(&out, 0x604), 0, "debug stamp cleared");
        assert_eq!(
            &out[0x5c0..0x5d5],
            format!("{} startup ready", spaces(7)).as_bytes(),
            "the record's name, seen again in a URL, is a root"
        );
        if kind == 4 {
            assert_eq!(&out[at[0]..at[0] + 12], &record[..12], "header kept");
            assert_eq!(&out[at[0] + 12..at[0] + 0x20], &[0; 0x14]);
        } else {
            assert!(out[at[0]..at[0] + record.len()].iter().all(|&b| b == 0));
            assert_eq!(&out[0x610..0x61c], &[0; 12], "the entry points nowhere");
        }
        let view = SliceView::new("x", &out);
        let img = PeImage::parse(&view).unwrap();
        assert_eq!(
            Some(img.checksum),
            crate::parsers::pe::pe_checksum(&view, img.checksum_off)
        );
        assert!(
            deattribute_bytes_mode("x.dll", &out, Mode::Deep)
                .bytes
                .is_none()
        );
    }
}

#[test]
fn a_damaged_embedded_pdb_is_reported_and_left_in_place() {
    let mut record = b"MPDB".to_vec();
    record.extend(100u32.to_le_bytes());
    record.extend([0xff; 16]);
    let (source, at) = debug_pe(&[(17, record.clone())]);
    let out = deattribute_bytes_mode("x.dll", &source, Mode::Deep);
    assert!(out.skipped.contains(&Reason::MalformedMetadata));
    let bytes = out.bytes.expect("other fields still change");
    assert_eq!(&bytes[at[0]..at[0] + record.len()], &record[..]);
    assert!(
        has(&bytes[0x5c0..0x5d6], b"Glimmer startup"),
        "a URL alone names nobody"
    );
}

#[test]
fn the_checksum_covers_edits_on_both_sides_of_a_chunk_edge() {
    let mut source = pe_fixture(0x1234);
    let size = 0x18_0000;
    source.resize(size, 0);
    put_u16(&mut source, 0x86, 3);
    let section = OPT + 0xf0 + 80;
    put(&mut source, section, b".data");
    put_u32(&mut source, section + 8, (size - 0xc00) as u32);
    put_u32(&mut source, section + 12, 0x3000);
    put_u32(&mut source, section + 16, (size - 0xc00) as u32);
    put_u32(&mut source, section + 20, 0xc00);
    put_u32(&mut source, section + 36, 0xc000_0040);
    // The first blank straddles the 1 MiB edge; the second lies past it.
    put(&mut source, 0xf_fffc, b"NovaFlow straddles\0");
    put(&mut source, 0x15_0000, b"NovaFlow far tail\0");
    let out = deep("x.dll", &source);
    assert_eq!(&out[0xf_fffc..0x10_0004], &[b' '; 8]);
    assert_eq!(&out[0x15_0000..0x15_0008], &[b' '; 8]);
    let view = SliceView::new("x", &out);
    let img = PeImage::parse(&view).unwrap();
    assert_eq!(
        Some(img.checksum),
        crate::parsers::pe::pe_checksum(&view, img.checksum_off)
    );
}

/// An ELF64 whose executable `.text` and `.debug_str` both hold a build path,
/// followed in `.debug_str` by a producer string and a copyright line.
fn elf_debug_fixture() -> Vec<u8> {
    let path = b"/home/alice/glimmer/src/main.c\0";
    let mut b = vec![0u8; 0x300];
    put(&mut b, 0, b"\x7fELF\x02\x01\x01");
    put_u16(&mut b, 16, 3);
    put_u16(&mut b, 18, 0x3e);
    put_u32(&mut b, 20, 1);
    put_u64(&mut b, 40, 0x200);
    put_u16(&mut b, 52, 64);
    put_u16(&mut b, 54, 56);
    put_u16(&mut b, 58, 64);
    put_u16(&mut b, 60, 4);
    put_u16(&mut b, 62, 3);
    put(&mut b, 0x41, path);
    put(&mut b, 0x80, path);
    put(
        &mut b,
        0x80 + path.len(),
        b"GNU C17 13.2.0 -O2\0Copyright 2024 Glimmer Labs\0",
    );
    let names = b"\0.text\0.debug_str\0.shstrtab\0";
    put(&mut b, 0x100, names);
    // (name, type, flags, offset, size)
    let shdrs: [(u32, u32, u64, u64, u64); 4] = [
        (0, 0, 0, 0, 0),
        (1, 1, 0x6, 0x40, 0x40),
        (7, 1, 0x30, 0x80, 0x80),
        (18, 3, 0, 0x100, names.len() as u64),
    ];
    for (i, (name, kind, flags, off, size)) in shdrs.into_iter().enumerate() {
        let at = 0x200 + i * 64;
        put_u32(&mut b, at, name);
        put_u32(&mut b, at + 4, kind);
        put_u64(&mut b, at + 8, flags);
        put_u64(&mut b, at + 24, off);
        put_u64(&mut b, at + 32, size);
    }
    b
}

#[test]
fn deep_elf_cleans_build_paths_and_credits_in_debug_strings() {
    let source = elf_debug_fixture();
    let out = deep("glimmer.so", &source);
    assert_eq!(&out[0x40..0x80], &source[0x40..0x80], ".text kept");
    let want = format!("{}\0GNU C17 13.2.0 -O2\0{}\0", spaces(30), spaces(27));
    assert_eq!(&out[0x80..0x80 + want.len()], want.as_bytes());
    assert!(
        deattribute_bytes_mode("glimmer.so", &out, Mode::Deep)
            .bytes
            .is_none()
    );
}

/// An embedded signature whose CodeDirectory names `ident` and `team`.
fn code_signature(ident: &str, team: &str) -> Vec<u8> {
    let fixed = 52;
    let mut cd = vec![0u8; fixed];
    let mut strings = ident.as_bytes().to_vec();
    strings.push(0);
    let team_at = fixed + strings.len();
    strings.extend_from_slice(team.as_bytes());
    strings.push(0);
    put_be32(&mut cd, 0, 0xfade_0c02);
    put_be32(&mut cd, 8, 0x20200);
    put_be32(&mut cd, 16, (fixed + strings.len()) as u32);
    put_be32(&mut cd, 20, fixed as u32);
    put_be32(&mut cd, 48, team_at as u32);
    cd.extend(strings);
    let len = cd.len() as u32;
    put_be32(&mut cd, 4, len);
    let mut sb = Vec::new();
    for v in [0xfade_0cc0, 20 + len, 1, 0, 20] {
        sb.extend(u32::to_be_bytes(v));
    }
    sb.extend(cd);
    sb
}

/// Offset of the LC_CODE_SIGNATURE command in [`signed_macho`].
const MACHO_SIG_CMD: usize = 32 + 152 + 24;

/// A thin 64-bit Mach-O: `__TEXT,__cstring` at 0x200, LC_SYMTAB with a source
/// file stab and an external symbol at 0x240 and their strings at 0x260, and
/// LC_CODE_SIGNATURE pointing at a signature for `ident` and `team` at 0x2a0.
fn signed_macho(ident: &str, team: &str) -> Vec<u8> {
    let sig = code_signature(ident, team);
    let mut b = vec![0u8; 0x2a0];
    put(&mut b, 0, &[0xcf, 0xfa, 0xed, 0xfe]);
    put_u32(&mut b, 4, 0x0100_0007);
    put_u32(&mut b, 8, 3);
    put_u32(&mut b, 12, 2);
    put_u32(&mut b, 16, 3);
    put_u32(&mut b, 20, 192);
    let lc = 32;
    put_u32(&mut b, lc, 0x19);
    put_u32(&mut b, lc + 4, 152);
    put(&mut b, lc + 8, b"__TEXT");
    put_u64(&mut b, lc + 48, 0x2a0);
    put_u32(&mut b, lc + 64, 1);
    let s = lc + 72;
    put(&mut b, s, b"__cstring");
    put(&mut b, s + 16, b"__TEXT");
    put_u64(&mut b, s + 40, 0x40);
    put_u32(&mut b, s + 48, 0x200);
    put_u32(&mut b, s + 64, 2);
    let symtab = lc + 152;
    for (i, v) in [2, 24, 0x240, 2, 0x260, 0x40].into_iter().enumerate() {
        put_u32(&mut b, symtab + i * 4, v);
    }
    for (i, v) in [0x1d, 16, 0x2a0, sig.len() as u32].into_iter().enumerate() {
        put_u32(&mut b, MACHO_SIG_CMD + i * 4, v);
    }
    put(&mut b, 0x200, b"NovaFlow ready\0");
    // nlist_64: an N_SO stab, then an external symbol in section 1.
    put_u32(&mut b, 0x240, 1);
    b[0x244] = 0x64;
    put_u32(&mut b, 0x250, 27);
    b[0x254] = 0x0f;
    b[0x255] = 1;
    put_u64(&mut b, 0x258, 0x1000);
    put(
        &mut b,
        0x261,
        b"/Users/alice/glimmer/src/\0_novaflow_init\0",
    );
    b.extend(sig);
    b
}

#[test]
fn a_signed_macho_loses_its_signature_and_the_names_its_identifier_gives() {
    let source = signed_macho("com.glimmer.novaflow", "GLMR12345X");
    assert!(
        sweep_as("macho", "novaflow", &source)
            .caveats
            .contains(&Caveat::SignatureInvalidated)
    );
    let out = deep("novaflow", &source);
    assert_eq!(
        &out[0x200..0x20e],
        format!("{} ready", spaces(8)).as_bytes()
    );
    assert_eq!(&out[0x261..0x27a], spaces(25).as_bytes(), "stab path");
    assert_eq!(&out[0x27b..0x289], b"_novaflow_init", "symbol name kept");
    assert!(out[0x2a0..].iter().all(|&b| b == 0), "signature cleared");
    assert_eq!(u32_of(&out, MACHO_SIG_CMD + 8), 0);
    assert_eq!(u32_of(&out, MACHO_SIG_CMD + 12), 0);
    assert!(
        deattribute_bytes_mode("novaflow", &out, Mode::Deep)
            .bytes
            .is_none()
    );
}

/// A file of `size` bytes holding `head` and then zeros it never allocates.
struct Sparse {
    head: Vec<u8>,
    size: u64,
}

impl FileView for Sparse {
    fn path(&self) -> &std::path::Path {
        std::path::Path::new("big")
    }
    fn size(&self) -> u64 {
        self.size
    }
    fn header(&self) -> &[u8] {
        &self.head
    }
    fn tail(&self) -> &[u8] {
        &[]
    }
    fn tail_start(&self) -> u64 {
        self.size
    }
    fn read_at(&self, offset: u64, len: usize) -> std::io::Result<Vec<u8>> {
        let end = offset.saturating_add(len as u64).min(self.size);
        Ok((offset..end)
            .map(|at| self.head.get(at as usize).copied().unwrap_or(0))
            .collect())
    }
}

#[test]
fn signatures_out_of_reach_are_reported_instead_of_blanked() {
    let mut head = vec![0u8; 0x30];
    put(&mut head, 0, &[0xcf, 0xfa, 0xed, 0xfe]);
    put_u32(&mut head, 4, 0x0100_0007);
    put_u32(&mut head, 12, 2);
    put_u32(&mut head, 16, 1);
    put_u32(&mut head, 20, 16);
    put_u32(&mut head, 32, 0x1d);
    put_u32(&mut head, 36, 16);
    put_u32(&mut head, 40, 0x1000);
    put_u32(&mut head, 44, MAX_TOTAL as u32 + 1);
    let big = Sparse {
        head: head.clone(),
        size: MAX_TOTAL + 0x2000,
    };
    let report = crate::model::FileReport {
        format: Some("macho".into()),
        ..crate::model::FileReport::new("big".into(), big.size)
    };
    let found = sweep(&report, &big);
    assert_eq!(found.skipped, [Reason::DeepBudget]);
    assert!(found.blanks.is_empty() && found.rewrites.is_empty());
    assert!(found.caveats.contains(&Caveat::SignatureInvalidated));

    // A signature past the end of the file cannot be read at all.
    put_u32(&mut head, 40, 0x10000);
    put_u32(&mut head, 44, 0x100);
    let found = sweep_as("macho", "small", &head);
    assert_eq!(found.skipped, [Reason::MalformedMetadata]);
    assert!(found.caveats.contains(&Caveat::SignatureInvalidated));
}

/// A resource's type, its name if it has one, and its data.
type Resource<'a> = (&'a [u8; 4], Option<&'a [u8]>, Vec<u8>);

/// A Macintosh resource fork with resource data from 0x100 on and the map
/// after it. Every type holds one resource, named or not.
fn resource_fork(resources: &[Resource<'_>]) -> Vec<u8> {
    let mut data = Vec::new();
    let mut at = Vec::new();
    for (_, _, body) in resources {
        at.push(data.len() as u32);
        data.extend((body.len() as u32).to_be_bytes());
        data.extend_from_slice(body);
    }
    let n = resources.len();
    let types_len = 2 + 8 * n;
    let mut map = vec![0u8; 24];
    map.extend(28u16.to_be_bytes());
    map.extend(((28 + types_len + 12 * n) as u16).to_be_bytes());
    map.extend(((n - 1) as u16).to_be_bytes());
    for (i, (kind, _, _)) in resources.iter().enumerate() {
        map.extend_from_slice(&kind[..]);
        map.extend(0u16.to_be_bytes());
        map.extend(((types_len + 12 * i) as u16).to_be_bytes());
    }
    let mut names = Vec::new();
    for (i, (_, name, _)) in resources.iter().enumerate() {
        map.extend((128 + i as u16).to_be_bytes());
        match name {
            Some(name) => {
                map.extend((names.len() as u16).to_be_bytes());
                names.extend(pstr(name));
            }
            None => map.extend(0xffffu16.to_be_bytes()),
        }
        map.extend(at[i].to_be_bytes());
        map.extend(0u32.to_be_bytes());
    }
    map.extend(names);
    let mut fork = vec![0u8; 0x100];
    let header = [0x100, 0x100 + data.len(), data.len(), map.len()];
    for (i, v) in header.into_iter().enumerate() {
        put_be32(&mut fork, i * 4, v as u32);
    }
    fork.extend(data);
    fork.extend(map);
    fork
}

/// An AppleDouble file holding empty Finder info and then `fork`.
fn apple_double(fork: &[u8]) -> Vec<u8> {
    let mut b = vec![0, 5, 0x16, 7, 0, 2, 0, 0];
    b.resize(24, 0);
    b.extend(2u16.to_be_bytes());
    for (id, off, len) in [(9u32, 50u32, 32u32), (2, 82, fork.len() as u32)] {
        for v in [id, off, len] {
            b.extend(v.to_be_bytes());
        }
    }
    b.resize(82, 0);
    b.extend_from_slice(fork);
    b
}

#[test]
fn resource_forks_clean_strings_and_pipl_and_keep_resource_names() {
    let pipl = pipl_list(
        false,
        &[
            (b"kind", b"eFKT".to_vec()),
            (b"name", pstr(b"NovaFlow Glow")),
            (b"eMNA", pstr(b"Glimmer NovaFlow Glow")),
            (b"mi64", b"EffectMain\0\0".to_vec()),
        ],
    );
    let mut list = 4u16.to_be_bytes().to_vec();
    let texts: [&[u8]; 4] = [
        b"Glimmer NovaFlow",
        b"",
        b"\xa9 2024 Glimmer Labs",
        b"Render ready",
    ];
    for text in texts {
        list.extend(pstr(text));
    }
    let fork = resource_fork(&[
        (b"PiPL", Some(b"Glimmer Glow"), pipl),
        (b"STR#", None, list),
        (b"STR ", None, pstr(b"Patched by Nobody Group")),
    ]);
    let edits: [(&[u8], Vec<u8>); 4] = [
        (b"\x0dNovaFlow Glow", b"Effect       ".to_vec()),
        (
            b"\x10Glimmer NovaFlow",
            format!("{} NovaFlow", spaces(7)).into_bytes(),
        ),
        (b"\x13\xa9 2024 Glimmer Labs", spaces(19).into_bytes()),
        (b"\x17Patched by Nobody Group", spaces(23).into_bytes()),
    ];
    for (name, source, format) in [
        ("NovaFlow.rsrc", fork.clone(), "rsrc"),
        ("._NovaFlow.dll", apple_double(&fork), "appledouble"),
    ] {
        let (found, findings) = crate::parsers::identify(&SliceView::new(name, &source));
        assert_eq!(found, Some(format));
        assert!(findings.is_empty(), "{name}: no extension mismatch");
        let out = deattribute_bytes_mode(name, &source, Mode::Deep);
        assert_eq!((out.brand, out.patch), (4, 1), "{name}");
        assert!(
            out.skipped.contains(&Reason::FunctionalName),
            "the resource name is kept"
        );
        let bytes = out.bytes.expect("edits");
        let mut want = source.clone();
        for (old, new) in &edits {
            let at = find(&source, old) + 1;
            want[at..at + new.len()].copy_from_slice(new);
        }
        let id = find(&source, b"\x15Glimmer NovaFlow Glow") + 1;
        assert!(bytes[id..].starts_with(b"de"));
        assert!(bytes[id + 2..id + 21].iter().all(u8::is_ascii_hexdigit));
        want[id..id + 21].copy_from_slice(&bytes[id..id + 21]);
        assert_eq!(bytes, want, "{name}");
        assert!(
            deattribute_bytes_mode(name, &bytes, Mode::Deep)
                .bytes
                .is_none()
        );
    }
}
