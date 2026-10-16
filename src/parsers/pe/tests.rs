//! PE probe tests over a synthetic PE32+ image: DOS header, Rich block, PE
//! header, two sections, a CodeView debug record, a version resource, an
//! optional certificate table and an optional overlay.

use super::*;
use crate::model::RemovalStrategy;
use crate::scan::MemView;

const E_LFANEW: usize = 0x100;
const OPT: usize = E_LFANEW + 24;
const OPT_SIZE: usize = 0xf0;
const SECTIONS: usize = OPT + OPT_SIZE;
const DIRS: usize = OPT + 112;
const DIRS32: usize = OPT + 96;
const CHECKSUM_OFF: usize = OPT + 64;
const TEXT_RAW: usize = 0x400;
const TEXT_VA: u32 = 0x1000;
const RSRC_RAW: usize = 0x600;
const RSRC_VA: u32 = 0x2000;
const DEBUG_RVA: u32 = 0x1100;
const RSDS_RVA: u32 = 0x1120;
const CLR_RVA: u32 = 0x1180;
const BSJB_RVA: u32 = 0x11d0;
const PDB: &str = "C:\\Users\\dev\\proj\\target\\release\\app.pdb";
const RICH_AT: usize = 0x80;
const RICH_KEY: u32 = 0x9b1c_2a3d;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Sum {
    Zero,
    Good,
    Bad,
}

#[derive(Clone)]
struct Opts {
    rich: bool,
    cert: bool,
    overlay: Vec<u8>,
    after_cert: Vec<u8>,
    checksum: Sum,
    company: &'static str,
    names: [&'static str; 2],
    clr: bool,
    coff_symbols: bool,
    pe32: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            rich: true,
            cert: true,
            overlay: b"OVERLAY-PAYLOAD-0123456789abcdef".repeat(4),
            after_cert: Vec::new(),
            checksum: Sum::Good,
            company: "Example Corp",
            names: [".text", ".rsrc"],
            clr: false,
            coff_symbols: false,
            pe32: false,
        }
    }
}

fn put(buf: &mut Vec<u8>, off: usize, bytes: &[u8]) {
    if buf.len() < off + bytes.len() {
        buf.resize(off + bytes.len(), 0);
    }
    buf[off..off + bytes.len()].copy_from_slice(bytes);
}

fn p16(buf: &mut Vec<u8>, off: usize, v: u16) {
    put(buf, off, &v.to_le_bytes());
}

fn p32(buf: &mut Vec<u8>, off: usize, v: u32) {
    put(buf, off, &v.to_le_bytes());
}

fn utf16z(s: &str) -> Vec<u8> {
    s.encode_utf16()
        .chain([0])
        .flat_map(|u| u.to_le_bytes())
        .collect()
}

fn pad4(v: &mut Vec<u8>) {
    while !v.len().is_multiple_of(4) {
        v.push(0);
    }
}

fn vblock(key: &str, value: &[u8], value_len: u16, text: bool, children: &[Vec<u8>]) -> Vec<u8> {
    let mut b = vec![0u8; 6];
    b.extend(utf16z(key));
    pad4(&mut b);
    b.extend_from_slice(value);
    for c in children {
        pad4(&mut b);
        b.extend_from_slice(c);
    }
    let len = b.len() as u16;
    p16(&mut b, 0, len);
    p16(&mut b, 2, value_len);
    p16(&mut b, 4, u16::from(text));
    b
}

fn vstring(key: &str, value: &str) -> Vec<u8> {
    let v = utf16z(value);
    vblock(
        key,
        &v,
        (value.encode_utf16().count() + 1) as u16,
        true,
        &[],
    )
}

fn version_blob(strings: &[(&str, &str)]) -> Vec<u8> {
    let kids: Vec<Vec<u8>> = strings.iter().map(|(k, v)| vstring(k, v)).collect();
    let table = vblock("040904B0", &[], 0, true, &kids);
    let sfi = vblock("StringFileInfo", &[], 0, true, &[table]);
    let var = vblock("Translation", &[0x09, 0x04, 0xb0, 0x04], 4, false, &[]);
    let vfi = vblock("VarFileInfo", &[], 0, true, &[var]);
    let mut fixed = vec![0u8; 52];
    p32(&mut fixed, 0, 0xfeef_04bd);
    p32(&mut fixed, 4, 0x0001_0000);
    vblock("VS_VERSION_INFO", &fixed, 52, false, &[sfi, vfi])
}

/// A three-level resource tree (type 16, name 1, language 0x409) pointing at
/// `version`, laid out for the section at RSRC_VA.
fn rsrc(version: &[u8]) -> Vec<u8> {
    let mut r = vec![0u8; 0x58];
    p16(&mut r, 14, 1);
    p32(&mut r, 0x10, 16);
    p32(&mut r, 0x14, 0x8000_0018);
    p16(&mut r, 0x18 + 14, 1);
    p32(&mut r, 0x28, 1);
    p32(&mut r, 0x2c, 0x8000_0030);
    p16(&mut r, 0x30 + 14, 1);
    p32(&mut r, 0x40, 0x409);
    p32(&mut r, 0x44, 0x48);
    p32(&mut r, 0x48, RSRC_VA + 0x58);
    p32(&mut r, 0x4c, version.len() as u32);
    r.extend_from_slice(version);
    r
}

fn section(f: &mut Vec<u8>, i: usize, name: &str, vsize: u32, va: u32, raw: u32, ptr: u32) {
    let at = SECTIONS + i * 40;
    let mut n = [0u8; 8];
    n[..name.len()].copy_from_slice(name.as_bytes());
    put(f, at, &n);
    p32(f, at + 8, vsize);
    p32(f, at + 12, va);
    p32(f, at + 16, raw);
    p32(f, at + 20, ptr);
    p32(f, at + 36, 0x6000_0020);
}

fn rich_block() -> Vec<u8> {
    let mut words = vec![0x536e_6144 ^ RICH_KEY, RICH_KEY, RICH_KEY, RICH_KEY];
    for (comp, count) in [
        ((0x0102u32 << 16) | 33135, 1u32),
        ((0x0105 << 16) | 33135, 12),
        ((0x0093 << 16) | 30729, 5),
    ] {
        words.push(comp ^ RICH_KEY);
        words.push(count ^ RICH_KEY);
    }
    words.push(u32::from_le_bytes(*b"Rich"));
    words.push(RICH_KEY);
    words.iter().flat_map(|w| w.to_le_bytes()).collect()
}

fn build(o: &Opts) -> Vec<u8> {
    let mut f = vec![0u8; TEXT_RAW];
    put(&mut f, 0, b"MZ");
    p32(&mut f, 0x3c, E_LFANEW as u32);
    put(
        &mut f,
        0x4e,
        b"This program cannot be run in DOS mode.\r\r\n$",
    );
    if o.rich {
        put(&mut f, RICH_AT, &rich_block());
    }

    put(&mut f, E_LFANEW, b"PE\0\0");
    let dirs = if o.pe32 { DIRS32 } else { DIRS };
    p16(&mut f, E_LFANEW + 4, if o.pe32 { 0x14c } else { 0x8664 });
    p16(&mut f, E_LFANEW + 6, 2);
    p32(&mut f, E_LFANEW + 8, 0x6500_0000);
    p16(&mut f, E_LFANEW + 20, OPT_SIZE as u16);
    p16(&mut f, E_LFANEW + 22, if o.pe32 { 0x102 } else { 0x22 });

    if o.pe32 {
        p16(&mut f, OPT, 0x10b);
        p32(&mut f, OPT + 28, 0x40_0000);
        p32(&mut f, OPT + 92, 16);
    } else {
        p16(&mut f, OPT, 0x20b);
        put(&mut f, OPT + 24, &0x1_4000_0000u64.to_le_bytes());
        p32(&mut f, OPT + 108, 16);
    }
    p32(&mut f, OPT + 16, TEXT_VA);
    p32(&mut f, OPT + 32, 0x1000);
    p32(&mut f, OPT + 36, 0x200);
    p32(&mut f, OPT + 56, 0x3000);
    p32(&mut f, OPT + 60, 0x400);
    p16(&mut f, OPT + 68, 3);

    // .text: entry point, debug directory, RSDS record, optional CLR header.
    f.resize(RSRC_RAW, 0);
    f[TEXT_RAW] = 0xc3;
    let dbg = TEXT_RAW + (DEBUG_RVA - TEXT_VA) as usize;
    let rsds = TEXT_RAW + (RSDS_RVA - TEXT_VA) as usize;
    p32(&mut f, dbg + 12, 2);
    p32(&mut f, dbg + 16, (24 + PDB.len() + 1) as u32);
    p32(&mut f, dbg + 20, RSDS_RVA);
    p32(&mut f, dbg + 24, rsds as u32);
    put(&mut f, rsds, b"RSDS");
    put(&mut f, rsds + 4, &[0x11; 16]);
    p32(&mut f, rsds + 20, 1);
    put(&mut f, rsds + 24, PDB.as_bytes());
    p32(&mut f, dirs + 6 * 8, DEBUG_RVA);
    p32(&mut f, dirs + 6 * 8 + 4, 28);
    if o.clr {
        let clr = TEXT_RAW + (CLR_RVA - TEXT_VA) as usize;
        let md = TEXT_RAW + (BSJB_RVA - TEXT_VA) as usize;
        p32(&mut f, clr, 72);
        p16(&mut f, clr + 4, 2);
        p16(&mut f, clr + 6, 5);
        p32(&mut f, clr + 8, BSJB_RVA);
        p32(&mut f, clr + 12, 28);
        p32(&mut f, clr + 16, 1);
        put(&mut f, md, b"BSJB");
        p16(&mut f, md + 4, 1);
        p16(&mut f, md + 6, 1);
        p32(&mut f, md + 12, 12);
        put(&mut f, md + 16, b"v4.0.30319\0\0");
        p32(&mut f, dirs + 14 * 8, CLR_RVA);
        p32(&mut f, dirs + 14 * 8 + 4, 72);
    }
    section(
        &mut f,
        0,
        o.names[0],
        0x200,
        TEXT_VA,
        0x200,
        TEXT_RAW as u32,
    );

    // .rsrc: the version resource.
    let blob = version_blob(&[
        ("CompanyName", o.company),
        ("ProductName", "Meow Tool"),
        ("FileDescription", "Meow utility"),
        ("OriginalFilename", "meow.exe"),
        ("FileVersion", "1.2.3.4"),
        ("LegalCopyright", "Copyright (c) 2026 Example"),
        ("Comments", "built by alice on box7"),
    ]);
    let r = rsrc(&blob);
    let raw = r.len().div_ceil(0x200) * 0x200;
    put(&mut f, RSRC_RAW, &r);
    f.resize(RSRC_RAW + raw, 0);
    section(
        &mut f,
        1,
        o.names[1],
        r.len() as u32,
        RSRC_VA,
        raw as u32,
        RSRC_RAW as u32,
    );
    p32(&mut f, dirs + 2 * 8, RSRC_VA);
    p32(&mut f, dirs + 2 * 8 + 4, r.len() as u32);

    if o.coff_symbols {
        let at = f.len();
        p32(&mut f, E_LFANEW + 12, at as u32);
        p32(&mut f, E_LFANEW + 16, 2);
        f.extend_from_slice(&[0x2e; 36]);
        f.extend_from_slice(&4u32.to_le_bytes());
    }
    f.extend_from_slice(&o.overlay);
    if o.cert {
        while !f.len().is_multiple_of(8) {
            f.push(0);
        }
        let at = f.len();
        p32(&mut f, at, 32);
        p16(&mut f, at + 4, 0x0200);
        p16(&mut f, at + 6, 0x0002);
        put(&mut f, at + 8, &[0x30; 24]);
        p32(&mut f, dirs + 4 * 8, at as u32);
        p32(&mut f, dirs + 4 * 8 + 4, 32);
    }
    f.extend_from_slice(&o.after_cert);

    match o.checksum {
        Sum::Zero => {}
        Sum::Good => {
            let c = reference_checksum(&f, CHECKSUM_OFF);
            p32(&mut f, CHECKSUM_OFF, c);
        }
        Sum::Bad => {
            let c = reference_checksum(&f, CHECKSUM_OFF) ^ 0x55;
            p32(&mut f, CHECKSUM_OFF, c);
        }
    }
    f
}

/// The dword-based checksum used by common PE tooling, as an independent
/// cross-check of the word-based implementation under test.
fn reference_checksum(data: &[u8], csum_off: usize) -> u32 {
    let mut padded = data.to_vec();
    while !padded.len().is_multiple_of(4) {
        padded.push(0);
    }
    let mut sum: u64 = 0;
    for (i, d) in padded.as_chunks::<4>().0.iter().enumerate() {
        if i == csum_off / 4 {
            continue;
        }
        let dword = u64::from(u32::from_le_bytes(*d));
        sum = (sum & 0xffff_ffff) + dword + (sum >> 32);
        if sum > 1 << 32 {
            sum = (sum & 0xffff_ffff) + (sum >> 32);
        }
    }
    sum = (sum & 0xffff) + (sum >> 16);
    sum += sum >> 16;
    sum &= 0xffff;
    (sum + data.len() as u64) as u32
}

fn run(bytes: &[u8]) -> Vec<Finding> {
    run_at("sample.exe", bytes)
}

fn run_at(path: &str, bytes: &[u8]) -> Vec<Finding> {
    let view = MemView::new(path, bytes.to_vec());
    let ctx = ProbeCtx::new(&view, Some("pe"));
    let mut out = Vec::new();
    for p in probes() {
        assert_eq!(p.id(), "pe");
        assert_eq!(p.formats(), &["pe"]);
        p.run(&ctx, &mut out);
    }
    out
}

#[test]
fn deattribute_blanks_version_values_and_rich_without_breaking_pe() {
    let opts = Opts {
        company: "InventedCo",
        cert: false,
        ..Opts::default()
    };
    let mut bytes = build(&opts);
    let view = MemView::new("app.exe", bytes.clone());
    let mut report = crate::model::FileReport::new("app.exe".into(), bytes.len() as u64);
    report.format = Some("pe".into());
    report.findings = run(&bytes);
    let plan = crate::edit::deattribute::plan(&report, &view);
    assert!(plan.targets.len() >= 2);
    for target in &plan.targets {
        let RemovalStrategy::RawBlank { fill } = target.marker.removal else {
            panic!("raw blank");
        };
        let start = target.marker.region.offset as usize;
        let end = target.marker.region.end() as usize;
        bytes[start..end].fill(fill);
    }
    assert!(
        !bytes
            .windows("InventedCo".encode_utf16().count() * 2)
            .any(|window| window
                == "InventedCo"
                    .encode_utf16()
                    .flat_map(u16::to_le_bytes)
                    .collect::<Vec<_>>())
    );
    let after = MemView::new("app.exe", bytes.clone());
    assert!(PeImage::parse(&after).is_some());
    let mut second = crate::model::FileReport::new("app.exe".into(), bytes.len() as u64);
    second.format = Some("pe".into());
    second.findings = run(&bytes);
    assert!(
        crate::edit::deattribute::plan(&second, &after)
            .targets
            .is_empty()
    );
}

fn all<'a>(f: &'a [Finding], id: &str) -> Vec<&'a Finding> {
    f.iter().filter(|x| x.signature_id == id).collect()
}

fn one<'a>(f: &'a [Finding], id: &str) -> &'a Finding {
    let hits = all(f, id);
    assert_eq!(hits.len(), 1, "expected exactly one {id}: {f:#?}");
    hits[0]
}

fn apply(bytes: &mut Vec<u8>, m: &Marker) {
    match m.removal {
        RemovalStrategy::RawBlank { fill } => {
            assert_ne!(m.region.offset, 0, "never blank offset 0");
            let s = m.region.offset as usize;
            let e = m.region.end() as usize;
            bytes[s..e].fill(fill);
        }
        RemovalStrategy::Truncate { from } => bytes.truncate(from as usize),
        ref other => panic!("unexpected removal {other:?}"),
    }
}

fn note(f: &Finding) -> &str {
    f.evidence.note.as_deref().unwrap_or("")
}

#[test]
fn signed_image_reports_brand_integrity_and_junk() {
    let f = run(&build(&Opts::default()));

    let rich = one(&f, "pe.rich_header");
    assert_eq!(rich.category, Category::Brand(BrandKind::Toolchain));
    assert_eq!(rich.confidence, Confidence::Strong);
    assert_eq!(rich.severity, Severity::Info);
    assert_eq!(rich.title, "MSVC toolchain (VS2022 or later)");
    assert!(note(rich).contains("Linker (VS2022 or later) build 33135 x1"));
    assert!(note(rich).contains("C++ (VS2022 or later) build 33135 x12"));
    assert!(note(rich).contains("prodid 0x0093 build 30729 x5"));
    assert_eq!(rich.evidence.offset, RICH_AT as u64);
    let m = rich.marker.as_ref().unwrap();
    assert_eq!(m.region, Region::new(RICH_AT as u64, 48));
    assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0 });
    assert_eq!(m.container, ContainerKind::Raw);

    let pdb = one(&f, "pe.pdb_path");
    assert_eq!(pdb.category, Category::Junk(JunkKind::PdbPath));
    assert_eq!(pdb.confidence, Confidence::Strong);
    assert_eq!(pdb.severity, Severity::Notice);
    assert_eq!(pdb.title, "PDB path app.pdb");
    assert!(note(pdb).starts_with(PDB));
    assert!(note(pdb).contains("RSDS"));
    assert!(note(pdb).contains("Authenticode"));
    let rsds = (TEXT_RAW + (RSDS_RVA - TEXT_VA) as usize) as u64;
    assert_eq!(
        pdb.marker.as_ref().unwrap().region,
        Region::new(rsds + 24, PDB.len() as u64)
    );

    let v = one(&f, "pe.version_info");
    assert_eq!(v.category, Category::Brand(BrandKind::Vendor));
    assert_eq!(v.confidence, Confidence::Moderate);
    assert_eq!(v.title, "Example Corp Meow Tool");
    for pair in [
        "CompanyName = Example Corp",
        "OriginalFilename = meow.exe",
        "FileVersion = 1.2.3.4",
        "LegalCopyright = Copyright (c) 2026 Example",
    ] {
        assert!(note(v).contains(pair), "{pair} missing from {}", note(v));
    }

    let junk = one(&f, "pe.version_info.junk");
    assert_eq!(junk.category, Category::Junk(JunkKind::VersionInfo));
    assert_eq!(junk.severity, Severity::Notice);
    let jm = junk.marker.as_ref().unwrap();
    assert_eq!(jm.container, ContainerKind::PeResource);
    assert_eq!(jm.region.len, ("built by alice on box7".len() * 2) as u64);
    let bytes = build(&Opts::default());
    let s = jm.region.offset as usize;
    assert_eq!(&bytes[s..s + 10], &utf16z("built")[..10]);

    let sig = one(&f, "pe.authenticode");
    assert_eq!(sig.category, Category::Integrity(SignatureStatus::Present));
    assert_eq!(sig.confidence, Confidence::Strong);
    assert!(note(sig).contains("revision 0x0200"));
    assert!(note(sig).contains("PKCS#7"));

    // The overlay sits before the certificate table: reported, not removable.
    let ov = one(&f, "pe.overlay");
    assert_eq!(ov.category, Category::Tamper(TamperKind::AppendedData));
    assert_eq!(ov.severity, Severity::Notice);
    assert!(ov.marker.is_none());
    assert!(note(ov).contains("before the Authenticode table"));

    let sum = one(&f, "pe.checksum");
    assert_eq!(
        sum.category,
        Category::Integrity(SignatureStatus::ChecksumOk)
    );
    assert_eq!(sum.evidence.offset, CHECKSUM_OFF as u64);

    assert!(all(&f, "pe.brand_impersonation").is_empty());
    assert!(all(&f, "pe.dotnet").is_empty());
    assert!(all(&f, "pe.packer_section").is_empty());
    assert!(all(&f, "pe.overlay_bloat").is_empty());
    for x in &f {
        assert!(x.evidence.matched.len() <= 64);
    }
}

#[test]
fn unsigned_image_offers_a_truncatable_overlay() {
    let o = Opts {
        cert: false,
        ..Opts::default()
    };
    let bytes = build(&o);
    let f = run(&bytes);
    let sig = one(&f, "pe.authenticode");
    assert_eq!(
        sig.category,
        Category::Integrity(SignatureStatus::NoEmbedded)
    );
    assert_eq!(sig.evidence.offset, (DIRS + 4 * 8) as u64);

    let ov = one(&f, "pe.overlay");
    let start = (bytes.len() - o.overlay.len()) as u64;
    assert_eq!(ov.evidence.offset, start);
    assert_eq!(
        ov.marker,
        Some(Marker::truncate_at(start, ContainerKind::PeOverlay))
    );
    assert!(note(ov).contains(&format!("{} bytes", o.overlay.len())));
}

#[test]
fn every_marker_scrubs_its_finding_and_keeps_the_image_parsing() {
    for o in [
        Opts {
            cert: false,
            ..Opts::default()
        },
        Opts {
            after_cert: b"TAGGED-AFTER-SIGNING".repeat(8),
            ..Opts::default()
        },
    ] {
        let bytes = build(&o);
        let before = run(&bytes);
        let marked: Vec<&Finding> = before.iter().filter(|x| x.marker.is_some()).collect();
        assert!(marked.len() >= 4, "{marked:#?}");
        for finding in marked {
            let mut edited = bytes.clone();
            apply(&mut edited, finding.marker.as_ref().unwrap());
            let after = run(&edited);
            assert!(
                !after.iter().any(|x| x.signature_id == finding.signature_id
                    && x.evidence.offset == finding.evidence.offset),
                "{} survived its own marker",
                finding.signature_id
            );
            // Still a parseable PE: the signature state is always reported.
            assert_eq!(all(&after, "pe.authenticode").len(), 1);
            assert_eq!(all(&after, "pe.version_info").len(), 1);
        }
    }
}

#[test]
fn data_after_the_certificate_truncates_without_touching_it() {
    let tail = b"TAGGED-AFTER-SIGNING".repeat(8);
    let o = Opts {
        overlay: Vec::new(),
        after_cert: tail.clone(),
        ..Opts::default()
    };
    let bytes = build(&o);
    let f = run(&bytes);
    let ov = one(&f, "pe.overlay");
    let cut = (bytes.len() - tail.len()) as u64;
    assert_eq!(
        ov.marker,
        Some(Marker::truncate_at(cut, ContainerKind::PeOverlay))
    );
    assert!(note(ov).contains("after the Authenticode table"));

    let mut edited = bytes.clone();
    apply(&mut edited, ov.marker.as_ref().unwrap());
    let after = run(&edited);
    assert!(all(&after, "pe.overlay").is_empty());
    assert_eq!(
        one(&after, "pe.authenticode").category,
        Category::Integrity(SignatureStatus::Present)
    );
}

#[test]
fn scrubbed_rich_and_pdb_leave_no_trace() {
    let mut bytes = build(&Opts {
        cert: false,
        checksum: Sum::Zero,
        ..Opts::default()
    });
    let f = run(&bytes);
    for id in ["pe.rich_header", "pe.pdb_path", "pe.version_info.junk"] {
        apply(&mut bytes, one(&f, id).marker.as_ref().unwrap());
    }
    let after = run(&bytes);
    assert!(all(&after, "pe.rich_header").is_empty());
    assert!(all(&after, "pe.pdb_path").is_empty());
    assert!(all(&after, "pe.version_info.junk").is_empty());
    assert_eq!(&bytes[RICH_AT..RICH_AT + 48], &[0u8; 48][..]);
    // The RSDS header and GUID survive the scrub.
    let rsds = TEXT_RAW + (RSDS_RVA - TEXT_VA) as usize;
    assert_eq!(&bytes[rsds..rsds + 4], b"RSDS");
    assert_eq!(&bytes[rsds + 4..rsds + 20], &[0x11; 16][..]);
    // The version strings around the scrubbed one are intact.
    assert_eq!(
        one(&after, "pe.version_info").title,
        "Example Corp Meow Tool"
    );
}

#[test]
fn rich_header_with_dirty_padding_is_moderate() {
    let mut bytes = build(&Opts::default());
    bytes[RICH_AT + 4] ^= 0x01;
    let f = run(&bytes);
    let rich = one(&f, "pe.rich_header");
    assert_eq!(rich.confidence, Confidence::Moderate);
}

#[test]
fn checksum_matches_reference_and_flags_mismatch() {
    let bytes = build(&Opts::default());
    let view = MemView::new("x.exe", bytes.clone());
    assert_eq!(
        pe_checksum(&view, CHECKSUM_OFF as u64),
        Some(reference_checksum(&bytes, CHECKSUM_OFF))
    );
    // Odd length exercises the trailing half word.
    let mut odd = bytes.clone();
    odd.push(0x7f);
    let view = MemView::new("x.exe", odd.clone());
    assert_eq!(
        pe_checksum(&view, CHECKSUM_OFF as u64),
        Some(reference_checksum(&odd, CHECKSUM_OFF))
    );

    let f = run(&build(&Opts {
        checksum: Sum::Bad,
        ..Opts::default()
    }));
    let sum = one(&f, "pe.checksum");
    assert_eq!(
        sum.category,
        Category::Integrity(SignatureStatus::ChecksumBad)
    );
    assert_eq!(sum.severity, Severity::Notice);

    let f = run(&build(&Opts {
        checksum: Sum::Zero,
        ..Opts::default()
    }));
    assert!(all(&f, "pe.checksum").is_empty());
}

#[test]
fn unsigned_vendor_claim_is_impersonation() {
    let unsigned = |company| {
        run(&build(&Opts {
            cert: false,
            company,
            ..Opts::default()
        }))
    };
    let f = unsigned("Microsoft Corporation");
    let imp = one(&f, "pe.brand_impersonation");
    assert_eq!(
        imp.category,
        Category::Deception(DeceptionKind::BrandImpersonation)
    );
    assert_eq!(imp.confidence, Confidence::Moderate);
    assert_eq!(imp.severity, Severity::Warn);
    assert!(imp.title.contains("Microsoft"));

    assert_eq!(
        all(&unsigned("NVIDIA Corporation"), "pe.brand_impersonation").len(),
        1
    );
    assert_eq!(
        all(&unsigned("Intel(R) Corporation"), "pe.brand_impersonation").len(),
        1
    );
    assert!(
        all(
            &unsigned("Intelligent Widgets Ltd"),
            "pe.brand_impersonation"
        )
        .is_empty()
    );

    let signed = run(&build(&Opts {
        company: "Microsoft Corporation",
        ..Opts::default()
    }));
    assert!(all(&signed, "pe.brand_impersonation").is_empty());

    // Inside the Windows directory the claim is a weak notice.
    let bytes = build(&Opts {
        cert: false,
        company: "Microsoft Corporation",
        ..Opts::default()
    });
    let f = run_at("C:/Windows/System32/drivers/sample.sys", &bytes);
    let imp = one(&f, "pe.brand_impersonation");
    assert_eq!(imp.confidence, Confidence::Weak);
    assert_eq!(imp.severity, Severity::Notice);
    assert!(in_windows_dir(std::path::Path::new(
        "c:/WINDOWS/notepad.exe"
    )));
    assert!(!in_windows_dir(std::path::Path::new(
        "/home/u/windows-tools.exe"
    )));
}

#[test]
fn pe32_image_reports_the_same_findings() {
    let o = Opts {
        pe32: true,
        cert: false,
        clr: true,
        ..Opts::default()
    };
    let bytes = build(&o);
    let f = run(&bytes);
    for id in [
        "pe.rich_header",
        "pe.pdb_path",
        "pe.version_info",
        "pe.version_info.junk",
        "pe.overlay",
        "pe.checksum",
    ] {
        assert_eq!(all(&f, id).len(), 1, "{id} missing from PE32: {f:#?}");
    }
    let sig = one(&f, "pe.authenticode");
    assert_eq!(
        sig.category,
        Category::Integrity(SignatureStatus::NoEmbedded)
    );
    assert_eq!(sig.evidence.offset, (DIRS32 + 4 * 8) as u64);
    assert_eq!(
        one(&f, "pe.checksum").category,
        Category::Integrity(SignatureStatus::ChecksumOk)
    );
    let net = one(&f, "pe.dotnet");
    assert!(note(net).starts_with("PE32,"), "{}", note(net));
    assert_eq!(one(&f, "pe.version_info").title, "Example Corp Meow Tool");
}

#[test]
fn dotnet_header_names_the_runtime() {
    let f = run(&build(&Opts {
        clr: true,
        ..Opts::default()
    }));
    let net = one(&f, "pe.dotnet");
    assert_eq!(net.category, Category::Brand(BrandKind::Toolchain));
    assert_eq!(net.confidence, Confidence::Strong);
    assert_eq!(net.title, ".NET assembly (v4.0.30319)");
    assert!(note(net).contains("IL only"));
    assert!(note(net).contains("PE32+"));
}

#[test]
fn packer_sections_are_strong_with_corroboration() {
    let f = run(&build(&Opts {
        names: ["UPX0", "UPX1"],
        ..Opts::default()
    }));
    let p = one(&f, "pe.packer_section");
    assert_eq!(p.category, Category::Brand(BrandKind::Packer));
    assert_eq!(p.severity, Severity::Notice);
    assert_eq!(p.confidence, Confidence::Strong);
    assert_eq!(p.title, "Packed with UPX");
    assert_eq!(p.evidence.offset, SECTIONS as u64);
    assert!(note(p).contains("entry point inside UPX0"));

    // One name, entry point elsewhere: moderate.
    let f = run(&build(&Opts {
        names: [".text", ".aspack"],
        ..Opts::default()
    }));
    let p = one(&f, "pe.packer_section");
    assert_eq!(p.confidence, Confidence::Moderate);
    assert_eq!(p.title, "Packed with ASPack");
    assert_eq!(p.evidence.offset, (SECTIONS + 40) as u64);
}

#[test]
fn installer_overlay_is_informational() {
    let mut overlay = vec![0u8, 0, 0, 0];
    overlay.extend_from_slice(b"\xEF\xBE\xAD\xDENullsoftInst");
    overlay.resize(2 * 1024 * 1024, 0x5a);
    let f = run(&build(&Opts {
        cert: false,
        overlay,
        ..Opts::default()
    }));
    let ov = one(&f, "pe.overlay");
    assert_eq!(ov.severity, Severity::Info);
    assert!(ov.title.contains("NSIS"));

    let f = run(&build(&Opts {
        cert: false,
        overlay: vec![0x5a; 2 * 1024 * 1024],
        ..Opts::default()
    }));
    assert_eq!(one(&f, "pe.overlay").severity, Severity::Warn);
}

#[test]
fn zero_bloat_overlay_is_deception() {
    let mut overlay = vec![0u8; 51 * 1024 * 1024];
    overlay[..4].copy_from_slice(b"PAD!");
    let bytes = build(&Opts {
        cert: false,
        overlay,
        checksum: Sum::Zero,
        ..Opts::default()
    });
    let f = run(&bytes);
    let bloat = one(&f, "pe.overlay_bloat");
    assert_eq!(
        bloat.category,
        Category::Deception(DeceptionKind::OverlayBloat)
    );
    assert_eq!(bloat.severity, Severity::Warn);
    assert_eq!(one(&f, "pe.overlay").severity, Severity::Warn);

    let mut edited = bytes;
    apply(&mut edited, bloat.marker.as_ref().unwrap());
    let after = run(&edited);
    assert!(all(&after, "pe.overlay").is_empty());
    assert!(all(&after, "pe.overlay_bloat").is_empty());
}

#[test]
fn coff_symbol_table_is_not_an_overlay() {
    let f = run(&build(&Opts {
        cert: false,
        overlay: Vec::new(),
        coff_symbols: true,
        ..Opts::default()
    }));
    assert!(all(&f, "pe.overlay").is_empty());
}

#[test]
fn zero_alignment_tail_is_not_an_overlay() {
    let f = run(&build(&Opts {
        cert: false,
        overlay: vec![0u8; 200],
        ..Opts::default()
    }));
    assert!(all(&f, "pe.overlay").is_empty());
}

#[test]
fn certificate_past_eof_is_damaged() {
    let mut bytes = build(&Opts {
        overlay: Vec::new(),
        checksum: Sum::Zero,
        ..Opts::default()
    });
    bytes.truncate(bytes.len() - 8);
    let f = run(&bytes);
    let sig = one(&f, "pe.authenticode");
    assert_eq!(sig.category, Category::Integrity(SignatureStatus::Absent));
    assert_eq!(sig.severity, Severity::Warn);
}

#[test]
fn dos_executables_and_garbage_report_nothing() {
    let mut dos = vec![0u8; 512];
    dos[..2].copy_from_slice(b"MZ");
    assert!(run(&dos).is_empty());
    dos[0x3c..0x40].copy_from_slice(&0x7fff_fff0u32.to_le_bytes());
    assert!(run(&dos).is_empty());
    dos[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    dos[0x40..0x44].copy_from_slice(b"NE\0\0");
    assert!(run(&dos).is_empty());
    assert!(run(b"MZ").is_empty());
    assert!(run(b"").is_empty());

    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for _ in 0..64 {
        let mut junk: Vec<u8> = (0..4096)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                (seed >> 24) as u8
            })
            .collect();
        junk[..2].copy_from_slice(b"MZ");
        assert!(run(&junk).is_empty());
    }
}

#[test]
fn truncated_and_mutated_images_never_panic() {
    let bytes = build(&Opts {
        clr: true,
        after_cert: vec![1; 40],
        ..Opts::default()
    });
    for len in 0..bytes.len() {
        let f = run(&bytes[..len]);
        if len < SECTIONS {
            assert!(f.is_empty(), "truncated at {len}: {f:#?}");
        }
    }
    let mut seed = 0x9e37_79b9_7f4a_7c15u64;
    for _ in 0..2000 {
        let mut m = bytes.clone();
        for _ in 0..4 {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            let at = (seed % m.len() as u64) as usize;
            m[at] = (seed >> 32) as u8;
        }
        let _ = run(&m);
    }
    for at in 0..0x300 {
        let mut m = bytes.clone();
        m[at] = 0xff;
        let _ = run(&m);
    }
}

/// The integration repro: a PE32 header with SizeOfHeaders 0 and one all-zero
/// section header, 1024 bytes long.
fn zeroed_section_image() -> Vec<u8> {
    let mut f = vec![0u8; 1024];
    put(&mut f, 0, b"MZ");
    p32(&mut f, 0x3c, 0x80);
    put(&mut f, 0x80, b"PE\0\0");
    p16(&mut f, 0x84, 0x14c);
    p16(&mut f, 0x86, 1);
    p16(&mut f, 0x94, 0xe0);
    p16(&mut f, 0x98, 0x10b);
    f
}

fn no_truncate_into_headers(f: &[Finding], table_end: u64) {
    for x in f {
        if let Some(m) = &x.marker {
            assert_ne!(m.region.offset, 0, "{} marks offset 0", x.signature_id);
            if let RemovalStrategy::Truncate { from } = m.removal {
                assert!(
                    from >= table_end,
                    "{} truncates at {from}, inside the headers",
                    x.signature_id
                );
            }
        }
    }
}

#[test]
fn inconsistent_headers_never_offer_an_overlay_truncate() {
    const TABLE_END: u64 = 0x178 + 40;
    let base = zeroed_section_image();
    let f = run(&base);
    assert!(all(&f, "pe.overlay").is_empty(), "{f:#?}");
    assert!(all(&f, "pe.overlay_bloat").is_empty());
    no_truncate_into_headers(&f, TABLE_END);

    // The rest use a non-zero tail, so only the layout check holds them back.
    let mut tailed = base.clone();
    tailed[0x200..].fill(0x41);

    // SizeOfHeaders smaller than the section table end.
    let mut small = tailed.clone();
    p32(&mut small, 0x98 + 60, 0x100);
    p32(&mut small, 0x178 + 16, 0x100);
    p32(&mut small, 0x178 + 20, 0x200);
    let f = run(&small);
    assert!(all(&f, "pe.overlay").is_empty(), "{f:#?}");
    no_truncate_into_headers(&f, TABLE_END);

    // Valid SizeOfHeaders, but every section is zero-sized.
    let mut empty = tailed.clone();
    p32(&mut empty, 0x98 + 60, 0x200);
    let f = run(&empty);
    assert!(all(&f, "pe.overlay").is_empty(), "{f:#?}");

    // Section raw data that lies inside the headers.
    let mut inside = empty.clone();
    p32(&mut inside, 0x178 + 16, 0x40);
    p32(&mut inside, 0x178 + 20, 0x100);
    let f = run(&inside);
    assert!(all(&f, "pe.overlay").is_empty(), "{f:#?}");

    // The same image with a consistent layout reports its overlay past the
    // section data and nowhere earlier.
    let mut good = empty;
    p32(&mut good, 0x178 + 16, 0x100);
    p32(&mut good, 0x178 + 20, 0x200);
    good[0x300..].fill(0x41);
    let f = run(&good);
    let ov = one(&f, "pe.overlay");
    assert_eq!(
        ov.marker,
        Some(Marker::truncate_at(0x300, ContainerKind::PeOverlay))
    );
    no_truncate_into_headers(&f, TABLE_END);
}

#[test]
fn image_end_covers_headers_table_and_sections() {
    let mut bytes = zeroed_section_image();
    p32(&mut bytes, 0x98 + 60, 0x100);
    let view = MemView::new("x.exe", bytes.clone());
    let img = PeImage::parse(&view).unwrap();
    assert_eq!(img.table_end, 0x178 + 40);
    assert_eq!(img.image_end(), 0x178 + 40);
    assert!(!img.layout_ok());
    p32(&mut bytes, 0x178 + 16, 0x80);
    p32(&mut bytes, 0x178 + 20, 0x300);
    let view = MemView::new("x.exe", bytes);
    let img = PeImage::parse(&view).unwrap();
    assert_eq!(img.image_end(), 0x380);
}
