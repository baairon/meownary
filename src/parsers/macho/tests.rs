//! Mach-O probe tests over a synthetic thin image (LC_UUID, LC_BUILD_VERSION,
//! LC_RPATH and LC_CODE_SIGNATURE with an ad hoc CodeDirectory), in both
//! byte orders and word sizes, and the same image wrapped in fat headers.

use super::*;
use crate::model::RemovalStrategy;
use crate::scan::MemView;

const USER_RPATH: &str = "/Users/alice/dev/app/build/lib";
const APP_RPATH: &str = "@executable_path/../Frameworks";
const IDENT: &str = "com.example.meow";
const ARM64: u32 = 0x0100_000c;
const X86_64: u32 = 0x0100_0007;

#[derive(Clone)]
struct Opts {
    le: bool,
    is64: bool,
    cputype: u32,
    signature: bool,
    adhoc: bool,
    team: Option<&'static str>,
    encrypted: bool,
    version_min: bool,
    rpaths: Vec<&'static str>,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            le: true,
            is64: true,
            cputype: ARM64,
            signature: true,
            adhoc: true,
            team: None,
            encrypted: false,
            version_min: false,
            rpaths: vec![USER_RPATH, APP_RPATH],
        }
    }
}

fn w32(le: bool, v: u32) -> [u8; 4] {
    if le { v.to_le_bytes() } else { v.to_be_bytes() }
}

fn be(v: u32) -> [u8; 4] {
    v.to_be_bytes()
}

/// The built image and the absolute offset of each load command.
struct Built {
    bytes: Vec<u8>,
    cmds: Vec<(u32, u64)>,
}

impl Built {
    fn cmd_offs(&self, cmd: u32) -> Vec<u64> {
        self.cmds
            .iter()
            .filter(|(c, _)| *c == cmd)
            .map(|&(_, o)| o)
            .collect()
    }
}

fn code_directory(o: &Opts) -> Vec<u8> {
    let version: u32 = if o.team.is_some() { 0x20200 } else { 0x20100 };
    let fixed = if o.team.is_some() { 52 } else { 48 };
    let mut cd = vec![0u8; fixed];
    let mut strings = Vec::new();
    let ident_off = fixed as u32;
    strings.extend_from_slice(IDENT.as_bytes());
    strings.push(0);
    let team_off = fixed as u32 + strings.len() as u32;
    if let Some(t) = o.team {
        strings.extend_from_slice(t.as_bytes());
        strings.push(0);
    }
    cd[0..4].copy_from_slice(&be(CSMAGIC_CODEDIRECTORY));
    cd[8..12].copy_from_slice(&be(version));
    cd[12..16].copy_from_slice(&be(if o.adhoc { 0x2_0002 } else { 0 }));
    cd[16..20].copy_from_slice(&be(fixed as u32 + strings.len() as u32));
    cd[20..24].copy_from_slice(&be(ident_off));
    cd[32..36].copy_from_slice(&be(0x4000));
    cd[36] = 32;
    cd[37] = 2;
    cd[39] = 12;
    if o.team.is_some() {
        cd[48..52].copy_from_slice(&be(team_off));
    }
    cd.extend_from_slice(&strings);
    let len = cd.len() as u32;
    cd[4..8].copy_from_slice(&be(len));
    cd
}

fn superblob(o: &Opts) -> Vec<u8> {
    let cd = code_directory(o);
    let mut sb = Vec::new();
    sb.extend_from_slice(&be(CSMAGIC_EMBEDDED_SIGNATURE));
    sb.extend_from_slice(&be((20 + cd.len()) as u32));
    sb.extend_from_slice(&be(1));
    sb.extend_from_slice(&be(0));
    sb.extend_from_slice(&be(20));
    sb.extend_from_slice(&cd);
    sb
}

fn thin_image(o: &Opts) -> Built {
    let le = o.le;
    let hdr = if o.is64 { 32 } else { 28 };
    let align = if o.is64 { 8 } else { 4 };
    let mut cmds: Vec<(u32, Vec<u8>)> = Vec::new();

    let mut uuid = Vec::new();
    uuid.extend_from_slice(&w32(le, LC_UUID));
    uuid.extend_from_slice(&w32(le, 24));
    uuid.extend((0u8..16).collect::<Vec<_>>());
    cmds.push((LC_UUID, uuid));

    if o.version_min {
        let mut v = Vec::new();
        v.extend_from_slice(&w32(le, LC_VERSION_MIN_MACOSX));
        v.extend_from_slice(&w32(le, 16));
        v.extend_from_slice(&w32(le, 0x000a_0f00));
        v.extend_from_slice(&w32(le, 0x000b_0000));
        cmds.push((LC_VERSION_MIN_MACOSX, v));
    } else {
        let mut v = Vec::new();
        v.extend_from_slice(&w32(le, LC_BUILD_VERSION));
        v.extend_from_slice(&w32(le, 32));
        v.extend_from_slice(&w32(le, 1));
        v.extend_from_slice(&w32(le, 0x000d_0000));
        v.extend_from_slice(&w32(le, 0x000e_0200));
        v.extend_from_slice(&w32(le, 1));
        v.extend_from_slice(&w32(le, 3));
        v.extend_from_slice(&w32(le, 0x03f7_0700));
        cmds.push((LC_BUILD_VERSION, v));
    }

    for path in &o.rpaths {
        let mut r = Vec::new();
        let size = (12 + path.len() + 1).div_ceil(align) * align;
        r.extend_from_slice(&w32(le, LC_RPATH));
        r.extend_from_slice(&w32(le, size as u32));
        r.extend_from_slice(&w32(le, 12));
        r.extend_from_slice(path.as_bytes());
        r.resize(size, 0);
        cmds.push((LC_RPATH, r));
    }

    if o.encrypted {
        let mut e = Vec::new();
        e.extend_from_slice(&w32(le, LC_ENCRYPTION_INFO_64));
        e.extend_from_slice(&w32(le, 24));
        e.extend_from_slice(&w32(le, 0x4000));
        e.extend_from_slice(&w32(le, 0x1000));
        e.extend_from_slice(&w32(le, 1));
        e.extend_from_slice(&w32(le, 0));
        cmds.push((LC_ENCRYPTION_INFO_64, e));
    }

    let sizeofcmds: usize =
        cmds.iter().map(|(_, c)| c.len()).sum::<usize>() + if o.signature { 16 } else { 0 };
    let code_at = (hdr + sizeofcmds).div_ceil(16) * 16 + 0x40;
    let sig = superblob(o);
    if o.signature {
        let mut c = Vec::new();
        c.extend_from_slice(&w32(le, LC_CODE_SIGNATURE));
        c.extend_from_slice(&w32(le, 16));
        c.extend_from_slice(&w32(le, code_at as u32));
        c.extend_from_slice(&w32(le, sig.len() as u32));
        cmds.push((LC_CODE_SIGNATURE, c));
    }

    let mut f = Vec::new();
    let magic: u32 = if o.is64 { 0xfeed_facf } else { 0xfeed_face };
    f.extend_from_slice(&w32(le, magic));
    f.extend_from_slice(&w32(le, if o.is64 { o.cputype } else { 7 }));
    f.extend_from_slice(&w32(le, 0));
    f.extend_from_slice(&w32(le, 2));
    f.extend_from_slice(&w32(le, cmds.len() as u32));
    f.extend_from_slice(&w32(le, sizeofcmds as u32));
    f.extend_from_slice(&w32(le, 0));
    if o.is64 {
        f.extend_from_slice(&w32(le, 0));
    }
    let mut offs = Vec::new();
    for (cmd, c) in &cmds {
        offs.push((*cmd, f.len() as u64));
        f.extend_from_slice(c);
    }
    f.resize(code_at, 0x90);
    if o.signature {
        f.extend_from_slice(&sig);
    }
    Built {
        bytes: f,
        cmds: offs,
    }
}

/// Wrap thin images in a fat header, each slice 4 KiB aligned.
fn fat(slices: &[(u32, Vec<u8>)], wide: bool) -> (Vec<u8>, Vec<u64>) {
    let mut f = Vec::new();
    f.extend_from_slice(&be(if wide { 0xcafe_babf } else { 0xcafe_babe }));
    f.extend_from_slice(&be(slices.len() as u32));
    let entsize = if wide { 32 } else { 20 };
    let mut at = 0x1000usize;
    let mut bases = Vec::new();
    let mut table = Vec::new();
    for (cpu, body) in slices {
        table.extend_from_slice(&be(*cpu));
        table.extend_from_slice(&be(0));
        if wide {
            table.extend_from_slice(&(at as u64).to_be_bytes());
            table.extend_from_slice(&(body.len() as u64).to_be_bytes());
            table.extend_from_slice(&be(12));
            table.extend_from_slice(&be(0));
        } else {
            table.extend_from_slice(&be(at as u32));
            table.extend_from_slice(&be(body.len() as u32));
            table.extend_from_slice(&be(12));
        }
        bases.push(at as u64);
        at += body.len().div_ceil(0x1000) * 0x1000;
    }
    assert_eq!(table.len(), entsize * slices.len());
    f.extend_from_slice(&table);
    for ((_, body), base) in slices.iter().zip(&bases) {
        f.resize(*base as usize, 0);
        f.extend_from_slice(body);
    }
    (f, bases)
}

fn run(bytes: &[u8]) -> Vec<Finding> {
    let view = MemView::new("app", bytes.to_vec());
    let ctx = ProbeCtx::new(&view, Some("macho"));
    let mut out = Vec::new();
    for p in probes() {
        assert_eq!(p.id(), "macho");
        assert_eq!(p.formats(), &["macho"]);
        p.run(&ctx, &mut out);
    }
    out
}

fn all<'a>(f: &'a [Finding], id: &str) -> Vec<&'a Finding> {
    f.iter().filter(|x| x.signature_id == id).collect()
}

fn one<'a>(f: &'a [Finding], id: &str) -> &'a Finding {
    let hits = all(f, id);
    assert_eq!(hits.len(), 1, "expected exactly one {id}: {f:#?}");
    hits[0]
}

fn note(f: &Finding) -> &str {
    f.evidence.note.as_deref().unwrap_or("")
}

fn apply(bytes: &mut [u8], m: &Marker) {
    let RemovalStrategy::RawBlank { fill } = m.removal else {
        panic!("Mach-O markers are blanks");
    };
    assert_ne!(m.region.offset, 0);
    bytes[m.region.offset as usize..m.region.end() as usize].fill(fill);
}

#[test]
fn thin_image_reports_signature_build_uuid_and_rpath() {
    for (le, is64) in [(true, true), (false, true), (true, false), (false, false)] {
        let o = Opts {
            le,
            is64,
            ..Opts::default()
        };
        let b = thin_image(&o);
        let f = run(&b.bytes);

        let sig = one(&f, "macho.code_signature");
        assert_eq!(sig.category, Category::Integrity(SignatureStatus::AdHoc));
        assert_eq!(sig.confidence, Confidence::Strong);
        assert_eq!(sig.severity, Severity::Notice);
        assert_eq!(sig.title, "Ad hoc code signature");
        assert!(note(sig).contains(IDENT));

        let bv = one(&f, "macho.build_version");
        assert_eq!(bv.category, Category::Brand(BrandKind::Toolchain));
        assert_eq!(bv.confidence, Confidence::Strong);
        assert_eq!(bv.title, "macOS 13.0 (SDK 14.2)");
        assert!(note(bv).contains("tools: ld 1015.7"));
        assert_eq!(bv.evidence.offset, b.cmd_offs(LC_BUILD_VERSION)[0]);

        let id = one(&f, "macho.uuid");
        assert_eq!(id.confidence, Confidence::Moderate);
        assert!(note(id).contains("00010203-0405-0607-0809-0A0B0C0D0E0F"));

        let r = one(&f, "macho.rpath");
        assert_eq!(r.category, Category::Junk(JunkKind::BuildPath));
        assert_eq!(r.confidence, Confidence::Strong);
        assert_eq!(r.severity, Severity::Notice);
        assert!(note(r).contains("re-sign"));
        let m = r.marker.as_ref().unwrap();
        let lc = b.cmd_offs(LC_RPATH)[0];
        assert_eq!(m.region, Region::new(lc + 12, USER_RPATH.len() as u64));
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0 });
        assert_eq!(m.container, ContainerKind::MachoLoadCmd);

        assert!(all(&f, "macho.encrypted").is_empty());
    }
}

#[test]
fn rpath_scrub_removes_only_the_user_path() {
    let b = thin_image(&Opts::default());
    let f = run(&b.bytes);
    let mut edited = b.bytes.clone();
    apply(&mut edited, one(&f, "macho.rpath").marker.as_ref().unwrap());
    let after = run(&edited);
    assert!(all(&after, "macho.rpath").is_empty());
    for id in ["macho.code_signature", "macho.build_version", "macho.uuid"] {
        assert_eq!(all(&after, id).len(), 1, "{id} lost after the scrub");
    }
    // The command framing and the second rpath are untouched.
    let lc = b.cmd_offs(LC_RPATH)[0] as usize;
    assert_eq!(&edited[lc..lc + 12], &b.bytes[lc..lc + 12]);
    let second = b.cmd_offs(LC_RPATH)[1] as usize;
    assert_eq!(cstr(&edited, second + 12, 64), Some(APP_RPATH.as_bytes()));
}

#[test]
fn signature_states() {
    let f = run(&thin_image(&Opts {
        adhoc: false,
        team: Some("ABCDE12345"),
        ..Opts::default()
    })
    .bytes);
    let sig = one(&f, "macho.code_signature");
    assert_eq!(sig.category, Category::Integrity(SignatureStatus::Present));
    assert_eq!(sig.severity, Severity::Info);
    assert!(note(sig).contains(&format!("identifier {IDENT}")));
    assert!(note(sig).contains("team ABCDE12345"));

    let f = run(&thin_image(&Opts {
        signature: false,
        ..Opts::default()
    })
    .bytes);
    let sig = one(&f, "macho.code_signature");
    assert_eq!(
        sig.category,
        Category::Integrity(SignatureStatus::NoEmbedded)
    );
    assert_eq!(sig.confidence, Confidence::Strong);
    assert!(!note(one(&f, "macho.rpath")).contains("re-sign"));

    // A signature command pointing past the end is damaged, not absent.
    let mut b = thin_image(&Opts::default()).bytes;
    b.truncate(b.len() - 8);
    let f = run(&b);
    let sig = one(&f, "macho.code_signature");
    assert_eq!(sig.category, Category::Integrity(SignatureStatus::Absent));
    assert_eq!(sig.severity, Severity::Warn);
}

#[test]
fn encryption_and_version_min() {
    let f = run(&thin_image(&Opts {
        encrypted: true,
        version_min: true,
        ..Opts::default()
    })
    .bytes);
    let enc = one(&f, "macho.encrypted");
    assert_eq!(enc.category, Category::Brand(BrandKind::Vendor));
    assert_eq!(enc.confidence, Confidence::Moderate);
    assert_eq!(enc.title, "App Store encrypted binary");
    assert_eq!(
        one(&f, "macho.build_version").title,
        "macOS 10.15 (SDK 11.0)"
    );
}

#[test]
fn fat_slices_use_absolute_offsets_and_arch_titles() {
    for wide in [false, true] {
        let arm = thin_image(&Opts::default());
        let intel = thin_image(&Opts {
            cputype: X86_64,
            ..Opts::default()
        });
        let (bytes, bases) = fat(
            &[(ARM64, arm.bytes.clone()), (X86_64, intel.bytes.clone())],
            wide,
        );
        let f = run(&bytes);
        let rpaths = all(&f, "macho.rpath");
        assert_eq!(rpaths.len(), 2);
        assert_eq!(
            rpaths[0].title,
            format!("[arm64] Build path in LC_RPATH: {USER_RPATH}")
        );
        assert!(rpaths[1].title.starts_with("[x86_64] "));
        let lc = arm.cmd_offs(LC_RPATH)[0];
        assert_eq!(
            rpaths[0].marker.as_ref().unwrap().region,
            Region::new(bases[0] + lc + 12, USER_RPATH.len() as u64)
        );
        assert_eq!(
            rpaths[1].marker.as_ref().unwrap().region,
            Region::new(bases[1] + lc + 12, USER_RPATH.len() as u64)
        );
        let sigs = all(&f, "macho.code_signature");
        assert_eq!(sigs.len(), 2);
        assert!(
            sigs.iter()
                .all(|s| s.category == Category::Integrity(SignatureStatus::AdHoc))
        );
        assert_eq!(sigs[0].title, "[arm64] Ad hoc code signature");
        assert!(sigs[0].evidence.offset > bases[0]);
        assert!(sigs[1].evidence.offset > bases[1]);
        assert_eq!(all(&f, "macho.uuid").len(), 2);
        assert_eq!(
            all(&f, "macho.uuid")[1].evidence.offset,
            bases[1] + intel.cmd_offs(LC_UUID)[0] + 8
        );

        // Scrubbing one slice leaves the other slice's finding in place.
        let mut edited = bytes.clone();
        apply(&mut edited, rpaths[0].marker.as_ref().unwrap());
        let after = run(&edited);
        let left = all(&after, "macho.rpath");
        assert_eq!(left.len(), 1);
        assert!(left[0].title.starts_with("[x86_64] "));
        apply(&mut edited, rpaths[1].marker.as_ref().unwrap());
        let after = run(&edited);
        assert!(all(&after, "macho.rpath").is_empty());
        assert_eq!(all(&after, "macho.build_version").len(), 2);
    }
}

#[test]
fn fat_slices_out_of_bounds_are_skipped() {
    let arm = thin_image(&Opts::default());
    let (mut bytes, _) = fat(&[(ARM64, arm.bytes)], false);
    // Point the only slice past the end of the file.
    bytes[16..20].copy_from_slice(&be(0x0100_0000));
    assert!(run(&bytes).is_empty());
}

#[test]
fn truncated_and_garbage_inputs_never_panic() {
    let thin = thin_image(&Opts {
        encrypted: true,
        team: Some("TEAM"),
        adhoc: false,
        ..Opts::default()
    })
    .bytes;
    let (fat_bytes, _) = fat(&[(ARM64, thin.clone()), (X86_64, thin.clone())], false);
    for bytes in [&thin, &fat_bytes] {
        for len in 0..bytes.len() {
            let f = run(&bytes[..len]);
            if len < 32 {
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
    }
    // A load command table that overruns the file is reported as nothing.
    let mut short = thin.clone();
    short.truncate(40);
    assert!(run(&short).is_empty());

    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for magic in [
        [0xcf, 0xfa, 0xed, 0xfe],
        [0xfe, 0xed, 0xfa, 0xce],
        [0xca, 0xfe, 0xba, 0xbe],
    ] {
        for _ in 0..64 {
            let mut junk: Vec<u8> = (0..4096)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    (seed >> 24) as u8
                })
                .collect();
            junk[..4].copy_from_slice(&magic);
            let _ = run(&junk);
        }
    }
    assert!(run(b"").is_empty());
    assert!(run(&[0xcf, 0xfa, 0xed, 0xfe]).is_empty());
}
