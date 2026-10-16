//! ELF probe tests over synthetic objects in all four class and byte-order
//! combinations: `.interp` behind PT_INTERP, `.comment`, the GNU build id
//! note, `.dynstr` and `.dynamic` with DT_RUNPATH, and `.shstrtab`.

use super::*;
use crate::model::RemovalStrategy;
use crate::scan::MemView;

const INTERP: &str = "/lib64/ld-linux-x86-64.so.2";
const GCC: &str = "GCC: (GNU) 13.2.0";
const LLD: &str = "Linker: LLD 17.0.6 (/home/alice/src/llvm-project/llvm 1234abcd)";
const RUNPATH: &str = "$ORIGIN/../lib:/home/alice/proj/build/lib";

#[derive(Clone, Copy)]
struct W {
    le: bool,
    is64: bool,
}

impl W {
    fn u16(&self, v: u16) -> Vec<u8> {
        if self.le {
            v.to_le_bytes().to_vec()
        } else {
            v.to_be_bytes().to_vec()
        }
    }
    fn u32(&self, v: u32) -> Vec<u8> {
        if self.le {
            v.to_le_bytes().to_vec()
        } else {
            v.to_be_bytes().to_vec()
        }
    }
    fn u64(&self, v: u64) -> Vec<u8> {
        if self.le {
            v.to_le_bytes().to_vec()
        } else {
            v.to_be_bytes().to_vec()
        }
    }
    fn word(&self, v: u64) -> Vec<u8> {
        if self.is64 {
            self.u64(v)
        } else {
            self.u32(v as u32)
        }
    }
    fn note(&self, name: &[u8], kind: u32, desc: &[u8]) -> Vec<u8> {
        let mut n = Vec::new();
        n.extend(self.u32(name.len() as u32));
        n.extend(self.u32(desc.len() as u32));
        n.extend(self.u32(kind));
        n.extend_from_slice(name);
        while n.len() % 4 != 0 {
            n.push(0);
        }
        n.extend_from_slice(desc);
        while n.len() % 4 != 0 {
            n.push(0);
        }
        n
    }
}

const ALL: [W; 4] = [
    W {
        le: true,
        is64: true,
    },
    W {
        le: false,
        is64: true,
    },
    W {
        le: true,
        is64: false,
    },
    W {
        le: false,
        is64: false,
    },
];

struct Opts {
    comment: Vec<&'static str>,
    runpath: &'static str,
    go: bool,
    symtab: bool,
    ext_numbering: bool,
}

impl Default for Opts {
    fn default() -> Self {
        Opts {
            comment: vec![GCC, LLD, GCC],
            runpath: RUNPATH,
            go: false,
            symtab: false,
            ext_numbering: false,
        }
    }
}

struct Sec {
    name: &'static str,
    kind: u32,
    data: Vec<u8>,
    link: u32,
}

/// The built file and the absolute data offset of each named section.
struct Built {
    bytes: Vec<u8>,
    offsets: Vec<(&'static str, u64)>,
}

impl Built {
    fn off(&self, name: &str) -> u64 {
        self.offsets.iter().find(|(n, _)| *n == name).unwrap().1
    }
}

fn build(w: W, o: &Opts) -> Built {
    let (ehsize, phentsize, shentsize) = if w.is64 { (64, 56, 64) } else { (52, 32, 40) };

    let mut comment = Vec::new();
    for s in &o.comment {
        comment.extend_from_slice(s.as_bytes());
        comment.push(0);
    }
    let dynstr = format!("\0libc.so.6\0{}\0", o.runpath).into_bytes();
    let mut dynamic = Vec::new();
    for (tag, val) in [(1u64, 1u64), (29, 11), (0, 0)] {
        dynamic.extend(w.word(tag));
        dynamic.extend(w.word(val));
    }
    let mut secs = vec![
        Sec {
            name: ".interp",
            kind: 1,
            data: format!("{INTERP}\0").into_bytes(),
            link: 0,
        },
        Sec {
            name: ".comment",
            kind: 1,
            data: comment,
            link: 0,
        },
        Sec {
            name: ".note.gnu.build-id",
            kind: 7,
            data: w.note(b"GNU\0", 3, &[0xab; 20]),
            link: 0,
        },
        Sec {
            name: ".dynstr",
            kind: 3,
            data: dynstr,
            link: 0,
        },
        Sec {
            name: ".dynamic",
            kind: 6,
            data: dynamic,
            link: 4,
        },
    ];
    if o.go {
        secs.push(Sec {
            name: ".note.go.buildid",
            kind: 7,
            data: w.note(b"Go\0\0", 4, b"abc123/def456"),
            link: 0,
        });
    }
    if o.symtab {
        secs.push(Sec {
            name: ".symtab",
            kind: 2,
            data: vec![0; if w.is64 { 24 } else { 16 }],
            link: 0,
        });
    }
    let mut shstr = vec![0u8];
    let mut name_offs = Vec::new();
    for s in secs.iter().map(|s| s.name).chain([".shstrtab"]) {
        name_offs.push(shstr.len() as u32);
        shstr.extend_from_slice(s.as_bytes());
        shstr.push(0);
    }
    secs.push(Sec {
        name: ".shstrtab",
        kind: 3,
        data: shstr,
        link: 0,
    });
    let shnum = secs.len() + 1;
    let shstrndx = secs.len();

    let mut f = vec![0u8; ehsize + phentsize];
    let mut offsets = Vec::new();
    for s in &secs {
        while f.len() % 8 != 0 {
            f.push(0);
        }
        offsets.push((s.name, f.len() as u64));
        f.extend_from_slice(&s.data);
    }
    while f.len() % 8 != 0 {
        f.push(0);
    }
    let shoff = f.len();

    // Section headers: the null entry, then each section.
    let mut null = vec![0u8; shentsize];
    if o.ext_numbering {
        let (size_at, link_at) = if w.is64 { (32, 40) } else { (20, 24) };
        let size = w.word(shnum as u64);
        null[size_at..size_at + size.len()].copy_from_slice(&size);
        null[link_at..link_at + 4].copy_from_slice(&w.u32(shstrndx as u32));
    }
    f.extend_from_slice(&null);
    for (i, s) in secs.iter().enumerate() {
        let mut h = Vec::new();
        let off = offsets[i].1;
        h.extend(w.u32(name_offs[i]));
        h.extend(w.u32(s.kind));
        h.extend(w.word(0));
        h.extend(w.word(0));
        h.extend(w.word(off));
        h.extend(w.word(s.data.len() as u64));
        h.extend(w.u32(s.link));
        h.extend(w.u32(0));
        h.extend(w.word(1));
        h.extend(w.word(if s.kind == 6 {
            if w.is64 { 16 } else { 8 }
        } else {
            0
        }));
        assert_eq!(h.len(), shentsize);
        f.extend_from_slice(&h);
    }

    // ELF header.
    let mut e = vec![
        0x7f,
        b'E',
        b'L',
        b'F',
        if w.is64 { 2 } else { 1 },
        if w.le { 1 } else { 2 },
        1,
    ];
    e.resize(16, 0);
    e.extend(w.u16(3));
    e.extend(w.u16(if w.is64 { 0x3e } else { 0x28 }));
    e.extend(w.u32(1));
    e.extend(w.word(0x1000));
    e.extend(w.word(ehsize as u64));
    e.extend(w.word(shoff as u64));
    e.extend(w.u32(0));
    e.extend(w.u16(ehsize as u16));
    e.extend(w.u16(phentsize as u16));
    e.extend(w.u16(1));
    e.extend(w.u16(shentsize as u16));
    if o.ext_numbering {
        e.extend(w.u16(0));
        e.extend(w.u16(0xffff));
    } else {
        e.extend(w.u16(shnum as u16));
        e.extend(w.u16(shstrndx as u16));
    }
    assert_eq!(e.len(), ehsize);
    f[..ehsize].copy_from_slice(&e);

    // PT_INTERP program header.
    let interp_off = offsets[0].1;
    let interp_len = secs[0].data.len() as u64;
    let mut p = Vec::new();
    if w.is64 {
        p.extend(w.u32(3));
        p.extend(w.u32(4));
        p.extend(w.u64(interp_off));
        p.extend(w.u64(0));
        p.extend(w.u64(0));
        p.extend(w.u64(interp_len));
        p.extend(w.u64(interp_len));
        p.extend(w.u64(1));
    } else {
        p.extend(w.u32(3));
        p.extend(w.u32(interp_off as u32));
        p.extend(w.u32(0));
        p.extend(w.u32(0));
        p.extend(w.u32(interp_len as u32));
        p.extend(w.u32(interp_len as u32));
        p.extend(w.u32(4));
        p.extend(w.u32(1));
    }
    assert_eq!(p.len(), phentsize);
    f[ehsize..ehsize + phentsize].copy_from_slice(&p);

    Built { bytes: f, offsets }
}

fn run(bytes: &[u8]) -> Vec<Finding> {
    let view = MemView::new("a.out", bytes.to_vec());
    let ctx = ProbeCtx::new(&view, Some("elf"));
    let mut out = Vec::new();
    for p in probes() {
        assert_eq!(p.id(), "elf");
        assert_eq!(p.formats(), &["elf"]);
        p.run(&ctx, &mut out);
    }
    out
}

#[test]
fn deattribute_comment_blanks_toolchain_value_only() {
    let opts = Opts {
        comment: vec![GCC],
        ..Opts::default()
    };
    let mut bytes = build(ALL[0], &opts).bytes;
    let view = MemView::new("a.out", bytes.clone());
    let mut report = crate::model::FileReport::new("a.out".into(), bytes.len() as u64);
    report.format = Some("elf".into());
    report.findings = run(&bytes);
    let plan = crate::edit::deattribute::plan(&report, &view);
    assert!(
        plan.targets
            .iter()
            .any(|t| t.kind == crate::edit::deattribute::Kind::Brand)
    );
    for target in &plan.targets {
        apply(&mut bytes, &target.marker);
    }
    assert!(!bytes.windows(GCC.len()).any(|w| w == GCC.as_bytes()));
    assert!(bytes.windows(INTERP.len()).any(|w| w == INTERP.as_bytes()));
    let after = MemView::new("a.out", bytes.clone());
    assert!(Elf::parse(&after).is_some());
    report.findings = run(&bytes);
    assert!(
        crate::edit::deattribute::plan(&report, &after)
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

fn note(f: &Finding) -> &str {
    f.evidence.note.as_deref().unwrap_or("")
}

fn apply(bytes: &mut [u8], m: &Marker) {
    let RemovalStrategy::RawBlank { fill } = m.removal else {
        panic!("ELF markers are blanks");
    };
    assert_ne!(m.region.offset, 0);
    bytes[m.region.offset as usize..m.region.end() as usize].fill(fill);
}

#[test]
fn every_class_and_byte_order_reports_the_same_findings() {
    for w in ALL {
        let b = build(w, &Opts::default());
        let f = run(&b.bytes);

        let c = one(&f, "elf.comment");
        assert_eq!(c.category, Category::Brand(BrandKind::Toolchain));
        assert_eq!(c.confidence, Confidence::Strong);
        assert_eq!(c.severity, Severity::Info);
        assert_eq!(c.evidence.offset, b.off(".comment"));
        assert_eq!(note(c).matches(GCC).count(), 1, "{}", note(c));
        assert!(note(c).contains("no .symtab (stripped)"));
        assert!(c.title.starts_with(GCC));

        let j = one(&f, "elf.comment.junk");
        assert_eq!(j.category, Category::Junk(JunkKind::BuildPath));
        assert_eq!(j.confidence, Confidence::Strong);
        assert_eq!(j.severity, Severity::Notice);
        let m = j.marker.as_ref().unwrap();
        let lld_off = b.off(".comment") + GCC.len() as u64 + 1;
        assert_eq!(m.region, Region::new(lld_off, LLD.len() as u64));
        assert_eq!(m.removal, RemovalStrategy::RawBlank { fill: 0 });
        assert_eq!(m.container, ContainerKind::ElfSection);

        let id = one(&f, "elf.build_id");
        assert_eq!(id.category, Category::Integrity(SignatureStatus::Present));
        assert_eq!(id.confidence, Confidence::Strong);
        assert!(note(id).contains(&"ab".repeat(20)));

        let i = one(&f, "elf.interp");
        assert_eq!(i.category, Category::Brand(BrandKind::Toolchain));
        assert_eq!(i.confidence, Confidence::Moderate);
        assert_eq!(i.title, format!("Loader {INTERP}"));
        assert!(note(i).contains("glibc"));

        let r = one(&f, "elf.rpath");
        assert_eq!(r.category, Category::Junk(JunkKind::BuildPath));
        assert_eq!(r.confidence, Confidence::Strong);
        assert_eq!(r.severity, Severity::Notice);
        assert!(r.title.contains("DT_RUNPATH"));
        let str_off = b.off(".dynstr") + 11;
        let keep = "$ORIGIN/../lib".len() as u64;
        assert_eq!(
            r.marker.as_ref().unwrap().region,
            Region::new(str_off + keep, RUNPATH.len() as u64 - keep)
        );
        assert!(all(&f, "elf.go_buildid").is_empty());
    }
}

#[test]
fn markers_scrub_their_findings_and_keep_the_file_parsing() {
    for w in ALL {
        let b = build(w, &Opts::default());
        let before = run(&b.bytes);
        let marked: Vec<&Finding> = before.iter().filter(|x| x.marker.is_some()).collect();
        assert_eq!(marked.len(), 2);
        for finding in marked {
            let mut edited = b.bytes.clone();
            apply(&mut edited, finding.marker.as_ref().unwrap());
            let after = run(&edited);
            assert!(all(&after, &finding.signature_id).is_empty());
            assert_eq!(all(&after, "elf.comment").len(), 1);
            assert_eq!(all(&after, "elf.build_id").len(), 1);
            assert_eq!(all(&after, "elf.interp").len(), 1);
        }
        // The legitimate RUNPATH prefix survives the scrub.
        let mut edited = b.bytes.clone();
        apply(
            &mut edited,
            one(&before, "elf.rpath").marker.as_ref().unwrap(),
        );
        let at = (b.off(".dynstr") + 11) as usize;
        assert_eq!(cstr(&edited, at, 256), Some(&b"$ORIGIN/../lib"[..]));
    }
}

#[test]
fn go_note_and_symtab_are_reported() {
    for w in ALL {
        let b = build(
            w,
            &Opts {
                go: true,
                symtab: true,
                ..Opts::default()
            },
        );
        let f = run(&b.bytes);
        let go = one(&f, "elf.go_buildid");
        assert_eq!(go.category, Category::Brand(BrandKind::Toolchain));
        assert_eq!(go.confidence, Confidence::Strong);
        assert_eq!(go.title, "Go");
        assert!(note(go).contains("abc123/def456"));
        assert!(note(one(&f, "elf.comment")).contains(".symtab present (not stripped)"));
    }
}

#[test]
fn extended_section_numbering_is_followed() {
    for w in ALL {
        let b = build(
            w,
            &Opts {
                ext_numbering: true,
                ..Opts::default()
            },
        );
        let f = run(&b.bytes);
        assert_eq!(all(&f, "elf.comment").len(), 1);
        assert_eq!(all(&f, "elf.rpath").len(), 1);
    }
}

#[test]
fn leading_user_path_clears_the_whole_runpath() {
    let w = ALL[0];
    let b = build(
        w,
        &Opts {
            runpath: "/home/bob/lib:$ORIGIN",
            ..Opts::default()
        },
    );
    let f = run(&b.bytes);
    let r = one(&f, "elf.rpath");
    let str_off = b.off(".dynstr") + 11;
    assert_eq!(
        r.marker.as_ref().unwrap().region,
        Region::new(str_off, "/home/bob/lib:$ORIGIN".len() as u64)
    );
    assert!(note(r).contains("also clears the later entries $ORIGIN"));
}

#[test]
fn invalid_utf8_in_runpath_keeps_exact_byte_offsets() {
    let path = "?????:/home/eve/lib";
    let mut b = build(
        ALL[0],
        &Opts {
            runpath: path,
            ..Opts::default()
        },
    );
    let str_off = b.off(".dynstr") + 11;
    let at = str_off as usize;
    b.bytes[at..at + 5].fill(0xff);
    let f = run(&b.bytes);
    let m = one(&f, "elf.rpath").marker.clone().unwrap();
    assert_eq!(m.region, Region::new(str_off + 5, (path.len() - 5) as u64));

    let mut edited = b.bytes.clone();
    apply(&mut edited, &m);
    assert!(all(&run(&edited), "elf.rpath").is_empty());
    assert_eq!(&edited[at..at + 5], &[0xff; 5]);
}

#[test]
fn clean_runpath_and_comment_are_not_junk() {
    let b = build(
        ALL[0],
        &Opts {
            comment: vec![
                GCC,
                "clang version 17.0.6 (https://github.com/llvm/llvm-project 6009708b)",
            ],
            runpath: "$ORIGIN/../lib:/usr/lib/x86_64-linux-gnu",
            ..Opts::default()
        },
    );
    let f = run(&b.bytes);
    assert!(all(&f, "elf.comment.junk").is_empty());
    assert!(all(&f, "elf.rpath").is_empty());
    assert_eq!(all(&f, "elf.comment").len(), 1);
}

#[test]
fn path_heuristics() {
    assert!(names_user_path("/home/alice/lib"));
    assert!(names_user_path("/Users/alice/dev/app"));
    assert!(names_user_path("C:\\Users\\alice\\proj"));
    assert!(names_user_path("d:/work/out"));
    assert!(names_user_path("/tmp/build-1234/lib"));
    assert!(names_user_path("/srv/ci/build/lib"));
    assert!(!names_user_path("@executable_path/../Frameworks"));
    assert!(!names_user_path("$ORIGIN/../lib"));
    assert!(!names_user_path("/usr/lib/swift"));
    assert!(!names_user_path("version 1:2"));

    assert!(contains_fs_path(LLD));
    assert!(contains_fs_path("built in ~/src/thing"));
    assert!(contains_fs_path("from C:\\src\\x"));
    assert!(!contains_fs_path(GCC));
    assert!(!contains_fs_path(
        "GCC: (Ubuntu 11.4.0-1ubuntu1~22.04) 11.4.0"
    ));
    assert!(!contains_fs_path(
        "rustc version 1.75.0 (82e1608df 2023-12-21)"
    ));
    assert!(!contains_fs_path(
        "(https://github.com/llvm/llvm-project abc)"
    ));
    assert!(!contains_fs_path("and/or"));
}

#[test]
fn truncated_and_garbage_inputs_never_panic() {
    for w in ALL {
        let b = build(
            w,
            &Opts {
                go: true,
                symtab: true,
                ..Opts::default()
            },
        );
        let ehsize = if w.is64 { 64 } else { 52 };
        for len in 0..b.bytes.len() {
            let f = run(&b.bytes[..len]);
            if len < ehsize {
                assert!(f.is_empty(), "truncated at {len}: {f:#?}");
            }
        }
        let mut seed = 0x9e37_79b9_7f4a_7c15u64;
        for _ in 0..1500 {
            let mut m = b.bytes.clone();
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

    let mut seed = 0x2545_f491_4f6c_dd1du64;
    for i in 0..64 {
        let mut junk: Vec<u8> = (0..4096)
            .map(|_| {
                seed ^= seed << 13;
                seed ^= seed >> 7;
                seed ^= seed << 17;
                (seed >> 24) as u8
            })
            .collect();
        junk[..4].copy_from_slice(b"\x7fELF");
        let _ = run(&junk);
        // A bad class or byte order is not ELF at all.
        junk[4] = 3 + (i % 200) as u8;
        assert!(run(&junk).is_empty());
    }
    assert!(run(b"").is_empty());
    assert!(run(b"\x7fELF").is_empty());
}
