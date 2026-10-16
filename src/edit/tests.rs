//! Engine tests over real temp files, each with its own state dir via
//! `EditEngine::open_in`, so nothing touches the environment or user data.

use std::fs;
use std::path::{Path, PathBuf};

use tempfile::TempDir;

use super::engine::{EditEngine, EditError, INLINE_MAX};
use super::journal::{Fingerprint, UndoAction, UndoRecord};
use crate::model::{ContainerKind, Marker, Region, RemovalStrategy};

struct Env {
    state: TempDir,
    work: TempDir,
}

impl Env {
    fn new() -> Self {
        Self {
            state: tempfile::tempdir().unwrap(),
            work: tempfile::tempdir().unwrap(),
        }
    }

    fn engine(&self) -> EditEngine {
        EditEngine::open_in(self.state.path()).unwrap()
    }

    fn file(&self, name: &str, data: &[u8]) -> PathBuf {
        let p = self.work.path().join(name);
        fs::write(&p, data).unwrap();
        p
    }

    fn journal_text(&self) -> String {
        fs::read_to_string(self.state.path().join("undo-journal.jsonl")).unwrap_or_default()
    }

    /// Every file under the trash root (session folders excluded).
    fn trash_files(&self) -> Vec<PathBuf> {
        let mut out = Vec::new();
        let root = self.state.path().join("trash");
        if let Ok(rd) = fs::read_dir(&root) {
            for d in rd.flatten() {
                if let Ok(inner) = fs::read_dir(d.path()) {
                    out.extend(inner.flatten().map(|e| e.path()));
                }
            }
        }
        out
    }

    fn trash_sessions(&self) -> usize {
        fs::read_dir(self.state.path().join("trash"))
            .map(|rd| rd.count())
            .unwrap_or(0)
    }
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 + 3) as u8).collect()
}

fn blank(off: u64, len: u64) -> Marker {
    Marker::blank(Region::new(off, len), ContainerKind::Raw)
}

fn delete_marker() -> Marker {
    Marker {
        region: Region::new(0, 0),
        removal: RemovalStrategy::DeleteFile,
        container: ContainerKind::Generic,
        reversible: true,
    }
}

fn apply(e: &mut EditEngine, p: &Path, m: &Marker, size: u64) -> Result<super::Applied, EditError> {
    e.apply(p, m, None, size, None, true, "test.marker")
}

#[test]
fn blank_then_undo_restores_bytes() {
    let env = Env::new();
    let orig = data(200);
    let p = env.file("a.bin", &orig);
    let mut e = env.engine();
    let applied = apply(&mut e, &p, &blank(40, 20), 200).unwrap();
    let now = fs::read(&p).unwrap();
    assert!(now[40..60].iter().all(|&b| b == 0));
    assert_eq!(&now[..40], &orig[..40]);
    assert!(applied.path.is_absolute());
    assert!(!applied.path.to_string_lossy().starts_with(r"\\?\"));
    assert!(env.journal_text().contains("restore_bytes"));
    assert!(env.trash_files().is_empty(), "small blanks stay inline");

    assert_eq!(e.undo_last().unwrap(), 1);
    assert_eq!(fs::read(&p).unwrap(), orig);
    assert!(e.journal().records().unwrap().is_empty());
}

#[test]
fn large_blank_goes_through_trash_and_back() {
    let env = Env::new();
    let n = (INLINE_MAX as usize) * 3;
    let orig = data(n);
    let p = env.file("big.bin", &orig);
    let mut e = env.engine();
    let m = Marker {
        region: Region::new(32, INLINE_MAX * 2),
        removal: RemovalStrategy::RawBlank { fill: 0x20 },
        container: ContainerKind::Raw,
        reversible: true,
    };
    apply(&mut e, &p, &m, n as u64).unwrap();
    assert_eq!(env.trash_files().len(), 1);
    assert!(
        fs::read(&p).unwrap()[32..32 + INLINE_MAX as usize * 2]
            .iter()
            .all(|&b| b == 0x20)
    );
    assert_eq!(e.undo_last().unwrap(), 1);
    assert_eq!(fs::read(&p).unwrap(), orig);
    assert_eq!(env.trash_sessions(), 0, "no empty session folders left");
}

#[test]
fn truncate_then_undo() {
    let env = Env::new();
    let orig = data(1000);
    let p = env.file("t.bin", &orig);
    let mut e = env.engine();
    apply(
        &mut e,
        &p,
        &Marker::truncate_at(600, ContainerKind::Raw),
        1000,
    )
    .unwrap();
    assert_eq!(fs::read(&p).unwrap(), &orig[..600]);
    assert_eq!(e.undo_last().unwrap(), 1);
    assert_eq!(fs::read(&p).unwrap(), orig);
    assert_eq!(env.trash_sessions(), 0);
}

#[test]
fn truncate_refusals_record_nothing() {
    let env = Env::new();
    let p = env.file("t.bin", &data(100));
    let mut e = env.engine();
    for from in [0, 100, 150] {
        let r = apply(
            &mut e,
            &p,
            &Marker::truncate_at(from, ContainerKind::Raw),
            100,
        );
        assert!(
            matches!(r, Err(EditError::Refused(_))),
            "from {from}: {r:?}"
        );
    }
    assert!(env.journal_text().is_empty());
    assert_eq!(env.trash_sessions(), 0);
}

#[test]
fn truncate_undo_never_grows_past_the_original() {
    let env = Env::new();
    let orig = data(500);
    let p = env.file("t.bin", &orig);
    let mut e = env.engine();
    apply(
        &mut e,
        &p,
        &Marker::truncate_at(300, ContainerKind::Raw),
        500,
    )
    .unwrap();
    // Something appended after the edit: undo must refuse, not stack the tail.
    let mut grown = orig[..300].to_vec();
    grown.extend_from_slice(b"appended later");
    fs::write(&p, &grown).unwrap();
    assert!(matches!(e.undo_last(), Err(EditError::Changed)));
    assert_eq!(fs::read(&p).unwrap(), grown);
    assert_eq!(e.journal().records().unwrap().len(), 1, "record kept");
}

#[test]
fn delete_then_undo() {
    let env = Env::new();
    let orig = data(64);
    let p = env.file("gone.exe", &orig);
    let mut e = env.engine();
    apply(&mut e, &p, &delete_marker(), 64).unwrap();
    assert!(!p.exists());
    assert_eq!(env.trash_files().len(), 1);
    assert_eq!(e.undo_last().unwrap(), 1);
    assert_eq!(fs::read(&p).unwrap(), orig);
    assert_eq!(env.trash_sessions(), 0);
}

#[test]
fn delete_undo_refuses_to_clobber_a_new_file() {
    let env = Env::new();
    let p = env.file("gone.exe", &data(64));
    let mut e = env.engine();
    apply(&mut e, &p, &delete_marker(), 64).unwrap();
    fs::write(&p, b"someone else's new file").unwrap();
    assert!(matches!(e.undo_last(), Err(EditError::Changed)));
    assert_eq!(fs::read(&p).unwrap(), b"someone else's new file");
}

#[test]
fn group_of_three_undone_at_once() {
    let env = Env::new();
    let a = env.file("a.bin", &data(100));
    let b = env.file("b.bin", &data(100));
    let c = env.file("c.bin", &data(100));
    let mut e = env.engine();

    // An earlier, separate group that must survive.
    e.begin_group();
    apply(&mut e, &a, &blank(80, 4), 100).unwrap();

    let g = e.begin_group();
    let r1 = apply(&mut e, &a, &blank(20, 4), 100).unwrap();
    let r2 = apply(
        &mut e,
        &b,
        &Marker::truncate_at(50, ContainerKind::Raw),
        100,
    )
    .unwrap();
    let r3 = apply(&mut e, &c, &delete_marker(), 100).unwrap();
    assert!([r1.group, r2.group, r3.group].iter().all(|&x| x == g));

    let report = e.undo_last_report().unwrap();
    assert!(report.failure.is_none());
    assert_eq!(report.reverted, 3);
    assert_eq!(report.paths.len(), 3);
    assert_eq!(fs::read(&b).unwrap(), data(100));
    assert_eq!(fs::read(&c).unwrap(), data(100));
    let a_now = fs::read(&a).unwrap();
    assert_eq!(&a_now[20..24], &data(100)[20..24]);
    assert!(
        a_now[80..84].iter().all(|&x| x == 0),
        "older group untouched"
    );
    assert_eq!(e.journal().records().unwrap().len(), 1);

    assert_eq!(e.undo_all().unwrap(), 1);
    assert_eq!(fs::read(&a).unwrap(), data(100));
    assert_eq!(e.undo_last().unwrap(), 0);
}

#[test]
fn partial_undo_failure_leaves_a_consistent_journal() {
    let env = Env::new();
    let a = env.file("a.bin", &data(100));
    let b = env.file("b.bin", &data(100));
    let c = env.file("c.bin", &data(100));
    let mut e = env.engine();
    e.begin_group();
    let ra = apply(&mut e, &a, &blank(20, 4), 100).unwrap();
    let rb = apply(&mut e, &b, &blank(20, 4), 100).unwrap();
    let rc = apply(&mut e, &c, &blank(20, 4), 100).unwrap();

    // b changes after the edit; undo runs c, then stops at b.
    let mut tampered = fs::read(&b).unwrap();
    tampered[21] = 0xAA;
    fs::write(&b, &tampered).unwrap();

    let report = e.undo_last_report().unwrap();
    assert!(matches!(report.failure, Some(EditError::Changed)));
    assert_eq!(report.reverted, 1);
    assert_eq!(fs::read(&c).unwrap(), data(100));
    assert_eq!(fs::read(&b).unwrap(), tampered, "b untouched");

    let ids: Vec<u64> = e
        .journal()
        .records()
        .unwrap()
        .iter()
        .map(|r| r.id)
        .collect();
    assert_eq!(
        ids,
        vec![ra.undo_id, rb.undo_id],
        "c's record is gone, a and b remain"
    );
    assert!(!rc.path.as_os_str().is_empty());
    assert!(
        !env.journal_text().contains("undone"),
        "compacted after the run"
    );

    // Put b back the way the edit left it; the rest of the group undoes.
    tampered[21] = 0;
    fs::write(&b, &tampered).unwrap();
    assert_eq!(e.undo_last().unwrap(), 2);
    assert_eq!(fs::read(&a).unwrap(), data(100));
    assert_eq!(fs::read(&b).unwrap(), data(100));
}

#[test]
fn corrupt_journal_lines_survive_and_are_reported() {
    let env = Env::new();
    let p = env.file("a.bin", &data(100));
    {
        let mut e = env.engine();
        apply(&mut e, &p, &blank(30, 4), 100).unwrap();
    }
    let jpath = env.state.path().join("undo-journal.jsonl");
    let mut text = fs::read(&jpath).unwrap();
    text.extend_from_slice(b"this is not json\n");
    text.extend_from_slice(&[0xff, 0xfe, b'{', b'\n']);
    fs::write(&jpath, &text).unwrap();

    let mut e = env.engine();
    assert_eq!(e.unparsed_journal_lines().unwrap(), 2);
    let report = e.undo_last_report().unwrap();
    assert_eq!(report.reverted, 1);
    assert_eq!(report.unparsed_lines, 2);
    let after = fs::read(&jpath).unwrap();
    assert!(
        after.windows(16).any(|w| w == b"this is not json"),
        "garbage kept verbatim"
    );
    assert!(after.windows(3).any(|w| w == [0xff, 0xfe, b'{']));
    assert!(e.journal().records().unwrap().is_empty());
}

#[test]
fn changed_on_size_or_hash_mismatch() {
    let env = Env::new();
    let orig = data(100);
    let p = env.file("a.bin", &orig);
    let mut e = env.engine();
    let m = blank(10, 4);
    assert!(matches!(apply(&mut e, &p, &m, 99), Err(EditError::Changed)));

    let good = crate::util::hash::hash_hex(&orig[10..14]);
    let bad = crate::util::hash::hash_hex(b"nope");
    let r = e.apply(&p, &m, None, 100, Some(&bad), true, "x");
    assert!(matches!(r, Err(EditError::Changed)));
    let t = Marker::truncate_at(60, ContainerKind::Raw);
    let r = e.apply(&p, &t, None, 100, Some(&bad), true, "x");
    assert!(
        matches!(r, Err(EditError::Changed)),
        "truncate checks the dropped tail"
    );
    assert_eq!(fs::read(&p).unwrap(), orig, "nothing changed");
    assert!(env.journal_text().is_empty(), "nothing recorded");

    e.apply(&p, &m, None, 100, Some(&good), true, "x").unwrap();
    let tail = crate::util::hash::hash_hex(&orig[60..]);
    e.apply(&p, &t, None, 100, Some(&tail), true, "x").unwrap();
    assert_eq!(fs::read(&p).unwrap().len(), 60);
}

#[test]
fn warn_needs_force_and_refuse_never_applies() {
    let env = Env::new();
    let p = env.file("a.bin", &data(100));
    let mut e = env.engine();
    let r = e.apply(&p, &delete_marker(), None, 100, None, false, "x");
    assert!(matches!(r, Err(EditError::NeedsForce(_))));
    let r = e.apply(&p, &blank(4, 4), Some("png"), 100, None, true, "x");
    assert!(matches!(r, Err(EditError::Refused(_))));
    assert!(p.exists());
    assert!(env.journal_text().is_empty());
}

#[test]
fn structural_without_a_remover_changes_nothing() {
    let env = Env::new();
    let orig = data(100);
    let p = env.file("a.zip", &orig);
    let mut e = env.engine();
    let m = Marker {
        region: Region::new(90, 10),
        removal: RemovalStrategy::StructuralRemove,
        container: ContainerKind::Raw,
        reversible: true,
    };
    let r = e.apply(&p, &m, Some("zip"), 100, None, true, "x");
    assert!(matches!(r, Err(EditError::Unsupported(_))));
    assert_eq!(fs::read(&p).unwrap(), orig);
    assert!(env.journal_text().is_empty());
    assert_eq!(env.trash_sessions(), 0);
}

#[test]
fn crash_between_journal_and_mutate_is_dropped_on_undo() {
    let env = Env::new();
    let orig = data(100);
    let p = env.file("a.bin", &orig);
    let mut e = env.engine();
    // A real edit first, so the session and journal exist.
    apply(&mut e, &p, &blank(50, 4), 100).unwrap();
    // Then a record whose edit "never happened": bytes 10..14 still original.
    let canon = fs::canonicalize(&p).unwrap();
    let canon = super::fsio::clean_path(canon);
    let rec = UndoRecord {
        id: 99,
        group: 99,
        ts: 0,
        path: canon,
        label: "crashed".into(),
        action: UndoAction::RestoreBytes {
            offset: 10,
            bytes_hex: super::fsio::to_hex(&orig[10..14]),
        },
        before: Some(Fingerprint::span(
            100,
            10,
            4,
            crate::util::hash::hash_hex(&orig[10..14]),
        )),
        after: Some(Fingerprint::span(
            100,
            10,
            4,
            crate::util::hash::hash_hex(&[0; 4]),
        )),
    };
    e.journal().append(&rec).unwrap();

    let report = e.undo_last_report().unwrap();
    assert!(report.failure.is_none());
    assert_eq!(report.reverted, 0);
    assert_eq!(report.never_landed, 1);
    assert_eq!(e.undo_last().unwrap(), 1);
    assert_eq!(fs::read(&p).unwrap(), orig);
}

#[test]
fn records_pointing_outside_the_trash_are_refused() {
    let env = Env::new();
    let p = env.file("a.bin", &data(100));
    let e0 = env.engine();
    let outside = env.work.path().join("evil.bin");
    fs::write(&outside, b"x").unwrap();
    let rec = UndoRecord {
        id: 1,
        group: 1,
        ts: 0,
        path: super::fsio::clean_path(fs::canonicalize(&p).unwrap()),
        label: "bad".into(),
        action: UndoAction::RestoreSnapshot {
            trash_path: super::fsio::clean_path(fs::canonicalize(&outside).unwrap()),
        },
        before: None,
        after: None,
    };
    e0.journal().append(&rec).unwrap();
    let mut rel = rec.clone();
    rel.id = 2;
    rel.group = 2;
    rel.path = PathBuf::from("relative/a.bin");
    e0.journal().append(&rel).unwrap();
    drop(e0);

    let mut e = env.engine();
    assert!(
        matches!(e.undo_last(), Err(EditError::Refused(_))),
        "relative path"
    );
    assert!(matches!(e.undo_all(), Err(EditError::Refused(_))));
    assert_eq!(fs::read(&p).unwrap(), data(100));
    assert_eq!(e.journal().records().unwrap().len(), 2, "nothing dropped");
}

#[test]
fn legacy_records_still_undo() {
    let env = Env::new();
    let orig = data(100);
    let p = env.file("a.bin", &orig);
    let mut blanked = orig.clone();
    blanked[10..14].fill(0);
    fs::write(&p, &blanked).unwrap();
    let canon = super::fsio::clean_path(fs::canonicalize(&p).unwrap());
    let line = serde_json::json!({
        "id": 1, "group": 1, "ts": 0, "path": canon, "label": "old",
        "action": {"action": "restore_bytes", "offset": 10, "bytes_hex": super::fsio::to_hex(&orig[10..14])}
    });
    fs::write(
        env.state.path().join("undo-journal.jsonl"),
        format!("{line}\n"),
    )
    .unwrap();
    let mut e = env.engine();
    assert_eq!(e.undo_last().unwrap(), 1);
    assert_eq!(fs::read(&p).unwrap(), orig);
}

#[test]
fn external_edit_is_recorded_only_when_bytes_change() {
    let env = Env::new();
    let p = env.file("notes.txt", b"hello");
    let mut e = env.engine();

    assert!(e.open_with(&p, |_| Ok(())).unwrap().is_none());
    assert!(e.journal().records().unwrap().is_empty());
    assert!(env.trash_files().is_empty());

    let applied = e
        .open_with(&p, |path| fs::write(path, b"hello, edited"))
        .unwrap()
        .expect("change recorded");
    assert_eq!(applied.label, "external edit");
    let recs = e.journal().records().unwrap();
    assert_eq!(recs.len(), 1);
    assert!(recs[0].after.is_some());

    let failed = e.open_with(&p, |_| Err(std::io::Error::other("editor crashed")));
    assert!(matches!(failed, Err(EditError::Io(_))));
    assert_eq!(e.journal().records().unwrap().len(), 1);

    assert_eq!(e.undo_last().unwrap(), 1);
    assert_eq!(fs::read(&p).unwrap(), b"hello");
    assert_eq!(env.trash_sessions(), 0);
}

#[test]
fn lock_contention_between_engines() {
    let env = Env::new();
    let p = env.file("a.bin", &data(100));
    let mut a = env.engine();
    let mut b = env.engine();
    apply(&mut a, &p, &blank(10, 2), 100).unwrap();
    assert!(a.holds_lock());
    match apply(&mut b, &p, &blank(20, 2), 100) {
        Err(EditError::Locked(who)) => assert!(who.contains("pid")),
        other => panic!("expected Locked, got {other:?}"),
    }
    assert!(matches!(b.undo_last(), Err(EditError::Locked(_))));
    drop(a);
    assert_eq!(b.undo_last().unwrap(), 1, "free once the holder is gone");
    assert_eq!(fs::read(&p).unwrap(), data(100));
}

#[test]
fn ids_and_groups_continue_across_engines() {
    let env = Env::new();
    let p = env.file("a.bin", &data(100));
    let first = {
        let mut e = env.engine();
        e.begin_group();
        apply(&mut e, &p, &blank(10, 2), 100).unwrap()
    };
    let mut e = env.engine();
    e.begin_group();
    let second = apply(&mut e, &p, &blank(20, 2), 100).unwrap();
    assert!(second.undo_id > first.undo_id);
    assert!(second.group > first.group);
    assert_eq!(e.undo_last().unwrap(), 1, "only the newest group");
}

#[cfg(unix)]
#[test]
fn symlinks_are_refused() {
    let env = Env::new();
    let real = env.file("real.bin", &data(100));
    let link = env.work.path().join("link.bin");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let mut e = env.engine();
    let r = apply(&mut e, &link, &blank(10, 2), 100);
    assert!(matches!(r, Err(EditError::Symlink(_))));
    assert_eq!(fs::read(&real).unwrap(), data(100));
    assert!(matches!(
        e.open_with(&link, |_| Ok(())),
        Err(EditError::Symlink(_))
    ));
}

// ---------------------------------------------------------------------------
// Deattributed copies: no state store, the original is only read.

fn credit(off: u64, len: u64, original: &[u8]) -> super::deattribute::Target {
    let span = &original[off as usize..(off + len) as usize];
    super::deattribute::Target {
        kind: super::deattribute::Kind::Patch,
        marker: blank(off, len),
        expected_hash: crate::util::hash::hash_hex(span),
    }
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn deattributed_copy_blanks_targets_and_never_touches_the_original() {
    use super::deattribute::write_deattributed;
    let env = Env::new();
    let original = data(300);
    let p = env.file("setup-tool.exe", &original);
    let mtime = fs::metadata(&p).unwrap().modified().unwrap();
    let targets = [credit(10, 5, &original), credit(200, 20, &original)];

    let out = write_deattributed(&p, None, 300, &targets).unwrap();
    assert_eq!(out, env.work.path().join("setup-tool.deattributed.exe"));
    let copy = fs::read(&out).unwrap();
    let mut want = original.clone();
    want[10..15].fill(0);
    want[200..220].fill(0);
    assert_eq!(copy, want);
    assert_eq!(fs::read(&p).unwrap(), original, "original bytes unchanged");
    assert_eq!(fs::metadata(&p).unwrap().modified().unwrap(), mtime);
    assert_eq!(
        names_in(env.work.path()),
        vec!["setup-tool.deattributed.exe", "setup-tool.exe"],
        "no temp file left behind"
    );
    assert_eq!(env.trash_sessions(), 0, "no state store used");
    assert!(env.journal_text().is_empty());
}

#[test]
fn deattributed_copy_replaces_an_older_copy() {
    use super::deattribute::write_deattributed;
    let env = Env::new();
    let original = data(100);
    let p = env.file("report.pdf", &original);
    let old = env.file("report.deattributed.pdf", b"an older copy");
    let out = write_deattributed(&p, None, 100, &[credit(40, 4, &original)]).unwrap();
    assert_eq!(out, old);
    assert_eq!(fs::read(&out).unwrap().len(), 100);
    let again = write_deattributed(&p, None, 100, &[credit(40, 4, &original)]).unwrap();
    assert_eq!(again, old);
    assert_eq!(
        names_in(env.work.path()),
        vec!["report.deattributed.pdf", "report.pdf"],
        "replaced, never stacked"
    );
}

#[test]
fn deattributed_copy_skips_a_changed_original_without_leftovers() {
    use super::deattribute::write_deattributed;
    let env = Env::new();
    let original = data(100);
    let p = env.file("a.bin", &original);
    let old = env.file("a.deattributed.bin", b"keep me");
    let mut stale = credit(40, 4, &original);
    stale.expected_hash = crate::util::hash::hash_hex(b"nope");
    assert!(matches!(
        write_deattributed(&p, None, 100, &[stale]),
        Err(EditError::Changed)
    ));
    assert!(matches!(
        write_deattributed(&p, None, 99, &[credit(40, 4, &original)]),
        Err(EditError::Changed)
    ));
    assert_eq!(fs::read(&old).unwrap(), b"keep me", "older copy untouched");
    assert_eq!(
        names_in(env.work.path()),
        vec!["a.bin", "a.deattributed.bin"]
    );
    assert_eq!(fs::read(&p).unwrap(), original);
}

#[test]
fn deattributed_copy_refusals_write_nothing() {
    use super::deattribute::write_deattributed;
    let env = Env::new();
    let original = data(100);
    let p = env.file("a.bin", &original);
    let refused = |r: Result<PathBuf, EditError>| matches!(r, Err(EditError::Refused(_)));
    assert!(refused(write_deattributed(&p, None, 100, &[])));
    assert!(refused(write_deattributed(
        &p,
        None,
        100,
        &[credit(0, 4, &original)]
    )));
    let copy = env.file("b.deattributed.bin", &original);
    assert!(refused(write_deattributed(
        &copy,
        None,
        100,
        &[credit(40, 4, &original)]
    )));
    fs::create_dir(env.work.path().join("c.deattributed.bin")).unwrap();
    let c = env.file("c.bin", &original);
    assert!(refused(write_deattributed(
        &c,
        None,
        100,
        &[credit(40, 4, &original)]
    )));
    assert_eq!(
        names_in(env.work.path()),
        vec!["a.bin", "b.deattributed.bin", "c.bin", "c.deattributed.bin"]
    );
}
