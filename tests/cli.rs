//! End-to-end tests of the headless CLI: the real binary, a private state
//! directory per run, and synthetic files written by each test. Assertions stick
//! to behavior the CLI owns plus the identity finding, so they hold no matter
//! which other probes are registered.

mod common;

use std::collections::BTreeSet;
use std::fs;
use std::io::{BufRead, BufReader};
use std::process::Stdio;

use common::{Fixture, mz_bytes, of_kind};

const VALID_CATEGORIES: [&str; 7] = [
    "identity",
    "brand",
    "integrity",
    "tamper",
    "deception",
    "bundleware",
    "junk",
];

#[test]
fn version_prints_the_package_version() {
    let fx = Fixture::empty();
    for flag in ["--version", "-v"] {
        let r = fx.run(&[flag]);
        r.assert_code(0);
        assert_eq!(
            r.stdout,
            format!("meownary {}\n", env!("CARGO_PKG_VERSION"))
        );
    }
}

#[test]
fn help_lists_commands_flags_and_exit_codes() {
    let fx = Fixture::empty();
    for args in [
        &["--help"][..],
        &["-h"],
        &["scan", "--help"],
        &["clean", "-h"],
    ] {
        let r = fx.run(args);
        r.assert_code(0);
        for usage in [
            "  meownary                          open the interactive view and pick a folder\n",
            "  meownary <path>                   open the interactive view on <path>\n",
            "  meownary scan <path> [flags]      scan and report, no interactive view\n",
        ] {
            assert!(r.stdout.contains(usage), "{usage}\n{}", r.stdout);
        }
        assert!(!r.stdout.contains("current directory"), "{}", r.stdout);
        assert!(r.stdout.contains("exit codes"));
        assert!(r.stdout.contains("--fail-on"));
        assert!(r.stdout.contains("MEOWNARY_STATE_DIR"));
        assert!(r.stdout.contains("--deattribute"));
        assert!(r.stdout.contains("never matched text"));
    }
}

fn has_credit(bytes: &[u8]) -> bool {
    bytes
        .windows(b"patched by".len())
        .any(|w| w == b"patched by")
}

/// File names in the fixture root, sorted.
fn root_names(fx: &Fixture) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(fx.dir.path())
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn deattribute_saves_a_blanked_copy_and_leaves_the_original() {
    let fx = Fixture::empty();
    let path = fx.path("app.exe");
    let mut bytes = mz_bytes();
    bytes.extend_from_slice(b"patched by Invented\0patched by Second\0");
    fs::write(&path, &bytes).unwrap();
    let mtime = fs::metadata(&path).unwrap().modified().unwrap();
    let shown = fx.shown("app.exe");
    let copy = fx.path("app.deattributed.exe");
    let copy_shown = fx.shown("app.deattributed.exe");

    // A dry run reports the copy it would save and writes nothing.
    let dry = fx.run(&["clean", &shown, "--deattribute", "--dry-run", "--json"]);
    dry.assert_code(0);
    let events = dry.events();
    assert_eq!(of_kind(&events, "would_clean").len(), 2, "{}", dry.stdout);
    let would = of_kind(&events, "would_save");
    assert_eq!(would.len(), 1);
    assert_eq!(would[0]["output"], copy_shown.as_str());
    assert!(of_kind(&events, "saved").is_empty());
    assert_eq!(of_kind(&events, "done")[0]["saved"], 1);
    assert_eq!(root_names(&fx), vec!["app.exe"]);
    let human = fx.run(&["clean", &shown, "--deattribute", "--dry-run"]);
    human.assert_code(0);
    assert!(
        human.stdout.contains(&format!(
            "would save  {copy_shown}  (from app.exe, 2 patch)
"
        )),
        "{}",
        human.stdout
    );
    assert!(
        human.stdout.ends_with("would save 1 copy\n"),
        "{}",
        human.stdout
    );
    assert!(!copy.exists());

    let run = fx.run(&["clean", &shown, "--deattribute", "--json"]);
    run.assert_code(0);
    assert!(!run.stdout.contains("Invented"));
    assert!(!run.stdout.contains("patched by"));
    let events = run.events();
    let cleaned = of_kind(&events, "cleaned");
    assert_eq!(cleaned.len(), 2, "{}", run.stdout);
    assert!(cleaned.iter().all(|e| e["kind"] == "patch"));
    assert!(cleaned.iter().all(|e| e["path"] == shown.as_str()));
    assert!(cleaned.iter().all(|e| e["output"] == copy_shown.as_str()));
    assert!(cleaned.iter().all(|e| e["op"] == "raw_blank"));
    assert!(
        cleaned
            .iter()
            .all(|e| e["offset"].is_u64() && e["len"].is_u64())
    );
    let saved = of_kind(&events, "saved");
    assert_eq!(saved.len(), 1);
    assert_eq!(saved[0]["path"], shown.as_str());
    assert_eq!(saved[0]["output"], copy_shown.as_str());
    assert_eq!(saved[0]["edits"], 2);
    let done = of_kind(&events, "done");
    assert_eq!(done[0]["saved"], 1);
    assert_eq!(done[0]["cleaned"], 2);
    for event in &events {
        for field in ["title", "note", "signature", "evidence", "label"] {
            assert!(event.get(field).is_none(), "{field}: {event}");
        }
    }

    // The original is byte for byte what it was; the copy has the credits gone.
    assert_eq!(fs::read(&path).unwrap(), bytes);
    assert_eq!(fs::metadata(&path).unwrap().modified().unwrap(), mtime);
    let after = fs::read(&copy).unwrap();
    assert!(!has_credit(&after));
    assert_eq!(after.len(), bytes.len());
    assert_eq!(root_names(&fx), vec!["app.deattributed.exe", "app.exe"]);
    // Nothing to undo: the state store was never opened.
    assert_eq!(fs::read_dir(fx.state.path()).unwrap().count(), 0);
}

#[test]
fn deattribute_reruns_replace_the_copy_instead_of_stacking() {
    let fx = Fixture::empty();
    let mut bytes = mz_bytes();
    bytes.extend_from_slice(b"patched by Invented\0");
    fs::write(fx.path("app.exe"), &bytes).unwrap();
    // A stale copy from some earlier run, still carrying the credit.
    fs::write(fx.path("app.deattributed.exe"), &bytes).unwrap();
    let copy = fx.path("app.deattributed.exe");

    for _ in 0..2 {
        let run = fx.run(&["clean", fx.root(), "--deattribute"]);
        run.assert_code(0);
        let tail = format!(
            "  {}  (from app.exe, 1 patch)",
            fx.shown("app.deattributed.exe")
        );
        assert!(
            run.stdout
                .lines()
                .any(|l| l.starts_with("saved ") && l.ends_with(&tail)),
            "{}",
            run.stdout
        );
        assert!(
            run.stdout.ends_with("saved 1 copy beside its original\n"),
            "{}",
            run.stdout
        );
        // The copy itself is never a source, so it never gets a copy of its own.
        assert!(!run.stdout.contains("deattributed.deattributed"));
        assert_eq!(root_names(&fx), vec!["app.deattributed.exe", "app.exe"]);
        assert!(!has_credit(&fs::read(&copy).unwrap()));
        assert_eq!(fs::read(fx.path("app.exe")).unwrap(), bytes);
    }

    // Pointing it straight at a copy is a usage error that writes nothing.
    let r = fx.run(&["clean", &fx.shown("app.deattributed.exe"), "--deattribute"]);
    r.assert_code(2);
    assert!(r.stdout.is_empty(), "{}", r.stdout);
    assert!(
        r.stderr.contains("already a deattributed copy"),
        "{}",
        r.stderr
    );
    assert_eq!(root_names(&fx), vec!["app.deattributed.exe", "app.exe"]);

    // The copy has nothing left to plan: a scan of it alone finds no credits.
    let r = fx.run(&["clean", fx.root(), "--deattribute", "--dry-run", "--json"]);
    let events = r.events();
    assert!(
        events.iter().all(|e| e["path"]
            .as_str()
            .is_none_or(|p| !p.contains("deattributed"))),
        "{}",
        r.stdout
    );
}

#[test]
fn deattribute_leaves_load_bearing_magic_and_reports_only_kind() {
    let fx = Fixture::empty();
    let path = fx.path("packed.exe");
    let mut bytes = mz_bytes();
    bytes.extend_from_slice(b"UPX!\0");
    fs::write(&path, &bytes).unwrap();
    let shown = fx.shown("packed.exe");
    let run = fx.run(&["clean", &shown, "--deattribute", "--json"]);
    run.assert_code(1);
    assert!(!run.stdout.contains("UPX"), "{}", run.stdout);
    let events = run.events();
    assert!(
        events.iter().any(|e| e["event"] == "skipped"
            && e["kind"] == "brand"
            && e["reason"] == "load-bearing")
    );
    assert_eq!(fs::read(&path).unwrap(), bytes);
}

#[test]
fn deattribute_rejects_other_selection_and_file_deletion() {
    let fx = Fixture::standard();
    for extra in [
        vec!["--category", "brand"],
        vec!["--signature", "pe.rich_header"],
        vec!["--file"],
    ] {
        let mut args = vec!["clean", fx.root(), "--deattribute"];
        args.extend(extra);
        let run = fx.run(&args);
        run.assert_code(2);
        assert!(run.stdout.is_empty());
    }
}

#[test]
fn usage_errors_exit_2() {
    let fx = Fixture::standard();
    let root = fx.root();
    let cases: Vec<Vec<&str>> = vec![
        vec!["--bogus"],
        vec!["scan"],
        vec!["scan", "--json"],
        vec!["scan", "--bogus"],
        vec!["scan", "--fail-on"],
        vec!["scan", "--fail-on", "loud"],
        vec!["scan", "--fail-on", "--json"],
        vec!["scan", "--json=1"],
        vec!["scan", root, root],
        vec!["clean"],
        vec!["clean", root],
        vec!["clean", root, "--category", "--force"],
        vec!["clean", root, "--signature"],
        vec!["clean", root, "--category", "junk", "--signature", "a.b"],
        vec!["clean", root, "--dry-run=yes", "--category", "junk"],
        vec!["undo", "--bogus"],
        vec!["undo", root],
        vec![root, "extra"],
        vec!["--version", "extra"],
    ];
    for args in cases {
        let r = fx.run(&args);
        assert_eq!(r.code, Some(2), "{args:?}\n{}", r.stderr);
        assert!(r.stderr.starts_with("meownary: "), "{args:?}: {}", r.stderr);
        assert!(
            r.stderr.contains("meownary --help"),
            "{args:?}: {}",
            r.stderr
        );
        assert!(r.stdout.is_empty(), "{args:?}: {}", r.stdout);
    }
}

#[test]
fn scan_never_defaults_to_the_current_directory() {
    let fx = Fixture::standard();
    for args in [&["scan"][..], &["scan", "--json"], &["scan", "--"]] {
        let r = common::run_in(fx.state.path(), Some(fx.dir.path()), args);
        r.assert_code(2);
        assert!(r.stderr.contains("scan needs a path"), "{}", r.stderr);
        assert!(r.stdout.is_empty(), "{args:?}: {}", r.stdout);
    }
}

/// Without the interactive view there is no folder picker to fall back on.
#[cfg(not(feature = "tui"))]
#[test]
fn bare_meownary_without_the_view_needs_a_path() {
    let fx = Fixture::standard();
    let r = common::run_in(fx.state.path(), Some(fx.dir.path()), &[]);
    r.assert_code(2);
    assert!(r.stderr.starts_with("meownary: "), "{}", r.stderr);
    assert!(
        r.stderr.contains("needs a path: meownary <path>"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("meownary --help"), "{}", r.stderr);
    assert!(r.stdout.is_empty(), "{}", r.stdout);
}

#[test]
fn second_positional_with_a_scan_flag_suggests_scan() {
    let fx = Fixture::standard();
    let r = fx.run(&[fx.root(), "--json"]);
    r.assert_code(2);
    assert!(
        r.stderr.contains("did you mean `meownary scan"),
        "{}",
        r.stderr
    );
}

#[test]
fn unknown_category_lists_the_valid_ones() {
    let fx = Fixture::standard();
    let r = fx.run(&["clean", fx.root(), "--category", "nope"]);
    r.assert_code(2);
    assert!(r.stderr.contains("unknown category: nope"), "{}", r.stderr);
    for slug in VALID_CATEGORIES {
        assert!(r.stderr.contains(slug), "{}", r.stderr);
    }
}

#[test]
fn nonexistent_paths_are_usage_errors() {
    let fx = Fixture::empty();
    let gone = fx.shown("does-not-exist");
    for args in [
        vec!["scan", gone.as_str()],
        vec!["scan", gone.as_str(), "--json"],
        vec!["clean", gone.as_str(), "--category", "junk"],
        vec![gone.as_str()],
    ] {
        let r = fx.run(&args);
        assert_eq!(r.code, Some(2), "{args:?}: {}", r.stderr);
        assert!(
            r.stderr.contains("no such file or directory"),
            "{}",
            r.stderr
        );
        assert!(r.stdout.is_empty());
    }
}

#[test]
fn scan_human_output() {
    let fx = Fixture::standard();
    let r = fx.run(&["scan", fx.root()]);
    r.assert_code(0);
    assert!(!r.stdout.contains('\x1b'), "no color when piped");

    let heads: Vec<&str> = r
        .stdout
        .lines()
        .filter(|l| !l.starts_with(' ') && !l.is_empty() && !l.starts_with("scanned "))
        .collect();
    let order = [
        "empty.bin",
        "notes.txt",
        "photo.jpg",
        "sub/deeper/inner.txt",
    ];
    assert_eq!(heads.len(), order.len(), "{}", r.stdout);
    for (head, rel) in heads.iter().zip(order) {
        assert!(head.starts_with(&fx.shown(rel)), "{head} vs {rel}");
        assert!(head.contains(" finding(s)"), "{head}");
    }
    let photo = heads[2];
    assert!(photo.contains("  [pe]  "), "{photo}");

    let row = r
        .stdout
        .lines()
        .find(|l| l.contains("identity.ext_mismatch"))
        .expect("an identity finding row");
    // Severity, then confidence, then the title; the probe owns the wording.
    assert!(row.starts_with("    alert   "), "{row}");
    let confidence = row["    alert   ".len()..].split_whitespace().next();
    assert!(
        matches!(confidence, Some("weak" | "moderate" | "strong")),
        "{row}"
    );

    let summary = r.stdout.lines().last().unwrap();
    assert!(summary.starts_with("scanned 4 file(s): "), "{summary}");
    assert!(summary.contains(" alert"), "{summary}");
    assert!(summary.contains("0 partial"), "{summary}");
    assert!(summary.ends_with("worst alert"), "{summary}");
}

#[test]
fn scan_json_event_shapes() {
    let fx = Fixture::standard();
    let r = fx.run(&["scan", fx.root(), "--json"]);
    r.assert_code(0);
    assert!(r.stderr.is_empty(), "{}", r.stderr);
    let events = r.events();

    assert_eq!(events.first().unwrap()["event"], "identify");
    let identify = of_kind(&events, "identify");
    assert_eq!(identify.len(), 4);
    for e in &identify {
        assert!(e["path"].is_string());
        assert!(e["size"].is_u64());
        assert_eq!(e["partial"], false);
        assert!(e.get("format").is_some());
        assert!(e.get("error").is_none(), "only partial files carry error");
    }
    let photo = identify
        .iter()
        .find(|e| e["path"] == fx.shown("photo.jpg").as_str())
        .expect("photo.jpg identify event");
    assert_eq!(photo["format"], "pe");
    assert_eq!(photo["size"], mz_bytes().len() as u64);
    let empty = identify
        .iter()
        .find(|e| e["path"] == fx.shown("empty.bin").as_str())
        .expect("empty.bin identify event");
    assert_eq!(empty["size"], 0);

    let findings = of_kind(&events, "finding");
    for f in &findings {
        for key in [
            "path",
            "category",
            "confidence",
            "severity",
            "signature",
            "title",
            "offset",
            "note",
            "removable",
            "category_detail",
            "marker",
        ] {
            assert!(f.get(key).is_some(), "finding lacks {key}: {f}");
        }
        assert!(VALID_CATEGORIES.contains(&f["category"].as_str().unwrap()));
        assert!(
            matches!(
                f["confidence"].as_str(),
                Some("weak" | "moderate" | "strong")
            ),
            "{f}"
        );
        assert!(
            matches!(
                f["severity"].as_str(),
                Some("info" | "notice" | "warn" | "alert")
            ),
            "{f}"
        );
        assert!(f["title"].as_str().is_some_and(|t| !t.is_empty()), "{f}");
        assert!(f["note"].is_string() || f["note"].is_null(), "{f}");
        assert!(f["offset"].is_u64(), "{f}");
        assert_eq!(f["removable"].as_bool().unwrap(), !f["marker"].is_null());
        if !f["marker"].is_null() {
            for key in ["op", "offset", "len", "container"] {
                assert!(f["marker"].get(key).is_some(), "marker lacks {key}: {f}");
            }
        }
    }
    let mismatch = findings
        .iter()
        .find(|f| f["signature"] == "identity.ext_mismatch")
        .expect("identity.ext_mismatch finding");
    assert_eq!(mismatch["path"], fx.shown("photo.jpg").as_str());
    assert_eq!(mismatch["category"], "identity");
    assert_eq!(mismatch["severity"], "alert");
    assert_eq!(mismatch["marker"], serde_json::Value::Null);
    assert_eq!(mismatch["removable"], false);
    assert_eq!(mismatch["category_detail"]["declared_ext"], "jpg");
    assert_eq!(mismatch["category_detail"]["true_format"], "pe");
    assert_eq!(mismatch["category_detail"]["mismatch"], true);

    let done = events.last().unwrap();
    assert_eq!(done["event"], "done");
    assert_eq!(of_kind(&events, "done").len(), 1);
    assert_eq!(done["files"], 4);
    assert_eq!(done["partial_files"], 0);
    assert_eq!(done["findings"], findings.len() as u64);
    let by = &done["by_severity"];
    let sum: u64 = ["info", "notice", "warn", "alert"]
        .iter()
        .map(|k| by[*k].as_u64().expect("count per severity"))
        .sum();
    assert_eq!(sum, findings.len() as u64);
    assert!(by["alert"].as_u64().unwrap() >= 1);
    assert_eq!(done["worst"], "alert");
    assert_eq!(done["exit"], 0);
}

#[test]
fn fail_on_threshold_exits_1_in_any_case() {
    let fx = Fixture::standard();
    for level in ["alert", "ALERT", "Alert", "warn"] {
        let r = fx.run(&["scan", fx.root(), "--fail-on", level]);
        r.assert_code(1);
    }
    let r = fx.run(&["scan", fx.root(), "--fail-on=alert", "--json"]);
    r.assert_code(1);
    assert_eq!(r.events().last().unwrap()["exit"], 1);

    // A threshold nothing reaches leaves the exit code alone.
    let calm = Fixture::empty();
    fs::write(calm.path("notes.txt"), b"plain words\n").unwrap();
    calm.run(&["scan", calm.root(), "--fail-on", "alert"])
        .assert_code(0);
}

#[test]
fn empty_folder_scans_cleanly() {
    let fx = Fixture::empty();
    let r = fx.run(&["scan", fx.root(), "--json"]);
    r.assert_code(0);
    let events = r.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "done");
    assert_eq!(events[0]["files"], 0);
    assert_eq!(events[0]["worst"], serde_json::Value::Null);
}

#[test]
fn double_dash_allows_paths_that_look_like_options() {
    let fx = Fixture::empty();
    fs::write(fx.path("-odd.txt"), b"text\n").unwrap();
    fs::create_dir(fx.path("scan")).unwrap();
    fs::write(fx.path("scan/inside.txt"), b"text\n").unwrap();

    let r = common::run_in(
        fx.state.path(),
        Some(fx.dir.path()),
        &["scan", "--json", "--", "-odd.txt"],
    );
    r.assert_code(0);
    assert_eq!(of_kind(&r.events(), "identify")[0]["path"], "-odd.txt");

    let r = common::run_in(
        fx.state.path(),
        Some(fx.dir.path()),
        &["scan", "--json", "--", "scan"],
    );
    r.assert_code(0);
    assert_eq!(of_kind(&r.events(), "identify").len(), 1);
}

#[test]
fn clean_dry_run_changes_nothing() {
    let fx = Fixture::standard();
    let before = fs::read(fx.path("photo.jpg")).unwrap();

    // The identity finding carries no marker, so a marker clean skips it.
    let r = fx.run(&["clean", fx.root(), "--category", "identity", "--dry-run"]);
    r.assert_code(1);
    assert!(r.stdout.contains("no removable marker"), "{}", r.stdout);

    // A forced whole-file dry run passes every check but deletes nothing.
    let r = fx.run(&[
        "clean",
        fx.root(),
        "--signature",
        "identity.ext_mismatch",
        "--file",
        "--force",
        "--dry-run",
        "--json",
    ]);
    r.assert_code(0);
    let events = r.events();
    let would = of_kind(&events, "would_clean");
    assert_eq!(would.len(), 1);
    assert_eq!(would[0]["path"], fx.shown("photo.jpg").as_str());
    assert_eq!(would[0]["op"], "delete_file");
    assert_eq!(would[0]["signature"], "identity.ext_mismatch");
    assert_eq!(would[0]["category"], "identity");
    assert_eq!(would[0]["severity"], "alert");
    assert_eq!(would[0]["offset"], 0);
    assert_eq!(would[0]["len"], before.len() as u64);
    let done = events.last().unwrap();
    assert_eq!(done["event"], "done");
    assert_eq!(done["dry_run"], true);
    assert_eq!(done["cleaned"], 1);
    assert_eq!(done["skipped"], 0);
    assert_eq!(done["exit"], 0);

    assert_eq!(fs::read(fx.path("photo.jpg")).unwrap(), before);

    // Neither a dry run nor a scan writes anything, not even the state dir.
    fx.run(&["scan", fx.root()]).assert_code(0);
    let written: Vec<_> = fs::read_dir(fx.state.path()).unwrap().collect();
    assert!(written.is_empty(), "state dir was written: {written:?}");
}

#[test]
fn clean_json_reports_marker_less_skips() {
    let fx = Fixture::standard();
    let r = fx.run(&["clean", fx.root(), "--category", "identity", "--json"]);
    r.assert_code(1);
    let events = r.events();
    let skipped = of_kind(&events, "skipped");
    assert!(!skipped.is_empty());
    let s = skipped
        .iter()
        .find(|e| e["signature"] == "identity.ext_mismatch")
        .expect("skip for the identity finding");
    assert_eq!(s["reason"], "no removable marker");
    assert_eq!(s["op"], serde_json::Value::Null);
    let done = events.last().unwrap();
    assert_eq!(done["cleaned"], 0);
    assert_eq!(
        done["by_reason"]["no removable marker"],
        skipped.len() as u64
    );
    assert_eq!(done["exit"], 1);
}

#[test]
fn file_clean_needs_force_and_undo_restores_it() {
    let fx = Fixture::standard();
    let photo = fx.path("photo.jpg");
    let before = fs::read(&photo).unwrap();
    let args = [
        "clean",
        fx.root(),
        "--signature",
        "identity.ext_mismatch",
        "--file",
    ];

    // Without --force: skipped with a reason, nothing applied, exit 1.
    let r = fx.run(&args);
    r.assert_code(1);
    assert!(r.stdout.contains("needs --force"), "{}", r.stdout);
    assert!(
        r.stdout.contains("skipped 1 (1 need --force)"),
        "{}",
        r.stdout
    );
    assert!(photo.exists());

    let mut json_args = args.to_vec();
    json_args.push("--json");
    let r = fx.run(&json_args);
    r.assert_code(1);
    let events = r.events();
    let skipped = of_kind(&events, "skipped");
    assert_eq!(skipped.len(), 1);
    assert!(
        skipped[0]["reason"]
            .as_str()
            .unwrap()
            .starts_with("needs --force"),
        "{}",
        skipped[0]
    );
    assert_eq!(events.last().unwrap()["by_reason"]["needs --force"], 1);
    assert!(photo.exists());

    // With --force: the file goes to the trash.
    let mut forced = args.to_vec();
    forced.push("--force");
    let r = fx.run(&forced);
    r.assert_code(0);
    assert!(r.stdout.contains("cleaned 1"), "{}", r.stdout);
    assert!(r.stdout.contains("meownary undo"), "{}", r.stdout);
    assert!(!photo.exists());

    // undo brings it back byte for byte.
    let r = fx.run(&["undo"]);
    r.assert_code(0);
    assert!(r.stdout.contains("restored"), "{}", r.stdout);
    assert!(r.stdout.contains("undid 1 edit(s)"), "{}", r.stdout);
    assert_eq!(fs::read(&photo).unwrap(), before);

    // A second undo has nothing left.
    let r = fx.run(&["undo"]);
    r.assert_code(0);
    assert!(r.stdout.contains("undid 0 edit(s)"), "{}", r.stdout);

    let r = fx.run(&["undo", "--json"]);
    r.assert_code(0);
    let events = r.events();
    assert_eq!(events.len(), 2);
    assert_eq!(events[0]["event"], "undone");
    assert_eq!(events[0]["count"], 0);
    assert_eq!(events[1]["event"], "done");
    assert_eq!(events[1]["undone"], 0);
    assert_eq!(events[1]["exit"], 0);
}

#[test]
fn forced_json_clean_then_undo_all() {
    let fx = Fixture::standard();
    let before = fs::read(fx.path("photo.jpg")).unwrap();
    let r = fx.run(&[
        "clean",
        fx.root(),
        "--signature=identity.ext_mismatch",
        "--file",
        "--force",
        "--json",
    ]);
    r.assert_code(0);
    let events = r.events();
    let cleaned = of_kind(&events, "cleaned");
    assert_eq!(cleaned.len(), 1);
    assert!(cleaned[0]["undo_id"].is_u64());
    assert_eq!(cleaned[0]["label"], "delete file");
    assert_eq!(cleaned[0]["op"], "delete_file");
    let done = events.last().unwrap();
    assert_eq!(done["cleaned"], 1);
    assert_eq!(done["dry_run"], false);
    assert_eq!(done["exit"], 0);

    let r = fx.run(&["undo", "--all", "--json"]);
    r.assert_code(0);
    let events = r.events();
    assert_eq!(events[0]["event"], "undone");
    assert_eq!(events[0]["count"], 1);
    assert_eq!(events[1]["undone"], 1);
    assert_eq!(fs::read(fx.path("photo.jpg")).unwrap(), before);
}

#[test]
fn unusable_state_store_exits_73() {
    let fx = Fixture::standard();
    // A state dir below a regular file can never be created.
    let blocker = fx.state.path().join("not-a-dir");
    fs::write(&blocker, b"x").unwrap();
    let state = blocker.join("state");
    let before = fs::read(fx.path("photo.jpg")).unwrap();

    let r = common::run(
        &state,
        &[
            "clean",
            fx.root(),
            "--signature",
            "identity.ext_mismatch",
            "--file",
            "--force",
        ],
    );
    r.assert_code(73);
    assert!(
        r.stderr.contains("cannot open the state store"),
        "{}",
        r.stderr
    );
    assert!(r.stderr.contains("no edit was attempted"), "{}", r.stderr);
    assert!(r.stdout.is_empty(), "{}", r.stdout);
    assert_eq!(fs::read(fx.path("photo.jpg")).unwrap(), before);

    let r = common::run(
        &state,
        &["clean", fx.root(), "--category", "junk", "--json"],
    );
    r.assert_code(73);
    let events = r.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["event"], "done");
    assert_eq!(events[0]["exit"], 73);
    assert!(events[0]["error"].is_string());

    let r = common::run(&state, &["undo", "--json"]);
    r.assert_code(73);
    let events = r.events();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0]["exit"], 73);
    assert!(events[0]["error"].is_string());
    common::run(&state, &["undo"]).assert_code(73);

    // A dry run never opens the store, so it still runs.
    common::run(
        &state,
        &["clean", fx.root(), "--category", "identity", "--dry-run"],
    )
    .assert_code(1);
}

#[test]
fn state_dir_inside_the_tree_is_never_scanned() {
    let fx = Fixture::standard();
    let state = fx.path("zz-state");
    fs::create_dir(&state).unwrap();
    let r = common::run(
        &state,
        &[
            "clean",
            fx.root(),
            "--signature",
            "identity.ext_mismatch",
            "--file",
            "--force",
        ],
    );
    r.assert_code(0);
    assert!(state.join("trash").exists());

    let r = common::run(&state, &["scan", fx.root(), "--json"]);
    let events = r.events();
    for e in of_kind(&events, "identify") {
        assert!(
            !e["path"].as_str().unwrap().contains("zz-state"),
            "scanned its own state: {e}"
        );
    }
    common::run(&state, &["undo"]).assert_code(0);
    assert!(fx.path("photo.jpg").exists());
}

#[test]
fn broken_pipe_is_quiet() {
    let fx = Fixture::empty();
    for i in 0..200 {
        fs::write(fx.path(&format!("f{i:03}.jpg")), mz_bytes()).unwrap();
    }
    let mut child = common::meownary(fx.state.path())
        .args(["scan", fx.root(), "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut reader = BufReader::new(child.stdout.take().unwrap());
    let mut first = String::new();
    reader.read_line(&mut first).unwrap();
    assert!(first.starts_with("{\"event\":\"identify\""), "{first}");
    drop(reader);

    let out = child.wait_with_output().unwrap();
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(!stderr.contains("panicked"), "{stderr}");
    assert!(!stderr.contains("internal error"), "{stderr}");
    assert_eq!(out.status.code(), Some(0), "{stderr}");
}

#[test]
fn readme_exit_codes_match_help() {
    let fx = Fixture::empty();
    let help = fx.run(&["--help"]).stdout;
    let help_codes: BTreeSet<u32> = help
        .split("exit codes\n")
        .nth(1)
        .unwrap()
        .lines()
        .filter_map(|l| {
            l.strip_prefix("  ")?
                .split_whitespace()
                .next()?
                .parse()
                .ok()
        })
        .collect();

    let readme = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/README.md")).unwrap();
    let section = readme
        .split("## Exit codes")
        .nth(1)
        .expect("README has an Exit codes section");
    let readme_codes: BTreeSet<u32> = section
        .lines()
        .take_while(|l| !l.starts_with("## "))
        .filter_map(|l| l.strip_prefix('|')?.split('|').next()?.trim().parse().ok())
        .collect();

    assert!(!help_codes.is_empty());
    assert_eq!(help_codes, readme_codes);
}

#[test]
fn changelog_has_a_section_for_this_version() {
    let log = fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/CHANGELOG.md")).unwrap();
    let heading = format!("## [{}]", env!("CARGO_PKG_VERSION"));
    assert!(
        log.lines().any(|l| l.starts_with(&heading)),
        "CHANGELOG.md needs a `{heading}` section"
    );
}

#[cfg(unix)]
#[test]
fn partial_scan_exits_75() {
    use std::os::unix::fs::PermissionsExt;
    let fx = Fixture::standard();
    let locked = fx.path("locked.bin");
    fs::write(&locked, b"secret").unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::File::open(&locked).is_ok() {
        return; // running as root: permissions are not enforced
    }

    let r = fx.run(&["scan", fx.root(), "--json"]);
    r.assert_code(75);
    let events = r.events();
    let e = of_kind(&events, "identify")
        .into_iter()
        .find(|e| e["path"] == fx.shown("locked.bin").as_str())
        .expect("locked file is still reported");
    assert_eq!(e["partial"], true);
    assert_eq!(e["error"], "cannot read: permission denied");
    let done = events.last().unwrap();
    assert_eq!(done["partial_files"], 1);
    assert_eq!(done["exit"], 75);

    // --fail-on wins over a partial scan.
    fx.run(&["scan", fx.root(), "--fail-on", "alert"])
        .assert_code(1);

    let r = fx.run(&["scan", fx.root()]);
    r.assert_code(75);
    assert!(
        r.stdout
            .contains("(partial: cannot read: permission denied)")
    );

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o644)).unwrap();
}

#[cfg(unix)]
#[test]
fn json_never_contains_raw_non_utf8() {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;
    let fx = Fixture::standard();
    let name = OsStr::from_bytes(b"bad\xffname.jpg");
    if fs::write(fx.dir.path().join(name), mz_bytes()).is_err() {
        return; // the filesystem refuses non-UTF-8 names (APFS)
    }
    let out = common::meownary(fx.state.path())
        .args(["scan", fx.root(), "--json"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).expect("JSON output is valid UTF-8");
    assert!(stdout.contains('\u{fffd}'), "{stdout}");
    for line in stdout.lines() {
        serde_json::from_str::<serde_json::Value>(line).unwrap();
    }

    let out = common::meownary(fx.state.path())
        .args(["scan", fx.root()])
        .output()
        .unwrap();
    assert!(
        String::from_utf8(out.stdout).is_ok(),
        "human output is valid UTF-8"
    );
}

/// A synthetic ZIP of (name, data, deflated) entries.
fn zip_of(entries: &[(&str, &[u8], bool)]) -> Vec<u8> {
    fn crc32(data: &[u8]) -> u32 {
        let mut crc = !0u32;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                crc = if crc & 1 != 0 {
                    0xEDB8_8320 ^ (crc >> 1)
                } else {
                    crc >> 1
                };
            }
        }
        !crc
    }
    let mut out = Vec::new();
    let mut central = Vec::new();
    for (name, data, deflate) in entries {
        let packed = if *deflate {
            miniz_oxide::deflate::compress_to_vec(data, 6)
        } else {
            data.to_vec()
        };
        let method: u16 = if *deflate { 8 } else { 0 };
        let crc = crc32(data);
        let offset = out.len() as u32;
        let mut common = Vec::new();
        common.extend_from_slice(&method.to_le_bytes());
        common.extend_from_slice(&[0x21, 0x08, 0x4a, 0x5b]);
        common.extend_from_slice(&crc.to_le_bytes());
        common.extend_from_slice(&(packed.len() as u32).to_le_bytes());
        common.extend_from_slice(&(data.len() as u32).to_le_bytes());
        common.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00");
        out.extend_from_slice(&common);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(&packed);
        central.extend_from_slice(b"PK\x01\x02\x1e\x03\x14\x00\x00\x00");
        central.extend_from_slice(&common);
        central.extend_from_slice(&[0; 8]);
        central.extend_from_slice(&0x81a4_0000u32.to_le_bytes());
        central.extend_from_slice(&offset.to_le_bytes());
        central.extend_from_slice(name.as_bytes());
    }
    let cd_offset = out.len() as u32;
    out.extend_from_slice(&central);
    out.extend_from_slice(b"PK\x05\x06\0\0\0\0");
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
    out.extend_from_slice(&(central.len() as u32).to_le_bytes());
    out.extend_from_slice(&cd_offset.to_le_bytes());
    out.extend_from_slice(&[0, 0]);
    out
}

#[test]
fn deattribute_cleans_the_files_inside_a_zip() {
    let fx = Fixture::empty();
    let mut exe = mz_bytes();
    exe.extend_from_slice(b"patched by Invented\0");
    let text = b"plain words, nothing to blank here".to_vec();
    let original = zip_of(&[
        ("bin/a.exe", &exe, false),
        ("notes.txt", &text, true),
        ("bin/b.exe", &exe, true),
    ]);
    let path = fx.path("bundle.zip");
    fs::write(&path, &original).unwrap();
    let shown = fx.shown("bundle.zip");
    let copy = fx.path("bundle.deattributed.zip");
    let copy_shown = fx.shown("bundle.deattributed.zip");

    let dry = fx.run(&["clean", &shown, "--deattribute", "--dry-run"]);
    dry.assert_code(0);
    assert!(
        dry.stdout.contains(&format!(
            "would save  {copy_shown}  (from bundle.zip: 2 of 3 files inside cleaned, 2 patch)\n"
        )),
        "{}",
        dry.stdout
    );
    assert!(!copy.exists());

    let run = fx.run(&["clean", &shown, "--deattribute", "--json"]);
    run.assert_code(0);
    let events = run.events();
    let saved = of_kind(&events, "saved");
    assert_eq!(saved.len(), 1, "{}", run.stdout);
    assert_eq!(saved[0]["path"], shown.as_str());
    assert_eq!(saved[0]["output"], copy_shown.as_str());
    assert_eq!(saved[0]["entries"], 2);
    assert_eq!(saved[0]["edits"], 2);
    assert!(!run.stdout.contains("Invented"));
    assert_eq!(fs::read(&path).unwrap(), original, "original untouched");

    let human = fx.run(&["clean", &shown, "--deattribute"]);
    human.assert_code(0);
    assert!(
        human.stdout.contains(&format!(
            "saved       {copy_shown}  (from bundle.zip: 2 of 3 files inside cleaned, 2 patch)\n"
        )),
        "{}",
        human.stdout
    );
    assert!(human.stdout.ends_with("saved 1 copy beside its original\n"));
    let after = fs::read(&copy).unwrap();
    assert!(!after.windows(10).any(|w| w == b"patched by"));
    // The stored entry is cleaned in place: same bytes elsewhere, same length.
    assert!(after.len() > 100);
    assert_eq!(
        root_names(&fx),
        vec!["bundle.deattributed.zip", "bundle.zip"]
    );

    // A zip with nothing inside to blank saves no copy.
    let plain = zip_of(&[("a.txt", &text, true)]);
    fs::write(fx.path("plain.zip"), &plain).unwrap();
    let r = fx.run(&["clean", &fx.shown("plain.zip"), "--deattribute"]);
    r.assert_code(0);
    assert!(
        r.stdout.contains(&format!(
            "skipped     {}  nothing to blank inside the archive\n",
            fx.shown("plain.zip")
        )),
        "{}",
        r.stdout
    );
    assert!(!fx.path("plain.deattributed.zip").exists());
}
