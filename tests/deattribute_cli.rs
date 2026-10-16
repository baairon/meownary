//! End-to-end tests of `clean --deattribute` JSON Lines: the `done` event on
//! usage errors, the `verified` field and `op` of a saved copy, and exit 75
//! winning over exit 1 when a copy cannot be written.

mod common;

use std::fs;

use common::{Fixture, mz_bytes, of_kind};

/// A small PE stand-in carrying one `patched by` credit.
fn credited_exe() -> Vec<u8> {
    let mut bytes = mz_bytes();
    bytes.extend_from_slice(b"patched by Invented\0");
    bytes
}

/// A ZIP of stored entries, enough for the archive path to clean inside it.
fn stored_zip(entries: &[(&str, &[u8])]) -> Vec<u8> {
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
    for (name, data) in entries {
        let offset = out.len() as u32;
        let mut common = Vec::new();
        common.extend_from_slice(&0u16.to_le_bytes());
        common.extend_from_slice(&[0x21, 0x08, 0x4a, 0x5b]);
        common.extend_from_slice(&crc32(data).to_le_bytes());
        common.extend_from_slice(&(data.len() as u32).to_le_bytes());
        common.extend_from_slice(&(data.len() as u32).to_le_bytes());
        common.extend_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(b"PK\x03\x04\x14\x00\x00\x00");
        out.extend_from_slice(&common);
        out.extend_from_slice(&[0, 0]);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(data);
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

/// A Macintosh resource fork holding one `STR#` list of `texts` under the
/// resource name `Glimmer Glow`, and the same fork as the resource entry of an
/// AppleDouble file. All names invented.
fn resource_forks(texts: &[&[u8]]) -> (Vec<u8>, Vec<u8>) {
    let mut list = (texts.len() as u16).to_be_bytes().to_vec();
    for text in texts {
        list.push(text.len() as u8);
        list.extend_from_slice(text);
    }
    let mut data = (list.len() as u32).to_be_bytes().to_vec();
    data.extend_from_slice(&list);
    // The map: header copy and handles, then the type list at 28, one
    // reference after it and the name list at 50.
    let mut map = vec![0u8; 24];
    for v in [28u16, 50, 0] {
        map.extend_from_slice(&v.to_be_bytes());
    }
    map.extend_from_slice(b"STR#");
    for v in [0u16, 10, 128, 0] {
        map.extend_from_slice(&v.to_be_bytes());
    }
    map.extend_from_slice(&[0; 8]);
    map.extend_from_slice(b"\x0cGlimmer Glow");
    let mut fork = Vec::new();
    for v in [0x100, 0x100 + data.len(), data.len(), map.len()] {
        fork.extend_from_slice(&(v as u32).to_be_bytes());
    }
    fork.resize(0x100, 0);
    fork.extend_from_slice(&data);
    fork.extend_from_slice(&map);
    let mut double = vec![0, 5, 0x16, 7, 0, 2, 0, 0];
    double.resize(24, 0);
    double.extend_from_slice(&1u16.to_be_bytes());
    for v in [2u32, 38, fork.len() as u32] {
        double.extend_from_slice(&v.to_be_bytes());
    }
    double.extend_from_slice(&fork);
    (fork, double)
}

#[test]
fn deep_mode_cleans_resource_forks_and_appledouble_files() {
    let fx = Fixture::empty();
    let (fork, double) = resource_forks(&[b"\xa9 2024 Glimmer Labs", b"Patched by Nobody Group"]);
    fs::write(fx.path("Glow.rsrc"), &fork).unwrap();
    fs::write(fx.path("._Glow.dll"), &double).unwrap();

    // The basic pass has nothing to say about a resource fork.
    let basic = fx.run(&["clean", fx.root(), "--deattribute", "--json"]);
    basic.assert_code(0);
    assert!(
        of_kind(&basic.events(), "saved").is_empty(),
        "{}",
        basic.stdout
    );

    let run = fx.run(&["clean", fx.root(), "--deattribute", "--deep", "--json"]);
    run.assert_code(0);
    let events = run.events();
    let saved = of_kind(&events, "saved");
    assert_eq!(saved.len(), 2, "{}", run.stdout);
    assert!(
        saved.iter().all(|e| e["verified"] == true),
        "{}",
        run.stdout
    );
    assert!(
        of_kind(&events, "skipped")
            .iter()
            .any(|e| e["reason"] == "functional name kept"),
        "the resource name stays and is reported: {}",
        run.stdout
    );
    for (name, original) in [("Glow", &fork), ("._Glow", &double)] {
        let ext = if name == "Glow" { "rsrc" } else { "dll" };
        let copy = fs::read(fx.path(&format!("{name}.deattributed.{ext}"))).unwrap();
        assert_eq!(copy.len(), original.len());
        let has = |needle: &[u8]| copy.windows(needle.len()).any(|w| w == needle);
        assert!(!has(b"2024 Glimmer Labs") && !has(b"Nobody"), "{name}");
        assert!(has(b"Glimmer Glow"), "{name}: the resource name is kept");
    }
    assert!(!run.stdout.contains("Glimmer") && !run.stdout.contains("Nobody"));
    assert!(
        !run.stderr.contains("verification incomplete"),
        "{}",
        run.stderr
    );
}

#[test]
fn usage_errors_still_end_with_a_done_event() {
    let fx = Fixture::empty();
    let missing = fx.shown("nope.exe");
    let r = fx.run(&["clean", &missing, "--deattribute", "--json"]);
    r.assert_code(2);
    let events = r.events();
    assert_eq!(events.len(), 1, "{}", r.stdout);
    let done = of_kind(&events, "done");
    assert_eq!(done.len(), 1);
    assert_eq!(done[0]["exit"], 2);
    assert_eq!(done[0]["saved"], 0);
    assert!(done[0]["error"].is_string(), "{}", r.stdout);
    assert!(r.stderr.contains("path unavailable"), "{}", r.stderr);

    fs::write(fx.path("app.deattributed.exe"), credited_exe()).unwrap();
    let r = fx.run(&[
        "clean",
        &fx.shown("app.deattributed.exe"),
        "--deattribute",
        "--dry-run",
        "--json",
    ]);
    r.assert_code(2);
    let events = r.events();
    let done = of_kind(&events, "done");
    assert_eq!(done.len(), 1, "{}", r.stdout);
    assert_eq!(done[0]["exit"], 2);
    assert_eq!(done[0]["dry_run"], true);

    // Without --json a usage error prints nothing on stdout.
    let r = fx.run(&["clean", &missing, "--deattribute"]);
    r.assert_code(2);
    assert!(r.stdout.is_empty(), "{}", r.stdout);
}

#[test]
fn a_saved_copy_reports_verified_and_its_op_after_the_edits() {
    let fx = Fixture::empty();
    fs::write(fx.path("app.exe"), credited_exe()).unwrap();
    let shown = fx.shown("app.exe");

    let dry = fx.run(&["clean", &shown, "--deattribute", "--dry-run", "--json"]);
    dry.assert_code(0);
    let events = dry.events();
    let would = of_kind(&events, "would_save");
    assert_eq!(would.len(), 1, "{}", dry.stdout);
    assert!(would[0].get("verified").is_none(), "{}", dry.stdout);

    for args in [
        &["clean", &shown, "--deattribute", "--json"][..],
        &["clean", &shown, "--deattribute", "--deep", "--json"],
    ] {
        let run = fx.run(args);
        run.assert_code(0);
        let events = run.events();
        let cleaned = of_kind(&events, "cleaned");
        assert!(!cleaned.is_empty(), "{}", run.stdout);
        assert!(
            cleaned
                .iter()
                .all(|e| e["op"] == "raw_blank" || e["op"] == "replace"),
            "{}",
            run.stdout
        );
        let saved = of_kind(&events, "saved");
        assert_eq!(saved.len(), 1, "{}", run.stdout);
        assert_eq!(saved[0]["verified"], true, "{}", run.stdout);
        // The saved event comes after every edit of its copy.
        let at = |kind: &str| events.iter().rposition(|e| e["event"] == kind);
        assert!(at("cleaned") < at("saved"), "{}", run.stdout);
        assert!(at("saved") < at("done"), "{}", run.stdout);
        let done = of_kind(&events, "done");
        assert_eq!(done[0]["partial_files"], 0);
        assert!(done[0].get("error").is_none(), "{}", run.stdout);
        assert!(!run.stdout.contains("Invented"));
        assert!(!run.stderr.contains("verification incomplete"));
    }
}

#[test]
fn a_blocked_copy_path_is_partial_in_real_and_dry_runs() {
    let fx = Fixture::empty();
    fs::write(fx.path("app.exe"), credited_exe()).unwrap();
    // Something that is not a file holds the copy's path.
    fs::create_dir(fx.path("app.deattributed.exe")).unwrap();
    let shown = fx.shown("app.exe");

    for dry in [true, false] {
        let mut args = vec!["clean", shown.as_str(), "--deattribute", "--json"];
        if dry {
            args.push("--dry-run");
        }
        let run = fx.run(&args);
        run.assert_code(75);
        let events = run.events();
        assert!(of_kind(&events, "would_save").is_empty(), "{}", run.stdout);
        assert!(of_kind(&events, "saved").is_empty(), "{}", run.stdout);
        let skipped = of_kind(&events, "skipped");
        assert!(
            skipped
                .iter()
                .any(|e| e["kind"] == "patch" && e["reason"] == "unsafe edit"),
            "{}",
            run.stdout
        );
        let done = of_kind(&events, "done");
        assert_eq!(done[0]["exit"], 75);
        assert_eq!(done[0]["partial_files"], 1);
        assert!(fx.path("app.deattributed.exe").is_dir());
    }
}

#[test]
fn exit_75_wins_over_exit_1() {
    let fx = Fixture::empty();
    // Exit 1 on its own: a load-bearing stamp matched and nothing was saved.
    let mut packed = mz_bytes();
    packed.extend_from_slice(b"UPX!\0");
    fs::write(fx.path("packed.exe"), &packed).unwrap();
    let r = fx.run(&["clean", fx.root(), "--deattribute"]);
    r.assert_code(1);

    // A copy that cannot be written makes the same run partial.
    fs::write(fx.path("app.exe"), credited_exe()).unwrap();
    fs::create_dir(fx.path("app.deattributed.exe")).unwrap();
    let r = fx.run(&["clean", fx.root(), "--deattribute", "--json"]);
    r.assert_code(75);
    let events = r.events();
    assert_eq!(of_kind(&events, "done")[0]["exit"], 75);
    let human = fx.run(&["clean", fx.root(), "--deattribute"]);
    human.assert_code(75);
}

#[test]
fn archive_copies_are_verified_and_dry_runs_check_the_copy_path() {
    let fx = Fixture::empty();
    let exe = credited_exe();
    fs::write(
        fx.path("bundle.zip"),
        stored_zip(&[("bin/a.exe", &exe), ("notes.txt", b"plain words")]),
    )
    .unwrap();
    let shown = fx.shown("bundle.zip");

    let run = fx.run(&["clean", &shown, "--deattribute", "--json"]);
    run.assert_code(0);
    let events = run.events();
    let saved = of_kind(&events, "saved");
    assert_eq!(saved.len(), 1, "{}", run.stdout);
    assert_eq!(saved[0]["verified"], true, "{}", run.stdout);
    assert_eq!(saved[0]["entries"], 1);

    // Replace the copy with a folder: a dry run now reports what a real run
    // would hit instead of promising a copy.
    fs::remove_file(fx.path("bundle.deattributed.zip")).unwrap();
    fs::create_dir(fx.path("bundle.deattributed.zip")).unwrap();
    let dry = fx.run(&["clean", &shown, "--deattribute", "--dry-run", "--json"]);
    dry.assert_code(75);
    let events = dry.events();
    assert!(of_kind(&events, "would_save").is_empty(), "{}", dry.stdout);
    assert!(
        of_kind(&events, "skipped")
            .iter()
            .any(|e| e["reason"] == "unsafe edit" && e.get("entry").is_none()),
        "{}",
        dry.stdout
    );
}
