mod common;

use common::{Fixture, run};
use std::fs;

#[test]
fn saved_plan_applies_verifies_and_refuses_changed_inputs() {
    let fx = Fixture::empty();
    let root = fx.dir.path();
    fs::write(root.join("input.bin"), b"North Star data").unwrap();
    let input = root.join("input.bin");
    let plan = root.join("edit.json");
    let output = root.join("output.bin");
    let args = [
        "bytes",
        "replace",
        input.to_str().unwrap(),
        "--offset",
        "0",
        "--text",
        "South",
        "--plan-out",
        plan.to_str().unwrap(),
        "--json",
    ];
    run(fx.state.path(), &args).assert_code(0);
    assert!(!output.exists());
    let apply = [
        "apply",
        plan.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--json",
    ];
    run(fx.state.path(), &apply).assert_code(0);
    assert_eq!(fs::read(&output).unwrap(), b"South Star data");
    run(
        fx.state.path(),
        &[
            "verify",
            plan.to_str().unwrap(),
            output.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
    fs::write(&input, b"Other Star data").unwrap();
    fs::remove_file(&output).unwrap();
    run(fx.state.path(), &apply).assert_code(2);
    assert!(!output.exists());
}

#[test]
fn in_place_edits_verify_against_snapshot_and_undo_exactly() {
    let fx = Fixture::empty();
    let input = fx.dir.path().join("input.bin");
    let plan = fx.dir.path().join("edit.json");
    fs::write(&input, b"North Star").unwrap();
    run(
        fx.state.path(),
        &[
            "bytes",
            "replace",
            input.to_str().unwrap(),
            "--offset",
            "0",
            "--text",
            "South",
            "--plan-out",
            plan.to_str().unwrap(),
            "--in-place",
            "--json",
        ],
    )
    .assert_code(0);
    run(
        fx.state.path(),
        &[
            "verify",
            plan.to_str().unwrap(),
            input.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
    run(fx.state.path(), &["undo", "--json"]).assert_code(0);
    assert_eq!(fs::read(&input).unwrap(), b"North Star");
}

#[test]
fn flags_payloads_and_destinations_are_unambiguous() {
    let fx = Fixture::empty();
    let input = fx.dir.path().join("input.bin");
    let output = fx.dir.path().join("result");
    fs::write(&input, b"abcdef").unwrap();
    run(
        fx.state.path(),
        &[
            "bytes",
            "replace",
            input.to_str().unwrap(),
            "--offset",
            "0",
            "--text",
            "--help",
            "--output",
            output.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
    assert_eq!(fs::read(&output).unwrap(), b"--help");
    fs::remove_file(&output).unwrap();
    run(
        fx.state.path(),
        &[
            "bytes",
            "replace",
            input.to_str().unwrap(),
            "--offset",
            "0",
            "--text",
            "x",
            "--plan-out",
            output.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(2);
    assert!(!output.exists());
    run(
        fx.state.path(),
        &["hash", input.to_str().unwrap(), "--length", "1", "--json"],
    )
    .assert_code(2);
    run(fx.state.path(), &["capabilities", "junk", "--json"]).assert_code(2);
}

#[test]
fn deattribution_rules_preserve_exclusions_and_report_incomplete_scans() {
    let fx = Fixture::empty();
    let input = fx.dir.path().join("input.bin");
    let rules = fx.dir.path().join("rules.json");
    let output = fx.dir.path().join("output.bin");
    fs::write(&input, b"North Star\0keep North Star\0").unwrap();
    fs::write(&rules, br#"{"version":1,"identities":[{"id":"publisher","scope":"publisher","names":["North Star"],"encodings":["utf8"],"boundary":"word"}],"exclusions":[{"kind":"text","value":"keep North Star"}]}"#).unwrap();
    let args = [
        "deattribute",
        input.to_str().unwrap(),
        "--rules",
        rules.to_str().unwrap(),
        "--verify",
        "protected",
        "--output",
        output.to_str().unwrap(),
        "--json",
    ];
    run(fx.state.path(), &args).assert_code(0);
    assert_eq!(fs::read(&output).unwrap(), b"          \0keep North Star\0");
    fs::remove_file(&output).unwrap();
    run(
        fx.state.path(),
        &[
            "deattribute",
            input.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--verify",
            "strict",
            "--output",
            output.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(75);
    assert!(!output.exists());
    run(
        fx.state.path(),
        &[
            "deattribute",
            input.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--max-scan",
            "8",
            "--output",
            output.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(2);
    assert!(!output.exists());
}

#[test]
fn an_exclusion_alone_leaves_a_retained_residual_that_strict_refuses() {
    let fx = Fixture::empty();
    let input = fx.dir.path().join("input.exe");
    let rules = fx.dir.path().join("rules.json");
    let output = fx.dir.path().join("output.exe");
    let mut bytes = common::pe_bytes();
    bytes.extend(b"patched by North Star\0");
    fs::write(&input, &bytes).unwrap();
    fs::write(
        &rules,
        br#"{"version":1,"exclusions":[{"kind":"text","value":"North Star"}]}"#,
    )
    .unwrap();
    // The credit the catalog would blank is kept by the exclusion. Strict
    // verification refuses a copy that still carries it.
    let strict = run(
        fx.state.path(),
        &[
            "deattribute",
            input.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--verify",
            "strict",
            "--output",
            output.to_str().unwrap(),
            "--json",
        ],
    );
    strict.assert_code(75);
    assert!(!output.exists());
    // Protected verification passes, naming the exclusion as the reason.
    let protected = run(
        fx.state.path(),
        &[
            "deattribute",
            input.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--verify",
            "protected",
            "--output",
            output.to_str().unwrap(),
            "--json",
        ],
    );
    protected.assert_code(0);
    let events = protected.events();
    let report = events
        .iter()
        .find(|e| e["event"] == "verification")
        .unwrap_or_else(|| panic!("{}", protected.stdout));
    let residuals = report["data"]["audit"]["residuals"]
        .as_array()
        .unwrap_or_else(|| panic!("{}", protected.stdout));
    assert_eq!(residuals.len(), 1, "{}", protected.stdout);
    assert_eq!(residuals[0]["retained"], "explicit exclusion");
    assert_eq!(fs::read(&input).unwrap(), bytes, "nothing was written");
}

#[test]
fn an_expected_match_count_checks_the_input_not_the_cleaned_output() {
    let fx = Fixture::empty();
    let root = fx.dir.path();
    let input = root.join("input.bin");
    let rules = root.join("rules.json");
    let plan = root.join("plan.json");
    let output = root.join("output.bin");
    let applied = root.join("applied.bin");
    fs::write(&input, b"North Star data\0").unwrap();
    fs::write(&rules, br#"{"version":1,"identities":[{"id":"publisher","scope":"publisher","names":["North Star"],"encodings":["utf8"],"boundary":"word","expected_matches":1}]}"#).unwrap();
    run(
        fx.state.path(),
        &[
            "deattribute",
            input.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--plan-out",
            plan.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
    assert_eq!(fs::read(&output).unwrap(), b"           data\0");
    run(
        fx.state.path(),
        &[
            "apply",
            plan.to_str().unwrap(),
            "--output",
            applied.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
    run(
        fx.state.path(),
        &[
            "verify",
            plan.to_str().unwrap(),
            applied.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
    // Too few matches in the input still stop the plan.
    fs::write(&input, b"no match here\0").unwrap();
    run(
        fx.state.path(),
        &[
            "deattribute",
            input.to_str().unwrap(),
            "--rules",
            rules.to_str().unwrap(),
            "--dry-run",
            "--json",
        ],
    )
    .assert_code(2);
}

#[test]
fn relative_file_selectors_match_on_apply_from_anywhere() {
    let fx = Fixture::empty();
    let root = fx.dir.path();
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::write(root.join("bin").join("sample.dll"), b"North Star data\0").unwrap();
    fs::write(root.join("rules.json"), br#"{"version":1,"identities":[{"id":"publisher","scope":"publisher","names":["North Star"],"encodings":["utf8"],"boundary":"word","files":["bin/*.dll"]}]}"#).unwrap();
    let cwd = Some(root);
    common::run_in(
        fx.state.path(),
        cwd,
        &[
            "deattribute",
            "bin/sample.dll",
            "--rules",
            "rules.json",
            "--output",
            "first.dll",
            "--plan-out",
            "plan.json",
            "--json",
        ],
    )
    .assert_code(0);
    assert_eq!(
        fs::read(root.join("first.dll")).unwrap(),
        b"           data\0"
    );
    common::run_in(
        fx.state.path(),
        cwd,
        &["apply", "plan.json", "--output", "second.dll", "--json"],
    )
    .assert_code(0);
    assert_eq!(
        fs::read(root.join("second.dll")).unwrap(),
        b"           data\0"
    );
    // From another folder the plan still knows the path it was planned as.
    let elsewhere = tempfile::tempdir().unwrap();
    let third = root.join("third.dll");
    common::run_in(
        fx.state.path(),
        Some(elsewhere.path()),
        &[
            "apply",
            root.join("plan.json").to_str().unwrap(),
            "--output",
            third.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
    assert_eq!(fs::read(&third).unwrap(), b"           data\0");
    common::run_in(
        fx.state.path(),
        Some(elsewhere.path()),
        &[
            "verify",
            root.join("plan.json").to_str().unwrap(),
            third.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
}

#[test]
fn a_plan_made_from_a_dotted_path_applies_and_verifies_from_anywhere() {
    let fx = Fixture::empty();
    let root = fx.dir.path();
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::write(root.join("bin").join("file.dll"), b"North Star data\0").unwrap();
    fs::write(root.join("rules.json"), br#"{"version":1,"identities":[{"id":"publisher","scope":"publisher","names":["North Star"],"encodings":["utf8"],"boundary":"word","files":["bin/*.dll"]}]}"#).unwrap();
    let spellings: &[&str] = if cfg!(windows) {
        &["./bin/file.dll", ".\\bin\\file.dll", "bin\\file.dll"]
    } else {
        &["./bin/file.dll", ".//bin/./file.dll"]
    };
    let elsewhere = tempfile::tempdir().unwrap();
    for (i, spelling) in spellings.iter().enumerate() {
        let plan = root.join(format!("plan{i}.json"));
        common::run_in(
            fx.state.path(),
            Some(root),
            &[
                "deattribute",
                spelling,
                "--rules",
                "rules.json",
                "--dry-run",
                "--plan-out",
                plan.to_str().unwrap(),
                "--json",
            ],
        )
        .assert_code(0);
        let saved: serde_json::Value = serde_json::from_slice(&fs::read(&plan).unwrap()).unwrap();
        assert_eq!(
            saved["deattribute"]["logical"], "bin/file.dll",
            "{spelling}: {saved}"
        );
        for cwd in [root, elsewhere.path()] {
            let output = root.join(format!("out{i}.dll"));
            let _ = fs::remove_file(&output);
            common::run_in(
                fx.state.path(),
                Some(cwd),
                &[
                    "apply",
                    plan.to_str().unwrap(),
                    "--output",
                    output.to_str().unwrap(),
                    "--json",
                ],
            )
            .assert_code(0);
            assert_eq!(fs::read(&output).unwrap(), b"           data\0");
            common::run_in(
                fx.state.path(),
                Some(cwd),
                &[
                    "verify",
                    plan.to_str().unwrap(),
                    output.to_str().unwrap(),
                    "--json",
                ],
            )
            .assert_code(0);
        }
    }
}

#[test]
fn malformed_pe_is_not_edited_and_header_edits_require_raw() {
    let fx = Fixture::empty();
    let input = fx.dir.path().join("input.exe");
    let mut bytes = common::mz_bytes();
    bytes.extend(b"patched by Invented\0");
    fs::write(&input, &bytes).unwrap();
    run(
        fx.state.path(),
        &[
            "deattribute",
            input.to_str().unwrap(),
            "--dry-run",
            "--json",
        ],
    )
    .assert_code(75);
    assert_eq!(fs::read(&input).unwrap(), bytes);
    fs::write(&input, common::pe_bytes()).unwrap();
    run(
        fx.state.path(),
        &[
            "bytes",
            "fill",
            input.to_str().unwrap(),
            "--offset",
            "0",
            "--length",
            "2",
            "--fill",
            "0",
            "--dry-run",
            "--json",
        ],
    )
    .assert_code(2);
    run(
        fx.state.path(),
        &[
            "bytes",
            "fill",
            input.to_str().unwrap(),
            "--offset",
            "0",
            "--length",
            "2",
            "--fill",
            "0",
            "--raw",
            "--dry-run",
            "--json",
        ],
    )
    .assert_code(0);
}

#[test]
fn archive_manifest_conflicts_are_refused_before_packaging() {
    let fx = Fixture::empty();
    let root = fx.dir.path().join("input");
    fs::create_dir(&root).unwrap();
    fs::write(root.join("data.bin"), b"fixture").unwrap();
    let output = fx.dir.path().join("bundle.zip");
    run(
        fx.state.path(),
        &[
            "archive",
            "pack",
            root.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--manifest",
            output.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(2);
    assert!(!output.exists());
    let manifest = fx.dir.path().join("manifest.json");
    run(
        fx.state.path(),
        &[
            "archive",
            "pack",
            root.to_str().unwrap(),
            "--output",
            output.to_str().unwrap(),
            "--manifest",
            manifest.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
    run(
        fx.state.path(),
        &[
            "archive",
            "verify",
            output.to_str().unwrap(),
            "--manifest",
            manifest.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
}

#[test]
fn strings_recover_after_invalid_utf8_and_decode_surrogate_pairs() {
    let fx = Fixture::empty();
    let input = fx.dir.path().join("input.bin");
    fs::write(&input, b"\xffNorth Star\0").unwrap();
    let result = run(
        fx.state.path(),
        &["strings", input.to_str().unwrap(), "--details", "--json"],
    );
    result.assert_code(0);
    let events = result.events();
    let hit = events.iter().find(|e| e["event"] == "string").unwrap();
    assert_eq!(hit["data"]["offset"], 1);
    assert_eq!(hit["data"]["text"], "North Star");
    let text = "North \u{1f680} Star";
    let mut bytes: Vec<_> = text.encode_utf16().flat_map(u16::to_be_bytes).collect();
    bytes.extend([0; 2]);
    fs::write(&input, bytes).unwrap();
    let result = run(
        fx.state.path(),
        &[
            "strings",
            input.to_str().unwrap(),
            "--encoding",
            "utf16be",
            "--details",
            "--json",
        ],
    );
    result.assert_code(0);
    assert_eq!(
        result
            .events()
            .iter()
            .find(|e| e["event"] == "string")
            .unwrap()["data"]["text"],
        text
    );
}

#[test]
fn changed_payloads_and_tampered_plans_leave_existing_output_intact() {
    let fx = Fixture::empty();
    let input = fx.dir.path().join("input.bin");
    let payload = fx.dir.path().join("payload.bin");
    let plan = fx.dir.path().join("edit.json");
    let output = fx.dir.path().join("output.bin");
    fs::write(&input, b"North Star").unwrap();
    fs::write(&payload, b"South").unwrap();
    fs::write(&output, b"existing output").unwrap();
    run(
        fx.state.path(),
        &[
            "bytes",
            "replace",
            input.to_str().unwrap(),
            "--offset",
            "0",
            "--data-file",
            payload.to_str().unwrap(),
            "--plan-out",
            plan.to_str().unwrap(),
            "--json",
        ],
    )
    .assert_code(0);
    let apply = [
        "apply",
        plan.to_str().unwrap(),
        "--output",
        output.to_str().unwrap(),
        "--overwrite",
        "--json",
    ];
    fs::write(&payload, b"Other").unwrap();
    run(fx.state.path(), &apply).assert_code(2);
    assert_eq!(fs::read(&output).unwrap(), b"existing output");
    fs::write(&payload, b"South").unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&fs::read(&plan).unwrap()).unwrap();
    value["operations"][0]["edit"]["offset"] = serde_json::json!(1);
    fs::write(&plan, serde_json::to_vec(&value).unwrap()).unwrap();
    run(fx.state.path(), &apply).assert_code(2);
    assert_eq!(fs::read(&output).unwrap(), b"existing output");
}

#[test]
fn an_excluded_utf16_credit_is_audited_in_either_byte_order() {
    for (encoding, units) in [
        ("utf16le", (|c: u16| c.to_le_bytes()) as fn(u16) -> [u8; 2]),
        ("utf16be", |c: u16| c.to_be_bytes()),
    ] {
        let fx = Fixture::empty();
        let input = fx.dir.path().join("input.exe");
        let rules = fx.dir.path().join("rules.json");
        let output = fx.dir.path().join("output.exe");
        let mut bytes = common::pe_bytes();
        // Two bullets (U+2022) sit right before the credit: punctuation
        // whose bytes are nonzero in either order, so the credit starts on a
        // word boundary with no zero byte ahead of it.
        bytes.extend(
            "\u{2022}\u{2022}patched by North Star"
                .encode_utf16()
                .chain([0])
                .flat_map(units),
        );
        fs::write(&input, &bytes).unwrap();
        fs::write(
            &rules,
            format!(
                r#"{{"version":1,"exclusions":[{{"kind":"text","value":"North Star","encoding":"{encoding}"}}]}}"#
            ),
        )
        .unwrap();
        let args = |policy: &'static str| {
            vec![
                "deattribute".to_string(),
                input.to_str().unwrap().to_string(),
                "--rules".into(),
                rules.to_str().unwrap().into(),
                "--verify".into(),
                policy.into(),
                "--output".into(),
                output.to_str().unwrap().into(),
                "--json".into(),
            ]
        };
        let strict_args = args("strict");
        let strict_args: Vec<&str> = strict_args.iter().map(String::as_str).collect();
        let strict = run(fx.state.path(), &strict_args);
        strict.assert_code(75);
        assert!(!output.exists(), "{encoding}: {}", strict.stdout);
        let protected_args = args("protected");
        let protected_args: Vec<&str> = protected_args.iter().map(String::as_str).collect();
        let protected = run(fx.state.path(), &protected_args);
        protected.assert_code(0);
        let events = protected.events();
        let report = events
            .iter()
            .find(|e| e["event"] == "verification")
            .unwrap_or_else(|| panic!("{encoding}: {}", protected.stdout));
        let residuals = report["data"]["audit"]["residuals"]
            .as_array()
            .unwrap_or_else(|| panic!("{encoding}: {}", protected.stdout));
        assert!(
            !residuals.is_empty()
                && residuals
                    .iter()
                    .all(|r| r["retained"] == "explicit exclusion"),
            "{encoding}: {}",
            protected.stdout
        );
        assert_eq!(fs::read(&input).unwrap(), bytes, "{encoding}");
    }
}
