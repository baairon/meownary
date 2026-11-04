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
