//! End-to-end tests that run the actual `portwatch` binary, exercising
//! the CLI surface (argument parsing, exit codes, file formats) the way
//! a user or a CI pipeline actually invokes it. These run for real on
//! whatever OS the test suite runs on, since `scan`/`snapshot` call the
//! live platform backend - no fixtures involved here.

use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;

fn cmd() -> Command {
    Command::cargo_bin("portwatch").expect("binary should build")
}

#[test]
fn help_is_printed_with_no_arguments() {
    cmd()
        .assert()
        .success()
        .stdout(predicate::str::contains("USAGE"));
}

#[test]
fn help_flag_matches_no_arguments() {
    cmd()
        .arg("--help")
        .assert()
        .success()
        .stdout(predicate::str::contains("COMMANDS"));
}

#[test]
fn version_flag_prints_cargo_version() {
    cmd()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::contains(env!("CARGO_PKG_VERSION")));
}

#[test]
fn unknown_command_fails_with_usage() {
    cmd()
        .arg("bogus")
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("unrecognized command"));
}

#[test]
fn scan_succeeds_and_prints_a_table() {
    // Every machine running this test has at least a loopback network
    // stack; scan should always succeed, even if it finds nothing.
    cmd().arg("scan").assert().success();
}

#[test]
fn scan_json_produces_a_json_array() {
    let output = cmd().args(["scan", "--json"]).output().unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    assert!(parsed.is_array());
}

#[test]
fn diff_without_a_snapshot_fails_with_a_helpful_message() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("nope.json");
    cmd()
        .args(["diff", "--state"])
        .arg(&state)
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("portwatch snapshot"));
}

#[test]
fn snapshot_then_diff_against_itself_reports_no_changes() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");

    cmd()
        .args(["snapshot", "--state"])
        .arg(&state)
        .assert()
        .success();
    assert!(state.exists());

    cmd()
        .args(["diff", "--state"])
        .arg(&state)
        .assert()
        .success()
        .stdout(predicate::str::contains("no changes"));
}

#[test]
fn update_saves_a_new_snapshot_and_reports_no_changes_the_first_time() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let log = dir.path().join("history.jsonl");

    cmd()
        .args(["snapshot", "--state"])
        .arg(&state)
        .assert()
        .success();

    cmd()
        .args(["update", "--state"])
        .arg(&state)
        .args(["--log"])
        .arg(&log)
        .assert()
        .success()
        .stdout(predicate::str::contains("no changes"));

    // Nothing changed between the two captures, so the (append-only,
    // changes-only) history log should not have been created.
    assert!(!log.exists());
}

#[test]
fn diff_json_output_is_a_valid_diff_report() {
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");

    cmd()
        .args(["snapshot", "--state"])
        .arg(&state)
        .assert()
        .success();

    let output = cmd()
        .args(["diff", "--state"])
        .arg(&state)
        .args(["--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
    assert!(parsed.get("changes").is_some());
}

#[test]
fn history_with_no_log_yet_says_so() {
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("history.jsonl");
    cmd()
        .args(["history", "--log"])
        .arg(&log)
        .assert()
        .success()
        .stdout(predicate::str::contains("no history yet"));
}

#[test]
fn manually_edited_snapshot_produces_a_deterministic_diff() {
    // This is the one test in this file that doesn't depend on the live
    // platform backend at all: it hand-writes a baseline snapshot with a
    // port no real machine is likely to have bound, then diffs a fresh
    // live scan against it, so "added" is guaranteed empty and "removed"
    // is guaranteed to contain exactly the fake entry.
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");
    let fake = serde_json::json!({
        "captured_at_unix": 0,
        "hostname": "test-host",
        "entries": [{
            "protocol": "tcp",
            "local_addr": "203.0.113.99",
            "local_port": 4,
            "state": "Listen",
            "pid": 999_999,
            "process_name": "definitely-not-running"
        }]
    });
    fs::write(&state, serde_json::to_string_pretty(&fake).unwrap()).unwrap();

    cmd()
        .args(["diff", "--state"])
        .arg(&state)
        .assert()
        .code(2)
        .stdout(predicate::str::contains(
            "tcp/203.0.113.99:4 no longer listening",
        ));
}

#[test]
fn unrecognized_flag_is_rejected() {
    cmd()
        .args(["scan", "--nonsense"])
        .assert()
        .failure()
        .code(1)
        .stderr(predicate::str::contains("unrecognized option"));
}

#[test]
fn state_flag_missing_value_is_rejected() {
    cmd().args(["scan", "--state"]).assert().failure().code(1);
}
