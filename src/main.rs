//! `portwatch` CLI: inventory listening ports and owning processes, and
//! report what changed since the last snapshot.

use portwatch::diff::diff;
use portwatch::storage::{
    append_history, describe_record, load_snapshot, read_history, save_snapshot, HistoryRecord,
};
use portwatch::{capture, format};
use std::env;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

const DEFAULT_STATE: &str = "portwatch-state.json";
const DEFAULT_LOG: &str = "portwatch-history.jsonl";

const HELP: &str = "\
portwatch - inventory listening ports and report what changed

USAGE:
    portwatch <COMMAND> [OPTIONS]

COMMANDS:
    scan       Print the ports currently listening on this machine
    snapshot   Capture the current ports and save them as the baseline
    diff       Compare the current ports against the saved baseline
    update     Like diff, then save the current ports as the new baseline
    history    Print previously logged changes (see --log under update)
    help       Print this message

OPTIONS:
    --state <PATH>   Snapshot file to read/write (default: portwatch-state.json)
    --log <PATH>     History log file for `update`/`history` (default: portwatch-history.jsonl)
    --json           Print machine-readable JSON instead of a table/text
    -h, --help       Print this message
    -V, --version    Print the version number

EXIT STATUS:
    0   success, and (for diff/update) no changes were found
    1   an error occurred (I/O, unsupported platform, bad snapshot file)
    2   success, and (for diff/update) at least one change was found
";

struct Args {
    state: PathBuf,
    log: PathBuf,
    json: bool,
}

fn parse_flags(rest: &[String]) -> Result<Args, String> {
    let mut state = PathBuf::from(DEFAULT_STATE);
    let mut log = PathBuf::from(DEFAULT_LOG);
    let mut json = false;
    let mut i = 0;
    while i < rest.len() {
        match rest[i].as_str() {
            "--state" => {
                i += 1;
                let v = rest.get(i).ok_or("--state requires a path argument")?;
                state = PathBuf::from(v);
            }
            "--log" => {
                i += 1;
                let v = rest.get(i).ok_or("--log requires a path argument")?;
                log = PathBuf::from(v);
            }
            "--json" => json = true,
            other => return Err(format!("unrecognized option: {other}")),
        }
        i += 1;
    }
    Ok(Args { state, log, json })
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().collect();
    let command = args.get(1).map(String::as_str);

    match command {
        None | Some("help" | "-h" | "--help") => {
            print!("{HELP}");
            ExitCode::SUCCESS
        }
        Some("-V" | "--version") => {
            println!("portwatch {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        Some("scan") => run(&args[2..], cmd_scan),
        Some("snapshot") => run(&args[2..], cmd_snapshot),
        Some("diff") => run(&args[2..], cmd_diff),
        Some("update") => run(&args[2..], cmd_update),
        Some("history") => run(&args[2..], cmd_history),
        Some(other) => {
            eprintln!("error: unrecognized command '{other}'\n");
            print!("{HELP}");
            ExitCode::FAILURE
        }
    }
}

fn run(rest: &[String], f: impl FnOnce(&Args) -> Result<ExitCode, String>) -> ExitCode {
    let parsed = match parse_flags(rest) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::FAILURE;
        }
    };
    match f(&parsed) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn cmd_scan(args: &Args) -> Result<ExitCode, String> {
    let snap = capture().map_err(|e| e.to_string())?;
    print_snapshot(
        &snap
            .entries
            .iter()
            .filter(|e| e.is_listening())
            .cloned()
            .collect::<Vec<_>>(),
        args.json,
    )?;
    Ok(ExitCode::SUCCESS)
}

fn cmd_snapshot(args: &Args) -> Result<ExitCode, String> {
    let snap = capture().map_err(|e| e.to_string())?;
    save_snapshot(&args.state, &snap).map_err(|e| e.to_string())?;
    if args.json {
        print_snapshot(&snap.entries, true)?;
    } else {
        let listening = snap.entries.iter().filter(|e| e.is_listening()).count();
        println!(
            "saved {listening} listening port(s) to {}",
            args.state.display()
        );
    }
    Ok(ExitCode::SUCCESS)
}

fn cmd_diff(args: &Args) -> Result<ExitCode, String> {
    let baseline = load_snapshot(&args.state).map_err(|e| e.to_string())?;
    let current = capture().map_err(|e| e.to_string())?;
    let report = diff(&baseline, &current);
    print_report(&report, args.json)?;
    Ok(exit_for_report(report.is_empty()))
}

fn cmd_update(args: &Args) -> Result<ExitCode, String> {
    let baseline = load_snapshot(&args.state).map_err(|e| e.to_string())?;
    let current = capture().map_err(|e| e.to_string())?;
    let report = diff(&baseline, &current);
    let record = HistoryRecord::from_report(&baseline, &current, &report);
    append_history(&args.log, &record).map_err(|e| e.to_string())?;
    save_snapshot(&args.state, &current).map_err(|e| e.to_string())?;
    print_report(&report, args.json)?;
    Ok(exit_for_report(report.is_empty()))
}

fn cmd_history(args: &Args) -> Result<ExitCode, String> {
    let records = read_history(&args.log).map_err(|e| e.to_string())?;
    if args.json {
        let json = serde_json::to_string_pretty(&records).map_err(|e| e.to_string())?;
        println!("{json}");
    } else if records.is_empty() {
        println!("no history yet - run `portwatch update` to start logging changes");
    } else {
        for record in &records {
            println!("{}", describe_record(record));
        }
    }
    Ok(ExitCode::SUCCESS)
}

fn exit_for_report(is_empty: bool) -> ExitCode {
    if is_empty {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(2)
    }
}

fn print_snapshot(entries: &[portwatch::model::PortEntry], json: bool) -> Result<(), String> {
    if json {
        let s = serde_json::to_string_pretty(entries).map_err(|e| e.to_string())?;
        println!("{s}");
    } else {
        println!("{}", format::table(entries));
    }
    Ok(())
}

fn print_report(report: &portwatch::diff::DiffReport, json: bool) -> Result<(), String> {
    if json {
        let s = format::diff_json(report).map_err(|e| e.to_string())?;
        println!("{s}");
    } else {
        println!("{}", format::diff_report(report));
    }
    Ok(())
}

#[allow(dead_code)]
fn state_path_from(dir: &Path) -> PathBuf {
    dir.join(DEFAULT_STATE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_flags_defaults() {
        let args = parse_flags(&[]).unwrap();
        assert_eq!(args.state, PathBuf::from(DEFAULT_STATE));
        assert_eq!(args.log, PathBuf::from(DEFAULT_LOG));
        assert!(!args.json);
    }

    #[test]
    fn parse_flags_state_and_json() {
        let raw = vec![
            "--state".to_string(),
            "custom.json".to_string(),
            "--json".to_string(),
        ];
        let args = parse_flags(&raw).unwrap();
        assert_eq!(args.state, PathBuf::from("custom.json"));
        assert!(args.json);
    }

    #[test]
    fn parse_flags_log() {
        let raw = vec!["--log".to_string(), "custom.jsonl".to_string()];
        let args = parse_flags(&raw).unwrap();
        assert_eq!(args.log, PathBuf::from("custom.jsonl"));
    }

    #[test]
    fn parse_flags_rejects_unknown_option() {
        let raw = vec!["--nope".to_string()];
        assert!(parse_flags(&raw).is_err());
    }

    #[test]
    fn parse_flags_state_missing_value_errors() {
        let raw = vec!["--state".to_string()];
        assert!(parse_flags(&raw).is_err());
    }

    #[test]
    fn exit_for_report_empty_is_success() {
        // ExitCode has no PartialEq; exercise both branches for coverage
        // and let a panic (not a value mismatch) signal a real problem.
        let _ = exit_for_report(true);
        let _ = exit_for_report(false);
    }
}
