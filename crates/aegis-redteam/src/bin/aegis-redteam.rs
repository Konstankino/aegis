//! `aegis-redteam` — run the adaptive attack suite as a CI release gate.
//!
//! Exits non-zero if any attack breaches a control, so nothing ships on a static benchmark
//! alone (architecture-considerations.md §5). Pass `--json` for machine-readable output.
//!
//! ```bash
//! cargo run -p aegis-redteam            # human-readable, exit 1 on breach
//! cargo run -p aegis-redteam -- --json  # JSON report
//! ```

use std::process::ExitCode;

fn main() -> ExitCode {
    let json = std::env::args().any(|a| a == "--json");
    let report = aegis_redteam::run_suite(&aegis_redteam::default_suite());

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        println!("Aegis red-team — adaptive attack suite\n");
        for r in &report.results {
            let mark = if r.contained {
                "✅ contained"
            } else {
                "❌ BREACH   "
            };
            println!("  {mark}  [{:?}] {}", r.category, r.name);
            println!("               {}", r.note);
        }
        println!(
            "\n{} contained / {} breached (of {})",
            report.passed(),
            report.failed(),
            report.results.len()
        );
    }

    match report.gate() {
        Ok(()) => {
            if !json {
                println!("GATE: PASS — every adaptive attack was contained.");
            }
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("GATE: FAIL — {e}");
            ExitCode::FAILURE
        }
    }
}
