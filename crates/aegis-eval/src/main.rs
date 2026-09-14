//! `aegis-eval` — the CI regression gate (Roadmap T3).
//!
//! Runs the **deterministic** evaluator suite over a file of samples and exits non-zero if any
//! sample fails a threshold — the gate you put in front of a PR. It is model-free by design (fast,
//! reproducible); the LLM-judge evaluators run in a separate, sampled job.
//!
//! ```text
//! aegis-eval <samples.json> [--forbid <t1,t2,...>] [--json]
//! ```
//!
//! `samples.json` is either `{"samples":[<EvalSample>,...]}` or a bare `[<EvalSample>,...]`. Each
//! `EvalSample` carries at least a `response`. Exit codes: 0 all passed · 1 one or more failed ·
//! 2 usage/IO error.

use std::process::ExitCode;

use aegis_eval::{deterministic_evaluators, EvalSample, Report, ThresholdEngine};
use serde::Deserialize;

#[derive(Deserialize)]
struct SamplesFile {
    #[serde(default)]
    samples: Vec<EvalSample>,
}

struct Args {
    path: String,
    forbidden: Vec<String>,
    json: bool,
}

fn parse_args() -> Result<Args, String> {
    let mut path: Option<String> = None;
    let mut forbidden = Vec::new();
    let mut json = false;
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--json" => json = true,
            "--forbid" => {
                let list = it.next().ok_or("--forbid needs a comma-separated value")?;
                forbidden = list
                    .split(',')
                    .map(str::trim)
                    .filter(|s| !s.is_empty())
                    .map(str::to_string)
                    .collect();
            }
            "-h" | "--help" => return Err("help".into()),
            other if other.starts_with('-') => return Err(format!("unknown flag: {other}")),
            other => {
                if path.replace(other.to_string()).is_some() {
                    return Err("only one samples file may be given".into());
                }
            }
        }
    }
    Ok(Args {
        path: path.ok_or("missing <samples.json>")?,
        forbidden,
        json,
    })
}

fn load_samples(path: &str) -> Result<Vec<EvalSample>, String> {
    let src = std::fs::read_to_string(path).map_err(|e| format!("reading {path}: {e}"))?;
    // Accept both {"samples":[...]} and a bare [...] array.
    if let Ok(f) = serde_json::from_str::<SamplesFile>(&src) {
        return Ok(f.samples);
    }
    serde_json::from_str::<Vec<EvalSample>>(&src).map_err(|e| format!("parsing {path}: {e}"))
}

fn main() -> ExitCode {
    let args = match parse_args() {
        Ok(a) => a,
        Err(e) => {
            if e != "help" {
                eprintln!("error: {e}");
            }
            eprintln!("usage: aegis-eval <samples.json> [--forbid <t1,t2,...>] [--json]");
            return ExitCode::from(2);
        }
    };

    let samples = match load_samples(&args.path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("error: {e}");
            return ExitCode::from(2);
        }
    };

    let evaluators = deterministic_evaluators(args.forbidden);
    let engine = ThresholdEngine::new();
    let reports: Vec<Report> = samples.iter().map(|s| engine.run(&evaluators, s)).collect();
    let failed = reports.iter().filter(|r| !r.passed).count();

    if args.json {
        let out = serde_json::json!({
            "total": reports.len(),
            "passed": reports.len() - failed,
            "failed": failed,
            "samples": reports.iter().enumerate().map(|(i, r)| {
                serde_json::json!({ "index": i, "passed": r.passed, "report": r })
            }).collect::<Vec<_>>(),
        });
        println!("{}", serde_json::to_string_pretty(&out).unwrap_or_default());
    } else {
        for (i, r) in reports.iter().enumerate() {
            if !r.passed {
                println!("FAIL  sample #{i} (min score {:.2})", r.min_score());
                for f in r.failures() {
                    println!(
                        "        {} = {:.2} < {:.2}  [{}]  {}",
                        f.evaluator,
                        f.score,
                        f.threshold,
                        f.risk.map(|r| r.code()).unwrap_or("-"),
                        f.reasoning
                    );
                }
            }
        }
        println!(
            "\n{} / {} samples passed{}",
            reports.len() - failed,
            reports.len(),
            if failed == 0 { " ✓" } else { "" }
        );
    }

    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}
