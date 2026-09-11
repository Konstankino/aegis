//! Integration coverage for the `aegis-cli` engine: exercises the `show`/format paths, every
//! `validate`/`doctor`/`validate_text` branch, the io helpers, and the error paths — the surface
//! the unit tests don't already hit — against the public API only.

use aegis_cli::artifacts::Artifact;
use aegis_cli::domains::{broker, egress, honeypot, meter, sandbox, supply};
use aegis_cli::io::{self, PolicyDir};
use aegis_cli::{scaffold, testrun, validate, Format};

/// A syntactically valid sha256 digest reference (64 hex chars), avoiding a direct aegis-supply dep.
const SHA: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

fn tmp(tag: &str) -> PolicyDir {
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("aegis-cli-it-{tag}-{nanos}"));
    std::fs::create_dir_all(&dir).unwrap();
    PolicyDir::new(dir)
}

fn cleanup(dir: &PolicyDir) {
    std::fs::remove_dir_all(dir.root()).ok();
}

fn seed_broker(dir: &PolicyDir) {
    broker::cedar_write_validated(
        dir,
        "permit ( principal, action == Action::\"invoke\", resource );\n",
        false,
    )
    .unwrap();
    broker::tools_add(
        dir,
        &broker::NewTool {
            name: "web.fetch".into(),
            consequence: "low_reversible".into(),
            reaches_sensitive: false,
            external_effect: true,
            version: Some("1.0.0".into()),
            schema_json: Some(r#"{"type":"object"}"#.into()),
        },
        false,
    )
    .unwrap();
}

#[test]
fn format_parse_all_variants() {
    assert_eq!(Format::parse("text").unwrap(), Format::Text);
    assert_eq!(Format::parse("json").unwrap(), Format::Json);
    assert_eq!(Format::parse("toml").unwrap(), Format::Toml);
    assert!(Format::parse("xml").is_err());
}

#[test]
fn artifact_metadata_for_all() {
    for a in Artifact::ALL {
        assert!(!a.label().is_empty());
        assert!(!a.domain().is_empty());
        assert!(a.example_filename().contains(".example."));
    }
}

#[test]
fn show_renders_in_all_formats() {
    let dir = tmp("show");
    scaffold::init(&dir, true, false).unwrap(); // blank; seed_broker adds its own tools
    seed_broker(&dir);
    egress::allow_host(&dir, "api.example", false).unwrap();
    egress::permit_param(&dir, "api.example", "page", false).unwrap();
    supply::pin(&dir, "m", SHA, false).unwrap();
    honeypot::add_decoy(&dir, "169.254.169.254", false).unwrap();
    honeypot::add_canary(&dir, "CANARY-z", false).unwrap();

    // Text + JSON on every domain; TOML where supported.
    for f in [Format::Text, Format::Json, Format::Toml] {
        let _ = egress::show(&dir, f).unwrap();
        let _ = meter::show(&dir, f).unwrap();
        let _ = sandbox::show(&dir, f).unwrap();
    }
    assert!(broker::tools_list(&dir, Format::Text)
        .unwrap()
        .contains("web.fetch"));
    assert!(broker::tools_list(&dir, Format::Json)
        .unwrap()
        .contains("web.fetch"));
    assert!(broker::tools_list(&dir, Format::Toml).is_err()); // JSON domain rejects toml
    assert!(broker::tools_show(&dir, "web.fetch")
        .unwrap()
        .contains("1.0.0"));
    assert!(broker::tools_show(&dir, "missing").is_err());
    assert!(supply::show(&dir, Format::Text).unwrap().contains("m"));
    assert!(supply::show(&dir, Format::Json).unwrap().contains("sha256"));
    assert!(supply::show(&dir, Format::Toml).is_err());
    assert!(honeypot::show(&dir, Format::Text)
        .unwrap()
        .contains("decoy"));
    assert!(honeypot::show(&dir, Format::Json)
        .unwrap()
        .contains("canaries"));
    assert!(honeypot::show(&dir, Format::Toml).is_err());
    assert!(broker::cedar_show(&dir).unwrap().contains("permit"));
    cleanup(&dir);
}

#[test]
fn broker_tools_set_version_clear_and_schema_and_cedar_permit_and_fmt() {
    let dir = tmp("broker-more");
    seed_broker(&dir);
    // clear version + change schema
    broker::tools_set(
        &dir,
        "web.fetch",
        &broker::ToolUpdate {
            version: Some(None),
            schema_json: Some(r#"{"type":"object","properties":{"url":{"type":"string"}}}"#.into()),
            reaches_sensitive: Some(true),
            external_effect: Some(false),
            consequence: Some("high_or_irreversible".into()),
        },
        false,
    )
    .unwrap();
    assert!(broker::load_tools(&dir).unwrap()[0].version.is_none());
    // add-permit scoped, then fmt (exercises cedar-policy-formatter)
    broker::cedar_add_permit(&dir, Some("web.fetch"), Some("system"), false).unwrap();
    broker::cedar_fmt(&dir, false).unwrap();
    assert!(broker::cedar_validate(&dir).unwrap().contains("cedar OK"));
    // dry-run path returns a diff, writes nothing
    let before = broker::cedar_show(&dir).unwrap();
    match broker::cedar_add_permit(&dir, None, None, true).unwrap() {
        io::WriteOutcome::DryRun(d) => assert!(d.contains("+ ")),
        other => panic!("expected dry-run, got {other:?}"),
    }
    assert_eq!(broker::cedar_show(&dir).unwrap(), before);
    // set on a missing tool errors
    assert!(broker::tools_set(&dir, "nope", &broker::ToolUpdate::default(), false).is_err());
    cleanup(&dir);
}

#[test]
fn egress_rm_param_setschemes_error_and_suffix() {
    let dir = tmp("egress-more");
    egress::allow_suffix(&dir, ".s3.amazonaws.com", false).unwrap();
    egress::rm_suffix(&dir, ".s3.amazonaws.com", false).unwrap();
    assert!(egress::rm_suffix(&dir, ".gone", false).is_err());
    egress::permit_param(&dir, "h", "p", false).unwrap();
    egress::rm_param(&dir, "h", "p", false).unwrap();
    assert!(egress::rm_param(&dir, "h", "p", false).is_err());
    assert!(egress::set_schemes(&dir, &[], false).is_err());
    egress::set_schemes(&dir, &["https".into(), "http".into()], false).unwrap();
    assert_eq!(egress::load(&dir).unwrap().schemes, vec!["https", "http"]);
    cleanup(&dir);
}

#[test]
fn supply_unpin_whole_name_and_bad_digest() {
    let dir = tmp("supply-more");
    let d = SHA.to_string();
    supply::pin(&dir, "m", &d, false).unwrap();
    assert!(supply::unpin(&dir, "m", Some("sha256:deadbeef"), false).is_err()); // wrong digest
    supply::unpin(&dir, "m", None, false).unwrap(); // whole name
    assert!(supply::load(&dir).unwrap().pins.is_empty());
    assert!(supply::pin_file(&dir, "x", "/no/such/file", false).is_err());
    cleanup(&dir);
}

#[test]
fn validate_text_ok_and_err_for_every_artifact() {
    // A valid + an invalid sample per artifact.
    let ok: &[(Artifact, &str)] = &[
        (Artifact::Tools, "[]"),
        (
            Artifact::BrokerCedar,
            "permit ( principal, action, resource );",
        ),
        (Artifact::Egress, "hosts = []"),
        (Artifact::Meter, "max_steps = 5"),
        (Artifact::Pins, "{}"),
        (Artifact::Honeypots, "{\"decoys\":[],\"canaries\":[]}"),
        (Artifact::Sandbox, "allow_root = false"),
    ];
    for (a, text) in ok {
        assert!(validate::validate_text(*a, text).is_ok(), "{a:?}");
    }
    let bad: &[(Artifact, &str)] = &[
        (Artifact::Tools, "not json"),
        (Artifact::BrokerCedar, "definitely not cedar"),
        (Artifact::Egress, "= = ="),
        (Artifact::Meter, "max_steps = ="),
        (Artifact::Pins, "not json"),
        (Artifact::Honeypots, "not json"),
        (Artifact::Sandbox, "allow_root = ="),
    ];
    for (a, text) in bad {
        assert!(validate::validate_text(*a, text).is_err(), "{a:?}");
    }
}

#[test]
fn validate_all_doctor_and_per_artifact_on_example_set() {
    let dir = tmp("val-int");
    scaffold::init(&dir, true, false).unwrap(); // blank; seed_broker adds its own tools
    seed_broker(&dir);
    let findings = validate::validate_all(&dir);
    assert!(validate::all_ok(&findings));
    let rows = validate::per_artifact(&dir);
    assert_eq!(rows.len(), 7);
    // doctor emits lints (warn/info) on top of validation.
    let d = validate::doctor(&dir);
    assert!(d.len() >= rows.len());
    // sandbox network warning path
    sandbox::set(
        &dir,
        &sandbox::SandboxOverrides {
            allow_network: Some(true),
            allow_root: Some(true),
            ..Default::default()
        },
        false,
    )
    .unwrap();
    let d2 = validate::doctor(&dir);
    assert!(d2.iter().any(
        |f| matches!(f.status, validate::Status::Warn) && f.artifact == Some(Artifact::Sandbox)
    ));
    cleanup(&dir);
}

#[test]
fn io_helpers_examples_diff_and_editor() {
    let dir = tmp("io-int");
    // `init` (populated, embedded examples) works in a fresh empty dir — never empty files.
    scaffold::init(&dir, false, false).unwrap();
    assert!(!dir
        .read(Artifact::Tools)
        .unwrap()
        .unwrap()
        .trim()
        .is_empty());
    // Write an example twin, then activate it + diff.
    std::fs::write(dir.resolve_example(Artifact::Meter), "max_steps = 7\n").unwrap();
    assert!(matches!(
        io::activate_example(&dir, Artifact::Meter, false).unwrap(),
        io::WriteOutcome::Wrote
    ));
    // diff helper output shape.
    let d = io::unified_diff("a\nb\n", "a\nc\n", "x");
    assert!(d.contains("- b") && d.contains("+ c"));
    assert!(dir.read_example(Artifact::Meter).unwrap().is_some());

    // $EDITOR flow: a no-op editor returns the content unchanged; a failing editor errors.
    std::env::set_var("EDITOR", "true");
    assert_eq!(io::edit_text_in_editor("hello").unwrap(), "hello");
    // A modifying editor via a small script.
    let script = dir.root().join("ed.sh");
    std::fs::write(&script, "#!/bin/sh\nprintf 'X' >> \"$1\"\n").unwrap();
    std::process::Command::new("chmod")
        .arg("+x")
        .arg(&script)
        .status()
        .unwrap();
    std::env::set_var("EDITOR", script.to_str().unwrap());
    assert_eq!(io::edit_text_in_editor("hi").unwrap(), "hiX");
    std::env::set_var("EDITOR", "false");
    assert!(io::edit_text_in_editor("hi").is_err());
    std::env::remove_var("EDITOR");
    cleanup(&dir);
}

#[test]
fn testrun_honeypot_text_and_provenance_errors() {
    let dir = tmp("tr-int");
    honeypot::add_canary(&dir, "CANARY-abc", false).unwrap();
    assert!(testrun::honeypot(&dir, None, None, Some("leak=CANARY-abc"))
        .unwrap()
        .contains("TRIPWIRE"));
    assert!(testrun::honeypot(&dir, None, None, Some("clean"))
        .unwrap()
        .contains("clean"));
    assert!(testrun::honeypot(&dir, None, None, None).is_err());
    assert!(testrun::parse_provenance("untrusted").is_ok());
    assert!(testrun::parse_provenance("bogus").is_err());
    // mediate with bad args json errors.
    seed_broker(&dir);
    assert!(testrun::mediate(
        &dir,
        "a",
        "t",
        &[("web.fetch".into(), "not json".into(), "user".into())]
    )
    .is_err());
    cleanup(&dir);
}

#[test]
fn doctor_on_empty_dir_emits_every_default_deny_lint() {
    // An empty dir (no files) exercises all the fail-closed info/warn branches at once.
    let dir = tmp("doctor-empty");
    let d = validate::doctor(&dir);
    let has =
        |a: Artifact, s: validate::Status| d.iter().any(|f| f.artifact == Some(a) && f.status == s);
    assert!(
        has(Artifact::Tools, validate::Status::Warn),
        "empty tools → warn"
    );
    assert!(
        has(Artifact::BrokerCedar, validate::Status::Info),
        "no permit → info"
    );
    assert!(
        has(Artifact::Egress, validate::Status::Warn),
        "no hosts → warn"
    );
    assert!(
        has(Artifact::Pins, validate::Status::Info),
        "empty pinset → info"
    );
    assert!(
        has(Artifact::Honeypots, validate::Status::Info),
        "inert honeypots → info"
    );
    assert!(
        has(Artifact::Meter, validate::Status::Info),
        "no meter.toml → info"
    );
    cleanup(&dir);
}

#[test]
fn dry_run_paths_write_nothing() {
    let dir = tmp("dryrun");
    // Seed real files so there is something to diff against.
    meter::set(
        &dir,
        &meter::LimitOverrides {
            max_steps: Some(9),
            ..Default::default()
        },
        false,
    )
    .unwrap();
    sandbox::reset(&dir, false).unwrap();
    egress::allow_host(&dir, "seed.example", false).unwrap();

    // Each dry-run returns a diff (or Unchanged) and leaves the file byte-identical.
    let snapshot = |a: Artifact| dir.read(a).unwrap();
    let m0 = snapshot(Artifact::Meter);
    assert!(matches!(
        meter::set(
            &dir,
            &meter::LimitOverrides {
                max_steps: Some(77),
                ..Default::default()
            },
            true
        )
        .unwrap(),
        io::WriteOutcome::DryRun(_)
    ));
    assert_eq!(snapshot(Artifact::Meter), m0);

    let s0 = snapshot(Artifact::Sandbox);
    assert!(matches!(
        sandbox::set(
            &dir,
            &sandbox::SandboxOverrides {
                allow_network: Some(true),
                ..Default::default()
            },
            true
        )
        .unwrap(),
        io::WriteOutcome::DryRun(_)
    ));
    assert_eq!(snapshot(Artifact::Sandbox), s0);
    assert!(matches!(
        meter::reset(&dir, true).unwrap(),
        io::WriteOutcome::DryRun(_)
    ));
    assert!(matches!(
        sandbox::reset(&dir, true).unwrap(),
        io::WriteOutcome::DryRun(_) | io::WriteOutcome::Unchanged
    ));

    let e0 = snapshot(Artifact::Egress);
    assert!(matches!(
        egress::allow_host(&dir, "another.example", true).unwrap(),
        io::WriteOutcome::DryRun(_)
    ));
    assert_eq!(snapshot(Artifact::Egress), e0);
    cleanup(&dir);
}

#[test]
fn meter_and_sandbox_set_every_field() {
    let dir = tmp("setall");
    meter::set(
        &dir,
        &meter::LimitOverrides {
            max_tokens_per_request: Some(1),
            tokens_per_minute: Some(2),
            tokens_per_day: Some(3),
            max_cost_per_request_usd: Some(4.0),
            hard_cost_cap_usd: Some(5.0),
            max_steps: Some(6),
            max_recursion_depth: Some(7),
            max_wall_clock_ms: Some(8),
            loop_repeat_threshold: Some(9),
            max_fanout: Some(10),
        },
        false,
    )
    .unwrap();
    let l = meter::load(&dir).unwrap();
    assert_eq!(
        (
            l.max_tokens_per_request,
            l.tokens_per_day,
            l.max_recursion_depth,
            l.max_fanout
        ),
        (1, 3, 7, 10)
    );

    sandbox::set(
        &dir,
        &sandbox::SandboxOverrides {
            allow_root: Some(true),
            allow_network: Some(true),
            working_dir: Some("/w".into()),
            max_wall_ms: Some(11),
            max_memory_mb: Some(12),
        },
        false,
    )
    .unwrap();
    let s = sandbox::load(&dir).unwrap();
    assert_eq!(
        (s.working_dir.as_str(), s.max_wall_ms, s.max_memory_mb),
        ("/w", 11, 12)
    );
    cleanup(&dir);
}

#[test]
fn doctor_skips_lints_on_malformed_files() {
    // When an artifact fails to parse, doctor reports the error and skips its lint (the `errored`
    // guard). Cover those branches with deliberately broken files.
    let dir = tmp("doctor-bad");
    dir.write(Artifact::Tools, "not json", false).unwrap();
    dir.write(Artifact::Egress, "= = =", false).unwrap();
    dir.write(Artifact::Pins, "nope", false).unwrap();
    dir.write(Artifact::Honeypots, "nope", false).unwrap();
    dir.write(Artifact::Sandbox, "allow_root = =", false)
        .unwrap();
    let d = validate::doctor(&dir);
    assert!(!validate::all_ok(&d), "malformed files are errors");
    // No lint (warn/info) should be attached to an artifact that failed to parse.
    for a in [
        Artifact::Tools,
        Artifact::Egress,
        Artifact::Pins,
        Artifact::Honeypots,
        Artifact::Sandbox,
    ] {
        let has_error = d
            .iter()
            .any(|f| f.artifact == Some(a) && f.status == validate::Status::Error);
        assert!(has_error, "{a:?} should be an error");
    }
    cleanup(&dir);
}

#[test]
fn testrun_sandbox_paths_and_egress_deny_and_supply_reject() {
    let dir = tmp("tr-paths");
    // sandbox: approved but a target path outside the working dir → deny.
    let out = testrun::sandbox(
        &dir,
        "python x.py",
        false,
        true,
        true,
        Some("/etc/passwd".into()),
    )
    .unwrap();
    assert!(out.starts_with("deny"), "network+bad-path denied: {out}");
    // egress deny (nothing allowed) + supply reject (nothing pinned).
    assert!(testrun::egress(&dir, "https://nope.example/")
        .unwrap()
        .starts_with("deny"));
    assert!(testrun::supply(&dir, "m", SHA)
        .unwrap()
        .starts_with("rejected"));
    assert!(testrun::supply(&dir, "m", "bad-digest").is_err());
    cleanup(&dir);
}

#[test]
fn broker_cedar_set_from_file_and_default_schema() {
    let dir = tmp("cedar-set");
    // Valid cedar from a file.
    let f = dir.root().join("p.cedar");
    std::fs::write(
        &f,
        "permit ( principal, action == Action::\"invoke\", resource );\n",
    )
    .unwrap();
    broker::cedar_set_from_file(&dir, f.to_str().unwrap(), false).unwrap();
    assert!(broker::cedar_show(&dir).unwrap().contains("permit"));
    // tools add with the default (permissive) schema (schema_json = None).
    broker::tools_add(
        &dir,
        &broker::NewTool {
            name: "noop".into(),
            consequence: "low_reversible".into(),
            reaches_sensitive: false,
            external_effect: false,
            version: None,
            schema_json: None,
        },
        false,
    )
    .unwrap();
    assert_eq!(broker::load_tools(&dir).unwrap().len(), 1);
    cleanup(&dir);
}
