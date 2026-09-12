//! `aegis` — the developer policy-management CLI (and TUI launcher).
//!
//! Thin `clap` front-end over the `aegis_cli` engine. Local files only: every command operates on
//! the seven policy artifacts inside `--dir`; there is no network/AWS path and no infrastructure is
//! touched. Running with no subcommand launches the TUI.

use std::io::{IsTerminal, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

use aegis_cli::domains::{broker, egress, honeypot, jit, meter, sandbox, supply};
use aegis_cli::io::WriteOutcome;
use aegis_cli::validate::{self, Status};
use aegis_cli::{scaffold, testrun, tui, Artifact, Format, PolicyDir};

#[derive(Parser)]
#[command(
    name = "aegis",
    version,
    about = "Aegis policy management — author, review, test, and validate policies (local files only)."
)]
struct Cli {
    /// Policy directory (default: $AEGIS_POLICY_DIR or ./policies).
    #[arg(long, global = true)]
    dir: Option<PathBuf>,
    /// Output format for `show`/`list`: text | json | toml.
    #[arg(long, global = true, default_value = "text")]
    format: String,
    /// Print what would change and exit without writing.
    #[arg(long, global = true)]
    dry_run: bool,
    /// Skip confirmation prompts for destructive actions.
    #[arg(long = "yes", short = 'y', global = true)]
    yes: bool,
    /// Disable colored output.
    #[arg(long, global = true)]
    no_color: bool,
    #[command(subcommand)]
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Launch the interactive TUI (also the default with no subcommand).
    Tui,
    /// Scaffold a policy directory with the populated example set (use --blank for safe
    /// default-deny starters).
    Init {
        /// Write empty/default-deny safe starters instead of the populated example set.
        #[arg(long)]
        blank: bool,
    },
    /// Strictly validate every policy artifact (non-zero exit on any error).
    Validate,
    /// Validate + higher-level lints and default-deny notices.
    Doctor,
    /// Show each live artifact vs its `.example.*` twin.
    Diff,
    /// Dry-run a real decision against the current policies.
    Test {
        #[command(subcommand)]
        what: TestCmd,
    },
    /// Broker policies: the tool registry (tools.json) and Cedar (broker.cedar).
    Broker {
        #[command(subcommand)]
        cmd: BrokerCmd,
    },
    /// Egress allowlist (egress-allowlist.toml).
    Egress {
        #[command(subcommand)]
        cmd: EgressCmd,
    },
    /// Meter budget limits (meter.toml).
    Meter {
        #[command(subcommand)]
        cmd: MeterCmd,
    },
    /// Supply-chain pinset (pins.json).
    Supply {
        #[command(subcommand)]
        cmd: SupplyCmd,
    },
    /// Honeypot decoys/canaries (honeypots.json).
    Honeypot {
        #[command(subcommand)]
        cmd: HoneypotCmd,
    },
    /// Sandbox exec policy (sandbox.toml).
    Sandbox {
        #[command(subcommand)]
        cmd: SandboxCmd,
    },
    /// JIT credential grant catalog (grants.toml).
    Jit {
        #[command(subcommand)]
        cmd: JitCmd,
    },
}

#[derive(Subcommand)]
enum TestCmd {
    /// Run a chain of tool calls through the real broker (watch taint accumulate).
    Mediate {
        #[arg(long, default_value = "agent")]
        agent: String,
        #[arg(long, default_value = "thread")]
        thread: String,
        /// A call as `tool=<name>` followed by `args=<json>` and `prov=<provenance>`. Repeatable;
        /// simplest form: `--call web.fetch --args '{"url":"x"}' --prov untrusted`.
        #[arg(long = "call", required = true)]
        calls: Vec<String>,
        #[arg(long = "args")]
        args: Vec<String>,
        #[arg(long = "prov")]
        provs: Vec<String>,
    },
    /// Check a URL against the egress allowlist.
    Egress {
        #[arg(long)]
        url: String,
    },
    /// Verify an artifact digest against the pinset.
    Supply {
        #[arg(long)]
        name: String,
        #[arg(long)]
        digest: String,
    },
    /// Check a command/path for decoys and/or scan outbound text for canaries.
    Honeypot {
        #[arg(long)]
        command: Option<String>,
        #[arg(long)]
        path: Option<String>,
        #[arg(long)]
        text: Option<String>,
    },
    /// Validate a proposed code execution against the sandbox policy.
    Sandbox {
        #[arg(long)]
        command: String,
        #[arg(long)]
        wants_root: bool,
        #[arg(long)]
        wants_network: bool,
        #[arg(long)]
        approved: bool,
        #[arg(long)]
        path: Option<String>,
    },
    /// Dry-run the JIT credential decision for a grant against a signed identity credential —
    /// deterministic, no AWS call. Prints Grant/HumanApprove/Deny + clamped TTL + (STS) session
    /// policy.
    Issue {
        /// The grant id from grants.toml.
        #[arg(long)]
        grant: String,
        /// Path to a JSON-serialized `aegis_identity::Credential` to present.
        #[arg(long)]
        cred: String,
        /// Requested lifetime in seconds (clamped to the grant ceiling and the credential's life).
        #[arg(long, default_value_t = 300)]
        ttl: u64,
        /// The action scope requested (defaults to the grant's required_scope).
        #[arg(long)]
        scope: Option<String>,
        /// Simulated already-accumulated session taint legs, e.g. `--legs AB` (A=untrusted,
        /// B=sensitive, C=external). Lets you preview the trifecta gate.
        #[arg(long)]
        legs: Option<String>,
        /// Clock in Unix ms for the decision (defaults to now).
        #[arg(long)]
        now_ms: Option<u64>,
    },
    /// Run ONE tool call through the whole deterministic gate chain
    /// (ingress → honeypot → broker mediate → egress → sandbox), end to end.
    Pipeline {
        #[arg(long)]
        tool: String,
        #[arg(long, default_value = "{}")]
        args: String,
        #[arg(long, default_value = "untrusted")]
        prov: String,
        /// Untrusted text for the ingress stage (defaults to the args JSON).
        #[arg(long)]
        input: Option<String>,
        /// URL for the egress stage (defaults to args.url).
        #[arg(long)]
        url: Option<String>,
        /// Code/command for the sandbox stage (defaults to args.code/command).
        #[arg(long)]
        command: Option<String>,
    },
}

#[derive(Subcommand)]
enum BrokerCmd {
    /// Tool registry operations.
    Tools {
        #[command(subcommand)]
        cmd: ToolsCmd,
    },
    /// Cedar policy operations.
    Policy {
        #[command(subcommand)]
        cmd: PolicyCmd,
    },
}

#[derive(Subcommand)]
enum ToolsCmd {
    List,
    Show {
        name: String,
    },
    Add {
        name: String,
        #[arg(long, default_value = "low_reversible")]
        consequence: String,
        #[arg(long)]
        reaches_sensitive: bool,
        #[arg(long)]
        external_effect: bool,
        #[arg(long)]
        version: Option<String>,
        /// JSON schema: inline JSON, a file path, or `-` for stdin (default: permissive object).
        #[arg(long)]
        schema: Option<String>,
    },
    Set {
        name: String,
        #[arg(long)]
        consequence: Option<String>,
        #[arg(long)]
        reaches_sensitive: Option<bool>,
        #[arg(long)]
        external_effect: Option<bool>,
        #[arg(long)]
        version: Option<String>,
        #[arg(long)]
        clear_version: bool,
        #[arg(long)]
        schema: Option<String>,
    },
    Rm {
        name: String,
    },
}

#[derive(Subcommand)]
enum PolicyCmd {
    Show,
    Validate,
    Fmt,
    Edit,
    Set {
        file: String,
    },
    AddForbidTool {
        tool: String,
        #[arg(long)]
        when_untrusted: bool,
        #[arg(long)]
        unless_agent: Option<String>,
    },
    AddPermit {
        #[arg(long)]
        tool: Option<String>,
        #[arg(long)]
        agent: Option<String>,
    },
}

#[derive(Subcommand)]
enum EgressCmd {
    Show,
    AllowHost { host: String },
    RmHost { host: String },
    AllowSuffix { suffix: String },
    RmSuffix { suffix: String },
    SetSchemes { schemes: Vec<String> },
    PermitParam { host: String, param: String },
    RmParam { host: String, param: String },
}

#[derive(Subcommand)]
enum MeterCmd {
    Show,
    Reset,
    Set {
        #[arg(long)]
        max_tokens_per_request: Option<u64>,
        #[arg(long)]
        tokens_per_minute: Option<u64>,
        #[arg(long)]
        tokens_per_day: Option<u64>,
        #[arg(long)]
        max_cost_per_request_usd: Option<f64>,
        #[arg(long)]
        hard_cost_cap_usd: Option<f64>,
        #[arg(long)]
        max_steps: Option<u32>,
        #[arg(long)]
        max_recursion_depth: Option<u32>,
        #[arg(long)]
        max_wall_clock_ms: Option<u64>,
        #[arg(long)]
        loop_repeat_threshold: Option<u32>,
        #[arg(long)]
        max_fanout: Option<u32>,
    },
}

#[derive(Subcommand)]
enum SupplyCmd {
    Show,
    Pin {
        name: String,
        digest: String,
    },
    PinFile {
        name: String,
        path: String,
    },
    Unpin {
        name: String,
        digest: Option<String>,
    },
}

#[derive(Subcommand)]
enum HoneypotCmd {
    Show,
    AddDecoy { decoy: String },
    RmDecoy { decoy: String },
    AddCanary { canary: String },
    RmCanary { canary: String },
    GenCanary,
}

#[derive(Subcommand)]
enum SandboxCmd {
    Show,
    Reset,
    Set {
        #[arg(long)]
        allow_root: Option<bool>,
        #[arg(long)]
        allow_network: Option<bool>,
        #[arg(long)]
        working_dir: Option<String>,
        #[arg(long)]
        max_wall_ms: Option<u64>,
        #[arg(long)]
        max_memory_mb: Option<u64>,
    },
}

#[derive(Subcommand)]
enum JitCmd {
    /// List all grants.
    List,
    /// Show one grant by id.
    Show { id: String },
    /// Add (or replace) an STS-session grant.
    AddSts {
        id: String,
        #[arg(long)]
        audience: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        role_arn: String,
        /// A resource ARN this grant may touch (repeatable).
        #[arg(long = "resource")]
        resources: Vec<String>,
        /// Inline session-policy JSON, a file path, or `-` for stdin.
        #[arg(long)]
        session_policy: Option<String>,
        #[arg(long, default_value_t = 300)]
        max_ttl: u64,
        /// Which Rule-of-Two leg: read (sensitive, leg B) or write (external, leg C).
        #[arg(long, default_value = "read")]
        leg: String,
        /// Mark the effect irreversible/high-consequence (always human-approved).
        #[arg(long)]
        irreversible: bool,
    },
    /// Add (or replace) a Secrets Manager grant.
    AddSecret {
        id: String,
        #[arg(long)]
        audience: String,
        #[arg(long)]
        scope: String,
        #[arg(long)]
        secret_arn: String,
        /// Optional JSON key to pluck from the secret value.
        #[arg(long)]
        json_key: Option<String>,
        #[arg(long, default_value_t = 60)]
        max_ttl: u64,
        #[arg(long, default_value = "write")]
        leg: String,
        #[arg(long)]
        irreversible: bool,
    },
    /// Change a grant's TTL ceiling (seconds).
    SetTtl { id: String, secs: u64 },
    /// Remove a grant.
    Rm { id: String },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            let p = Painter::for_stderr(false);
            eprintln!("{} {e:#}", p.paint(Status::Error, "error:"));
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let dir = PolicyDir::new(
        cli.dir
            .or_else(|| std::env::var_os("AEGIS_POLICY_DIR").map(PathBuf::from))
            .unwrap_or_else(|| PathBuf::from("policies")),
    );
    let format = Format::parse(&cli.format)?;
    let dry = cli.dry_run;
    let color = !cli.no_color;

    let Some(command) = cli.command else {
        return tui::run(dir, cli.no_color).map(|()| ExitCode::SUCCESS);
    };

    match command {
        Command::Tui => tui::run(dir, cli.no_color)?,
        Command::Init { blank } => {
            for (a, outcome) in scaffold::init(&dir, blank, dry)? {
                print_outcome(a, &outcome, color);
            }
        }
        Command::Validate => return Ok(report(validate::validate_all(&dir), color)),
        Command::Doctor => return Ok(report(validate::doctor(&dir), color)),
        Command::Diff => diff(&dir)?,
        Command::Test { what } => run_test(&dir, what, color)?,
        Command::Broker { cmd } => run_broker(&dir, cmd, format, dry, cli.yes, color)?,
        Command::Egress { cmd } => run_egress(&dir, cmd, format, dry, cli.yes, color)?,
        Command::Meter { cmd } => run_meter(&dir, cmd, format, dry, cli.yes, color)?,
        Command::Supply { cmd } => run_supply(&dir, cmd, format, dry, cli.yes, color)?,
        Command::Honeypot { cmd } => run_honeypot(&dir, cmd, format, dry, cli.yes, color)?,
        Command::Sandbox { cmd } => run_sandbox(&dir, cmd, format, dry, cli.yes, color)?,
        Command::Jit { cmd } => run_jit(&dir, cmd, format, dry, cli.yes, color)?,
    }
    Ok(ExitCode::SUCCESS)
}

// ── dispatch ────────────────────────────────────────────────────────────────────────────────────

fn run_test(dir: &PolicyDir, what: TestCmd, color: bool) -> Result<()> {
    let p = Painter::for_stdout(color);
    match what {
        TestCmd::Mediate {
            agent,
            thread,
            calls,
            args,
            provs,
        } => {
            if calls.len() != args.len() || calls.len() != provs.len() {
                anyhow::bail!(
                    "each --call needs a matching --args and --prov ({} calls, {} args, {} provs)",
                    calls.len(),
                    args.len(),
                    provs.len()
                );
            }
            let chain: Vec<(String, String, String)> = calls
                .into_iter()
                .zip(args)
                .zip(provs)
                .map(|((c, a), pr)| (c, a, pr))
                .collect();
            let trace = testrun::mediate(dir, &agent, &thread, &chain)?;
            for (i, step) in trace.steps.iter().enumerate() {
                let status = match step.decision.as_str() {
                    "allow" => Status::Ok,
                    "human_approve" => Status::Warn,
                    _ => Status::Error,
                };
                let legs = format!(
                    "A={} B={} C={}{}",
                    step.cap.reads_untrusted as u8,
                    step.cap.reads_sensitive as u8,
                    step.cap.external_effect as u8,
                    if step.cap.is_trifecta() {
                        " TRIFECTA"
                    } else {
                        ""
                    },
                );
                println!(
                    "{}. {:<20} {}  [{}]{}",
                    i + 1,
                    step.tool,
                    p.paint(status, &step.decision),
                    legs,
                    step.reason
                        .as_deref()
                        .map(|r| format!("  {r}"))
                        .unwrap_or_default(),
                );
            }
        }
        TestCmd::Egress { url } => println!("{}", testrun::egress(dir, &url)?),
        TestCmd::Supply { name, digest } => println!("{}", testrun::supply(dir, &name, &digest)?),
        TestCmd::Honeypot {
            command,
            path,
            text,
        } => print!(
            "{}",
            testrun::honeypot(dir, command.as_deref(), path.as_deref(), text.as_deref())?
        ),
        TestCmd::Sandbox {
            command,
            wants_root,
            wants_network,
            approved,
            path,
        } => println!(
            "{}",
            testrun::sandbox(dir, &command, wants_root, wants_network, approved, path)?
        ),
        TestCmd::Issue {
            grant,
            cred,
            ttl,
            scope,
            legs,
            now_ms,
        } => {
            let t = testrun::issue(
                dir,
                &grant,
                &cred,
                ttl,
                scope.as_deref(),
                legs.as_deref(),
                now_ms,
            )?;
            let status = match t.decision.as_str() {
                "grant" => Status::Ok,
                "human_approve" => Status::Warn,
                _ => Status::Error,
            };
            println!(
                "grant {} [{}]  {}  {}",
                t.grant_id,
                t.provider,
                p.paint(status, &t.decision),
                t.detail
            );
            if let Some(policy) = &t.session_policy {
                println!("  session policy (rendered):");
                for line in policy.trim().lines() {
                    println!("    {line}");
                }
            }
        }
        TestCmd::Pipeline {
            tool,
            args,
            prov,
            input,
            url,
            command,
        } => {
            let trace = testrun::pipeline(
                dir,
                &testrun::PipelineInput {
                    tool,
                    args_json: args,
                    prov,
                    input,
                    url,
                    command,
                },
            )?;
            for (i, s) in trace.stages.iter().enumerate() {
                let status = match s.verdict.as_str() {
                    "allow" | "ok" => Status::Ok,
                    "human_approve" => Status::Warn,
                    "deny" | "tripwire" => Status::Error,
                    _ => Status::Info, // skip
                };
                println!(
                    "{}. {:<26} {:<14} {}",
                    i + 1,
                    s.name,
                    p.paint(status, &s.verdict),
                    s.detail
                );
            }
            let ostatus = match trace.outcome.as_str() {
                "ALLOWED" => Status::Ok,
                "NEEDS HUMAN APPROVAL" => Status::Warn,
                _ => Status::Error,
            };
            println!("→ {}", p.paint(ostatus, &trace.outcome));
        }
    }
    Ok(())
}

fn run_broker(
    dir: &PolicyDir,
    cmd: BrokerCmd,
    format: Format,
    dry: bool,
    yes: bool,
    color: bool,
) -> Result<()> {
    match cmd {
        BrokerCmd::Tools { cmd } => match cmd {
            ToolsCmd::List => print!("{}", broker::tools_list(dir, format)?),
            ToolsCmd::Show { name } => print!("{}", broker::tools_show(dir, &name)?),
            ToolsCmd::Add {
                name,
                consequence,
                reaches_sensitive,
                external_effect,
                version,
                schema,
            } => {
                let new = broker::NewTool {
                    name,
                    consequence,
                    reaches_sensitive,
                    external_effect,
                    version,
                    schema_json: resolve_schema(schema)?,
                };
                let out = broker::tools_add(dir, &new, dry)?;
                print_outcome(Artifact::Tools, &out, color);
            }
            ToolsCmd::Set {
                name,
                consequence,
                reaches_sensitive,
                external_effect,
                version,
                clear_version,
                schema,
            } => {
                let up = broker::ToolUpdate {
                    consequence,
                    reaches_sensitive,
                    external_effect,
                    version: if clear_version {
                        Some(None)
                    } else {
                        version.map(Some)
                    },
                    schema_json: resolve_schema(schema)?,
                };
                let out = broker::tools_set(dir, &name, &up, dry)?;
                print_outcome(Artifact::Tools, &out, color);
            }
            ToolsCmd::Rm { name } => {
                if confirm(&format!("remove tool '{name}'?"), yes)? {
                    let out = broker::tools_rm(dir, &name, dry)?;
                    print_outcome(Artifact::Tools, &out, color);
                }
            }
        },
        BrokerCmd::Policy { cmd } => match cmd {
            PolicyCmd::Show => print!("{}", broker::cedar_show(dir)?),
            PolicyCmd::Validate => {
                let p = Painter::for_stdout(color);
                println!(
                    "{} {}",
                    p.paint(Status::Ok, "ok"),
                    broker::cedar_validate(dir)?
                );
            }
            PolicyCmd::Fmt => {
                print_outcome(Artifact::BrokerCedar, &broker::cedar_fmt(dir, dry)?, color)
            }
            PolicyCmd::Edit => {
                let seed = aegis_cli::domains::edit_seed(dir, Artifact::BrokerCedar)?;
                let edited = aegis_cli::io::edit_text_in_editor(&seed)?;
                let out = broker::cedar_write_validated(dir, &edited, dry)?;
                print_outcome(Artifact::BrokerCedar, &out, color);
            }
            PolicyCmd::Set { file } => {
                let out = broker::cedar_set_from_file(dir, &file, dry)?;
                print_outcome(Artifact::BrokerCedar, &out, color);
            }
            PolicyCmd::AddForbidTool {
                tool,
                when_untrusted,
                unless_agent,
            } => {
                let out = broker::cedar_add_forbid_tool(
                    dir,
                    &tool,
                    when_untrusted,
                    unless_agent.as_deref(),
                    dry,
                )?;
                print_outcome(Artifact::BrokerCedar, &out, color);
            }
            PolicyCmd::AddPermit { tool, agent } => {
                let out = broker::cedar_add_permit(dir, tool.as_deref(), agent.as_deref(), dry)?;
                print_outcome(Artifact::BrokerCedar, &out, color);
            }
        },
    }
    Ok(())
}

fn run_egress(
    dir: &PolicyDir,
    cmd: EgressCmd,
    format: Format,
    dry: bool,
    yes: bool,
    color: bool,
) -> Result<()> {
    let out = match cmd {
        EgressCmd::Show => {
            print!("{}", egress::show(dir, format)?);
            return Ok(());
        }
        EgressCmd::AllowHost { host } => egress::allow_host(dir, &host, dry)?,
        EgressCmd::RmHost { host } => {
            if !confirm(&format!("remove host '{host}'?"), yes)? {
                return Ok(());
            }
            egress::rm_host(dir, &host, dry)?
        }
        EgressCmd::AllowSuffix { suffix } => egress::allow_suffix(dir, &suffix, dry)?,
        EgressCmd::RmSuffix { suffix } => {
            if !confirm(&format!("remove suffix '{suffix}'?"), yes)? {
                return Ok(());
            }
            egress::rm_suffix(dir, &suffix, dry)?
        }
        EgressCmd::SetSchemes { schemes } => egress::set_schemes(dir, &schemes, dry)?,
        EgressCmd::PermitParam { host, param } => egress::permit_param(dir, &host, &param, dry)?,
        EgressCmd::RmParam { host, param } => egress::rm_param(dir, &host, &param, dry)?,
    };
    print_outcome(Artifact::Egress, &out, color);
    Ok(())
}

fn run_meter(
    dir: &PolicyDir,
    cmd: MeterCmd,
    format: Format,
    dry: bool,
    yes: bool,
    color: bool,
) -> Result<()> {
    match cmd {
        MeterCmd::Show => print!("{}", meter::show(dir, format)?),
        MeterCmd::Reset => {
            if confirm("reset meter.toml to defaults?", yes)? {
                print_outcome(Artifact::Meter, &meter::reset(dir, dry)?, color);
            }
        }
        MeterCmd::Set {
            max_tokens_per_request,
            tokens_per_minute,
            tokens_per_day,
            max_cost_per_request_usd,
            hard_cost_cap_usd,
            max_steps,
            max_recursion_depth,
            max_wall_clock_ms,
            loop_repeat_threshold,
            max_fanout,
        } => {
            let ov = meter::LimitOverrides {
                max_tokens_per_request,
                tokens_per_minute,
                tokens_per_day,
                max_cost_per_request_usd,
                hard_cost_cap_usd,
                max_steps,
                max_recursion_depth,
                max_wall_clock_ms,
                loop_repeat_threshold,
                max_fanout,
            };
            print_outcome(Artifact::Meter, &meter::set(dir, &ov, dry)?, color);
        }
    }
    Ok(())
}

fn run_supply(
    dir: &PolicyDir,
    cmd: SupplyCmd,
    format: Format,
    dry: bool,
    yes: bool,
    color: bool,
) -> Result<()> {
    let out = match cmd {
        SupplyCmd::Show => {
            print!("{}", supply::show(dir, format)?);
            return Ok(());
        }
        SupplyCmd::Pin { name, digest } => supply::pin(dir, &name, &digest, dry)?,
        SupplyCmd::PinFile { name, path } => supply::pin_file(dir, &name, &path, dry)?,
        SupplyCmd::Unpin { name, digest } => {
            if !confirm(&format!("unpin '{name}'?"), yes)? {
                return Ok(());
            }
            supply::unpin(dir, &name, digest.as_deref(), dry)?
        }
    };
    print_outcome(Artifact::Pins, &out, color);
    Ok(())
}

fn run_honeypot(
    dir: &PolicyDir,
    cmd: HoneypotCmd,
    format: Format,
    dry: bool,
    yes: bool,
    color: bool,
) -> Result<()> {
    let out = match cmd {
        HoneypotCmd::Show => {
            print!("{}", honeypot::show(dir, format)?);
            return Ok(());
        }
        HoneypotCmd::AddDecoy { decoy } => honeypot::add_decoy(dir, &decoy, dry)?,
        HoneypotCmd::RmDecoy { decoy } => {
            if !confirm(&format!("remove decoy '{decoy}'?"), yes)? {
                return Ok(());
            }
            honeypot::rm_decoy(dir, &decoy, dry)?
        }
        HoneypotCmd::AddCanary { canary } => honeypot::add_canary(dir, &canary, dry)?,
        HoneypotCmd::RmCanary { canary } => {
            if !confirm(&format!("remove canary '{canary}'?"), yes)? {
                return Ok(());
            }
            honeypot::rm_canary(dir, &canary, dry)?
        }
        HoneypotCmd::GenCanary => {
            let (token, out) = honeypot::gen_canary(dir, dry)?;
            println!("{token}");
            out
        }
    };
    print_outcome(Artifact::Honeypots, &out, color);
    Ok(())
}

fn run_sandbox(
    dir: &PolicyDir,
    cmd: SandboxCmd,
    format: Format,
    dry: bool,
    yes: bool,
    color: bool,
) -> Result<()> {
    match cmd {
        SandboxCmd::Show => print!("{}", sandbox::show(dir, format)?),
        SandboxCmd::Reset => {
            if confirm("reset sandbox.toml to the locked-down default?", yes)? {
                print_outcome(Artifact::Sandbox, &sandbox::reset(dir, dry)?, color);
            }
        }
        SandboxCmd::Set {
            allow_root,
            allow_network,
            working_dir,
            max_wall_ms,
            max_memory_mb,
        } => {
            let ov = sandbox::SandboxOverrides {
                allow_root,
                allow_network,
                working_dir,
                max_wall_ms,
                max_memory_mb,
            };
            print_outcome(Artifact::Sandbox, &sandbox::set(dir, &ov, dry)?, color);
        }
    }
    Ok(())
}

fn parse_leg(s: &str) -> Result<jit::Leg> {
    match s.to_ascii_lowercase().as_str() {
        "read" | "b" => Ok(jit::Leg::Read),
        "write" | "c" => Ok(jit::Leg::Write),
        other => anyhow::bail!("invalid --leg '{other}' (expected read|write)"),
    }
}

fn run_jit(
    dir: &PolicyDir,
    cmd: JitCmd,
    format: Format,
    dry: bool,
    yes: bool,
    color: bool,
) -> Result<()> {
    match cmd {
        JitCmd::List => print!("{}", jit::show(dir, format)?),
        JitCmd::Show { id } => print!("{}", jit::show_one(dir, &id, format)?),
        JitCmd::AddSts {
            id,
            audience,
            scope,
            role_arn,
            resources,
            session_policy,
            max_ttl,
            leg,
            irreversible,
        } => {
            let spec = jit::StsGrantSpec {
                id,
                audience,
                scope,
                role_arn,
                resource_arns: resources,
                session_policy_template: resolve_schema(session_policy)?.unwrap_or_default(),
                max_ttl_secs: max_ttl,
                leg: parse_leg(&leg)?,
                irreversible,
            };
            print_outcome(Artifact::Grants, &jit::add_sts(dir, spec, dry)?, color);
        }
        JitCmd::AddSecret {
            id,
            audience,
            scope,
            secret_arn,
            json_key,
            max_ttl,
            leg,
            irreversible,
        } => {
            let spec = jit::SecretGrantSpec {
                id,
                audience,
                scope,
                secret_arn,
                json_key,
                max_ttl_secs: max_ttl,
                leg: parse_leg(&leg)?,
                irreversible,
            };
            print_outcome(Artifact::Grants, &jit::add_secret(dir, spec, dry)?, color);
        }
        JitCmd::SetTtl { id, secs } => {
            print_outcome(Artifact::Grants, &jit::set_ttl(dir, &id, secs, dry)?, color);
        }
        JitCmd::Rm { id } => {
            if confirm(&format!("remove grant '{id}'?"), yes)? {
                print_outcome(Artifact::Grants, &jit::rm(dir, &id, dry)?, color);
            }
        }
    }
    Ok(())
}

// ── shared helpers ──────────────────────────────────────────────────────────────────────────────

/// Resolve a `--schema` value: `-` = stdin, an existing path = file, else inline JSON.
fn resolve_schema(schema: Option<String>) -> Result<Option<String>> {
    let Some(s) = schema else { return Ok(None) };
    if s == "-" {
        let mut buf = String::new();
        std::io::Read::read_to_string(&mut std::io::stdin(), &mut buf)
            .context("reading schema from stdin")?;
        Ok(Some(buf))
    } else if std::path::Path::new(&s).is_file() {
        Ok(Some(
            std::fs::read_to_string(&s).with_context(|| format!("reading schema file {s}"))?,
        ))
    } else {
        Ok(Some(s))
    }
}

/// Print the result of a write, colored.
fn print_outcome(artifact: Artifact, outcome: &WriteOutcome, color: bool) {
    let p = Painter::for_stdout(color);
    match outcome {
        WriteOutcome::Wrote => {
            println!("{} wrote {}", p.paint(Status::Ok, "✓"), artifact.filename())
        }
        WriteOutcome::Unchanged => println!(
            "{} {} unchanged",
            p.paint(Status::Info, "="),
            artifact.filename()
        ),
        WriteOutcome::DryRun(diff) => {
            println!(
                "{} dry-run — {} would change:",
                p.paint(Status::Warn, "~"),
                artifact.filename()
            );
            print!("{diff}");
        }
    }
}

/// Print validate/doctor findings; return an exit code (failure if any error).
fn report(findings: Vec<validate::Finding>, color: bool) -> ExitCode {
    let p = Painter::for_stdout(color);
    let mut ok = true;
    for f in &findings {
        let (tag, label) = match f.status {
            Status::Ok => ("ok  ", Status::Ok),
            Status::Info => ("info", Status::Info),
            Status::Warn => ("warn", Status::Warn),
            Status::Error => {
                ok = false;
                ("FAIL", Status::Error)
            }
        };
        let name = f.artifact.map(|a| a.filename()).unwrap_or("(cross-check)");
        println!("{}  {:<22} {}", p.paint(label, tag), name, f.message);
    }
    if ok {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

/// Show each artifact vs its `.example.*` twin.
fn diff(dir: &PolicyDir) -> Result<()> {
    let mut any = false;
    for a in Artifact::ALL {
        if let (Some(live), Some(example)) = (dir.read(a)?, dir.read_example(a)?) {
            if live != example {
                any = true;
                print!(
                    "{}",
                    aegis_cli::io::unified_diff(&example, &live, a.filename())
                );
                println!();
            }
        }
    }
    if !any {
        println!("no differences between live artifacts and their .example twins");
    }
    Ok(())
}

/// Prompt for confirmation on a destructive action (auto-yes when `--yes` or non-interactive stdin).
fn confirm(prompt: &str, yes: bool) -> Result<bool> {
    if yes || !std::io::stdin().is_terminal() {
        return Ok(true);
    }
    print!("{prompt} [y/N] ");
    std::io::stdout().flush().ok();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line)?;
    Ok(matches!(line.trim(), "y" | "Y" | "yes"))
}

/// Minimal ANSI colorizer honoring `--no-color`, `NO_COLOR`, and TTY detection.
struct Painter {
    enabled: bool,
}

impl Painter {
    fn new(color_flag: bool, is_tty: bool) -> Self {
        let enabled = color_flag && is_tty && std::env::var_os("NO_COLOR").is_none();
        Self { enabled }
    }
    fn for_stdout(color_flag: bool) -> Self {
        Self::new(color_flag, std::io::stdout().is_terminal())
    }
    fn for_stderr(color_flag: bool) -> Self {
        Self::new(color_flag, std::io::stderr().is_terminal())
    }
    fn paint(&self, status: Status, text: &str) -> String {
        if !self.enabled {
            return text.to_string();
        }
        let code = match status {
            Status::Ok => "32",
            Status::Info => "36",
            Status::Warn => "33",
            Status::Error => "31",
        };
        format!("\x1b[{code}m{text}\x1b[0m")
    }
}
