//! # aegis-cli — the policy-management engine
//!
//! Developer tooling to author, review, test, and validate the Aegis policy artifacts, so policy
//! management is **easy and error-free**. Every mutation round-trips through the owning crate's own
//! types (parse → mutate → serialize → **re-validate** → atomic write), so the tool can never emit
//! a file the runtime would reject.
//!
//! **Blast radius (enforced):** the tool touches only the seven local policy artifacts inside the
//! chosen `--dir` (see [`artifacts::Artifact`] + [`io::PolicyDir`]). It takes no AWS/network
//! dependency and never reads or writes infrastructure files or source.
//!
//! This `lib` is UI-free: both the `clap` subcommands (`main.rs`) and the TUI (`tui`) call *only*
//! into here, so the logic is unit-tested in one place.

pub mod artifacts;
pub mod domains;
pub mod io;
pub mod scaffold;
pub mod testrun;
pub mod tui;
pub mod validate;

pub use artifacts::Artifact;
pub use io::{PolicyDir, WriteOutcome};

/// How a `show`/`get` result is rendered.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Format {
    /// Human-readable text (the default).
    #[default]
    Text,
    /// The artifact's canonical JSON form.
    Json,
    /// The artifact's canonical TOML form.
    Toml,
}

impl Format {
    /// Parse a `--format` value.
    pub fn parse(s: &str) -> anyhow::Result<Format> {
        match s {
            "text" => Ok(Format::Text),
            "json" => Ok(Format::Json),
            "toml" => Ok(Format::Toml),
            other => anyhow::bail!("unknown format '{other}' (expected text|json|toml)"),
        }
    }
}
