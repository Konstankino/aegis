//! The fixed, whitelisted set of policy artifacts the tool may touch.
//!
//! This enum is the structural half of the guardrail: every read/write addresses one of these
//! seven **constant basenames** joined to the policy dir, so the tool can never be pointed at an
//! arbitrary path, an infrastructure file, or anything outside `--dir`. (`io::PolicyDir` enforces
//! the "inside `--dir`" half.)

/// A policy artifact managed by the CLI. The ONLY files the tool reads or writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Artifact {
    /// `tools.json` — the broker tool registry (`Vec<ToolSpec>`).
    Tools,
    /// `broker.cedar` — the broker Cedar policy (opaque, validated text).
    BrokerCedar,
    /// `egress-allowlist.toml` — the egress firewall allowlist.
    Egress,
    /// `meter.toml` — the meter budget/breaker limits.
    Meter,
    /// `pins.json` — the supply-chain digest pinset.
    Pins,
    /// `honeypots.json` — the deception decoys/canaries.
    Honeypots,
    /// `sandbox.toml` — the code-execution sandbox policy.
    Sandbox,
}

impl Artifact {
    /// Every managed artifact, in a stable display order.
    pub const ALL: [Artifact; 7] = [
        Artifact::Tools,
        Artifact::BrokerCedar,
        Artifact::Egress,
        Artifact::Meter,
        Artifact::Pins,
        Artifact::Honeypots,
        Artifact::Sandbox,
    ];

    /// The on-disk basename (a constant — never user-controlled).
    pub fn filename(self) -> &'static str {
        match self {
            Artifact::Tools => "tools.json",
            Artifact::BrokerCedar => "broker.cedar",
            Artifact::Egress => "egress-allowlist.toml",
            Artifact::Meter => "meter.toml",
            Artifact::Pins => "pins.json",
            Artifact::Honeypots => "honeypots.json",
            Artifact::Sandbox => "sandbox.toml",
        }
    }

    /// The populated-reference twin (`<name>.example.<ext>`), used by `init`/`diff`.
    pub fn example_filename(self) -> String {
        let name = self.filename();
        // Insert ".example" before the final extension.
        match name.rsplit_once('.') {
            Some((stem, ext)) => format!("{stem}.example.{ext}"),
            None => format!("{name}.example"),
        }
    }

    /// The domain (command group) this artifact belongs to. `tools.json` + `broker.cedar` share the
    /// `broker` domain.
    pub fn domain(self) -> &'static str {
        match self {
            Artifact::Tools | Artifact::BrokerCedar => "broker",
            Artifact::Egress => "egress",
            Artifact::Meter => "meter",
            Artifact::Pins => "supply",
            Artifact::Honeypots => "honeypot",
            Artifact::Sandbox => "sandbox",
        }
    }

    /// A short human label for status/detail display.
    pub fn label(self) -> &'static str {
        match self {
            Artifact::Tools => "broker tools",
            Artifact::BrokerCedar => "broker cedar",
            Artifact::Egress => "egress allowlist",
            Artifact::Meter => "meter limits",
            Artifact::Pins => "supply pinset",
            Artifact::Honeypots => "honeypots",
            Artifact::Sandbox => "sandbox policy",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_filename_inserts_before_extension() {
        assert_eq!(Artifact::Tools.example_filename(), "tools.example.json");
        assert_eq!(
            Artifact::BrokerCedar.example_filename(),
            "broker.example.cedar"
        );
        assert_eq!(
            Artifact::Egress.example_filename(),
            "egress-allowlist.example.toml"
        );
        assert_eq!(Artifact::Sandbox.example_filename(), "sandbox.example.toml");
    }

    #[test]
    fn all_filenames_are_bare_basenames() {
        // Guardrail invariant: no artifact filename contains a path separator or `..`.
        for a in Artifact::ALL {
            let f = a.filename();
            assert!(
                !f.contains('/') && !f.contains('\\') && !f.contains(".."),
                "{f}"
            );
        }
    }
}
