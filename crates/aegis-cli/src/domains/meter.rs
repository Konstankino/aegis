//! `meter.toml` — the budget/breaker limits (`aegis_meter::Limits`).

use anyhow::{bail, Context, Result};

use aegis_meter::Limits;

use crate::artifacts::Artifact;
use crate::io::{PolicyDir, WriteOutcome};
use crate::Format;

const A: Artifact = Artifact::Meter;
const HEADER: &str = "# Aegis meter limits (LLM06) — managed by `aegis meter`.\n\n";

/// The fields `aegis meter set` can override (each optional; unset = keep current).
#[derive(Debug, Default, Clone)]
pub struct LimitOverrides {
    pub max_tokens_per_request: Option<u64>,
    pub tokens_per_minute: Option<u64>,
    pub tokens_per_day: Option<u64>,
    pub max_cost_per_request_usd: Option<f64>,
    pub hard_cost_cap_usd: Option<f64>,
    pub max_steps: Option<u32>,
    pub max_recursion_depth: Option<u32>,
    pub max_wall_clock_ms: Option<u64>,
    pub loop_repeat_threshold: Option<u32>,
    pub max_fanout: Option<u32>,
}

impl LimitOverrides {
    fn is_empty(&self) -> bool {
        self.max_tokens_per_request.is_none()
            && self.tokens_per_minute.is_none()
            && self.tokens_per_day.is_none()
            && self.max_cost_per_request_usd.is_none()
            && self.hard_cost_cap_usd.is_none()
            && self.max_steps.is_none()
            && self.max_recursion_depth.is_none()
            && self.max_wall_clock_ms.is_none()
            && self.loop_repeat_threshold.is_none()
            && self.max_fanout.is_none()
    }
}

/// Load the current limits (partial/empty/absent all fill from `Limits::default()`).
pub fn load(dir: &PolicyDir) -> Result<Limits> {
    match dir.read(A)? {
        Some(text) => toml::from_str::<Limits>(&text)
            .with_context(|| format!("{} is not valid TOML", A.filename())),
        None => Ok(Limits::default()),
    }
}

/// Render for `show`.
pub fn show(dir: &PolicyDir, format: Format) -> Result<String> {
    let l = load(dir)?;
    Ok(match format {
        Format::Json => crate::domains::json_pretty(&l)?,
        Format::Toml => toml::to_string_pretty(&l)?,
        Format::Text => format!(
            "meter limits ({})\n\
             \x20 max_tokens_per_request  {}\n\
             \x20 tokens_per_minute       {}\n\
             \x20 tokens_per_day          {}\n\
             \x20 max_cost_per_request    ${}\n\
             \x20 hard_cost_cap           ${}\n\
             \x20 max_steps               {}\n\
             \x20 max_recursion_depth     {}\n\
             \x20 max_wall_clock_ms       {}\n\
             \x20 loop_repeat_threshold   {}\n\
             \x20 max_fanout              {}\n",
            if dir.exists(A) {
                A.filename()
            } else {
                "built-in defaults"
            },
            l.max_tokens_per_request,
            l.tokens_per_minute,
            l.tokens_per_day,
            l.max_cost_per_request_usd,
            l.hard_cost_cap_usd,
            l.max_steps,
            l.max_recursion_depth,
            l.max_wall_clock_ms,
            l.loop_repeat_threshold,
            l.max_fanout,
        ),
    })
}

/// Apply the provided overrides, preserving comments/formatting in the existing file, and write.
pub fn set(dir: &PolicyDir, ov: &LimitOverrides, dry_run: bool) -> Result<WriteOutcome> {
    if ov.is_empty() {
        bail!("nothing to set — pass at least one field (e.g. --max-steps 50)");
    }
    let current = dir.read(A)?;
    let mut doc = match &current {
        Some(t) => t
            .parse::<toml_edit::DocumentMut>()
            .with_context(|| format!("{} is not valid TOML", A.filename()))?,
        None => HEADER
            .parse::<toml_edit::DocumentMut>()
            .expect("header parses"),
    };
    let u = |n: u64| toml_edit::value(n as i64);
    let u32v = |n: u32| toml_edit::value(n as i64);
    if let Some(v) = ov.max_tokens_per_request {
        doc["max_tokens_per_request"] = u(v);
    }
    if let Some(v) = ov.tokens_per_minute {
        doc["tokens_per_minute"] = u(v);
    }
    if let Some(v) = ov.tokens_per_day {
        doc["tokens_per_day"] = u(v);
    }
    if let Some(v) = ov.max_cost_per_request_usd {
        doc["max_cost_per_request_usd"] = toml_edit::value(v);
    }
    if let Some(v) = ov.hard_cost_cap_usd {
        doc["hard_cost_cap_usd"] = toml_edit::value(v);
    }
    if let Some(v) = ov.max_steps {
        doc["max_steps"] = u32v(v);
    }
    if let Some(v) = ov.max_recursion_depth {
        doc["max_recursion_depth"] = u32v(v);
    }
    if let Some(v) = ov.max_wall_clock_ms {
        doc["max_wall_clock_ms"] = u(v);
    }
    if let Some(v) = ov.loop_repeat_threshold {
        doc["loop_repeat_threshold"] = u32v(v);
    }
    if let Some(v) = ov.max_fanout {
        doc["max_fanout"] = u32v(v);
    }
    let out = doc.to_string();
    // Belt-and-suspenders: the serialized result must parse back through the crate's own loader.
    toml::from_str::<Limits>(&out).context("the resulting meter.toml would be invalid")?;
    dir.write(A, &out, dry_run)
}

/// Reset to the built-in defaults (a complete, explicit file).
pub fn reset(dir: &PolicyDir, dry_run: bool) -> Result<WriteOutcome> {
    let out = format!("{HEADER}{}", toml::to_string(&Limits::default())?);
    toml::from_str::<Limits>(&out).context("default meter.toml is invalid (bug)")?;
    dir.write(A, &out, dry_run)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::unique_temp_dir;

    #[test]
    fn set_preserves_comments_and_revalidates() {
        let dir = unique_temp_dir("meter");
        // Seed a commented, complete file (like the example).
        dir.write(
            A,
            "# my budget\nmax_steps = 10\ntokens_per_minute = 100\n",
            false,
        )
        .unwrap();
        let ov = LimitOverrides {
            max_steps: Some(42),
            ..Default::default()
        };
        super::set(&dir, &ov, false).unwrap();
        let text = dir.read(A).unwrap().unwrap();
        assert!(text.contains("# my budget"), "comment preserved");
        assert!(text.contains("max_steps = 42"));
        assert!(
            text.contains("tokens_per_minute = 100"),
            "other field untouched"
        );
        assert_eq!(load(&dir).unwrap().max_steps, 42);
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn set_on_blank_starts_from_defaults() {
        let dir = unique_temp_dir("meter2");
        let ov = LimitOverrides {
            max_fanout: Some(3),
            ..Default::default()
        };
        super::set(&dir, &ov, false).unwrap();
        let l = load(&dir).unwrap();
        assert_eq!(l.max_fanout, 3);
        // Unset fields came from the default.
        assert_eq!(l.max_steps, Limits::default().max_steps);
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn empty_overrides_and_bad_toml_are_rejected() {
        let dir = unique_temp_dir("meter3");
        assert!(super::set(&dir, &LimitOverrides::default(), false).is_err());
        dir.write(A, "max_steps = = 3", false).unwrap();
        assert!(load(&dir).is_err());
        std::fs::remove_dir_all(dir.root()).ok();
    }

    #[test]
    fn reset_writes_valid_defaults() {
        let dir = unique_temp_dir("meter4");
        super::reset(&dir, false).unwrap();
        assert_eq!(load(&dir).unwrap(), Limits::default());
        std::fs::remove_dir_all(dir.root()).ok();
    }
}
