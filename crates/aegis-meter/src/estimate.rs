//! Pre-flight token estimation and cost modelling.
//!
//! The estimator is a **trait** so a real tokenizer (e.g. HF `tokenizers`, §9) can be plugged
//! in later; the default is a deterministic character-based heuristic that is good enough to
//! *reject before inference* (the point of pre-flight — it only needs to be conservative, not
//! exact).

use serde::{Deserialize, Serialize};

/// Estimates the number of tokens a piece of text will consume.
pub trait TokenEstimator {
    /// Estimated token count for `text`.
    fn estimate(&self, text: &str) -> u64;
}

/// A deterministic character-per-token heuristic (default ~4 chars/token, ceiling-rounded, with
/// a small floor so non-empty text always costs at least one token).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct HeuristicEstimator {
    /// Average characters per token.
    pub chars_per_token: f32,
}

impl Default for HeuristicEstimator {
    fn default() -> Self {
        Self {
            chars_per_token: 4.0,
        }
    }
}

impl TokenEstimator for HeuristicEstimator {
    fn estimate(&self, text: &str) -> u64 {
        let chars = text.chars().count() as f32;
        if chars == 0.0 {
            return 0;
        }
        let cpt = if self.chars_per_token <= 0.0 {
            4.0
        } else {
            self.chars_per_token
        };
        (chars / cpt).ceil().max(1.0) as u64
    }
}

/// Convenience: estimate with the default heuristic.
#[must_use]
pub fn estimate_tokens(text: &str) -> u64 {
    HeuristicEstimator::default().estimate(text)
}

/// A per-1000-token price model, used to turn a token estimate into an estimated cost.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CostModel {
    /// USD per 1000 input tokens.
    pub input_usd_per_1k: f64,
    /// USD per 1000 output tokens.
    pub output_usd_per_1k: f64,
}

impl CostModel {
    /// Estimated cost (USD) for the given input/output token counts.
    #[must_use]
    pub fn cost(&self, input_tokens: u64, output_tokens: u64) -> f64 {
        (input_tokens as f64) / 1000.0 * self.input_usd_per_1k
            + (output_tokens as f64) / 1000.0 * self.output_usd_per_1k
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn heuristic_estimates_are_conservative_and_ceiling_rounded() {
        let e = HeuristicEstimator::default();
        assert_eq!(e.estimate(""), 0);
        assert_eq!(e.estimate("abcd"), 1); // 4 chars / 4 = 1
        assert_eq!(e.estimate("abcde"), 2); // 5 / 4 -> ceil = 2
        assert_eq!(estimate_tokens("a"), 1); // floor of 1 for non-empty
    }

    #[test]
    fn zero_or_negative_ratio_falls_back_to_default() {
        let e = HeuristicEstimator {
            chars_per_token: 0.0,
        };
        assert_eq!(e.estimate("abcd"), 1);
    }

    #[test]
    fn cost_model_prices_input_and_output() {
        let m = CostModel {
            input_usd_per_1k: 3.0,
            output_usd_per_1k: 15.0,
        };
        // 1000 input @ $3 + 2000 output @ $15/1k = 3 + 30 = 33.
        assert!((m.cost(1000, 2000) - 33.0).abs() < 1e-9);
        assert_eq!(m.cost(0, 0), 0.0);
    }
}
