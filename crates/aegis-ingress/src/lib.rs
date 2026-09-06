//! # aegis-ingress — input normalization / prompt firewall (LLM01, LLM09)
//!
//! The **deterministic byte-hygiene** half of the ingress guard
//! (architecture-considerations.md §2.5, §3 LLM01). This is a `◐ Reduce` control at the input
//! that Aegis makes fully deterministic: it strips the invisible-character channels that hide
//! prompt-injection payloads and provenance-wraps the result. It is explicitly **not** trusted
//! to be sufficient on its own — the `● Contain` trio (broker/output/egress) sits behind it.
//!
//! What it removes (deterministic, complete for these classes):
//! * **Tag block** U+E0000–U+E007F (the classic invisible-instruction smuggling channel).
//! * **Variation selectors** U+FE00–U+FE0F and U+E0100–U+E01EF.
//! * **Zero-width & joiners** U+200B/C/D, word joiner U+2060, BOM/ZWNBSP U+FEFF, soft hyphen U+00AD.
//! * **Bidirectional controls** U+200E/200F, U+202A–U+202E, U+2066–U+2069 (neutralized).
//!
//! Then it applies Unicode **NFC** normalization so downstream comparisons are stable.

use aegis_core::{Provenance, Tagged};
use serde::Serialize;
use unicode_normalization::UnicodeNormalization;

/// True for a code point that Aegis strips at ingest: an invisible, tag, variation-selector, or
/// bidirectional-control character that carries no legitimate visible text but can smuggle
/// instructions or reorder rendering.
#[must_use]
pub fn is_dangerous(c: char) -> bool {
    matches!(c,
        // Zero-width, joiners, word joiner, BOM/ZWNBSP, soft hyphen.
        '\u{200B}' | '\u{200C}' | '\u{200D}' | '\u{2060}' | '\u{FEFF}' | '\u{00AD}'
        // Bidirectional controls (marks, embeddings, overrides, isolates).
        | '\u{200E}' | '\u{200F}'
        | '\u{202A}'..='\u{202E}'
        | '\u{2066}'..='\u{2069}'
        // Variation selectors.
        | '\u{FE00}'..='\u{FE0F}'
        | '\u{E0100}'..='\u{E01EF}'
        // Tag block.
        | '\u{E0000}'..='\u{E007F}'
    )
}

/// True for the bidirectional-control subset (worth surfacing on its own, since bidi reordering
/// is a distinct spoofing vector).
#[must_use]
pub fn is_bidi_control(c: char) -> bool {
    matches!(c,
        '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
    )
}

/// The outcome of sanitizing a piece of input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Sanitized {
    /// The cleaned, NFC-normalized text — safe to hand to a classifier or the model.
    pub text: String,
    /// How many dangerous code points were stripped.
    pub removed: usize,
    /// Whether any bidirectional-control character was present.
    pub had_bidi: bool,
    /// Whether NFC normalization changed the (already stripped) text.
    pub normalized: bool,
}

impl Sanitized {
    /// Whether the input was already clean (nothing stripped, nothing normalized).
    #[must_use]
    pub fn is_unchanged(&self) -> bool {
        self.removed == 0 && !self.normalized
    }
}

/// Strip every [`is_dangerous`] code point, reporting how many were removed and whether any were
/// bidirectional controls.
#[must_use]
pub fn strip_dangerous(input: &str) -> (String, usize, bool) {
    let mut out = String::with_capacity(input.len());
    let mut removed = 0;
    let mut had_bidi = false;
    for c in input.chars() {
        if is_dangerous(c) {
            removed += 1;
            had_bidi |= is_bidi_control(c);
        } else {
            out.push(c);
        }
    }
    (out, removed, had_bidi)
}

/// NFC-normalize (compose) a string.
#[must_use]
pub fn normalize_nfc(input: &str) -> String {
    input.nfc().collect()
}

/// Sanitize input: strip dangerous invisible/bidi/tag characters, then NFC-normalize.
///
/// **Done-when guarantee (§5):** no invisible-character payload survives — the result satisfies
/// [`is_clean`].
#[must_use]
pub fn sanitize(input: &str) -> Sanitized {
    let (stripped, removed, had_bidi) = strip_dangerous(input);
    let normalized_text = normalize_nfc(&stripped);
    let normalized = normalized_text != stripped;
    Sanitized {
        text: normalized_text,
        removed,
        had_bidi,
        normalized,
    }
}

/// True if a string contains no dangerous code points (the post-condition of [`sanitize`]).
#[must_use]
pub fn is_clean(input: &str) -> bool {
    !input.chars().any(is_dangerous)
}

/// Sanitize raw input and wrap it with its [`Provenance`] — the one entry point that keeps a
/// value from ever entering Aegis as an un-labelled, un-cleaned bare `String`.
#[must_use]
pub fn ingest(raw: &str, origin: Provenance) -> Tagged<String> {
    Tagged::new(sanitize(raw).text, origin)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strips_tag_block_smuggling_channel() {
        // "hi" + an invisible tag-block instruction payload.
        let payload: String = "hi".chars().chain("\u{E0041}\u{E0042}".chars()).collect();
        let s = sanitize(&payload);
        assert_eq!(s.text, "hi");
        assert_eq!(s.removed, 2);
        assert!(is_clean(&s.text));
    }

    #[test]
    fn strips_zero_width_and_joiners_and_bom() {
        let dirty = "a\u{200B}b\u{200D}c\u{FEFF}d\u{2060}e\u{00AD}f";
        let s = sanitize(dirty);
        assert_eq!(s.text, "abcdef");
        assert_eq!(s.removed, 5);
        assert!(!s.had_bidi);
    }

    #[test]
    fn neutralizes_bidi_controls_and_flags_them() {
        let dirty = "user\u{202E}drowssap\u{202C}";
        let s = sanitize(dirty);
        assert_eq!(s.text, "userdrowssap");
        assert!(s.had_bidi);
        assert_eq!(s.removed, 2);
    }

    #[test]
    fn strips_variation_selectors() {
        let dirty = "x\u{FE0F}\u{E0100}y";
        let (out, removed, _) = strip_dangerous(dirty);
        assert_eq!(out, "xy");
        assert_eq!(removed, 2);
    }

    #[test]
    fn nfc_normalizes_decomposed_sequences() {
        // "e" + combining acute accent -> single "é".
        let decomposed = "cafe\u{0301}";
        let s = sanitize(decomposed);
        assert_eq!(s.text, "café");
        assert!(s.normalized);
        assert_eq!(s.removed, 0);
    }

    #[test]
    fn clean_input_is_unchanged() {
        let s = sanitize("perfectly normal text 123");
        assert!(s.is_unchanged());
        assert!(is_clean("perfectly normal text 123"));
    }

    #[test]
    fn ingest_sanitizes_and_wraps_with_provenance() {
        let tagged = ingest("web\u{200B}page", Provenance::Untrusted);
        assert_eq!(tagged.value, "webpage");
        assert_eq!(tagged.origin, Provenance::Untrusted);
        assert!(tagged.is_tainting());
    }

    #[test]
    fn is_dangerous_matches_expected_classes() {
        assert!(is_dangerous('\u{200B}'));
        assert!(is_dangerous('\u{E0041}'));
        assert!(is_dangerous('\u{202E}'));
        assert!(!is_dangerous('a'));
        assert!(!is_dangerous('é'));
        assert!(!is_dangerous(' '));
    }
}
