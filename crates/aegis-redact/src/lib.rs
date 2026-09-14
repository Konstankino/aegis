//! # aegis-redact — disclosure / redaction filter (LLM02, LLM08)
//!
//! Sensitive-information disclosure is broader than the final answer: tool-call arguments,
//! reasoning traces, and logs all leak (architecture-considerations.md §3 LLM02). This crate
//! treats **traces and tool-args as first-class output** and provides one deterministic
//! classify-and-redact path to run before anything is logged or returned.
//!
//! Detection is a layered set of deterministic patterns (emails, US SSNs, Luhn-valid card
//! numbers, AWS access-key ids, common API-token prefixes, IPv4, phone numbers). It is a
//! `◐ Reduce` control — deterministic and complete for these classes, but not a claim to catch
//! every possible secret. Each match is replaced with a `[REDACTED:<KIND>]` marker.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

/// A class of sensitive value that redaction recognizes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingKind {
    Email,
    Ssn,
    CreditCard,
    AwsAccessKey,
    ApiToken,
    IpAddress,
    Phone,
    /// A JSON Web Token (`eyJ…​.…​.…`) — often a bearer credential.
    Jwt,
    /// A PEM private-key block (`-----BEGIN … PRIVATE KEY-----` … `END`).
    PrivateKey,
    /// An IBAN bank account number (validated by ISO-13616 mod-97).
    Iban,
    /// A Ukrainian individual taxpayer number (ІПН / РНОКПП) — 10 digits, checksum-validated.
    UaTaxId,
    /// A medical record number — a labelled `MRN …` identifier (PHI, Roadmap T2).
    Mrn,
    /// A date of birth — a labelled `DOB …` date (PHI, Roadmap T2).
    Dob,
}

impl FindingKind {
    fn marker(self) -> &'static str {
        match self {
            FindingKind::Email => "[REDACTED:EMAIL]",
            FindingKind::Ssn => "[REDACTED:SSN]",
            FindingKind::CreditCard => "[REDACTED:CREDIT_CARD]",
            FindingKind::AwsAccessKey => "[REDACTED:AWS_ACCESS_KEY]",
            FindingKind::ApiToken => "[REDACTED:API_TOKEN]",
            FindingKind::IpAddress => "[REDACTED:IP]",
            FindingKind::Phone => "[REDACTED:PHONE]",
            FindingKind::Jwt => "[REDACTED:JWT]",
            FindingKind::PrivateKey => "[REDACTED:PRIVATE_KEY]",
            FindingKind::Iban => "[REDACTED:IBAN]",
            FindingKind::UaTaxId => "[REDACTED:UA_TAX_ID]",
            FindingKind::Mrn => "[REDACTED:MRN]",
            FindingKind::Dob => "[REDACTED:DOB]",
        }
    }
}

/// The result of redacting a piece of text: the cleaned text plus a per-kind count of what was
/// removed (an ordered map, so output is deterministic).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Redacted {
    /// The redacted text, with each sensitive value replaced by a `[REDACTED:<KIND>]` marker.
    pub text: String,
    /// How many values of each kind were redacted.
    pub findings: BTreeMap<FindingKind, usize>,
}

impl Redacted {
    /// Total number of redactions across all kinds.
    #[must_use]
    pub fn total(&self) -> usize {
        self.findings.values().sum()
    }
    /// Whether anything was redacted.
    #[must_use]
    pub fn is_clean(&self) -> bool {
        self.findings.is_empty()
    }
}

struct Detector {
    kind: FindingKind,
    re: Regex,
    /// Optional validator on the matched text; `None` means "always a match".
    validate: Option<fn(&str) -> bool>,
}

fn detectors() -> &'static [Detector] {
    static DETECTORS: OnceLock<Vec<Detector>> = OnceLock::new();
    DETECTORS.get_or_init(|| {
        vec![
            // Most specific first; each runs on the progressively-redacted text, and markers
            // contain no digits/@ so later patterns cannot match inside them.
            //
            // Whole PEM key block FIRST — redact the entire key material (its base64 body could
            // otherwise contain substrings a later detector would match). `(?s)` lets `.` span
            // newlines; `.*?` is non-greedy so two adjacent keys are not merged into one match.
            Detector {
                kind: FindingKind::PrivateKey,
                re: Regex::new(
                    r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
                )
                .unwrap(),
                validate: None,
            },
            Detector {
                kind: FindingKind::AwsAccessKey,
                re: Regex::new(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b").unwrap(),
                validate: None,
            },
            Detector {
                kind: FindingKind::ApiToken,
                re: Regex::new(
                    r"\b(?:sk|pk|rk)-[A-Za-z0-9]{16,}\b|\bghp_[A-Za-z0-9]{20,}\b|\bxox[baprs]-[A-Za-z0-9-]{10,}\b",
                )
                .unwrap(),
                validate: None,
            },
            // JWT: three base64url segments; the leading `eyJ` is base64 of `{"`, so a real token
            // is unmistakable. No `@`/plain-digit overlap with the classes below.
            Detector {
                kind: FindingKind::Jwt,
                re: Regex::new(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")
                    .unwrap(),
                validate: None,
            },
            Detector {
                kind: FindingKind::Email,
                re: Regex::new(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}").unwrap(),
                validate: None,
            },
            // Labelled PHI (Roadmap T2) — run BEFORE the bare-digit detectors so a labelled MRN/DOB
            // is redacted whole under its own kind rather than caught as a phone/tax-id/card digit run.
            // A medical record number: `MRN` (any case) + 6–10 digits.
            Detector {
                kind: FindingKind::Mrn,
                re: Regex::new(r"(?i)\bMRN[:#\s]{0,3}\d{6,10}\b").unwrap(),
                validate: None,
            },
            // A date of birth: `DOB`/`D.O.B` + a date. The label gates it, so ordinary dates in text
            // are left alone (only a date asserted to be a birth date is PHI here).
            Detector {
                kind: FindingKind::Dob,
                re: Regex::new(r"(?i)\b(?:DOB|D\.O\.B\.?)[:\s]{0,3}\d{1,2}[/-]\d{1,2}[/-]\d{2,4}\b")
                    .unwrap(),
                validate: None,
            },
            // IBAN: 2 letters + 2 check digits + up to 30 alnum, gated by the ISO-13616 mod-97
            // checksum so random alphanumerics are not redacted.
            Detector {
                kind: FindingKind::Iban,
                re: Regex::new(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b").unwrap(),
                validate: Some(iban_mod97_valid),
            },
            Detector {
                kind: FindingKind::Ssn,
                re: Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap(),
                validate: None,
            },
            Detector {
                kind: FindingKind::CreditCard,
                re: Regex::new(r"\b\d(?:[ -]?\d){12,18}\b").unwrap(),
                validate: Some(luhn_valid),
            },
            // Ukrainian ІПН/РНОКПП: a bare 10-digit number, gated by its checksum. It runs BEFORE
            // Phone (which also matches a bare 10-digit run) so a checksum-valid id is labelled
            // UA_TAX_ID; non-matching 10-digit runs fall through to Phone. Either way the value is
            // redacted — only the KIND label differs on the rare overlap.
            Detector {
                kind: FindingKind::UaTaxId,
                re: Regex::new(r"\b\d{10}\b").unwrap(),
                validate: Some(ua_tax_id_valid),
            },
            Detector {
                kind: FindingKind::Phone,
                re: Regex::new(r"\b(?:\+?1[ .\-]?)?\(?\d{3}\)?[ .\-]?\d{3}[ .\-]?\d{4}\b").unwrap(),
                validate: None,
            },
            Detector {
                kind: FindingKind::IpAddress,
                re: Regex::new(r"\b(?:\d{1,3}\.){3}\d{1,3}\b").unwrap(),
                validate: Some(valid_ipv4),
            },
        ]
    })
}

/// Redact all recognized sensitive values in `input`.
#[must_use]
pub fn redact(input: &str) -> Redacted {
    let mut text = input.to_string();
    let mut findings: BTreeMap<FindingKind, usize> = BTreeMap::new();
    for d in detectors() {
        let mut count = 0usize;
        let replaced =
            d.re.replace_all(&text, |caps: &regex::Captures| {
                let matched = &caps[0];
                if d.validate.map(|v| v(matched)).unwrap_or(true) {
                    count += 1;
                    d.kind.marker().to_string()
                } else {
                    matched.to_string()
                }
            })
            .into_owned();
        if count > 0 {
            *findings.entry(d.kind).or_insert(0) += count;
        }
        text = replaced;
    }
    Redacted { text, findings }
}

/// Recursively redact every string leaf of a JSON value (tool-call args, traces). Object keys
/// are left intact; only values are redacted. Returns the redacted value and the aggregate
/// finding counts.
#[must_use]
pub fn redact_value(
    value: &serde_json::Value,
) -> (serde_json::Value, BTreeMap<FindingKind, usize>) {
    let mut findings: BTreeMap<FindingKind, usize> = BTreeMap::new();
    let out = redact_value_inner(value, &mut findings);
    (out, findings)
}

fn redact_value_inner(
    value: &serde_json::Value,
    findings: &mut BTreeMap<FindingKind, usize>,
) -> serde_json::Value {
    match value {
        serde_json::Value::String(s) => {
            let r = redact(s);
            for (k, c) in r.findings {
                *findings.entry(k).or_insert(0) += c;
            }
            serde_json::Value::String(r.text)
        }
        serde_json::Value::Array(items) => serde_json::Value::Array(
            items
                .iter()
                .map(|v| redact_value_inner(v, findings))
                .collect(),
        ),
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                out.insert(k.clone(), redact_value_inner(v, findings));
            }
            serde_json::Value::Object(out)
        }
        other => other.clone(),
    }
}

fn luhn_valid(candidate: &str) -> bool {
    let digits: Vec<u32> = candidate.chars().filter_map(|c| c.to_digit(10)).collect();
    if digits.len() < 13 || digits.len() > 19 {
        return false;
    }
    let mut sum = 0u32;
    let mut double = false;
    for &d in digits.iter().rev() {
        let mut x = d;
        if double {
            x *= 2;
            if x > 9 {
                x -= 9;
            }
        }
        sum += x;
        double = !double;
    }
    sum.is_multiple_of(10)
}

fn valid_ipv4(candidate: &str) -> bool {
    candidate
        .split('.')
        .all(|o| o.parse::<u16>().map(|n| n <= 255).unwrap_or(false))
}

/// ISO-13616 IBAN check: move the first four characters to the end, map letters A–Z to 10–35, and
/// verify the resulting number is ≡ 1 (mod 97). Computed piecewise so no big-integer type is
/// needed. Gates the broad IBAN regex so only genuine account numbers are redacted.
fn iban_mod97_valid(candidate: &str) -> bool {
    let s = candidate.to_ascii_uppercase();
    if s.len() < 15 || s.len() > 34 {
        return false;
    }
    let rearranged: String = s[4..].chars().chain(s[..4].chars()).collect();
    let mut rem: u32 = 0;
    for ch in rearranged.chars() {
        let val = if ch.is_ascii_digit() {
            ch as u32 - '0' as u32
        } else if ch.is_ascii_uppercase() {
            ch as u32 - 'A' as u32 + 10
        } else {
            return false;
        };
        // Append `val` (one or two decimal digits) to the running remainder, mod 97.
        rem = if val >= 10 {
            (rem * 100 + val) % 97
        } else {
            (rem * 10 + val) % 97
        };
    }
    rem == 1
}

/// Ukrainian ІПН / РНОКПП checksum: 10 digits where the 10th is a control digit over the first
/// nine with weights [-1, 5, 7, 9, 4, 6, 10, 5, 7] — control = (Σ wᵢ·dᵢ) mod 11, mapped 10→0.
fn ua_tax_id_valid(candidate: &str) -> bool {
    let d: Vec<i32> = candidate
        .bytes()
        .filter(u8::is_ascii_digit)
        .map(|b| i32::from(b - b'0'))
        .collect();
    if d.len() != 10 {
        return false;
    }
    const W: [i32; 9] = [-1, 5, 7, 9, 4, 6, 10, 5, 7];
    let sum: i32 = (0..9).map(|i| W[i] * d[i]).sum();
    let control = sum.rem_euclid(11) % 10;
    control == d[9]
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn redacts_email_and_reports_count() {
        let r = redact("contact me at alice@example.com or bob@example.org");
        assert!(!r.text.contains('@'));
        assert_eq!(r.findings.get(&FindingKind::Email), Some(&2));
        assert_eq!(r.total(), 2);
    }

    #[test]
    fn redacts_ssn() {
        let r = redact("SSN: 123-45-6789.");
        assert_eq!(r.text, "SSN: [REDACTED:SSN].");
        assert_eq!(r.findings.get(&FindingKind::Ssn), Some(&1));
    }

    #[test]
    fn redacts_luhn_valid_card_but_not_random_digits() {
        // 4242 4242 4242 4242 is a Luhn-valid test card.
        let r = redact("card 4242 4242 4242 4242 end");
        assert!(r.text.contains("[REDACTED:CREDIT_CARD]"));
        // A 16-digit non-Luhn number is left alone by the card detector.
        let r2 = redact("id 1234567890123456");
        assert_eq!(r2.findings.get(&FindingKind::CreditCard), None);
    }

    #[test]
    fn redacts_aws_key_and_api_tokens() {
        let r = redact("key AKIAIOSFODNN7EXAMPLE and token sk-abcdefghij0123456789");
        assert_eq!(r.findings.get(&FindingKind::AwsAccessKey), Some(&1));
        assert_eq!(r.findings.get(&FindingKind::ApiToken), Some(&1));
        assert!(!r.text.contains("AKIAIOSFODNN7EXAMPLE"));
    }

    #[test]
    fn redacts_ipv4_only_when_octets_valid() {
        let r = redact("host 10.0.0.5 up; bogus 999.1.1.1 here");
        assert_eq!(r.findings.get(&FindingKind::IpAddress), Some(&1));
        assert!(r.text.contains("999.1.1.1")); // invalid octet -> not redacted
    }

    #[test]
    fn redacts_phone_numbers() {
        let r = redact("call +1 (415) 555-2671 today");
        assert_eq!(r.findings.get(&FindingKind::Phone), Some(&1));
    }

    #[test]
    fn clean_text_is_unchanged() {
        let r = redact("nothing sensitive here, just words and 42");
        assert!(r.is_clean());
        assert_eq!(r.text, "nothing sensitive here, just words and 42");
    }

    #[test]
    fn redact_value_walks_nested_json_leaves() {
        let v = json!({
            "to": "alice@example.com",
            "meta": { "ip": "192.168.1.1", "note": "ok" },
            "cc": ["bob@example.org", 7]
        });
        let (out, findings) = redact_value(&v);
        assert_eq!(out["to"], "[REDACTED:EMAIL]");
        assert_eq!(out["meta"]["ip"], "[REDACTED:IP]");
        assert_eq!(out["meta"]["note"], "ok");
        assert_eq!(out["cc"][0], "[REDACTED:EMAIL]");
        assert_eq!(out["cc"][1], 7); // non-strings untouched
        assert_eq!(findings.get(&FindingKind::Email), Some(&2));
        assert_eq!(findings.get(&FindingKind::IpAddress), Some(&1));
    }

    #[test]
    fn redacts_jwt() {
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.\
                   eyJzdWIiOiIxMjM0NTY3ODkwIn0.\
                   SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
        let r = redact(&format!("Authorization: Bearer {jwt}"));
        assert_eq!(r.findings.get(&FindingKind::Jwt), Some(&1));
        assert!(!r.text.contains("eyJ"));
    }

    #[test]
    fn redacts_whole_private_key_block() {
        let text = "key:\n-----BEGIN RSA PRIVATE KEY-----\n\
                    MIIBOwIBAAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf9Cnzj4p4WGeKLs1Pt8Q\n\
                    uKUpRKfFLfRYC9AIKjbJTWit+CqvjTa1H9C3\n\
                    -----END RSA PRIVATE KEY-----\ndone";
        let r = redact(text);
        assert_eq!(r.findings.get(&FindingKind::PrivateKey), Some(&1));
        assert!(!r.text.contains("PRIVATE KEY"));
        assert!(!r.text.contains("MIIBOwIB")); // the whole body is gone, not just the header
        assert!(r.text.starts_with("key:") && r.text.trim_end().ends_with("done"));
    }

    #[test]
    fn redacts_valid_iban_but_not_bad_checksum() {
        // GB82WEST12345698765432 is the canonical ISO-13616 example (mod-97 valid).
        let r = redact("pay to GB82WEST12345698765432 today");
        assert_eq!(r.findings.get(&FindingKind::Iban), Some(&1));
        assert!(r.text.contains("[REDACTED:IBAN]"));
        // Same shape, wrong check digits -> left intact.
        let r2 = redact("pay to GB00WEST12345698765432 today");
        assert_eq!(r2.findings.get(&FindingKind::Iban), None);
        assert!(r2.text.contains("GB00WEST12345698765432"));
    }

    #[test]
    fn redacts_labelled_mrn_and_dob_but_not_plain_dates() {
        let r = redact("Patient MRN: 00123456 seen today");
        assert_eq!(r.findings.get(&FindingKind::Mrn), Some(&1));
        assert!(r.text.contains("[REDACTED:MRN]") && !r.text.contains("00123456"));

        let r = redact("DOB 01/02/1990 on file; D.O.B: 3-4-88 elsewhere");
        assert_eq!(r.findings.get(&FindingKind::Dob), Some(&2));
        assert!(!r.text.contains("1990"));

        // An unlabelled date (not asserted as a birth date) is not treated as DOB PHI.
        let r = redact("the appointment is on 01/02/1990");
        assert_eq!(r.findings.get(&FindingKind::Dob), None);
        assert!(r.text.contains("01/02/1990"));
    }

    #[test]
    fn redacts_valid_ua_tax_id_and_rejects_bad_checksum() {
        // 2954901234: control digit 4 satisfies the РНОКПП checksum.
        let r = redact("платник 2954901234 у реєстрі");
        assert_eq!(r.findings.get(&FindingKind::UaTaxId), Some(&1));
        assert!(!r.text.contains("2954901234"));
        // A bare 10-digit with a wrong control digit is NOT a tax id; it falls through to Phone
        // (still redacted — a 10-digit run — but under a different kind).
        let r2 = redact("платник 2954901239 у реєстрі");
        assert_eq!(r2.findings.get(&FindingKind::UaTaxId), None);
    }
}
