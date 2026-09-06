//! Focused walkthrough of `aegis-egress`: the pure default-deny allowlist decision, including
//! query-param stripping and suffix matching. (For the live HTTP proxy, run the binary instead:
//! `cargo run -p aegis-egress --bin aegis-egress`.)
//!
//! Run it:
//! ```bash
//! CARGO_TARGET_DIR=/tmp/aegis-target cargo run -p aegis-egress --example egress_firewall
//! ```

use aegis_egress::{Allowlist, EgressDecision};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Load the reference allowlist (the plain file is a blank starter; the example is populated).
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../policies/egress-allowlist.example.toml");
    let allow = Allowlist::from_toml(&std::fs::read_to_string(path)?)?;
    println!(
        "allowlist: {} host(s), {} suffix(es), schemes={:?}\n",
        allow.hosts.len(),
        allow.suffixes.len(),
        allow.schemes
    );

    let cases = [
        (
            "allowlisted host, permitted + data-bearing params",
            "https://api.internal.example/v1?page=2&leak=PHI_SECRET",
        ),
        (
            "suffix rule (any *.s3 subdomain)",
            "https://my-bucket.s3.us-east-1.amazonaws.com/key?sig=abc",
        ),
        (
            "unlisted host",
            "https://evil.example/collect?data=PHI_SECRET",
        ),
        ("disallowed scheme (http)", "http://api.internal.example/v1"),
        ("garbage input", "not a url"),
    ];

    for (label, url) in cases {
        match allow.decide(url) {
            EgressDecision::Allow(sanitized) => {
                println!("✅ allow  {label}");
                println!("          in : {url}");
                println!("          out: {sanitized}");
            }
            EgressDecision::Deny(reason) => {
                println!("⛔ deny   {label}  ({reason})\n          in : {url}")
            }
        }
    }
    Ok(())
}
