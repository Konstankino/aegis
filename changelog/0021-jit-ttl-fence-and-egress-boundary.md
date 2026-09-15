# 0021 — Security fixes: enforce short JIT TTL (STS time-fence) + egress label-boundary match

- **Date:** 2026-09-15
- **Status:** Done
- **Type:** Security fix (JIT minting / egress) + tests
- **Follows:** [0020-jit-subject-binding-and-resource-scope.md](0020-jit-subject-binding-and-resource-scope.md)

## #3 — "60–300s" STS credentials were really valid for 15 minutes

STS enforces a **900-second floor** on a session token's `DurationSeconds`, so `clamp_sts_duration`
minted every JIT credential for at least 15 minutes. The `expires_at_ms` returned to the caller was
only *advisory* — AWS still honored the token for the full 900s, so an exfiltrated short-TTL credential
had a 15-minute window.

**Fix:** time-fence the inline **session policy** so AWS itself refuses the credential at the intended
expiry, independent of the token's outer lifetime.

- `aegis-jit` (pure, unit-tested):
  - `unix_to_iso8601(secs)` — formats a Unix timestamp as `YYYY-MM-DDTHH:MM:SSZ` with no external
    date crate (Howard Hinnant's civil-from-days).
  - `fence_session_policy(rendered, expiry_unix_secs)` — appends an explicit
    `Deny * * when DateGreaterThan aws:CurrentTime = now+ttl` to the operator's session policy. The
    operator's `Allow`(s) are preserved (resource narrowing still holds before expiry); an explicit
    Deny overrides them after expiry. Empty/garbage input renders the fence alone → a session policy
    with no `Allow` grants nothing (fail-closed).
- `aegis-extension::jit::mint` (feature `jit`): builds the fenced policy from `now + ttl_secs` and
  passes it to `AssumeRole`. An empty operator template ("narrow via the role only") starts from an
  allow-all the role intersects down, still time-fenced. `expires_at_ms` is now ENFORCED for STS
  (documented as advisory-only for a static secret, which cannot be time-boxed once handed out).

Result: a 60s grant is unusable after 60s even though the STS token string remains parseable for 900s.

## #4 — Egress allowlist suffix matched across DNS label boundaries

`host_allowed` used `host.ends_with(suffix)`, so a suffix written without a leading dot — e.g.
`internal.example` — also permitted `evil-internal.example`, `notinternal.example`, and
`internal.example.attacker.net`: a classic allowlist bypass / exfiltration channel.

**Fix ([aegis-egress](../crates/aegis-egress/src/lib.rs)):** normalize each suffix to its bare apex and
match only on a **DNS label boundary** — `host == apex || host.ends_with(".{apex}")`. Dotted
(`.example.com`) and dotless (`example.com`) suffixes now behave identically: apex + subdomains only,
never a cross-boundary substring.

## Tests

- `aegis-jit`: `unix_to_iso8601_formats_utc` (epoch, a known timestamp, a leap day);
  `fence_appends_a_time_bounded_deny_and_keeps_the_allow`; `fence_wraps_a_single_statement_object`;
  `fence_of_empty_or_garbage_is_deny_only_fail_closed`.
- `aegis-egress`: `suffix_does_not_match_across_a_label_boundary`;
  `dotless_suffix_is_still_boundary_matched`; `suffix_rule_matches_subdomain` extended to the apex.

## Verification

`cargo test --workspace` green (56 groups, no failures); `cargo clippy --workspace --all-targets` and
`cargo clippy -p aegis-extension --features jit` clean; `cargo fmt --all --check` clean;
`cargo build -p aegis-extension --features jit` compiles.

## Remaining review items (lower severity — separate follow-ups)

Self-asserted `arg_provenance`/`approved`/`agent_id` at the loopback gate (#5); sandbox path prefix
boundary (#6); output-scan not wired into the agent loop (#7); best-effort ledger durability (#8).
