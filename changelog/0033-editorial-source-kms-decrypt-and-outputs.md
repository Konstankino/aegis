# 0033 — Editorial S3 ingest: SSE-KMS source decrypt + key-policy principal output

- **Date:** 2026-09-21
- **Status:** Done
- **Type:** Fix (correctness) + operability
- **Follows:** [0031-editorial-toctou-version-pin.md](0031-editorial-toctou-version-pin.md)

## What & why

Reading an **SSE-KMS** source object triggers `kms:Decrypt` using the *caller's* credentials — here, the
minted JIT STS session. Two gaps surfaced:

1. **Session policy dropped `kms:Decrypt`.** STS AssumeRole **intersects** the inline session policy
   with the role's policy. The session policy (from `grants.toml`) allowed only `s3:GetObject` /
   `s3:GetObjectVersion`, so even though the per-grant role has `kms:Decrypt` (added when
   `source_kms_key_arn` is set), the *session* did not — and an SSE-KMS object read would be denied at
   decrypt time.
2. **The key-policy principal wasn't surfaced.** A KMS CMK's key policy must authorize the principal
   that decrypts. For a cross-account or restrictively-policed source CMK, that principal is the
   per-grant JIT role — but its ARN wasn't in the Terraform outputs, so an operator had no clean way to
   know what to add to the key policy.

## Change

- **`modules/aegis-pipeline/jit.tf`:** when `source_kms_key_arn` is set, the deploy-rendered
  `grants.toml` swaps the s3-only session-policy template for an **s3 + `kms:Decrypt` (on the source
  CMK)** template. The committed catalog keeps the s3-only form (correct for SSE-S3 / an AWS-managed
  key). `{resource}` stays literal for mint-time substitution; verified the swap matches the committed
  string exactly and yields valid JSON. The two policy variants are authored with **`jsonencode`**
  (proper policy objects, not hand-escaped text); since `jsonencode` sorts keys alphabetically, the
  committed `grants.toml` `session_policy_template` is written in the same compact, sorted form so the
  `replace()` match holds.
- **`modules/aegis-pipeline/outputs.tf`:** `source_read_role_arn`'s description now states it is the
  **principal to authorize on the source bucket's KMS key policy** (with the same-account "EnableRoot
  delegates to IAM → no key-policy edit needed" vs cross-account/restrictive-key caveat); added
  `source_read_external_id` (the `sts:ExternalId` the broker passes). The stack
  (`stacks/editorial-pipeline/outputs.tf`) surfaces both per pipeline, plus `source_drop_rule`.

## Answer to "what principal do I state on the KMS key?"

`source_read_role_arn` — the per-grant role `${name}-jit-source-read` the JIT broker assumes. Add a
`kms:Decrypt` (+ `kms:DescribeKey`) allow for that ARN to the source CMK's key policy **only** if the
key is cross-account or its policy doesn't delegate to IAM via the account-root statement; a
same-account CMK with the standard root statement needs no key-policy edit (the module's role grant +
the now-included session-policy `kms:Decrypt` suffice).

## Verification

- `terraform validate` (module + stack) Success; `aegis validate` exit 0 (1 grant).
- Verified in Python that the committed s3-only session policy string matches the HCL local exactly and
  that the CMK swap renders valid JSON with a `kms:Decrypt` statement.
- PDF §16 least-privilege table gains a KMS-key row.

## Related

Distinct from the Secrets-Manager provider gap tracked as **D5** in `docs/future-improvements.md`
([changelog/0032](0032-todo-secrets-manager-jit-provider.md)) — that is about the *Secret* provider;
this is the *STS* provider decrypting an SSE-KMS S3 object.
