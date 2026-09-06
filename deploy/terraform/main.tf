# Aegis Phase-0 demo — AWS deployment.
#
# Deploys:
#   * aegis-extension as a Lambda LAYER (external extension) that hosts the inline-plane gate
#     (/mediate, /encode, /decide) on loopback and bakes in the policy artifacts under
#     /opt/policies.
#   * a Python agent Lambda that drives the gate and returns a full decision trace.
#   * (optional) a no-default-route VPC so egress containment is architectural, not just code.
#
# The extension binary is cross-compiled by build.sh (cargo-lambda) at apply time.

locals {
  # The aegis Cargo workspace root (this file lives at <workspace>/deploy/terraform).
  workspace_dir = abspath("${path.module}/../..")
  staging_dir   = "${path.module}/build/staging"

  # Rebuild the extension whenever any workspace source or policy artifact changes. fileset
  # does not support brace alternation, so union several patterns (each returns [] if absent).
  extension_src_files = toset(concat(
    tolist(fileset(local.workspace_dir, "Cargo.toml")),
    tolist(fileset(local.workspace_dir, "Cargo.lock")),
    tolist(fileset(local.workspace_dir, "crates/**/Cargo.toml")),
    tolist(fileset(local.workspace_dir, "crates/**/*.rs")),
    tolist(fileset(local.workspace_dir, "policies/*")),
  ))
  extension_src_hash = sha1(join("", [
    for f in local.extension_src_files : filesha1("${local.workspace_dir}/${f}")
  ]))

  tags = {
    Project   = var.project_name
    ManagedBy = "terraform"
    Component = "aegis-phase0"
  }
}

data "aws_availability_zones" "available" {
  state = "available"
}
