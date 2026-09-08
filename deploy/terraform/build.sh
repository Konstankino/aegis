#!/usr/bin/env bash
# Cross-compile aegis-extension for AWS Lambda and stage the layer contents.
# Invoked by Terraform (build.tf) with AEGIS_ARCH / AEGIS_WORKSPACE / AEGIS_STAGING set.
set -euo pipefail

ARCH="${AEGIS_ARCH:-arm64}"
WORKSPACE="${AEGIS_WORKSPACE:?AEGIS_WORKSPACE is required}"
STAGING="${AEGIS_STAGING:?AEGIS_STAGING is required}"

case "$ARCH" in
  arm64)  LAMBDA_FLAG="--arm64" ;;
  x86_64) LAMBDA_FLAG="--x86-64" ;;
  *) echo "unsupported AEGIS_ARCH: $ARCH (want arm64 or x86_64)" >&2; exit 1 ;;
esac

if ! command -v cargo-lambda >/dev/null 2>&1; then
  echo "cargo-lambda not found. Install it with:  cargo install cargo-lambda" >&2
  echo "(it also needs Zig for cross-compilation: https://www.cargo-lambda.info/guide/installation.html)" >&2
  exit 1
fi

# `s3` = fetch policies from S3 at cold start (§2.4); `otel` = OTLP traces/metrics export;
# `dynamodb` = durable per-thread taint + meter + quarantine (survives a cold-start HITL resume;
# reuses AEGIS_CHECKPOINT_TABLE). Without `dynamodb` the extension runs in-memory-only and taint
# is lost across a paused resume that lands on a cold environment.
FEATURES="${AEGIS_FEATURES:-s3,otel,dynamodb}"
echo "==> Building aegis-extension for $ARCH via cargo-lambda (features: $FEATURES)"
( cd "$WORKSPACE" && cargo lambda build --release --extension -p aegis-extension --features "$FEATURES" $LAMBDA_FLAG )

# cargo-lambda writes the extension binary under <target>/lambda/extensions/<name>.
TARGET_DIR="${CARGO_TARGET_DIR:-$WORKSPACE/target}"
BIN="$TARGET_DIR/lambda/extensions/aegis-extension"
if [ ! -f "$BIN" ]; then
  echo "extension binary not found at $BIN" >&2
  exit 1
fi

echo "==> Staging layer contents at $STAGING"
rm -rf "$STAGING"
mkdir -p "$STAGING/extensions" "$STAGING/policies"

# External extensions must live at extensions/<name> inside the layer (-> /opt/extensions/<name>).
cp "$BIN" "$STAGING/extensions/aegis-extension"
chmod +x "$STAGING/extensions/aegis-extension"

# Bake the policy artifacts into the layer at /opt/policies (AEGIS_POLICY_DIR).
cp "$WORKSPACE/policies/tools.json"            "$STAGING/policies/tools.json"
cp "$WORKSPACE/policies/broker.cedar"          "$STAGING/policies/broker.cedar"
cp "$WORKSPACE/policies/egress-allowlist.toml" "$STAGING/policies/egress-allowlist.toml"
cp "$WORKSPACE/policies/meter.toml"            "$STAGING/policies/meter.toml"
cp "$WORKSPACE/policies/pins.json"             "$STAGING/policies/pins.json"
cp "$WORKSPACE/policies/honeypots.json"        "$STAGING/policies/honeypots.json"

echo "==> Done. Layer staged:"
find "$STAGING" -type f | sort
