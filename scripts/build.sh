#!/usr/bin/env bash
# Build self-contained Linux binaries for x64 and arm64 with bun build --compile,
# emitting a SHA256 checksum alongside each artifact. Reproducible: pinned entry,
# fixed output names derived from the version, no timestamps in the names.
set -euo pipefail

cd "$(dirname "$0")/.."

VERSION="$(bun --eval 'import {VERSION} from "./src/version.ts"; process.stdout.write(VERSION)')"
PKG_VERSION="$(bun --eval 'process.stdout.write(require("./package.json").version)')"

if [[ "$VERSION" != "$PKG_VERSION" ]]; then
  echo "version mismatch: src/version.ts=$VERSION package.json=$PKG_VERSION" >&2
  exit 1
fi

OUT_DIR="dist"
AGENT_ENTRY="src/index.ts"
CTL_ENTRY="src/cli.ts"
mkdir -p "$OUT_DIR"

build_one() {
  local entry="$1" name="$2" target="$3" suffix="$4"
  local out="$OUT_DIR/${name}-${VERSION}-${suffix}"
  echo ">> building ${name} ${suffix} ($target)"
  bun build "$entry" \
    --compile \
    --target="$target" \
    --minify \
    --sourcemap=none \
    --outfile "$out"
  # SHA256 (portable across macOS/Linux).
  if command -v sha256sum >/dev/null 2>&1; then
    (cd "$OUT_DIR" && sha256sum "$(basename "$out")" > "$(basename "$out").sha256")
  else
    (cd "$OUT_DIR" && shasum -a 256 "$(basename "$out")" > "$(basename "$out").sha256")
  fi
  echo "   -> $out"
  echo "   -> $out.sha256"
}

build_one "$AGENT_ENTRY" "proxy-agent"     "bun-linux-x64"   "linux-x64"
build_one "$AGENT_ENTRY" "proxy-agent"     "bun-linux-arm64" "linux-arm64"
build_one "$CTL_ENTRY"   "proxy-agent-ctl" "bun-linux-x64"   "linux-x64"
build_one "$CTL_ENTRY"   "proxy-agent-ctl" "bun-linux-arm64" "linux-arm64"

echo
echo "Artifacts in $OUT_DIR/:"
ls -la "$OUT_DIR"
echo
echo "Checksums:"
cat "$OUT_DIR"/*.sha256
