#!/usr/bin/env bash
# Build a signed-lookalike (unsigned) macOS DMG for GoHex.
# Prerequisites: `wails3 build` on macOS produced bin/gohex.app (or
# bin/gohex), and create-dmg is on PATH (brew install create-dmg).
set -euo pipefail

APP="${1:-bin/gohex.app}"
OUT="${2:-dist/gohex-$(uname -m).dmg}"
VOL="GoHex"

if [[ ! -e "$APP" ]]; then
  echo "usage: $0 [path-to-app] [output.dmg]" >&2
  echo "missing app bundle: $APP" >&2
  exit 1
fi

mkdir -p "$(dirname "$OUT")"
rm -f "$OUT"

create-dmg \
  --volname "$VOL" \
  --window-pos 200 120 \
  --window-size 600 400 \
  --icon-size 100 \
  --icon "$(basename "$APP")" 150 200 \
  --app-drop-link 450 200 \
  --hide-extension \
  "$OUT" \
  "$APP"

echo "DMG written to $OUT"
echo "Sign before distribution: codesign --deep --force --options runtime -s \"Developer ID\" \"$OUT\""
