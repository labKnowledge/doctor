#!/usr/bin/env bash
# Install system-check for this user: copies the package to ~/.local/lib/system-check (on the system drive,
# so it keeps working when other drives are unmounted) and links system-check into ~/bin.
# Re-run after changing the source. Uninstall: ./install.sh --uninstall
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HOME/.local/lib/system-check"
BIN="${SYSTEM_CHECK_BIN:-$HOME/bin}"

if [[ "${1:-}" == "--uninstall" ]]; then
  rm -f "$BIN"/system-check; rm -rf "$DEST"
  echo "Removed system-check (reports in ~/.local/state/system-check kept)."; exit 0
fi

rm -rf "$DEST"; mkdir -p "$DEST" "$BIN"
cp -r "$SRC/src" "$SRC/bin" "$DEST/"
find "$DEST" -name __pycache__ -prune -exec rm -rf {} +
chmod +x "$DEST/bin/system-check"
ln -sfn "$DEST/bin/system-check" "$BIN/system-check"
echo "Installed to $DEST; command: $BIN/system-check"
