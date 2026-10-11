#!/usr/bin/env bash
# Install doctor for this user: copies the package to ~/.local/lib/doctor (on the system drive,
# so it keeps working when other drives are unmounted) and links doctor into ~/bin, plus the older
# system-check, disk-clean, deep and pick names. Re-run after changing the source. Uninstall: ./install.sh --uninstall
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DEST="$HOME/.local/lib/doctor"
BIN="${DOCTOR_BIN:-$HOME/bin}"
NAMES=(doctor system-check disk-clean deep pick)

if [[ "${1:-}" == "--uninstall" ]]; then
  for n in "${NAMES[@]}"; do rm -f "$BIN/$n"; done; rm -rf "$DEST"
  echo "Removed doctor (reports in ~/.local/state/doctor and scans in ~/.cache/disk-clean kept)."; exit 0
fi

rm -rf "$DEST" "$HOME/.local/lib/disk-clean" "$HOME/.local/lib/system-check"   # earlier names of this tool
OLD_STATE="$HOME/.local/state/system-check"
[[ -d "$OLD_STATE" && ! -e "$HOME/.local/state/doctor" ]] && mv "$OLD_STATE" "$HOME/.local/state/doctor"
mkdir -p "$DEST" "$BIN"
cp -r "$SRC/src" "$SRC/bin" "$DEST/"
find "$DEST" -name __pycache__ -prune -exec rm -rf {} +
chmod +x "$DEST/bin/doctor" "$DEST/src/disk_clean/quick.sh"
for n in "${NAMES[@]}"; do ln -sfn "$DEST/bin/doctor" "$BIN/$n"; done
echo "Installed to $DEST; commands in $BIN: ${NAMES[*]}"
