#!/usr/bin/env bash
# Install doctor for this user. Works two ways:
#   from a checkout:   ./install.sh
#   in one line:       curl -fsSL https://eligapris.com/doctor.sh | bash
# Copies the package to ~/.local/lib/doctor (on the system drive, so it keeps working when other drives
# are unmounted) and links doctor, plus the older system-check, disk-clean, deep and pick names, into a
# folder on PATH. Re-run to update. Uninstall: ./install.sh --uninstall  (or: curl ... | bash -s -- --uninstall)
set -euo pipefail
URL="${DOCTOR_URL:-https://eligapris.com/doctor.tar.gz}"
DEST="$HOME/.local/lib/doctor"
NAMES=(doctor system-check disk-clean deep pick)
say() { printf '%s\n' "$*"; }
die() { printf 'doctor install: %s\n' "$*" >&2; exit 1; }

# Where the commands go: an explicit DOCTOR_BIN, else ~/bin when an earlier install put them there,
# else ~/.local/bin (on PATH by default on Ubuntu once it exists).
on_path() { case ":$PATH:" in *":$1:"*) return 0;; esac; return 1; }
if [[ -n "${DOCTOR_BIN:-}" ]]; then BIN="$DOCTOR_BIN"
elif [[ -L "$HOME/bin/doctor" ]]; then BIN="$HOME/bin"
else BIN="$HOME/.local/bin"; fi

if [[ "${1:-}" == "--uninstall" ]]; then
  [[ -x "$DEST/bin/doctor" ]] && "$DEST/bin/doctor" guard off >/dev/null 2>&1 || true   # give git its own hooks back
  for b in "$BIN" "$HOME/bin" "$HOME/.local/bin"; do
    for n in "${NAMES[@]}"; do [[ -L "$b/$n" && "$(readlink "$b/$n")" == "$DEST/"* ]] && rm -f "$b/$n"; done
  done
  rm -rf "$DEST"
  say "Removed doctor (reports in ~/.local/state/doctor and scans in ~/.cache/disk-clean kept)."; exit 0
fi

[[ "$(uname -s)" == Linux ]] || die "doctor checks Linux computers only (this is $(uname -s))."
[[ $EUID -ne 0 ]] || die "run this as your normal user, not root; doctor asks for sudo itself when it needs it."
[[ -x /usr/bin/python3 ]] || die "needs /usr/bin/python3. Install it with: sudo apt install python3"
/usr/bin/python3 -c 'import sys; sys.exit(sys.version_info < (3, 9))' \
  || die "needs Python 3.9 or newer (found $(/usr/bin/python3 -V 2>&1))."

# Source: this checkout when run as a file next to src/, otherwise download the repo.
SRC=""
if [[ -n "${BASH_SOURCE[0]:-}" && -f "${BASH_SOURCE[0]}" ]]; then
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
  [[ -d "$here/src/doctor" && -f "$here/bin/doctor" ]] && SRC="$here"
fi
if [[ -z "$SRC" ]]; then
  TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
  say "Downloading doctor ..."
  if command -v curl >/dev/null; then curl -fsSL "$URL" -o "$TMP/d.tgz" || die "download failed: $URL"
  elif command -v wget >/dev/null; then wget -qO "$TMP/d.tgz" "$URL" || die "download failed: $URL"
  else die "needs curl or wget to download."; fi
  tar -xzf "$TMP/d.tgz" -C "$TMP" || die "the download is not a valid archive."
  SRC="$(find "$TMP" -mindepth 1 -maxdepth 1 -type d | head -n1)"
  [[ -d "$SRC/src/doctor" ]] || die "the download does not contain doctor."
fi

rm -rf "$DEST" "$HOME/.local/lib/disk-clean" "$HOME/.local/lib/system-check"   # earlier names of this tool
OLD_STATE="$HOME/.local/state/system-check"
[[ -d "$OLD_STATE" && ! -e "$HOME/.local/state/doctor" ]] && mv "$OLD_STATE" "$HOME/.local/state/doctor"
mkdir -p "$DEST" "$BIN"
cp -r "$SRC/src" "$SRC/bin" "$DEST/"
find "$DEST" -name __pycache__ -prune -exec rm -rf {} +
chmod +x "$DEST/bin/doctor" "$DEST/src/disk_clean/quick.sh"
for n in "${NAMES[@]}"; do ln -sfn "$DEST/bin/doctor" "$BIN/$n"; done
say "Installed doctor ($DEST); commands in $BIN: ${NAMES[*]}"

# Make sure the command works in new terminals without the user editing anything.
if ! on_path "$BIN"; then
  line="export PATH=\"$BIN:\$PATH\""
  for rc in "$HOME/.bashrc" "$HOME/.zshrc"; do
    [[ -f "$rc" ]] && ! grep -qF "$line" "$rc" && printf '\n# added by doctor installer\n%s\n' "$line" >> "$rc"
  done
  say "Open a new terminal (or run: $line), then type: doctor"
else
  say "Run: doctor"
fi
grep -qi ubuntu /etc/os-release 2>/dev/null \
  || say "Note: built for Ubuntu; on other Linux most checks work but vulnerabilities and some fixes are skipped."
