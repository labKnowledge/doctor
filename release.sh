#!/usr/bin/env bash
# Publish doctor on eligapris.com: writes the installer and the package into the site's public/ folder,
# served as https://eligapris.com/doctor.sh and https://eligapris.com/doctor.tar.gz. Then commit and deploy the site.
# Site checkout: $ELIGAPRIS_SITE, default ../../../key_projects/eligapris-site from here.
set -euo pipefail
SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SITE="${ELIGAPRIS_SITE:-$SRC/../../../key_projects/eligapris-site}"
[[ -f "$SITE/package.json" && -d "$SITE/public" ]] || { echo "eligapris-site not found at $SITE (set ELIGAPRIS_SITE)" >&2; exit 1; }
cd "$SRC"
# Reproducible archive of the committed tree (no caches, no uncommitted edits), under a doctor/ folder.
[[ -z "$(git status --porcelain -- src bin install.sh)" ]] || { echo "commit src/, bin/ and install.sh first" >&2; exit 1; }
git archive --format=tar.gz --prefix=doctor/ -o "$SITE/public/doctor.tar.gz" HEAD src bin
git show HEAD:install.sh > "$SITE/public/doctor.sh"
echo "doctor $(git rev-parse --short HEAD) -> $SITE/public/doctor.sh, doctor.tar.gz ($(du -h "$SITE/public/doctor.tar.gz" | cut -f1))"
