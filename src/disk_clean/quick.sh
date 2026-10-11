#!/usr/bin/env bash
# Quick clean: clear caches that rebuild themselves when needed.
# Never touches models, conda environments, Docker volumes, Android SDKs or projects.
# Safe to run unattended. Run through `disk-clean` (or disk_clean.quick_clean() from Python).
set -uo pipefail

free_mb() { df --output=avail -B1M / | tail -1 | tr -d ' '; }
usage() { df -h --output=pcent,avail / | tail -1 | awk '{print $1" used, "$2" free"}'; }
have() { command -v "$1" >/dev/null 2>&1; }
running() { pgrep -x "$1" >/dev/null 2>&1 || pgrep -f "$2" >/dev/null 2>&1; }
step() { printf '  %-22s' "$1"; }

before=$(free_mb)
echo "disk-clean: $(usage)"

# Package managers
step "conda";   [[ -x ~/miniconda3/bin/conda ]] && ~/miniconda3/bin/conda clean -a -y >/dev/null 2>&1; echo done
step "pip";     rm -rf ~/.cache/pip; echo done
step "npm";     have npm && npm cache clean --force >/dev/null 2>&1; rm -rf ~/.npm/_logs; echo done
# npx: only packages untouched for a week, so running MCP servers keep their files
step "npx (>7 days)"; find ~/.npm/_npx -mindepth 1 -maxdepth 1 -mtime +7 -exec rm -rf {} + 2>/dev/null; echo done
step "yarn";    { have yarn && yarn cache clean >/dev/null 2>&1; } || rm -rf ~/.cache/yarn/*; echo done
step "pnpm";    have pnpm && pnpm store prune >/dev/null 2>&1; echo done
step "bun";     have bun && bun pm cache rm >/dev/null 2>&1; echo done
step "uv";      have uv && uv cache clean >/dev/null 2>&1; echo done
step "cargo downloads"; rm -rf ~/.cargo/registry/cache; echo done
step "go build cache"; have go && go clean -cache >/dev/null 2>&1; echo done
step "gradle logs/daemons"; rm -rf ~/.gradle/daemon/*/*.log ~/.gradle/caches/transforms-* 2>/dev/null; echo done

# Docker: stopped containers, unused images/networks, build cache. Volumes are kept.
step "docker"
if have docker && docker info >/dev/null 2>&1; then
  docker system prune -af 2>/dev/null | tail -1
else
  echo "skipped (not running)"
fi

# Apps: only clear an editor's cache while it is closed
step "browser/app caches"
rm -rf ~/.cache/google-chrome/*/Cache ~/.cache/google-chrome/*/"Code Cache" \
       ~/.cache/typescript ~/.cache/gnome-software ~/.cache/thumbnails/* 2>/dev/null; echo done
step "vscode cache"
if running code '/usr/share/code/code'; then echo "skipped (open)"
else rm -rf ~/.config/Code/{Cache,CachedData,"Code Cache",GPUCache,logs} 2>/dev/null; echo done; fi
step "cursor cache"
if running cursor '[Cc]ursor.*--type'; then echo "skipped (open)"
else rm -rf ~/.config/Cursor/{Cache,CachedData,CachedExtensionVSIXs,"Code Cache",GPUCache,logs} 2>/dev/null; echo done; fi
step "android studio cache"
if pgrep -f 'com.google.AndroidStudio|android-studio' >/dev/null 2>&1; then echo "skipped (open)"
else rm -rf ~/.var/app/com.google.AndroidStudio/cache/* 2>/dev/null; echo done; fi

# System-ish
step "user journal";   journalctl --user --vacuum-time=14d >/dev/null 2>&1; echo done
step "trash";          gio trash --empty 2>/dev/null; echo done
step "flatpak unused"; have flatpak && flatpak uninstall --unused -y >/dev/null 2>&1; echo done
step "apt/journal/snaps"
if sudo -n true 2>/dev/null; then
  sudo apt-get clean -y >/dev/null 2>&1
  sudo journalctl --vacuum-time=14d >/dev/null 2>&1
  snap list --all 2>/dev/null | awk '/disabled/{print $1, $3}' |
    while read -r name rev; do sudo snap remove "$name" --revision="$rev" >/dev/null 2>&1; done
  echo done
else
  echo "skipped (needs sudo)"
fi

after=$(free_mb)
freed=$(( after - before ))
echo "Freed $(awk -v m="$freed" 'BEGIN{printf (m>=1024 ? "%.1f GB" : "%d MB"), (m>=1024 ? m/1024 : m)}'). Now: $(usage)"
echo "Largest caches left (models etc. are never touched):"
du -sh ~/.cache/* 2>/dev/null | sort -rh | head -5 | sed 's/^/  /'
