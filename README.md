# system-check

One command that tells you what's wrong with this computer and fixes it.

```
system-check            # full check-up, ~3 seconds; asks for sudo once (Ctrl+C skips root-only checks)
system-check fix        # apply the safe fixes from the last check
system-check fix 2 4    # apply specific fixes, including ones marked "review first" (or just: system-check 2 4)
system-check last       # show the last report again
system-check deep       # check-up + full rootkit scan (rkhunter + chkrootkit), a few minutes
system-check security   # only some areas: stability memory disk hardware services logs updates network security
```

Options: `--json`, `--no-sudo`, `-y` (no confirmation), `-v` (details for OK items too).
Exit code: 0 all fine, 1 warnings, 2 problems. From omnish chat: `!syscheck`, `!sysfix 2 4`.

## What it checks

| Area | Checks |
|---|---|
| stability | apps killed by systemd-oomd / kernel OOM (and whether it happened after the fix), crash reports in /var/crash, segfaults, core dumps, sessions that ended without a clean shutdown |
| memory | available RAM, memory stall (PSI), biggest apps, swap on a spinning disk |
| disk | full or read-only filesystems, inodes, kernel I/O errors, SMART health |
| hardware | temperatures and thermal throttling, NVIDIA driver and Xid errors, CPU load |
| services | failed units and restart loops (system + user), with the reason (missing folder/program, deprecated, missing config, can't send mail); stuck snap jobs; Docker containers unhealthy or restarting, reclaimable images |
| services (review) | every running service with its real memory (anon, not file cache); "not needed?" suggestions: cups with no working printer, cups-browsed, ModemManager with no modem, Bluetooth with nothing paired, VM agents on real hardware, brltty, unconfigured mail servers, idle gnome-remote-desktop, GNOME Software in the background, a heavy file indexer; always-on remote access (AnyDesk) and public tunnels (ngrok, pinggy, cloudflared…); big services idle for hours. Each comes with a "turn off" fix and the command to undo it |
| logs | kernel errors and error-level messages of the last 24 h grouped by source; journal retention too short to diagnose |
| updates | reboot pending, newer kernel installed, security updates, half-installed packages |
| network | default route, DNS, clock sync |
| security | chkrootkit daily alerts (files owned by installed packages filtered out, flagged ports checked against what really listens), ufw, ports open to the network (incl. Docker ports that bypass ufw), sshd settings, fail2ban, failed/successful SSH logins, sudo failures, UID-0 and password-less accounts, NOPASSWD sudo, auto security updates, AppArmor, screen lock, ld.so.preload, programs running from /tmp or named like miners, outdated binaries still running, new startup items, authorized_keys changes, ~/.ssh and home permissions, world-writable system files, SUID in temp folders, last rkhunter/chkrootkit result |

## Fixes

Every fix is a short bash snippet shown by name before it runs. "Safe" fixes (relax the oomd killer,
stop swapping to a hard drive, keep 1 GB of logs, enable auto security updates, lock the screen,
tighten ~/.ssh...) run with plain `system-check fix`. Fixes that change behaviour you might rely on
(turn on the firewall, disable a broken service, key-only SSH) are marked "review first" and only
run when picked by number. All root fixes go through one `sudo` prompt; after fixing, the affected
checks run again.

## Layout

- `src/system_check/core.py` – command runner (user/root, works under sudo too), findings, registry, parallel runner
- `src/system_check/health.py` – stability, memory, disk, hardware, services, logs, updates, network
- `src/system_check/security.py` – security checks
- `src/system_check/review.py` – running-services review and "not needed?" suggestions
- `src/system_check/cli.py` – rendering, report history, `fix`, `deep`

Add a check: write a function returning `finding(level, title, detail, fix(...))` and decorate it with
`@check("area", "name")`. State and the last 30 reports live in `~/.local/state/system-check/`.

Install: `./install.sh` (copies to `~/.local/lib/system-check`, links `~/bin/system-check`).
Tests: `python3 -m unittest discover -s tests`.
