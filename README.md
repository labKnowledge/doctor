# doctor

One command that tells you what's wrong with this computer, fixes it, and frees disk space safely.

```
doctor            # full check-up, ~3 seconds; asks for sudo once (Ctrl+C skips root-only checks)
doctor fix        # apply the safe fixes from the last check
doctor fix 2 4    # apply specific fixes, including ones marked "review first" (or just: doctor 2 4)
doctor i          # interactive: walk the issues, fix on the go, ask the assistant, free space, look closer
doctor ask "..."  # ask the assistant about this computer (read-only)

doctor clean      # free space: clear caches that rebuild themselves (safe, unattended)
doctor deep       # list big things safe to remove on the system drive; `deep storage` or `deep ~/Downloads`
doctor pick 1 3   # delete those items from the last deep scan

doctor history    # what doctor changed, with undo commands
doctor last       # show the last report again
doctor malware    # check-up + full rootkit scan (rkhunter + chkrootkit), a few minutes
doctor security   # only some areas: stability memory disk hardware services logs updates network security
```

The older commands `system-check`, `disk-clean`, `deep` and `pick` still work exactly as before (they're links to the same tool).
Options: `--json`, `--no-sudo`, `-y` (no confirmation), `-v` (details for OK items too).
Exit code: 0 all fine, 1 warnings, 2 problems. From omnish chat: `!syscheck`, `!sysfix 2 4`, `!sysask ...`, `!clean`, `!deep storage`, `!pick 1 3`.

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

## Interactive mode

`doctor i` opens on a main menu of everything doctor can do, with a one-line glance at this computer (uptime, RAM,
how full each drive is) that takes no time to gather. Nothing is scanned until you ask:

```
doctor · you@host · up 5h · RAM 11G of 31G  ·  disks / 69%  backup 69%  storage 85%

Check and fix
  › c  Check-up               find what's wrong and fix it, one issue at a time
    l  Last results           8 to look at, from 6 min ago
    a  Ask the assistant      any question about this computer, in plain words
Disk space
    f  Free up space          clear caches that rebuild themselves, safe
    b  Big files and folders  find what's safe to delete on a drive
Manage
    s  Services               2 failing · start, stop, turn off at boot
    h  History                what doctor changed, and how to undo it
Look closer
    t  Top apps · p Ports · n Network · e Temperatures · u Startup · k App kills · g Logs · r Rootkit scan
```

Arrow keys and Enter, or press an entry's letter. `:` opens the command line (`help` lists every command),
`q` goes back one level (issue card → issue list → main menu → quit), `m` jumps to the main menu from anywhere,
and **Ctrl+X** closes doctor from anywhere, even mid-task. On a terminal too short for the menu, type the letter and Enter.

The check-up asks for sudo once (Ctrl+C skips the root-only checks), then shows only what needs attention
(suggestions fold behind `more`). Press **Enter** to walk through the issues one by one: each card shows what's
wrong and the exact commands its fix runs; Enter applies the fix (or moves on), `e` has the assistant explain it,
`s` skips, `b` goes back one. The fixed check is re-run on the spot. Or type a number to jump to an issue,
`f safe` for every safe fix, or ask anything in plain words.

Every Look closer screen (Top apps, Ports, Network, Temperatures, Startup, App kills, Logs, Services) is a list you
move through with the arrow keys (PgUp/PgDn/Home/End too). The selected row explains itself in plain words under the
list ("Port 22 is SSH... Remote access: make sure you set this up on purpose"), `?` asks the assistant for more,
Enter acts on it (open the program, the service, or the full log), `/` finds, `r` refreshes, Esc goes back.
Live screens (Top apps, Temperatures) refresh by themselves. The plain-words notes live in `knowledge.py`.

Top apps (`t`) is live: the biggest processes refresh every 2 seconds, with the app or service each belongs to.
Enter (or its number) opens a process card: what it is, what started it, its command, and a plain warning when
ending it would hurt (your desktop, sound, network, Docker). `k` ends it (asks first; if it ignores the request for
3 seconds, offers to force it), `f` forces it, `a` ends the whole app or stops its service, `?` has the assistant
explain it. Processes of root or other users go through sudo. `s` switches between sorting by memory and by CPU.
From the command line: `kill PID` opens the same card.

Manage services: `services` lists every service (system and yours) in one numbered list, with problems first and then
what's running, biggest first. `/word` searches, `all` adds the ones not running, and `user`/`system` narrow it down.
Type a number to see its status and log, then `r` restart, `s` stop, `t` start, `d` disable, `e` enable,
`?` for the assistant to explain what it is and whether you need it, or type any question about it.

Look closer at one thing: `top` (memory/CPU right now), `ports` (what listens and who can reach it), `svc NAME`
(status + log, then restart/stop/disable/enable), `logs [NAME]`, `boot` (slow startup), `kills` (low-memory kills),
`temps`, `net` (router, internet, DNS, HTTPS timings), `disk` (usage and biggest caches), `malware`, any area name,
`!command`. Free space without leaving: `clean`, `deep [storage|folder]`, `pick 1 3` (asks before deleting). Tab completes.
The same focused checks work outside interactive mode: `doctor top`, `doctor ports`, ...

## Learn more with Claude

`?` explains in a few lines; `o` (learn more) goes further: it opens a full Claude Code session in a **new terminal
window** that already holds what you were looking at (the issue and its fix, the port, the process, the service's
status and log, or the whole last check-up from the main menu's "Learn with Claude"). It's set up as a patient tutor:
plain explanation first, then how it works underneath and the commands to see it yourself; it asks before changing
anything. doctor stays where you were. Works from every list row, issue card, process card and service screen
(`o 3` on the issue list). It uses GNOME Terminal, Konsole, kitty, Alacritty, WezTerm, Tilix, xterm and others
(`$TERMINAL` first), a tmux window inside tmux, and without a desktop it offers to run in the same terminal.
Each session's context is kept in `~/.local/state/doctor/learn/` (last 30); reopen one with `bash <folder>/run.sh`.

## The assistant

`e 3` in interactive mode, `doctor explain 3`, or `doctor ask "why is my PC slow?"` asks Claude (Claude
Code's `claude` command) to explain in plain language: what it is, whether it matters, and which fix to apply.
It is sandboxed read-only: a fixed list of read commands (journalctl, systemctl status, ss, ps, df, docker ps, ...),
everything else refused without asking (`dontAsk`), no MCP servers, no user/project settings, and no reading of
SSH keys, .env, credential or key files. It can look, never change; fixes stay with you. Without `claude`
installed everything else works and the assistant hints are hidden. `DOCTOR_NO_AGENT=1` turns it off.

## Free disk space

The disk area warns when a drive fills up; its fix runs `doctor clean`, and the warning names the
`deep` command for that drive. `clean` clears caches that rebuild themselves: package managers (conda, pip, npm,
yarn, pnpm, bun, uv), Gradle logs, browser and thumbnail caches, the Trash, unused Flatpak runtimes, Docker
leftovers (volumes kept), and editor caches only while those editors are closed. `deep` lists big things you
might not need; nothing is deleted until you `pick` numbers.

### What a deep scan finds

Only things that live on the drive or folder you point it at:

| Kind | What | When |
|---|---|---|
| build | `node_modules`, `build`, `dist`, `.next`, `target`, `.gradle`, `.venv`… | The project is idle 30+ days, the folder is real build output (it has the matching `package.json`, `build.gradle`…) and it isn't tracked in git |
| model | Hugging Face cache models | Not loaded by any running program |
| conda | conda environments | Unused 30+ days |
| android | NDKs, emulator images, emulators | No project's `ndkVersion` uses it / no AVD uses it / idle 30+ days |
| gradle | Gradle wrapper versions and their caches | No project's wrapper uses it |
| docker | Docker volumes | Not attached to any container |
| file | Single files of 1 GB+ | Untouched 90+ days, or an unfinished download |

### Safety rules

- Nothing is deleted at scan time.
- Anything a running process holds is never listed, and is checked again right before deleting. That covers open files, working directories, binaries, memory-mapped files and paths in command lines.
- Active and configured swap files are never listed.
- Build folders count only inside real projects: a git repo, or a folder with `src/`. Folders under hidden app directories (editor extensions, tool installs) never count.
- A scan expires after 24 hours; `pick` refuses to act on an old list.
- NDK and Gradle suggestions appear only after every mounted data drive has been deep-scanned once, because before that it can't know what your projects use.
- An old OS install on a data drive (a drive with `etc/` and `usr/` at its root) has its system folders skipped.

### Tuning

The constants at the top of `src/disk_clean/scan.py` control the behaviour: `IDLE_DAYS`, `BIG_FILE`, `BIG_FILE_DAYS`, `MIN_ITEM`, `MAX_ITEMS` and `TIME_BUDGET` (20 minutes, so chat commands finish before their 30-minute timeout). Scan state lives in `~/.cache/disk-clean`, or in `$DISK_CLEAN_DATA` if that's set.

### Python API

```python
from disk_clean import scan, remove, quick_clean, last_scan, DiskCleanError

result = scan("storage", on_progress=lambda p: print(p["dirs"], "folders"))
for n, item in enumerate(result["items"], 1):
    print(n, item["label"], item["size"], item["note"])

remove("1 3 5-7")                         # by number from the last scan
remove(None, ids=[result["items"][0]["id"]])  # or by stable item id (better for UIs)

quick_clean(on_line=print)                # returns {"freed", "disk", "log"}
```

Each call that fails for a user-facing reason raises `DiskCleanError`, and its message is safe to show as-is. Without installing, add `src/` to `sys.path`, or run `python -m disk_clean`.

Add `--json` to `clean`, `deep`, `pick` for the library's JSON output.

## Fixes

Every fix is a short bash snippet shown by name before it runs. "Safe" fixes (relax the oomd killer,
stop swapping to a hard drive, keep 1 GB of logs, enable auto security updates, lock the screen,
tighten ~/.ssh...) run with plain `doctor fix`. Fixes that change behaviour you might rely on
(turn on the firewall, disable a broken service, key-only SSH) are marked "review first" and only
run when picked by number. All root fixes go through one `sudo` prompt; after fixing, the affected
checks run again.

## Layout

- `src/doctor/core.py` – command runner (user/root, works under sudo too), findings, registry, parallel runner
- `src/doctor/health.py` – stability, memory, disk, hardware, services, logs, updates, network
- `src/doctor/security.py` – security checks
- `src/doctor/review.py` – running-services review and "not needed?" suggestions
- `src/doctor/cli.py` – rendering, report history, `fix`, `deep`
- `src/doctor/interactive.py` – `doctor i`: main menu, issue list and walkthrough, rendering of focused checks
- `src/doctor/procs.py` – processes: list, details, what owns them, ending safely (TERM, then KILL; sudo when not yours)
- `src/doctor/menu.py` – the keyboard widgets: main menu, list screens (`browse`), one-key questions, typed fallback
- `src/doctor/learn.py` – learn more: writes a session's context and opens Claude in a new terminal window
- `src/doctor/knowledge.py` – plain-words notes for ports, sensors, network steps, startup items, kills and log lines
- `src/doctor/probes.py` – focused checks as data (top, ports, kills, net, sensors)
- `src/doctor/agent.py` – read-only Claude assistant (prompting, sandbox flags, streaming)
- `src/doctor/clean.py` – `clean` / `deep` / `pick` on the command line and in interactive mode
- `src/disk_clean/` – the disk space library (scan, remove, quick_clean, quick.sh); no doctor imports

Add a check: write a function returning `finding(level, title, detail, fix(...))` and decorate it with
`@check("area", "name")`. State and the last 30 reports live in `~/.local/state/doctor/`.

Install: `./install.sh` (copies to `~/.local/lib/doctor`, links `doctor` and the older names `system-check`, `disk-clean`, `deep`, `pick` into `~/bin`).
Tests: `python3 -m unittest discover -s tests`.
