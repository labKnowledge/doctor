"""Stability, memory, disk, hardware, services, logs, updates and network checks."""
import collections, glob, json, os, re, shlex, time

from .core import CRIT, INFO, OK, SKIP, WARN, check, finding, fix, human, normalize, read

SINCE = "7 days ago"
OOMD_DROPIN = "/etc/systemd/system/user@.service.d/90-oomd-relaxed.conf"
JOURNAL_DROPIN = "/etc/systemd/journald.conf.d/size.conf"


# ---------- helpers ----------

def meminfo():
    out = {}
    for line in read("/proc/meminfo").splitlines():
        k, _, v = line.partition(":")
        parts = v.split()
        if parts:
            out[k] = int(parts[0]) * 1024
    return out


def psi(kind="memory"):
    m = re.search(r"some avg10=([\d.]+) avg60=([\d.]+) avg300=([\d.]+)", read(f"/proc/pressure/{kind}"))
    return tuple(float(x) for x in m.groups()) if m else (0.0, 0.0, 0.0)


def app_name(unit_path):
    """Turn a cgroup path into the app a person recognises."""
    s = unit_path.rstrip("/").split("/")[-1].replace("\\x2d", "-")
    s = re.sub(r"\.(scope|service|slice)$", "", s)
    s = re.sub(r"-[0-9a-f]{8}-[0-9a-f-]{27,}$|-\d+$", "", s)
    s = re.sub(r"^(app-gnome-|app-flatpak-|app-|snap\.)", "", s)
    known = {"code.code": "VS Code", "code": "VS Code", "google-chrome": "Google Chrome",
             "com.google.Chrome": "Google Chrome", "org.gnome.Terminal": "Terminal",
             "firefox.firefox": "Firefox", "cursor": "Cursor"}
    return known.get(s, s)


def top_processes(ctx, key="rss", n=5):
    col = "rss" if key == "rss" else "pcpu"
    out = ctx.run(f"ps -eo {col},comm --no-headers")
    agg = collections.Counter()
    for line in out.splitlines():
        parts = line.split(None, 1)
        if len(parts) == 2:
            try:
                agg[parts[1].strip()] += float(parts[0])
            except ValueError:
                pass
    return agg.most_common(n)


def block_dev_rotational(path):
    """True if `path` (file or device) lives on a spinning disk."""
    if not path.startswith("/dev/"):
        return None
    name = os.path.basename(os.path.realpath(path))
    # partition -> parent disk
    for cand in (name, re.sub(r"p?\d+$", "", name)):
        val = read(f"/sys/block/{cand}/queue/rotational").strip()
        if val:
            return val == "1"
    return None


# ---------- stability ----------

@check("stability", "app-kills")
def app_kills(ctx):
    out = ctx.run(f'journalctl -u systemd-oomd --since "{SINCE}" --no-pager -o short-iso | grep " Killed "')
    kills = []
    for line in out.splitlines():
        m = re.search(r"^(\S+).*Killed (\S+) due to memory pressure .*? being ([\d.]+)%", line)
        if m:
            kills.append((m.group(1)[:16].replace("T", " "), app_name(m.group(2)), m.group(3)))
    kout = ctx.run(f'journalctl -k --since "{SINCE}" --no-pager -o short-iso | grep -E "Out of memory: Killed process|oom-kill:"')
    for line in kout.splitlines():
        m = re.search(r"^(\S+).*Killed process \d+ \(([^)]+)\)", line)
        if m:
            kills.append((m.group(1)[:16].replace("T", " "), m.group(2) + " (kernel OOM)", ""))

    limit = ctx.run("systemctl show user@%d.service -p ManagedOOMMemoryPressureLimit -p ManagedOOMMemoryPressureDurationSec --value" % ctx.uid).split()
    relaxed = os.path.exists(OOMD_DROPIN)
    res = []
    if kills:
        by_app = collections.Counter(k[1] for k in kills)
        detail = [f"{n}x {app}" for app, n in by_app.most_common()]
        detail += [f"last: {kills[-1][1]} at {kills[-1][0]}",
                   "The system closed these on purpose because memory was stalling (systemd-oomd), not because they crashed.",
                   "Look under 'Memory' for what is using RAM and whether swap is on a slow disk."]
        f = None if relaxed else fix(
            "Make the out-of-memory killer less trigger-happy (act at 80% stall for 60s, not 50% for 20s)",
            f"mkdir -p {os.path.dirname(OOMD_DROPIN)}\n"
            f"printf '[Service]\\nManagedOOMMemoryPressureLimit=80%%\\nManagedOOMMemoryPressureDurationSec=60s\\n' > {OOMD_DROPIN}\n"
            "systemctl daemon-reload")
        fixed_at = os.path.getmtime(OOMD_DROPIN) if relaxed else None
        after = [k for k in kills if not fixed_at or time.mktime(time.strptime(k[0], "%Y-%m-%d %H:%M")) > fixed_at]
        if fixed_at and not after:
            res.append(finding(INFO, f"{len(kills)} app(s) were killed for low memory this week, all before the fix on "
                                     f"{time.strftime('%b %d %H:%M', time.localtime(fixed_at))}; none since", detail[:-2]))
        else:
            res.append(finding(CRIT if len(after) > 1 else WARN, f"{len(after)} app(s) killed for low memory in the last 7 days"
                               + (" (even after relaxing the killer)" if fixed_at else ""), detail, f))
    else:
        res.append(finding(OK, "No apps killed for low memory in the last 7 days"))
    if not relaxed and not kills and limit and limit[0].startswith("50"):
        res.append(finding(INFO, "Out-of-memory killer uses the strict Ubuntu default (50% stall for 20s)"))
    return res


@check("stability", "crashes")
def crashes(ctx):
    res = []
    week = time.time() - 7 * 86400
    files = sorted(glob.glob("/var/crash/*.crash"), key=lambda p: -os.path.getmtime(p))
    recent = [p for p in files if os.path.getmtime(p) > week]
    old = [p for p in files if os.path.getmtime(p) <= week]
    if recent:
        detail = [f"{time.strftime('%b %d %H:%M', time.localtime(os.path.getmtime(p)))}  "
                  f"{os.path.basename(p).rsplit('.', 2)[0].replace('_', '/')}" for p in recent[:8]]
        res.append(finding(WARN, f"{len(recent)} app crash report(s) this week", detail, key="crash-files"))
    if old:
        res.append(finding(INFO, f"{len(old)} old crash report(s) in /var/crash", [],
                           fix("Delete crash reports older than 7 days",
                               "find /var/crash -name '*.crash' -mtime +7 -delete")))
    seg = ctx.run(f'journalctl -k --since "{SINCE}" --no-pager -o cat | grep -E "segfault at|traps:.*general protection"')
    procs = collections.Counter(m.group(1) for m in re.finditer(r"^(?:traps: )?(\S+?)\[\d+\]", seg, re.M))
    if procs:
        res.append(finding(WARN, f"{sum(procs.values())} program crash(es) (segfaults) in the kernel log this week",
                           [f"{n}x {p}" for p, n in procs.most_common(8)]))
    cores = ctx.run(f'coredumpctl list --since "{SINCE}" --no-legend --no-pager 2>/dev/null')
    exes = collections.Counter(os.path.basename(l.split()[-1]) for l in cores.splitlines() if l.split())
    if exes:
        res.append(finding(WARN, f"{sum(exes.values())} core dump(s) this week", [f"{n}x {e}" for e, n in exes.most_common(8)]))
    if not res:
        res.append(finding(OK, "No crash reports or segfaults this week"))
    return res


@check("stability", "unclean-shutdowns")
def unclean_shutdowns(ctx):
    boots = [l.split() for l in ctx.run("journalctl --list-boots --no-pager 2>/dev/null").splitlines()]
    boots = [b for b in boots if b and b[0].lstrip("-").isdigit() and int(b[0]) < 0][-10:]
    bad = []
    for b in boots:
        tail = ctx.run(f"journalctl -b {b[0]} -n 40 --no-pager -o cat")
        if not re.search(r"Journal stopped|systemd-shutdown|Reached target (System )?(Power-?Off|Reboot|Shutdown)|Shutting down", tail):
            bad.append(" ".join(b[-4:-1]) if len(b) >= 4 else b[0])
    if not boots:
        return [finding(SKIP, "Boot history unavailable")]
    if bad:
        return [finding(WARN, f"{len(bad)} of the last {len(boots)} sessions ended without a clean shutdown",
                        [f"ended {t}" for t in bad[-5:]] +
                        ["Causes: hard freeze, power loss, or holding the power button. Check 'Kernel errors' and temperatures."])]
    return [finding(OK, f"Last {len(boots)} shutdowns were clean")]


# ---------- memory ----------

@check("memory", "ram")
def ram(ctx):
    m = meminfo()
    total, avail = m.get("MemTotal", 1), m.get("MemAvailable", 0)
    stotal, sfree = m.get("SwapTotal", 0), m.get("SwapFree", 0)
    p10, p60, _ = psi("memory")
    top = top_processes(ctx, "rss", 6)
    detail = [f"RAM {human(total - avail)} used of {human(total)} · swap {human(stotal - sfree)} used of {human(stotal)} · "
              f"stall {p60:.1f}% (60s avg)",
              "Biggest: " + ", ".join(f"{name} {human(kb * 1024)}" for name, kb in top)]
    pct_free = avail / total * 100
    if pct_free < 5 or p60 > 30:
        return [finding(CRIT, f"Memory is nearly exhausted ({pct_free:.0f}% available)", detail)]
    if pct_free < 15 or p60 > 10:
        return [finding(WARN, f"Memory is tight ({pct_free:.0f}% available)", detail)]
    return [finding(OK, f"Memory fine: {human(avail)} available", detail)]


@check("memory", "swap")
def swap(ctx):
    rows = [l.split() for l in read("/proc/swaps").splitlines()[1:] if l.split()]
    if not rows:
        return [finding(WARN, "No swap configured: a memory spike will kill apps immediately")]
    res, slow = [], []
    for r in rows:
        path = r[0]
        dev = path if r[1] == "partition" else ctx.run(f"findmnt -no SOURCE -T {shlex.quote(path)}").strip()
        if block_dev_rotational(dev):
            slow.append((path, int(r[2]) * 1024, r[4]))
    fast = sum(int(r[2]) * 1024 for r in rows) - sum(s[1] for s in slow)
    for path, size, prio in slow:
        q = shlex.quote(path)
        res.append(finding(
            CRIT, f"Swap on a slow hard drive: {path} ({human(size)})",
            ["When memory overflows here every app freezes, and the system then kills the biggest app (VS Code, Chrome).",
             f"{human(fast)} of swap on fast storage would remain."],
            fix(f"Stop using {path} as swap (also removed from /etc/fstab, backup kept)",
                f"swapoff {q}\ncp -n /etc/fstab /etc/fstab.bak-system-check\n"
                f"sed -i 's|^{path} |#system-check-disabled# {path} |' /etc/fstab")))
    if not slow:
        res.append(finding(OK, f"Swap {human(fast)}, all on fast storage"))
    return res


# ---------- disk ----------

@check("disk", "space")
def space(ctx):
    out = ctx.run("timeout 10 df -PT -x tmpfs -x devtmpfs -x squashfs -x overlay -x efivarfs -x nsfs "
                  "-x fuse.snapfuse -x fuse.portal 2>/dev/null")
    res, okay = [], []
    for line in out.splitlines()[1:]:
        p = line.split()
        if len(p) < 7 or p[6].startswith(("/snap", "/var/snap", "/run")):
            continue
        size, used, avail, pct, mnt = int(p[2]) * 1024, int(p[3]) * 1024, int(p[4]) * 1024, int(p[5].rstrip("%")), p[6]
        if size < 200 << 20:
            continue
        sys_disk = mnt in ("/", "/home", "/var", "/boot", "/boot/efi")
        level = CRIT if pct >= 97 or (sys_disk and size > 20 << 30 and avail < 2 << 30) else WARN if pct >= 90 else None
        if level:
            f = fix("Clear rebuildable caches with disk-clean (then use `disk-clean deep` for bigger items)",
                    "disk-clean", root=False) if mnt in ("/", "/home") and ctx.has("disk-clean") else None
            res.append(finding(level, f"{mnt} is {pct}% full ({human(avail)} free of {human(size)})", [], f))
        else:
            okay.append(f"{mnt} {pct}%")
    for line in ctx.run("timeout 10 df -Pi -x tmpfs -x devtmpfs -x squashfs -x overlay -x vfat 2>/dev/null").splitlines()[1:]:
        p = line.split()
        if len(p) >= 6 and p[4].rstrip("%").isdigit() and int(p[4].rstrip("%")) >= 90 and not p[5].startswith("/snap"):
            res.append(finding(WARN, f"{p[5]} is out of file slots (inodes {p[4]} used)", ["Usually millions of tiny files: node_modules, caches."]))
    ro = ctx.run("findmnt -rno TARGET,FSTYPE,OPTIONS -t ext4,btrfs,xfs | awk '$3 ~ /(^|,)ro(,|$)/{print $1}'").split()
    for mnt in ro:
        res.append(finding(CRIT, f"{mnt} switched to read-only", ["Linux does this after disk errors. Back up, then check the drive."]))
    if not res:
        res.append(finding(OK, "Disk space fine: " + ", ".join(okay[:6])))
    return res


@check("disk", "health")
def disk_health(ctx):
    res = []
    io = ctx.run(f'journalctl -k --since "{SINCE}" --no-pager -o cat | grep -E "I/O error|Buffer I/O error|EXT4-fs error|'
                 f'BTRFS error|critical medium error|nvme.*(timeout|reset)|ata[0-9.]+: (failed command|exception)"')
    if io.strip():
        devs = collections.Counter(m.group(0) for m in re.finditer(r"\b(sd[a-z]+|nvme\d+n\d+|ata\d+)\b", io))
        res.append(finding(CRIT, f"{len(io.splitlines())} disk error(s) in the kernel log this week",
                           [f"{n}x {d}" for d, n in devs.most_common(4)] + io.strip().splitlines()[-3:] +
                           ["Back up this drive soon; it may be failing or its cable is loose."]))
    if ctx.has("smartctl"):
        disks = ctx.run("lsblk -dno NAME,TYPE | awk '$2==\"disk\"{print $1}'").split()
        for d in disks:
            out = ctx.run(f"smartctl -H /dev/{d}", root=True)
            if out is None:
                res.append(finding(SKIP, "Drive health (SMART) needs sudo"))
                break
            if re.search(r"FAILED|FAILING_NOW", out):
                res.append(finding(CRIT, f"/dev/{d} reports failing health (SMART)", ["Back up now and replace the drive."]))
    else:
        res.append(finding(INFO, "Drive health monitor (smartmontools) not installed", [],
                           fix("Install smartmontools to watch drive health", "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq smartmontools")))
    if not any(f["level"] in (CRIT, WARN) for f in res):
        res.append(finding(OK, "No disk errors in the kernel log"))
    return res


# ---------- hardware ----------

@check("hardware", "temperature")
def temperature(ctx):
    temps = []
    for d in glob.glob("/sys/class/hwmon/hwmon*"):
        name = read(f"{d}/name").strip()
        for t in glob.glob(f"{d}/temp*_input"):
            v = read(t).strip()
            if v.lstrip("-").isdigit():
                label = read(t.replace("_input", "_label")).strip()
                temps.append((int(v) / 1000, f"{name} {label}".strip()))
    gpu = ctx.run("nvidia-smi --query-gpu=temperature.gpu,name --format=csv,noheader,nounits 2>/dev/null").strip()
    for line in gpu.splitlines():
        t, _, name = line.partition(",")
        if t.strip().isdigit():
            temps.append((float(t), name.strip()))
    throttle = ctx.run(f'journalctl -k --since "{SINCE}" --no-pager -o cat | grep -ciE "temperature above threshold|clock throttled|thermal.*critical"').strip()
    if not temps:
        return [finding(SKIP, "No temperature sensors readable")]
    hot = max(temps)
    detail = [", ".join(f"{n or 'sensor'} {t:.0f}°C" for t, n in sorted(temps, reverse=True)[:4])]
    res = []
    if throttle.isdigit() and int(throttle):
        res.append(finding(WARN, f"CPU overheated and slowed down {throttle} time(s) this week",
                           detail + ["Clean the fans/vents and check the cooler."]))
    level = CRIT if hot[0] >= 95 else WARN if hot[0] >= 85 else OK
    res.append(finding(level, f"Hottest sensor {hot[0]:.0f}°C ({hot[1]})" if level != OK else f"Temperatures fine (max {hot[0]:.0f}°C)", detail if level != OK else []))
    return res


@check("hardware", "gpu")
def gpu(ctx):
    if not os.path.exists("/proc/driver/nvidia/version") and not ctx.has("nvidia-smi"):
        return []
    out = ctx.run("nvidia-smi --query-gpu=name,driver_version,memory.used,memory.total,utilization.gpu --format=csv,noheader 2>&1")
    res = []
    if not out.strip() or "failed" in out.lower() or "mismatch" in out.lower():
        res.append(finding(CRIT, "NVIDIA driver is not working", [out.strip()[:200],
                           "Often a driver update waiting for a reboot. Reboot first; reinstall the driver if it persists."]))
    xid = ctx.run(f'journalctl -k --since "{SINCE}" --no-pager -o cat | grep -E "NVRM: Xid"')
    if xid.strip():
        codes = collections.Counter(m.group(1) for m in re.finditer(r"Xid \([^)]*\): (\d+)", xid))
        res.append(finding(WARN, f"{len(xid.splitlines())} GPU error(s) (Xid) this week",
                           [f"Xid {c}: {n}x" for c, n in codes.most_common(5)] +
                           ["Xid 79/119 = GPU fell off the bus (power/driver); 13/31/43 = app bugs; 48/63/64/94/95 = memory errors."]))
    if not res:
        res.append(finding(OK, f"GPU OK: {out.strip().splitlines()[0]}"))
    return res


@check("hardware", "cpu-load")
def cpu_load(ctx):
    l1, l5, _ = (float(x) for x in read("/proc/loadavg").split()[:3])
    top = top_processes(ctx, "cpu", 4)
    detail = ["Busiest: " + ", ".join(f"{n} {c:.0f}%" for n, c in top)]
    if l5 > ctx.ncpu * 2:
        return [finding(WARN, f"System overloaded: load {l5:.1f} on {ctx.ncpu} cores", detail)]
    return [finding(OK, f"CPU load {l1:.1f} on {ctx.ncpu} cores")]


# ---------- services ----------

def _unit_diagnosis(ctx, unit, user):
    """Why a unit fails, plus the fix that fits: disable it if its files are gone, otherwise restart it."""
    sc = "systemctl --user " if user else "systemctl "
    jflag = "--user-unit" if user else "-u"
    log = [l for l in ctx.run(f"journalctl {jflag} {shlex.quote(unit)} -n 12 --no-pager -o cat").splitlines() if l.strip()]
    text = "\n".join(log)
    reason = ("its working folder no longer exists" if re.search(r"status=200/CHDIR|working directory failed", text) else
              "its program no longer exists" if re.search(r"status=203/EXEC", text) else
              "it reports itself as deprecated" if re.search(r"deprecated", text, re.I) else
              "it only failed to email its report: no mail system is set up" if re.search(r"Can't send mail|sendmail", text) else
              "its config file is missing" if re.search(r"fatal: open \S+: No such file", text) else "")
    msgs = [l for l in log if not re.search(r"Scheduled restart|^Starting |^Started |^Stopped |^Failed to start|"
                                            r"Failed with result|Main process exited|Control process exited|Consumed ", l)]
    msgs = list(dict.fromkeys(msgs))
    detail = ([f"Reason: {reason}"] if reason else []) + msgs[-2:] + [f"More: journalctl {jflag} {unit} -n 30"]
    q = shlex.quote(unit)
    m = re.fullmatch(r"snap\.(.+)\.service", unit)
    busy = m and not user and snap_busy(ctx, m.group(1).split(".")[0])
    if reason.startswith("it only failed to email"):
        conf = "/etc/chkrootkit/chkrootkit.conf"
        f = fix(f"Let {unit} write its report to the log instead of email (system-check reads it)",
                f"sed -i 's/^MAILTO=.*/MAILTO=\"\"/' {conf}\n{sc}reset-failed {q}") if unit == "chkrootkit.service" and os.path.exists(conf) \
            else None
        if not f:
            detail.append("The job itself ran. Set up mail, or change its config so it doesn't send email.")
    elif busy:
        f = None
        detail.insert(0, f"snap is already changing this snap ({busy}); see 'Stuck snap job' if it doesn't finish")
    elif m and not user:
        f = fix(f"Turn off {unit} (it fails on this computer)", f"snap stop --disable {shlex.quote(m.group(1))}", safe=False)
    elif reason:
        f = fix(f"Disable {unit} ({reason})", f"{sc}disable --now {q} || {sc}stop {q}\n{sc}reset-failed {q}", root=not user, safe=False)
    else:
        f = fix(f"Restart {unit}", f"{sc}reset-failed {q}\n{sc}restart {q}", root=not user, safe=False)
    return detail, f


def snap_jobs(ctx):
    """Unfinished snap changes: [(id, status, started_epoch, summary)]."""
    jobs = []
    for line in ctx.cached("snap-changes", "snap changes --abs-time 2>/dev/null").splitlines()[1:]:
        p = line.split(None, 4)
        if len(p) == 5 and p[1] in ("Do", "Doing", "Undo", "Undoing", "Wait"):
            try:
                t = time.mktime(time.strptime(p[2][:19], "%Y-%m-%dT%H:%M:%S"))
            except ValueError:
                t = time.time()
            summary = p[4].split("  ")[-1].strip() if p[3] == "-" else p[4]
            jobs.append((p[0], p[1], t, summary.strip()))
    return jobs


def snap_busy(ctx, snap):
    for jid, _, _, summary in snap_jobs(ctx):
        if f'"{snap}"' in summary or snap in ctx.cached(f"snap-change-{jid}", f"snap tasks --abs-time {jid} 2>/dev/null"):
            return f"job {jid}: {summary}"
    return ""


@check("services", "snap-jobs")
def stuck_snap_jobs(ctx):
    if not ctx.has("snap"):
        return []
    res = []
    for jid, status, started, summary in snap_jobs(ctx):
        mins = (time.time() - started) / 60
        if mins < 15:
            continue
        tasks = ctx.run(f"snap tasks --abs-time {jid} 2>/dev/null")
        doing = next((l.split(None, 3)[-1] for l in tasks.splitlines() if l.startswith("Doing")), "")
        snaps = sorted(set(re.findall(r'snap "([^"]+)"', tasks)))
        cmd = f"snap abort {jid}\nfor i in $(seq 30); do snap tasks {jid} | grep -qE '^(Do|Doing|Undo|Undoing) ' || break; sleep 2; done"
        if summary.startswith("Remove") and snaps:
            cmd += "\nsnap remove --purge " + " ".join(shlex.quote(x) for x in snaps)
        res.append(finding(WARN, f"Stuck snap job {jid} for {mins:.0f} min: {summary}",
                           [f"Stuck at: {doing}" if doing else "", "Other snap installs/removals wait behind it."],
                           fix(f"Cancel snap job {jid}" + (" and remove " + ", ".join(snaps) + " without the data backup step"
                                                           if summary.startswith("Remove") and snaps else ""), cmd, safe=False)))
    return res


@check("services", "failed-units")
def failed_units(ctx):
    res, seen = [], set()
    for user in (False, True):
        flag = "--user " if user else ""
        for u in [l.split()[0] for l in ctx.run(f"systemctl {flag}--failed --no-legend --plain --no-pager").splitlines() if l.split()]:
            detail, f = _unit_diagnosis(ctx, u, user)
            seen.add(u)
            res.append(finding(WARN, f"{'User' if user else 'System'} service failed: {u}", detail, f))
        out = ctx.run(f"systemctl {flag}show -p Id -p NRestarts --no-pager '*.service' 2>/dev/null")
        for block in out.split("\n\n"):
            props = dict(l.split("=", 1) for l in block.splitlines() if "=" in l)
            u, n = props.get("Id", "?"), props.get("NRestarts", "0")
            if n.isdigit() and int(n) >= 5 and u not in seen:
                detail, f = _unit_diagnosis(ctx, u, user)
                res.append(finding(WARN, f"{u} keeps crashing: restarted {n} times since boot", detail, f))
    if not res:
        res.append(finding(OK, "All services running"))
    return res


@check("services", "docker")
def docker(ctx):
    if not ctx.has("docker"):
        return []
    out = ctx.run("docker ps -a --format '{{.Names}}\t{{.Status}}\t{{.Ports}}' 2>&1", timeout=15)
    if "permission denied" in out or "Cannot connect" in out:
        return [finding(SKIP, "Docker not reachable", [out.strip()[:120]])]
    res = []
    for line in out.splitlines():
        name, status, ports = (line.split("\t") + ["", ""])[:3]
        if "Restarting" in status or "unhealthy" in status:
            res.append(finding(WARN, f"Container {name} is unhealthy: {status}", [f"See why: docker logs --tail 30 {name}"]))
        elif re.match(r"Exited \((?!(0|137|143)\))\d+\).*(minutes?|hours?|seconds?) ago", status):
            res.append(finding(INFO, f"Container {name} stopped with an error: {status}", [f"docker logs --tail 30 {name}"]))
    df = ctx.run("docker system df --format '{{.Type}}\t{{.Reclaimable}}' 2>/dev/null", timeout=20)
    recl = 0.0
    for line in df.splitlines():
        m = re.match(r"(Images|Build Cache)\t([\d.]+)([kMGT]?B)", line)
        if m:
            recl += float(m.group(2)) * {"B": 1, "kB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[m.group(3)]
    if recl > 10e9:
        res.append(finding(INFO, f"Docker holds {recl / 1e9:.0f}GB of unused images and build cache", [],
                           fix("Remove unused Docker images and build cache (volumes and running containers are kept)",
                               "docker image prune -af && docker builder prune -af", root=False)))
    if not res:
        n = len([l for l in out.splitlines() if "Up " in l])
        res.append(finding(OK, f"Docker fine: {n} container(s) running"))
    return res


# ---------- logs ----------

@check("logs", "kernel-errors")
def kernel_errors(ctx):
    out = ctx.run('journalctl -k -p err --since "24 hours ago" --no-pager -o cat')
    groups = collections.Counter(normalize(l) for l in out.splitlines() if l.strip())
    if not groups:
        return [finding(OK, "No kernel errors in the last 24 hours")]
    return [finding(INFO, f"{sum(groups.values())} kernel error line(s) in the last 24 hours ({len(groups)} distinct)",
                    [f"{n}x {msg}" for msg, n in groups.most_common(6)])]


@check("logs", "app-errors")
def app_errors(ctx):
    out = ctx.run('journalctl -p err --since "24 hours ago" --no-pager -o json -n 5000 2>/dev/null', timeout=30)
    groups, sample = collections.Counter(), {}
    for line in out.splitlines():
        try:
            e = json.loads(line)
        except ValueError:
            continue
        if e.get("_TRANSPORT") == "kernel":
            continue
        src = e.get("_SYSTEMD_USER_UNIT") or e.get("_SYSTEMD_UNIT") or e.get("SYSLOG_IDENTIFIER") or "?"
        msg = e.get("MESSAGE")
        msg = msg if isinstance(msg, str) else ""
        if re.search(r"a password is required ; .*COMMAND=(/usr/bin/true|/usr/bin/bash -c|/bin/bash -c)", msg):
            continue  # system-check's own "is sudo cached?" probe
        key = (app_name(src), normalize(msg)[:90])
        groups[key] += 1
        sample.setdefault(key, msg.strip()[:160])
    if not groups:
        return [finding(OK, "No error-level log messages in the last 24 hours")]
    noisy = [(k, n) for k, n in groups.most_common(8)]
    level = WARN if any(n >= 100 for _, n in noisy) else INFO
    return [finding(level, f"{sum(groups.values())} error message(s) logged in the last 24 hours, top sources:",
                    [f"{n}x {src}: {sample[(src, m)]}" for (src, m), n in noisy] +
                    ["Full list: journalctl -p err --since today"])]


@check("logs", "journal-retention")
def journal_retention(ctx):
    first = ctx.run("journalctl --no-pager -o short-unix 2>/dev/null | head -1")
    try:
        days = (time.time() - float(first.split()[0])) / 86400
    except (ValueError, IndexError):
        return []
    usage = ctx.run("journalctl --disk-usage 2>/dev/null").strip()
    free = os.statvfs("/var/log")
    free_gb = free.f_bavail * free.f_frsize / 1e9
    limit = re.search(r"^SystemMaxUse=\s*(\d+)([KMGT]?)", read(JOURNAL_DROPIN), re.M)
    raised = limit and int(limit.group(1)) * {"": 1, "K": 1e3, "M": 1e6, "G": 1e9, "T": 1e12}[limit.group(2)] >= 1e9
    if days < 5 and raised:
        return [finding(OK, f"Logs cover {days:.1f} days; limit already raised to 1GB, history grows from here")]
    if days < 5 and free_gb > 30:
        return [finding(WARN, f"System logs only reach back {days:.1f} days", [usage, "Too short to diagnose problems that started last week."],
                        fix("Keep up to 1GB of logs (about 1-2 weeks here)",
                            f"mkdir -p {os.path.dirname(JOURNAL_DROPIN)}\nprintf '[Journal]\\nSystemMaxUse=1G\\n' > {JOURNAL_DROPIN}\n"
                            "systemctl restart systemd-journald"))]
    return [finding(OK, f"Logs cover {days:.0f} days")]


# ---------- updates ----------

@check("updates", "packages")
def packages(ctx):
    res = []
    if os.path.exists("/var/run/reboot-required"):
        pkgs = read("/var/run/reboot-required.pkgs").split()
        res.append(finding(WARN, "Reboot needed to finish installing updates", [", ".join(sorted(set(pkgs))[:8])]))
    running = os.uname().release
    kernels = sorted(glob.glob("/boot/vmlinuz-*"), key=os.path.getmtime)
    if kernels and not kernels[-1].endswith(running) and not os.path.exists("/var/run/reboot-required"):
        res.append(finding(INFO, f"A newer kernel is installed ({kernels[-1].split('vmlinuz-')[1]}); running {running}. Reboot to use it."))
    up = ctx.run("apt list --upgradable 2>/dev/null | tail -n +2", timeout=30).splitlines()
    sec = [l.split("/")[0] for l in up if "-security" in l]
    if sec:
        res.append(finding(WARN, f"{len(sec)} security update(s) waiting", [", ".join(sec[:10])],
                           fix("Install pending security updates",
                               "apt-get update -qq && DEBIAN_FRONTEND=noninteractive unattended-upgrade -v 2>&1 | tail -5")))
    elif up:
        res.append(finding(INFO, f"{len(up)} regular update(s) available", ["Install with: sudo apt upgrade"]))
    audit = ctx.run("dpkg --audit 2>/dev/null").strip()
    if audit:
        res.append(finding(WARN, "Some packages are half-installed", audit.splitlines()[:3],
                           fix("Finish interrupted package installs", "DEBIAN_FRONTEND=noninteractive dpkg --configure -a")))
    if not res:
        res.append(finding(OK, "System up to date, no reboot pending"))
    return res


# ---------- network ----------

@check("network", "connectivity")
def connectivity(ctx):
    res = []
    if not ctx.run("ip route show default").strip():
        return [finding(CRIT, "No default route: not connected to any network")]
    if not ctx.run("timeout 4 getent ahosts archive.ubuntu.com | head -1").strip():
        res.append(finding(CRIT, "DNS not working: names don't resolve", ["Check: resolvectl status"]))
    sync = ctx.run("timedatectl show -p NTPSynchronized -p NTP --value").split()
    if sync and sync[-1] == "no":
        res.append(finding(WARN, "Clock is not synced with internet time", ["Wrong time breaks HTTPS, logins and builds."],
                           fix("Turn on automatic time sync", "timedatectl set-ntp true")))
    if not res:
        res.append(finding(OK, "Network, DNS and clock fine"))
    return res
