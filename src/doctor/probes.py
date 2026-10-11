"""Focused checks as data: what runs right now, who listens where, low-memory kills, network timings, sensors.
Pure gathering; interactive.py (and anything else) decides how to show it."""
import glob, os, re, shlex, time

from .core import read
from .health import app_name, meminfo, psi, top_processes


def now(ctx):
    m = meminfo()
    procs = []
    for line in ctx.run("ps -eo pid,pcpu,rss,etime,comm --sort=-pcpu --no-headers | head -8").splitlines():
        p = line.split(None, 4)
        if len(p) == 5:
            procs.append({"pid": p[0], "cpu": p[1], "rss": int(p[2]) * 1024, "running": p[3], "name": p[4]})
    return {"ram_used": m["MemTotal"] - m["MemAvailable"], "ram_total": m["MemTotal"],
            "swap_used": m["SwapTotal"] - m["SwapFree"], "mem_stall": psi("memory")[0], "cpu_stall": psi("cpu")[0],
            "load": read("/proc/loadavg").split()[0], "cores": ctx.ncpu,
            "apps": [(name, kb * 1024) for name, kb in top_processes(ctx, "rss", 10)], "procs": procs}


def listeners(ctx):
    """[(reachable_from_network, proto, port, program)], and whether program names are complete (needs sudo)."""
    out = ctx.run("ss -tulnpH", root=True)
    full = out is not None
    out = out if full else ctx.run("ss -tulnpH")
    merged = {}  # IPv4 and IPv6 sockets of one port are one entry
    for line in out.splitlines():
        p = line.split()
        if len(p) < 5:
            continue
        addr, _, port = p[4].rpartition(":")
        if not port.isdigit():
            continue
        prog = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
        public = not (re.match(r"^(127\.|\[::1\]|\[::ffff:127\.)", addr) or "%lo" in addr)
        key = (public, p[0], int(port))
        if merged.get(key, "?") == "?":
            merged[key] = f"{prog.group(1)} ({prog.group(2)})" if prog else "?"
    rows = [(pub, proto, port, prog) for (pub, proto, port), prog in merged.items()]
    return sorted(rows, key=lambda r: (not r[0], r[2], r[1])), full


def memory_kills(ctx, days=30):
    rows = []
    out = ctx.run(f'journalctl -u systemd-oomd --since "{days} days ago" --no-pager -o short-iso | grep " Killed "')
    for line in out.splitlines():
        m = re.search(r"^(\S+).*Killed (\S+) due to memory pressure for \S+ being ([\d.]+)%", line)
        if m:
            rows.append((m.group(1)[:16].replace("T", " "), app_name(m.group(2)), f"{m.group(3)}% stalled"))
    out = ctx.run(f'journalctl -k --since "{days} days ago" --no-pager -o short-iso | grep "Out of memory: Killed process"')
    for line in out.splitlines():
        m = re.search(r"^(\S+).*Killed process \d+ \(([^)]+)\).*?anon-rss:(\d+)kB", line)
        if m:
            rows.append((m.group(1)[:16].replace("T", " "), m.group(2) + " (kernel)", f"{int(m.group(3)) >> 10} MB in RAM"))
    return sorted(rows)


def _ping(ctx, target):
    out = ctx.run(f"ping -c 3 -W 2 {shlex.quote(target)} 2>&1 | tail -2", timeout=12)
    avg = re.search(r"= [\d.]+/([\d.]+)/", out)
    loss = re.search(r"(\d+)% packet loss", out)
    return float(avg.group(1)) if avg else None, int(loss.group(1)) if loss else 100


def network(ctx):
    route = ctx.run("ip route show default").split()
    gw = route[2] if len(route) > 2 else ""
    res = {"dev": route[route.index("dev") + 1] if "dev" in route else None, "gateway": gw, "wifi": None, "checks": []}
    wifi = ctx.run("nmcli -t -f ACTIVE,SSID,SIGNAL dev wifi 2>/dev/null | grep '^yes'").strip()
    if wifi:
        _, ssid, sig = (wifi.split(":") + ["", ""])[:3]
        res["wifi"] = (ssid, sig)
    if gw:
        res["checks"].append(("router", *_ping(ctx, gw)))
    res["checks"].append(("internet (1.1.1.1)", *_ping(ctx, "1.1.1.1")))
    t = time.time()
    ok = ctx.run("timeout 4 getent ahosts archive.ubuntu.com | head -1").strip()
    res["checks"].append(("DNS lookup", (time.time() - t) * 1000 if ok else None, 0 if ok else 100))
    web = ctx.run("curl -s -o /dev/null -m 8 -w '%{time_total} %{http_code}' https://archive.ubuntu.com/ 2>/dev/null").split()
    good = len(web) == 2 and web[1] != "000"
    res["checks"].append(("HTTPS page load", float(web[0]) * 1000 if good else None, 0 if good else 100))
    return res


def sensors(ctx):
    rows = []
    for d in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
        chip = read(f"{d}/name").strip()
        for t in sorted(glob.glob(f"{d}/temp*_input")) + sorted(glob.glob(f"{d}/fan*_input")):
            v = read(t).strip()
            if v.lstrip("-").isdigit():
                label = read(t.replace("_input", "_label")).strip() or os.path.basename(t).replace("_input", "")
                rows.append((chip, label, f"{int(v) / 1000:.0f}°C" if "temp" in t else f"{v} rpm"))
    gpu = ctx.run("nvidia-smi --query-gpu=name,temperature.gpu,fan.speed,power.draw,clocks.sm --format=csv,noheader,nounits 2>/dev/null").strip()
    for line in gpu.splitlines():
        p = [x.strip() for x in line.split(",")]
        if len(p) == 5:
            rows.append(("gpu", p[0], f"{p[1]}°C, fan {p[2]}%, {p[3]} W, {p[4]} MHz"))
    freqs = [int(read(f).strip() or 0) for f in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq")]
    if freqs:
        rows.append(("cpu", "speed", f"{min(freqs) / 1e6:.1f}-{max(freqs) / 1e6:.1f} GHz on {len(freqs)} cores"))
    return rows
