"""Running services: what runs, what it costs, and which ones this computer probably doesn't need."""
import os, re, shlex, time

from .core import INFO, OK, WARN, check, finding, fix, human, read

# Core desktop/system plumbing: never suggested, even when big and idle.
CORE = re.compile(r"^(user@|systemd-|dbus|polkit|NetworkManager|wpa_supplicant|lightdm|gdm|org\.gnome\.|gnome-|pipewire|wireplumber|"
                  r"xdg-|at-spi|gvfs|dconf|snapd\.|accounts-daemon|udisks2|upower|rtkit|switcheroo|thermald|docker|containerd|"
                  r"nvidia|getty|cron|rsyslog|fail2ban|unattended|ssh|caddy|smartmontools|power-profiles|colord|filter-chain|"
                  r"gcr-|ibus|org\.freedesktop)")
TUNNEL = re.compile(r"ngrok|pinggy|cloudflared|localtunnel|\bfrpc\b|serveo|\bbore\b|tailscale funnel|zrok", re.I)


def services(ctx, user):
    """[{Id, MemoryCurrent, CPUUsageNSec, ActiveEnterTimestampMonotonic, ExecStart, user}] for running services."""
    flag = "--user " if user else ""
    names = [l.split()[0] for l in ctx.run(f"systemctl {flag}list-units --type=service --state=running --no-legend --plain").splitlines() if l.split()]
    if not names:
        return []
    out = ctx.run(f"systemctl {flag}show -p Id -p MemoryCurrent -p CPUUsageNSec -p ActiveEnterTimestampMonotonic -p ExecStart -p ControlGroup "
                  + " ".join(shlex.quote(n) for n in names))
    rows = []
    for block in out.split("\n\n"):
        p = dict(l.split("=", 1) for l in block.splitlines() if "=" in l)
        if p.get("Id"):
            if p["Id"].startswith("user@"):
                continue  # the container of every user service, not a service of its own
            p["user"] = user
            p["mem"] = anon_memory(p.get("ControlGroup", "")) or (int(p["MemoryCurrent"]) if p.get("MemoryCurrent", "").isdigit() else 0)
            p["cpu"] = int(p["CPUUsageNSec"]) / 1e9 if p.get("CPUUsageNSec", "").isdigit() else 0.0
            started = int(p.get("ActiveEnterTimestampMonotonic") or 0) / 1e6
            p["age"] = max(float(read("/proc/uptime", "0").split()[0]) - started, 1) if started else 0
            rows.append(p)
    return rows


def anon_memory(cgroup):
    """Memory the service really holds (anon + kernel), not file cache it happened to read."""
    stat = read(f"/sys/fs/cgroup{cgroup}/memory.stat") if cgroup else ""
    vals = dict(l.split() for l in stat.splitlines() if len(l.split()) == 2)
    return sum(int(vals.get(k, 0)) for k in ("anon", "kernel", "shmem")) if vals else 0


def disable(units, user=False, note=""):
    sc = "systemctl --user" if user else "systemctl"
    q = " ".join(shlex.quote(u) for u in units)
    return fix(f"Turn off {units[0].replace('.service', '')}{note}", f"{sc} disable --now {q}", root=not user, safe=False)


def undo(units, user=False):
    return f"Undo any time: {'systemctl --user' if user else 'sudo systemctl'} enable --now {' '.join(units)}"


@check("services", "running-services")
def running_services(ctx):
    rows = services(ctx, False) + services(ctx, True)
    running = {r["Id"] for r in rows}
    res = []
    total = sum(r["mem"] for r in rows)
    big = sorted(rows, key=lambda r: -r["mem"])[:6]
    res.append(finding(INFO, f"{len(rows)} services running ({sum(not r['user'] for r in rows)} system, "
                             f"{sum(r['user'] for r in rows)} yours), using {human(total)} RAM",
                       ["Biggest: " + ", ".join(f"{r['Id'].replace('.service', '')} {human(r['mem'])}" for r in big)]))

    def suggest(level, title, why, f, units=None, user=False):
        res.append(finding(level, title, why + ([undo(units, user)] if units else []), f))

    # --- printing ---
    printers = ctx.run("lpstat -v 2>/dev/null")
    real = [l for l in printers.splitlines() if not re.search(r":\s*(///dev/null|file:/dev/null)\s*$", l)]
    if "cups.service" in running and not real:
        units = ["cups.service", "cups.socket", "cups.path", "cups-browsed.service"]
        why = (["Your only printer entries point at /dev/null, so nothing can print anyway."] if printers.strip()
               else ["No printers are set up."])
        suggest(INFO, "Not needed? Printing service (cups) — no working printer", why,
                disable(units, note=" and cups-browsed (no working printer)"), units)
    elif "cups-browsed.service" in running:
        suggest(INFO, "Not needed? cups-browsed (auto-adds network printers)",
                ["Your printers keep working without it. It had a serious remote-attack bug in 2024 (CVE-2024-47176)."],
                disable(["cups-browsed.service"]), ["cups-browsed.service"])

    # --- hardware this machine doesn't have / doesn't use ---
    if "ModemManager.service" in running and "No modems were found" in ctx.run("mmcli -L 2>&1"):
        suggest(INFO, "Not needed? ModemManager — no mobile-broadband modem found",
                ["It also probes USB serial devices (Arduino, ESP32) when they're plugged in, which can get in the way."],
                disable(["ModemManager.service"]), ["ModemManager.service"])
    if "bluetooth.service" in running:
        if not (os.path.isdir("/sys/class/bluetooth") and os.listdir("/sys/class/bluetooth")):
            suggest(INFO, "Not needed? Bluetooth service — no Bluetooth adapter", [], disable(["bluetooth.service"]), ["bluetooth.service"])
        elif not ctx.run("timeout 3 bluetoothctl devices Paired 2>/dev/null").strip():
            suggest(INFO, "Not needed? Bluetooth service — no paired devices",
                    ["Keep it if you pair headphones, mice or phones now and then."], disable(["bluetooth.service"]), ["bluetooth.service"])
    if ctx.run("systemd-detect-virt 2>/dev/null").strip() == "none":
        for u in ("spice-vdagentd.service", "open-vm-tools.service", "vboxadd-service.service", "qemu-guest-agent.service"):
            if u in running:
                suggest(INFO, f"Not needed? {u} — only useful inside a virtual machine", [], disable([u]), [u])
    if "brltty.service" in running and ctx.run("gsettings get org.gnome.desktop.a11y.applications screen-reader-enabled 2>/dev/null").strip() != "true":
        suggest(INFO, "Not needed? brltty (braille displays)",
                ["It grabs USB serial adapters (CH340/CH341) so Arduino boards don't show up."], disable(["brltty.service"]), ["brltty.service"])
    for u in ("postfix.service", "exim4.service", "sendmail.service"):
        if u in running or (u == "postfix.service" and os.path.exists("/usr/sbin/postfix") and not os.path.exists("/etc/postfix/main.cf")):
            suggest(INFO, f"Not needed? {u.replace('.service', '')} mail server",
                    ["A desktop rarely needs its own mail server" +
                     (" and this one has no config, so cron jobs and chkrootkit fail with 'main.cf: No such file'." if not os.path.exists("/etc/postfix/main.cf") else ".")],
                    disable([u, "postfix@-.service"] if u == "postfix.service" else [u]), [u])

    # --- remote access and public tunnels ---
    if "anydesk.service" in running:
        suggest(WARN, "AnyDesk runs all the time and accepts remote connections (port 7070)",
                ["If you only use it now and then: turn the service off and start AnyDesk when you need it.",
                 "Remote-desktop tools are a favourite target for scammers and attackers."],
                disable(["anydesk.service"]), ["anydesk.service"])
    if "gnome-remote-desktop.service" in running and ":3389" not in ctx.run("ss -tlnH"):
        suggest(INFO, "Not needed? gnome-remote-desktop — running but remote login is not switched on", [],
                disable(["gnome-remote-desktop.service"]), ["gnome-remote-desktop.service"])
    for r in rows:
        if TUNNEL.search(r["Id"] + " " + r.get("ExecStart", "")):
            cmd = re.search(r"argv\[\]=([^;]+)", r.get("ExecStart", ""))
            suggest(WARN, f"{r['Id']} publishes something on this computer to the internet",
                    [f"Runs: {cmd.group(1).strip()[:140]}" if cmd else "",
                     "Anyone with the link can reach it. Keep it on only while you need it, and make sure it has a password."],
                    disable([r["Id"]], r["user"]), [r["Id"]], r["user"])

    # --- background apps that cost memory ---
    sw = ctx.run("ps -C gnome-software -o rss= 2>/dev/null").split()
    if sw and int(sw[0]) * 1024 > 200 << 20 and not os.path.exists(os.path.join(ctx.home, ".config/autostart/org.gnome.Software.desktop")):
        suggest(INFO, f"Not needed? GNOME Software stays open in the background ({human(int(sw[0]) * 1024)})",
                ["It only checks for updates; unattended-upgrades already installs security updates. It still opens normally from the menu."],
                fix("Stop GNOME Software from starting in the background at login",
                    "mkdir -p ~/.config/autostart\ncp /etc/xdg/autostart/org.gnome.Software.desktop ~/.config/autostart/\n"
                    "echo 'Hidden=true' >> ~/.config/autostart/org.gnome.Software.desktop\ngnome-software --quit || true",
                    root=False, safe=False))
    for r in rows:
        if r["Id"] == "tracker-miner-fs-3.service" and r["mem"] > 200 << 20:
            suggest(INFO, f"Not needed? File indexer (tracker) uses {human(r['mem'])}",
                    ["It powers search inside the Files app. Turn it off if you don't search files there."],
                    fix("Turn off the file indexer", "systemctl --user mask --now tracker-miner-fs-3.service\ntracker3 reset -s -r || true",
                        root=False, safe=False))

    # --- big and idle: likely forgotten ---
    for r in sorted(rows, key=lambda r: -r["mem"]):
        if CORE.search(r["Id"]) or r["mem"] < 300 << 20 or r["age"] < 2 * 3600:
            continue
        load = r["cpu"] / r["age"] * 100
        if load < 0.5:
            suggest(INFO, f"Idle but holding memory: {r['Id']} ({human(r['mem'])}, {load:.2f}% CPU over "
                          f"{r['age'] / 3600:.0f}h)",
                    ["Turn it off if you don't use it every day, and start it when you need it."],
                    disable([r["Id"]], r["user"]), [r["Id"]], r["user"])
    return res
