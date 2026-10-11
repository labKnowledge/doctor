"""Security checks: firewall, exposed ports, SSH, logins, accounts, hardening, suspicious processes, persistence."""
import collections, glob, os, re, shlex, stat, time

from .core import CRIT, INFO, OK, SKIP, WARN, check, finding, fix, read

# Services that should never face the network directly.
RISKY_PORTS = {2375: "Docker API", 2376: "Docker API", 3306: "MySQL", 5432: "Postgres", 6379: "Redis", 27017: "MongoDB",
               9200: "Elasticsearch", 11211: "Memcached", 8888: "Jupyter", 11434: "Ollama", 5900: "VNC", 3389: "RDP",
               9000: "admin panel", 15672: "RabbitMQ"}
MINERS = re.compile(r"xmrig|kdevtmpfsi|kinsing|minerd|cpuminer|ethminer|nbminer|t-rex|lolminer", re.I)
SSH_DROPIN = "/etc/ssh/sshd_config.d/00-system-check.conf"


def ufw_enabled():
    return bool(re.search(r"^ENABLED=yes", read("/etc/ufw/ufw.conf"), re.M))


def ssh_active(ctx):
    return ctx.run("systemctl is-active ssh.service sshd.service ssh.socket 2>/dev/null").split().count("active") > 0


def docker_published(ctx):
    """{port: container} for ports Docker publishes on every interface."""
    out = ctx.run("docker ps --format '{{.Names}}\t{{.Ports}}' 2>/dev/null", timeout=15) if ctx.has("docker") else ""
    pub = {}
    for line in out.splitlines():
        name, _, ports = line.partition("\t")
        for m in re.finditer(r"(0\.0\.0\.0|\[::\]|::):(\d+)->", ports):
            pub[int(m.group(2))] = name
    return pub


@check("security", "firewall")
def firewall(ctx):
    if ufw_enabled():
        rules = ctx.run("ufw status numbered", root=True)
        n = len(re.findall(r"^\[\s*\d+\]", rules or "", re.M))
        return [finding(OK, "Firewall (ufw) on" + (f", {n} allow rule(s)" if rules else ""))]
    allow_ssh = "ufw allow OpenSSH\n" if ssh_active(ctx) else ""
    return [finding(CRIT, "Firewall (ufw) is off: every listening service is reachable from the network", [],
                    fix("Turn on the firewall: block incoming, allow outgoing" + (", keep SSH open" if allow_ssh else ""),
                        f"ufw default deny incoming\nufw default allow outgoing\n{allow_ssh}ufw --force enable", safe=False))]


@check("security", "exposed-ports")
def exposed_ports(ctx):
    root_ss = ctx.run("ss -tlnpH", root=True)
    out = root_ss if root_ss is not None else ctx.run("ss -tlnpH")
    docker = docker_published(ctx)
    fw = ufw_enabled()
    res, seen, plain = [], set(), []
    for line in out.splitlines():
        p = line.split()
        if len(p) < 4:
            continue
        addr, _, port = p[3].rpartition(":")
        if not port.isdigit() or re.match(r"^(127\.|\[::1\]|\[::ffff:127\.)", addr) or "%lo" in addr:
            continue
        port = int(port)
        if port in seen:
            continue
        seen.add(port)
        proc = re.search(r'users:\(\("([^"]+)"', line)
        who = docker.get(port) and f"docker:{docker[port]}" or (proc.group(1) if proc else "?")
        what = RISKY_PORTS.get(port)
        if port in docker:
            res.append(finding(CRIT if what else WARN,
                               f"Port {port} ({what or 'container'}) from {docker[port]} is open to the network, past the firewall",
                               ["Docker writes its own firewall rules, so ufw does not block this.",
                                f"Fix in its compose file / run command: publish as \"127.0.0.1:{port}:{port}\" instead of \"{port}:{port}\"."]))
        elif what and not fw:
            res.append(finding(CRIT, f"{what} (port {port}, {who}) is open to the network with no firewall", ["Bind it to 127.0.0.1 or turn on ufw."]))
        else:
            plain.append(f"{port}/{who}")
    if plain:
        res.append(finding(INFO if fw else WARN, f"{len(plain)} service(s) listen on all interfaces" + (" (firewall filters them)" if fw else ""),
                           [" ".join(plain[:14])] + ([] if root_ss is not None else ["Program names need sudo."])))
    if not res:
        res.append(finding(OK, "Nothing listening beyond this computer"))
    return res


def sshd_effective(ctx):
    out = ctx.run("sshd -T 2>/dev/null", root=True)
    if out:
        return dict(l.split(None, 1) for l in out.lower().splitlines() if " " in l)
    eff = {}  # sshd: first value wins; Ubuntu includes sshd_config.d/*.conf at the top
    for path in sorted(glob.glob("/etc/ssh/sshd_config.d/*.conf")) + ["/etc/ssh/sshd_config"]:
        for line in read(path).lower().splitlines():
            line = line.split("#")[0].strip()
            if line.startswith("match "):
                break
            if " " in line:
                k, v = line.split(None, 1)
                eff.setdefault(k, v.strip())
    eff.setdefault("permitrootlogin", "prohibit-password")
    eff.setdefault("passwordauthentication", "yes")
    return eff


@check("security", "ssh")
def ssh(ctx):
    if not ssh_active(ctx):
        return [finding(OK, "SSH server not running")]
    eff = sshd_effective(ctx)
    res = []
    if eff.get("permitrootlogin") == "yes":
        res.append(finding(CRIT, "SSH lets root log in with a password", [],
                           fix("Block root logins over SSH", f"echo 'PermitRootLogin no' > {SSH_DROPIN}\nsshd -t && systemctl reload ssh")))
    if eff.get("permitemptypasswords") == "yes":
        res.append(finding(CRIT, "SSH accepts accounts with empty passwords", [],
                           fix("Refuse empty passwords over SSH", f"echo 'PermitEmptyPasswords no' >> {SSH_DROPIN}\nsshd -t && systemctl reload ssh")))
    if eff.get("passwordauthentication") == "yes":
        keys = read(os.path.join(ctx.home, ".ssh/authorized_keys")).strip()
        if keys:
            res.append(finding(WARN, "SSH still accepts passwords although you have login keys set up",
                               ["Password logins are what bots guess at."],
                               fix("Allow SSH logins with keys only (test a key login first!)",
                                   f"echo 'PasswordAuthentication no' >> {SSH_DROPIN}\nsshd -t && systemctl reload ssh", safe=False)))
        else:
            res.append(finding(INFO, "SSH uses password logins (no login keys set up)",
                               ["Stronger: add your key with ssh-copy-id from your other machine, then re-run system-check."]))
    if ctx.run("systemctl is-active fail2ban").strip() != "active":
        res.append(finding(WARN, "SSH is on but fail2ban (blocks password guessers) is not running", [],
                           fix("Start fail2ban", "systemctl enable --now fail2ban") if ctx.has("fail2ban-client") else
                           fix("Install and start fail2ban", "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq fail2ban && systemctl enable --now fail2ban")))
    if not res:
        res.append(finding(OK, "SSH settings fine"))
    return res


@check("security", "logins")
def logins(ctx):
    res = []
    out = ctx.run('journalctl --since "24 hours ago" --no-pager -o cat _COMM=sshd 2>/dev/null')
    fails = re.findall(r"(?:Failed password|Invalid user|authentication failure).*?(?:from|rhost=)\s*(\S+)", out)
    if fails:
        ips = collections.Counter(fails)
        res.append(finding(WARN if len(fails) >= 20 else INFO, f"{len(fails)} failed SSH login(s) in the last 24 hours",
                           ["From: " + ", ".join(f"{ip} ({n})" for ip, n in ips.most_common(5))]))
    ok = re.findall(r"Accepted (\S+) for (\S+) from (\S+)", out)
    if ok:
        res.append(finding(INFO, f"{len(ok)} successful SSH login(s) in the last 24 hours — confirm these were you",
                           [f"{u} from {ip} ({how})" for how, u, ip in ok[-5:]]))
    sudo = ctx.run('journalctl --since "24 hours ago" --no-pager -o cat _COMM=sudo 2>/dev/null')
    bad = len(re.findall(r"incorrect password attempt", sudo))
    if bad >= 3:
        res.append(finding(WARN, f"{bad} wrong sudo password attempt(s) in the last 24 hours"))
    if not res:
        res.append(finding(OK, "No failed or remote logins in the last 24 hours"))
    return res


@check("security", "accounts")
def accounts(ctx):
    res = []
    passwd = [l.split(":") for l in read("/etc/passwd").splitlines() if l.count(":") >= 6]
    uid0 = [p[0] for p in passwd if p[2] == "0" and p[0] != "root"]
    if uid0:
        res.append(finding(CRIT, f"Extra all-powerful (UID 0) account(s): {', '.join(uid0)}", ["Only root should have UID 0. Classic backdoor."]))
    empty = ctx.run("awk -F: '$2==\"\"{print $1}' /etc/shadow", root=True)
    if empty is None:
        res.append(finding(SKIP, "Empty-password check needs sudo"))
    elif empty.strip():
        users = empty.split()
        res.append(finding(CRIT, f"Account(s) with no password: {', '.join(users)}", [],
                           fix("Lock the password-less account(s)", "\n".join(f"passwd -l {shlex.quote(u)}" for u in users))))
    nopw = ctx.run("grep -rhsE '^[^#].*NOPASSWD' /etc/sudoers /etc/sudoers.d/", root=True)
    if nopw and nopw.strip():
        res.append(finding(INFO, "sudo without password is allowed for:", nopw.strip().splitlines()[:4]))
    if time.time() - os.path.getmtime("/etc/passwd") < 7 * 86400:
        humans = [p[0] for p in passwd if p[2].isdigit() and 1000 <= int(p[2]) < 60000]
        res.append(finding(INFO, "User accounts changed this week — confirm it was you", ["Human accounts: " + ", ".join(humans)]))
    if not any(f["level"] in (CRIT, WARN) for f in res):
        res.append(finding(OK, "Accounts look normal"))
    return res


@check("security", "hardening")
def hardening(ctx):
    res = []
    auto = read("/etc/apt/apt.conf.d/20auto-upgrades")
    if not re.search(r'Unattended-Upgrade\s+"1"', auto):
        res.append(finding(WARN, "Automatic security updates are off", [],
                           fix("Turn on automatic security updates",
                               "printf 'APT::Periodic::Update-Package-Lists \"1\";\\nAPT::Periodic::Unattended-Upgrade \"1\";\\n' "
                               "> /etc/apt/apt.conf.d/20auto-upgrades\nsystemctl enable --now unattended-upgrades")))
    aa = ctx.run("aa-enabled 2>/dev/null").strip()
    if aa and aa != "Yes":
        res.append(finding(WARN, "AppArmor (app sandboxing) is disabled", ["Re-enable: remove apparmor=0 from the kernel command line."]))
    lock = ctx.run("gsettings get org.gnome.desktop.screensaver lock-enabled 2>/dev/null").strip()
    if lock == "false":
        res.append(finding(WARN, "Screen does not lock when you step away", [],
                           fix("Lock the screen automatically", "gsettings set org.gnome.desktop.screensaver lock-enabled true", root=False)))
    if read("/etc/ld.so.preload").strip():
        res.append(finding(CRIT, "/etc/ld.so.preload is set — a common rootkit trick", [read("/etc/ld.so.preload").strip()[:200]]))
    if not res:
        res.append(finding(OK, "Auto security updates, AppArmor and screen lock on"))
    return res


@check("security", "processes")
def processes(ctx):
    script = 'for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null) && echo "${p#/proc/} $e"; done'
    out = ctx.run(script, root=True)
    full = out is not None
    out = out if full else ctx.run(script)
    bad, stale = [], set()
    for line in out.splitlines():
        pid, _, exe = line.partition(" ")
        name = os.path.basename(exe.replace(" (deleted)", ""))
        if re.match(r"/(tmp|dev/shm|var/tmp)/", exe) or MINERS.search(name):
            bad.append(f"pid {pid}: {exe}")
        elif exe.endswith(" (deleted)") and not exe.startswith("/memfd:"):
            stale.add(name)
    res = []
    if bad:
        res.append(finding(CRIT, f"{len(bad)} program(s) running from a temp folder or named like a crypto-miner", bad[:6] +
                           ["Malware usually runs from /tmp or /dev/shm. Inspect: ls -l /proc/<pid>/exe ; cat /proc/<pid>/cmdline"]))
    if stale:
        res.append(finding(INFO, f"{len(stale)} app(s) still running an old version after an update — restart them",
                           [", ".join(sorted(stale)[:12])]))
    if not bad:
        res.append(finding(OK, "No programs running from temp folders" + ("" if full else " (your processes only; sudo checks all)")))
    return res


@check("security", "startup-items")
def startup_items(ctx):
    since = time.time() - 3 * 86400
    places = ["/etc/systemd/system/*.service", "/etc/systemd/system/*.timer", "/etc/cron.d/*", "/etc/profile.d/*",
              f"{ctx.home}/.config/systemd/user/*.service", f"{ctx.home}/.config/systemd/user/*.timer",
              f"{ctx.home}/.config/autostart/*.desktop"]
    new = sorted((os.path.getmtime(p), p) for pat in places for p in glob.glob(pat)
                 if os.path.isfile(p) and os.path.getmtime(p) > since)
    res = []
    if new:
        res.append(finding(INFO, f"{len(new)} startup item(s) added or changed in the last 3 days — confirm you made them",
                           [f"{time.strftime('%b %d', time.localtime(t))}  {p.replace(ctx.home, '~')}" for t, p in new[-8:]]))
    ak = os.path.join(ctx.home, ".ssh/authorized_keys")
    if os.path.exists(ak) and read(ak).strip() and os.path.getmtime(ak) > time.time() - 7 * 86400:
        res.append(finding(WARN, "SSH login keys (authorized_keys) changed this week — confirm you added them",
                           [l[-60:] for l in read(ak).strip().splitlines()[-3:]]))
    cron = ctx.run("crontab -l 2>/dev/null | grep -vE '^\\s*(#|$)'").strip()
    if cron:
        res.append(finding(INFO, f"Your crontab runs {len(cron.splitlines())} job(s)", cron.splitlines()[:4]))
    if not res:
        res.append(finding(OK, "No new startup items in the last 3 days"))
    return res


@check("security", "permissions")
def permissions(ctx):
    res = []
    ssh_dir = os.path.join(ctx.home, ".ssh")
    loose = []
    if os.path.isdir(ssh_dir):
        if stat.S_IMODE(os.stat(ssh_dir).st_mode) & 0o077:
            loose.append(ssh_dir)
        for p in glob.glob(f"{ssh_dir}/*"):
            b = os.path.basename(p)
            if os.path.isfile(p) and not b.endswith(".pub") and b not in ("known_hosts", "known_hosts.old") \
                    and stat.S_IMODE(os.stat(p).st_mode) & 0o077:
                loose.append(p)
    if loose:
        res.append(finding(CRIT, "SSH keys/config readable by other users", [l.replace(ctx.home, "~") for l in loose],
                           fix("Make ~/.ssh private", f"chmod 700 {shlex.quote(ssh_dir)}\n" +
                               "\n".join(f"chmod 600 {shlex.quote(p)}" for p in loose if p != ssh_dir), root=False)))
    if stat.S_IMODE(os.stat(ctx.home).st_mode) & 0o007:
        res.append(finding(WARN, "Your home folder is readable by other accounts on this computer", [],
                           fix("Make your home folder private", f"chmod o-rwx {shlex.quote(ctx.home)}", root=False)))
    ww = ctx.run("find /etc /usr/local/bin /usr/local/sbin /usr/local/lib -xdev -type f -perm -0002 2>/dev/null | head -20").split()
    if ww:
        res.append(finding(CRIT, f"{len(ww)} system file(s) anyone can modify", ww[:6],
                           fix("Remove write access for other users", "\n".join(f"chmod o-w {shlex.quote(p)}" for p in ww))))
    suid = ctx.run("find /tmp /var/tmp /dev/shm -xdev -type f -perm -4000 2>/dev/null").split()
    if suid:
        res.append(finding(CRIT, "Run-as-root (SUID) program(s) in temp folders — likely a backdoor", suid[:6],
                           fix("Remove the SUID bit", "\n".join(f"chmod u-s {shlex.quote(p)}" for p in suid))))
    if not res:
        res.append(finding(OK, "File permissions fine (~/.ssh, home, system folders)"))
    return res


CHKROOTKIT_LOG = "/var/log/chkrootkit/log.today"
# chkrootkit "suspicious files" that ship with normal packages
CHK_NOISE = re.compile(r"/\.build-id$|/tests?/.*\.ht(access|passwd)$|\.sbom\.json$|\.eclipseproduct$|/\.(gitignore|keep|placeholder|travis\.yml|npmignore)$"
                       r"|PACKET SNIFFER\(\[systemd-networkd|not promisc|^WARNING$")


def chkrootkit_daily(ctx):
    """Real alerts from chkrootkit's daily run, with packaged-file noise removed: (alerts, noise_count, age_days)."""
    text = read(CHKROOTKIT_LOG)
    if not text:
        return None
    alerts, files, noise, in_list = [], [], 0, False
    for line in text.splitlines():
        s = line.strip()
        if s.startswith("WARNING: The following suspicious files"):
            in_list = True
            continue
        if in_list and s.startswith("/"):
            if CHK_NOISE.search(s):
                noise += 1
            else:
                files.append(s)
            continue
        in_list = False
        if s.startswith("Checking `") and "INFECTED" not in s:
            continue  # progress line, the verdict follows on its own line
        if re.search(r"INFECTED|bindshell|Possible .* installed|LKM Trojan|Warning: .* found", s) and "not infected" not in s.lower():
            ports = re.search(r"infected ports: ([\d ]+)", s)
            if ports:
                listening = ctx.run("ss -tulnH").split()
                live = [p for p in ports.group(1).split() if any(x.endswith(":" + p) for x in listening)]
                s += " — nothing listens there now (likely a short-lived socket)" if not live else f" — port(s) {' '.join(live)} ARE listening"
            alerts.append(s)
    if files:  # hidden files that belong to an installed package are normal
        owned = ctx.run("dpkg -S " + " ".join(shlex.quote(f) for f in files) + " 2>/dev/null", timeout=40)
        owned = {l.split(": ", 1)[1].strip() for l in owned.splitlines() if ": " in l}
        packaged = re.compile(r"^/usr/(lib|share)/[^/]+/.*node_modules/|^/usr/lib/(python3|node_modules|jvm)/")
        for f in files:
            if f in owned or packaged.search(f) or any(f.startswith(o.rstrip("/") + "/") for o in owned if o.startswith("/usr/lib/")):
                noise += 1
            else:
                alerts.append(f"suspicious file: {f}")
    return alerts, noise, (time.time() - os.path.getmtime(CHKROOTKIT_LOG)) / 86400


@check("security", "malware-scan")
def malware_scan(ctx):
    logs = sorted(glob.glob(os.path.join(ctx.home, "security-scan-*.log")))
    timer = ctx.run("systemctl is-enabled weekly-security-scan.timer 2>/dev/null").strip()
    setup = os.path.join(ctx.home, "bin/security-setup.sh")
    res = []
    if timer != "enabled" and os.path.exists(setup):
        res.append(finding(WARN, "Weekly rootkit/malware scan is not scheduled", [],
                           fix("Set up the weekly rootkit scan (rkhunter + chkrootkit)", f"bash {shlex.quote(setup)}", safe=False)))
    daily = chkrootkit_daily(ctx)
    if daily:
        alerts, noise, age = daily
        if alerts:
            listening = any("ARE listening" in a for a in alerts)
            res.append(finding(CRIT if listening or any("INFECTED" in a for a in alerts) else WARN,
                               f"chkrootkit daily scan ({age:.0f} day(s) ago) raised {len(alerts)} alert(s)",
                               alerts[:6] + ([f"{noise} more 'suspicious files' are normal files from installed packages."] if noise else []) +
                               [f"Full output: {CHKROOTKIT_LOG}. Re-scan now: system-check deep"]))
    if not logs:
        if not daily:
            res.append(finding(INFO, "No rootkit scan has run yet — run: system-check deep"))
        return res
    text = read(logs[-1])
    age = (time.time() - os.path.getmtime(logs[-1])) / 86400
    warns = [l.strip() for l in text.splitlines() if re.match(r"\s*Warning:", l)]
    infected = [l.strip() for l in text.splitlines() if "INFECTED" in l and "not infected" not in l.lower()]
    name = os.path.basename(logs[-1])
    if infected:
        res.append(finding(CRIT, f"Rootkit scanner flagged {len(infected)} item(s) ({name})", infected[:5] + ["Often false positives; check each."]))
    if warns:
        res.append(finding(WARN, f"Rootkit scan reported {len(warns)} warning(s) ({name})",
                           warns[:5] + ["Many are harmless after updates. Refresh the baseline after reviewing: sudo rkhunter --propupd"]))
    if age > 10:
        res.append(finding(WARN, f"Last rootkit scan was {age:.0f} days ago", ["Run one now: system-check deep"]))
    if not infected and not warns and age <= 10:
        res.append(finding(OK, f"Last rootkit scan clean ({age:.0f} day(s) ago)"))
    return res
