"""system-check i: scan once, then open issues, fix them on the go, and run focused checks from one prompt."""
import glob, os, re, shlex, subprocess, time

from .core import AREAS, CRIT, INFO, OK, RANK, SKIP, WARN, Ctx, human, read, run_checks
from .health import app_name, meminfo, psi, top_processes

HELP = """
  3            open issue 3: details and exactly what its fix runs
  f            fix the issue you just opened      f 3 5   fix issues 3 and 5      f safe   every safe fix
  l            list issues again                  ok      also list the checks that passed
  r            re-check everything                r memory  re-check one area ({areas})

  Focused checks
  top          what is using memory and CPU right now
  ports        what listens on the network, and which program
  svc NAME     one service: status and log, then restart / stop / disable / enable it
  logs [NAME]  recent errors, or one service's log
  boot         what makes startup slow
  kills        apps killed for low memory, one by one
  temps        temperatures, fans, CPU speed
  net          connection, DNS and response times
  disk         disk usage and the biggest caches
  deep         full rootkit/malware scan (a few minutes)

  !COMMAND     run a shell command          q  quit          Tab completes commands and service names
""".format(areas=" ".join(AREAS))

COMMANDS = ["f", "l", "ok", "r", "top", "ports", "svc", "logs", "boot", "kills", "temps", "net", "disk", "deep", "help", "q"] + AREAS


class Session:
    def __init__(self, ctx, cli):
        self.ctx, self.cli = ctx, cli          # cli = the cli module (render helpers, scan, apply_fixes)
        self.c = cli.c
        self.report, self.issues, self.current = None, [], None
        self._units = None

    # ---------- issues ----------

    def scan(self, areas=None):
        t = time.time()
        print(self.c("2", "Checking..."), flush=True)
        if areas:
            fresh = run_checks(self.ctx, areas)
            keep = [f for f in self.report["findings"] if f["area"] not in areas]
            self.report["findings"] = keep + fresh
        else:
            self.report = self.cli.scan(self.ctx, quiet=True)
        self.report["took"] = round(time.time() - t, 1)
        self.number()

    def number(self):
        fs = self.report["findings"]
        self.issues = sorted([f for f in fs if f["level"] in (CRIT, WARN, INFO)],
                             key=lambda f: (RANK[f["level"]], AREAS.index(f["area"]) if f["area"] in AREAS else 99))
        self.oks = [f for f in fs if f["level"] in (OK, SKIP)]

    def tag(self, f):
        if not f.get("fix"):
            return ""
        return self.c("32", "  [fix]") if f["fix"]["safe"] else self.c("33", "  [fix · review]")

    def list(self, show_ok=False):
        crit = sum(f["level"] == CRIT for f in self.issues)
        warn = sum(f["level"] == WARN for f in self.issues)
        print("\n" + self.c("1", f"{len(self.issues)} things to look at") +
              f"  ({self.c('31', f'{crit} problem(s)')}, {self.c('33', f'{warn} warning(s)')}, "
              f"{self.c('32', f'{len(self.oks)} OK')})")
        for n, f in enumerate(self.issues, 1):
            icon = self.c(self.cli.COLOR[f["level"]], self.cli.ICON[f["level"]])
            print(f" {n:>3} {icon} {self.c('2', f['area'][:8].ljust(8))} {f['title'][:110]}{self.tag(f)}")
        if show_ok:
            for f in self.oks:
                print(f"     {self.c(self.cli.COLOR[f['level']], self.cli.ICON[f['level']])} {self.c('2', f['area'][:8].ljust(8))} {f['title']}")
        fixable = [n for n, f in enumerate(self.issues, 1) if f.get("fix")]
        print(self.c("2", f"\nType a number to open it" + (f", f {fixable[0]} to fix it" if fixable else "") +
                     ", f safe for all safe fixes, help for focused checks, q to quit."))

    def open(self, n):
        if not 1 <= n <= len(self.issues):
            print(f"No issue {n}; there are {len(self.issues)}.")
            return
        f = self.current = self.issues[n - 1]
        print("\n" + self.c(self.cli.COLOR[f["level"]], f"{self.cli.ICON[f['level']]} {f['title']}") + self.c("2", f"   ({f['area']})"))
        for d in f["detail"]:
            print(f"    {d}")
        if f.get("fix"):
            x = f["fix"]
            notes = ", ".join(n for n, on in (("needs sudo", x["root"]), ("review first", not x["safe"])) if on)
            print("\n  " + self.c("1", f"Fix: {x['label']}") + (self.c("2", f"  ({notes})") if notes else ""))
            for line in x["cmd"].splitlines():
                print(self.c("2", f"      $ {line}"))
            print(self.c("2", "\n  f = apply this fix · l = back to the list"))

    def fix(self, args):
        if not args:
            if not self.current:
                print("Open an issue first (type its number), or: f 3 5")
                return
            chosen = [self.current]
        elif args == ["safe"] or args == ["all"]:
            chosen = [f for f in self.issues if f.get("fix") and f["fix"]["safe"]]
            if not chosen:
                print("No safe fixes left. The [fix · review] ones need a number: f 3")
                return
        else:
            try:
                nums = self.cli.parse_numbers(args, len(self.issues))
            except ValueError as e:
                print(e)
                return
            chosen = [self.issues[n - 1] for n in nums]
        nofix = [f for f in chosen if not f.get("fix")]
        for f in nofix:
            print(f"No automatic fix for: {f['title']}")
        chosen = [f for f in chosen if f.get("fix")]
        if not chosen:
            return
        review = [f for f in chosen if not f["fix"]["safe"]]
        if review:
            print(self.c("33", "These change something you may rely on:"))
            for f in review:
                print(f"  - {f['fix']['label']}")
            if not self.confirm("Apply?", default=False):
                return
        for i, f in enumerate(chosen, 1):
            f["fix"]["n"] = i
        failed = self.cli.apply_fixes(chosen)
        names = sorted({f["check"] for f in chosen})
        fresh = run_checks(Ctx(), names=names)
        self.report["findings"] = [f for f in self.report["findings"] if f["check"] not in names] + fresh
        self.number()
        self.current = None
        print(self.c("32" if not failed else "33", f"\n{len(chosen) - failed} of {len(chosen)} fixed. Re-checked:"))
        for f in fresh:
            print(f"  {self.c(self.cli.COLOR[f['level']], self.cli.ICON[f['level']])} {f['title']}")
        print(self.c("2", "l = updated list"))

    def confirm(self, q, default=True):
        try:
            a = input(f"{q} [{'Y/n' if default else 'y/N'}] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            return False
        return default if not a else a in ("y", "yes")

    # ---------- focused checks ----------

    def sh(self, cmd, root=False):
        """Run and show output live; root commands go through sudo (may ask for the password)."""
        if root and not self.ctx.is_root:
            cmd = "sudo " + cmd
        subprocess.run(cmd, shell=True)

    def top(self):
        m = meminfo()
        p10, p60, _ = psi("memory")
        c10, _, _ = psi("cpu")
        print(self.c("1", "\nRight now") + f"  RAM {human(m['MemTotal'] - m['MemAvailable'])} used of {human(m['MemTotal'])}, "
              f"swap {human(m['SwapTotal'] - m['SwapFree'])} used, memory stall {p10:.1f}%, CPU stall {c10:.1f}%, "
              f"load {read('/proc/loadavg').split()[0]} on {self.ctx.ncpu} cores")
        print(self.c("1", "\nMemory by app"))
        for name, kb in top_processes(self.ctx, "rss", 10):
            print(f"  {human(kb * 1024):>7}  {name}")
        print(self.c("1", "\nBusiest processes (CPU)"))
        out = self.ctx.run("ps -eo pid,pcpu,rss,etime,comm --sort=-pcpu --no-headers | head -8")
        print(f"  {'PID':>7} {'CPU%':>5} {'RAM':>7} {'RUNNING':>12}  NAME")
        for line in out.splitlines():
            pid, cpu, rss, et, comm = line.split(None, 4)
            print(f"  {pid:>7} {cpu:>5} {human(int(rss) * 1024):>7} {et:>12}  {comm}")
        print(self.c("2", "\nStop one: !kill PID   (or !kill -9 PID if it ignores you)"))

    def ports(self):
        out = self.ctx.run("ss -tulnpH", root=True)
        full = out is not None
        out = out if full else self.ctx.run("ss -tulnpH")
        rows = []
        for line in out.splitlines():
            p = line.split()
            if len(p) < 5:
                continue
            addr, _, port = p[4].rpartition(":")
            prog = re.search(r'users:\(\("([^"]+)",pid=(\d+)', line)
            local = bool(re.match(r"^(127\.|\[::1\]|\[::ffff:127\.)", addr)) or "%lo" in addr
            rows.append((local, p[0], int(port) if port.isdigit() else 0, addr, f"{prog.group(1)} ({prog.group(2)})" if prog else "?"))
        print(self.c("1", f"\n{'':2}{'PROTO':6}{'PORT':>6}  {'REACHABLE FROM':16}PROGRAM"))
        for local, proto, port, addr, prog in sorted(set(rows), key=lambda r: (r[0], r[2])):
            where = "this computer" if local else "the network"
            print(f"  {proto:6}{port:>6}  {self.c('2' if local else '33', where.ljust(16))}{prog}")
        if not full:
            print(self.c("2", "Program names for other users' services need sudo."))

    def units(self):
        if self._units is None:
            names = set()
            for flag in ("", "--user "):
                names |= {l.split()[0] for l in self.ctx.run(f"systemctl {flag}list-units --type=service --all --no-legend --plain").splitlines() if l.split()}
                names |= {l.split()[0] for l in self.ctx.run(f"systemctl {flag}list-unit-files --type=service --no-legend").splitlines() if l.split()}
            self._units = sorted(n for n in names if "@." not in n)
        return self._units

    def find_unit(self, name):
        if not name:
            print("Which service? e.g. svc docker")
            return None, None
        name = name if name.endswith((".service", ".timer", ".socket")) else name + ".service"
        cands = [name] if name in self.units() else [u for u in self.units() if name.replace(".service", "").lower() in u.lower()]
        if not cands:
            print(f"No service matching '{name}'.")
            return None, None
        if len(cands) > 1:
            print("Several match: " + ", ".join(cands[:12]) + (" ..." if len(cands) > 12 else ""))
            return None, None
        u = cands[0]
        user = bool(self.ctx.run(f"systemctl --user cat {shlex.quote(u)} 2>/dev/null | head -1").strip())
        return u, user

    def svc(self, name):
        u, user = self.find_unit(name)
        if not u:
            return
        flag = "--user " if user else ""
        q = shlex.quote(u)
        print()
        subprocess.run(f"systemctl {flag}status {q} --no-pager -n 0 | head -12", shell=True)
        print(self.c("1", "\nRecent log"))
        subprocess.run(f"journalctl {'--user-unit' if user else '-u'} {q} -n 15 --no-pager -o short", shell=True)
        while True:
            try:
                a = input(self.c("1", f"\n{u}: ") + "[r]estart [s]top [d]isable [e]nable [l]og more [b]ack > ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print()
                return
            verb = {"r": "restart", "s": "stop", "d": "disable --now", "e": "enable --now"}.get(a)
            if verb:
                self.sh(f"systemctl {flag}{verb} {q}", root=not user)
                subprocess.run(f"systemctl {flag}is-active {q}; systemctl {flag}is-enabled {q}", shell=True)
            elif a == "l":
                subprocess.run(f"journalctl {'--user-unit' if user else '-u'} {q} -n 80 --no-pager -o short", shell=True)
            else:
                return

    def logs(self, name):
        if name:
            u, user = self.find_unit(name)
            if u:
                subprocess.run(f"journalctl {'--user-unit' if user else '-u'} {shlex.quote(u)} -n 50 --no-pager -o short", shell=True)
            return
        for f in run_checks(self.ctx, names=["app-errors", "kernel-errors"]):
            print("\n" + self.c("1", f["title"]))
            for d in f["detail"]:
                print(f"  {d}")
        print(self.c("2", "\nOne service's log: logs NAME · everything today: !journalctl -p err --since today"))

    def boot(self):
        print()
        subprocess.run("systemd-analyze 2>/dev/null | head -2", shell=True)
        print(self.c("1", "\nSlowest system services at startup"))
        subprocess.run("systemd-analyze blame --no-pager 2>/dev/null | head -12", shell=True)
        print(self.c("1", "\nSlowest of your own services"))
        subprocess.run("systemd-analyze --user blame --no-pager 2>/dev/null | head -6", shell=True)
        print(self.c("2", "\nA service waiting on the network (NetworkManager-wait-online) often adds 5-30s; "
                          "turn one off with: svc NAME then d"))

    def kills(self):
        out = self.ctx.run('journalctl -u systemd-oomd --since "30 days ago" --no-pager -o short-iso | grep " Killed "')
        rows = []
        for line in out.splitlines():
            m = re.search(r"^(\S+).*Killed (\S+) due to memory pressure for (\S+) being ([\d.]+)%", line)
            if m:
                rows.append((m.group(1)[:16].replace("T", " "), app_name(m.group(2)), f"{m.group(4)}% stalled"))
        k = self.ctx.run('journalctl -k --since "30 days ago" --no-pager -o short-iso | grep -E "Out of memory: Killed process"')
        for line in k.splitlines():
            m = re.search(r"^(\S+).*Killed process \d+ \(([^)]+)\).*?anon-rss:(\d+)kB", line)
            if m:
                rows.append((m.group(1)[:16].replace("T", " "), m.group(2) + " (kernel)", f"{human(int(m.group(3)) * 1024)} in RAM"))
        if not rows:
            print("No apps killed for low memory in the logs (they reach back "
                  f"{self.ctx.run('journalctl --no-pager -o short -n 1 -r --reverse 2>/dev/null | head -1')[:15] or 'a few days'}).")
            return
        print(self.c("1", f"\n{len(rows)} app(s) killed for low memory"))
        for t, who, why in sorted(rows):
            print(f"  {t}  {who:28} {self.c('2', why)}")
        print(self.c("2", "\nSee what was running just before one: !journalctl --since 'YYYY-MM-DD HH:MM' -n 50 -u systemd-oomd"))

    def temps(self):
        print(self.c("1", "\nSensors"))
        for d in sorted(glob.glob("/sys/class/hwmon/hwmon*")):
            name = read(f"{d}/name").strip()
            for t in sorted(glob.glob(f"{d}/temp*_input")) + sorted(glob.glob(f"{d}/fan*_input")):
                v = read(t).strip()
                if not v.lstrip("-").isdigit():
                    continue
                label = read(t.replace("_input", "_label")).strip() or os.path.basename(t).replace("_input", "")
                val = f"{int(v) / 1000:.0f}°C" if "temp" in t else f"{v} rpm"
                print(f"  {name:12} {label:18} {val}")
        gpu = self.ctx.run("nvidia-smi --query-gpu=name,temperature.gpu,fan.speed,power.draw,clocks.sm --format=csv,noheader 2>/dev/null").strip()
        if gpu:
            print(f"  {'nvidia':12} {gpu}")
        freqs = [int(read(f).strip() or 0) for f in glob.glob("/sys/devices/system/cpu/cpu*/cpufreq/scaling_cur_freq")]
        if freqs:
            print(f"  {'cpu':12} {'speed':18} {min(freqs) / 1e6:.1f}-{max(freqs) / 1e6:.1f} GHz across {len(freqs)} cores")
        print(self.c("2", "\nAbove ~90°C under light load means dust or a failing fan/cooler."))

    def net(self):
        route = self.ctx.run("ip route show default").split()
        gw = route[2] if len(route) > 2 else ""
        dev = route[route.index("dev") + 1] if "dev" in route else "?"
        print(self.c("1", "\nConnection") + f"  via {dev}, gateway {gw or 'none'}")
        wifi = self.ctx.run("nmcli -t -f ACTIVE,SSID,SIGNAL dev wifi 2>/dev/null | grep '^yes'").strip()
        if wifi:
            _, ssid, sig = wifi.split(":")[:3]
            print(f"  Wi-Fi {ssid}, signal {sig}%")
        for label, target in (("router", gw), ("internet (1.1.1.1)", "1.1.1.1")):
            if target:
                out = self.ctx.run(f"ping -c 3 -W 2 {shlex.quote(target)} 2>&1 | tail -2", timeout=12)
                loss = re.search(r"(\d+)% packet loss", out)
                avg = re.search(r"= [\d.]+/([\d.]+)/", out)
                print(f"  {label:22} {(avg.group(1) + ' ms') if avg else 'no reply':>10}  {loss.group(1) + '% lost' if loss else ''}")
        t = time.time()
        ok = self.ctx.run("timeout 4 getent ahosts archive.ubuntu.com | head -1").strip()
        print(f"  {'DNS lookup':22} {(f'{(time.time() - t) * 1000:.0f} ms') if ok else 'FAILED':>10}")
        web = self.ctx.run("curl -s -o /dev/null -m 8 -w '%{time_total} %{http_code}' https://archive.ubuntu.com/ 2>/dev/null").split()
        print(f"  {'HTTPS page load':22} {(f'{float(web[0]) * 1000:.0f} ms') if web and web[-1] != '000' else 'FAILED':>10}")

    def disk(self):
        if self.ctx.has("disk-clean"):
            subprocess.run("disk-clean status", shell=True)
            print(self.c("2", "\nFree space: !disk-clean   bigger items: !disk-clean deep"))
        else:
            subprocess.run("df -h -x tmpfs -x squashfs -x overlay", shell=True)

    def deep(self):
        scanner = "/usr/local/sbin/weekly-security-scan.sh"
        if not os.path.exists(scanner):
            print("Rootkit scanner not set up; see the 'Weekly rootkit/malware scan' issue.")
            return
        print("Running rkhunter + chkrootkit (a few minutes, Ctrl+C to stop)...")
        try:
            self.sh(f"bash {scanner}", root=True)
        except KeyboardInterrupt:
            print("\nStopped.")
        self.scan(["security"])
        self.list()

    # ---------- loop ----------

    def complete(self, text, state):
        try:
            import readline
            line = readline.get_line_buffer()
        except ImportError:
            line = text
        words = line.split()
        if words and words[0] in ("svc", "logs") and (len(words) > 1 or line.endswith(" ")):
            opts = [u.replace(".service", "") for u in self.units()]
        else:
            opts = COMMANDS
        matches = [o + " " for o in opts if o.startswith(text)]
        return matches[state] if state < len(matches) else None

    def handle(self, line):
        if line.startswith("!"):
            subprocess.run(line[1:], shell=True)
            return True
        words = line.split()
        if not words:
            return True
        cmd, args = words[0].lower(), words[1:]
        if cmd.isdigit():
            self.open(int(cmd))
        elif cmd in ("q", "quit", "exit"):
            return False
        elif cmd in ("h", "help", "?"):
            print(HELP)
        elif cmd in ("l", "list", "ls"):
            self.list()
        elif cmd == "ok":
            self.list(show_ok=True)
        elif cmd in ("f", "fix"):
            self.fix(args)
        elif cmd in ("r", "rescan", "recheck"):
            bad = [a for a in args if a not in AREAS]
            if bad:
                print(f"Unknown area '{bad[0]}'. Areas: {' '.join(AREAS)}")
            else:
                self.scan(args or None)
                self.list()
        elif cmd in AREAS:
            self.scan([cmd])
            for f in [f for f in self.report["findings"] if f["area"] == cmd]:
                n = self.issues.index(f) + 1 if f in self.issues else None
                print(f" {str(n) if n else '':>3} {self.c(self.cli.COLOR[f['level']], self.cli.ICON[f['level']])} {f['title']}{self.tag(f)}")
                for d in f["detail"][:3]:
                    print(self.c("2", f"       {d[:140]}"))
        elif cmd in ("svc", "service"):
            self.svc(" ".join(args))
        elif hasattr(self, cmd) and cmd in ("top", "ports", "logs", "boot", "kills", "temps", "net", "disk", "deep"):
            getattr(self, cmd)(*([" ".join(args)] if cmd == "logs" else []))
        else:
            print(f"Unknown command '{cmd}'. Type help.")
        return True

    def run(self):
        try:
            import readline
            readline.set_completer(self.complete)
            readline.set_completer_delims(" ")
            readline.parse_and_bind("tab: complete")
            hist = os.path.join(self.cli.state_dir(), "history")
            try:
                readline.read_history_file(hist)
            except OSError:
                pass
        except ImportError:
            readline, hist = None, None
        self.scan()
        mode = "full" if self.ctx.sudo else "limited (no sudo)"
        print(self.c("1", f"system-check · {self.report['host']} · {mode} · {self.report['took']}s"))
        self.list()
        while True:
            try:
                line = input(self.c("1", "\nsystem-check> ")).strip()
            except KeyboardInterrupt:
                print()
                continue
            except EOFError:
                print()
                break
            try:
                if not self.handle(line):
                    break
            except KeyboardInterrupt:
                print("\nStopped.")
        if readline and hist:
            try:
                readline.set_history_length(500)
                readline.write_history_file(hist)
            except OSError:
                pass
        return 0
