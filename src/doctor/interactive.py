"""doctor i: one prompt where Enter walks through the issues (fix, explain, skip), numbers open them,
plain questions go to the assistant, and focused checks look closer at one thing."""
import os, re, shlex, shutil, subprocess, textwrap, time

from . import agent, clean, probes
from .core import AREAS, CRIT, INFO, OK, RANK, SKIP, WARN, Ctx, human, run_checks

FOCUSED = ["top", "ports", "svc", "logs", "boot", "kills", "temps", "net", "disk", "malware", "history"]
SPACE = ["clean", "deep", "pick"]   # free disk space (disk_clean)
TAKES_ARGS = ("svc", "logs", "deep", "pick")
COMMANDS = ["more", "menu", "f", "e", "r", "help", "q"] + FOCUSED + SPACE + AREAS

HELP = """
  Enter        go through the issues one by one: fix, explain or skip each (b back, m menu)
  m            back to the main menu: what needs attention and what you can do
  3            open issue 3            f 3 5   fix several            f safe   every safe fix
  e 3          the assistant explains issue 3 in plain words
  a question   ask the assistant anything: "is anydesk safe?", "why is the fan loud?"
  more         show the suggestions too                              r   check again
  history      what doctor changed on this computer, and how to undo it

  Free space   clean   caches that rebuild themselves    deep [storage|folder]   big things safe to remove
               pick 1 3   delete those from the last deep scan (asks first)
  Look closer  top · ports · svc NAME · logs [NAME] · boot · kills · temps · net · disk · malware · any area name
  !command runs a shell command · Tab completes · q quits"""


class Session:
    def __init__(self, ctx, cli):
        self.ctx, self.cli, self.c = ctx, cli, cli.c   # cli = the cli module: scan, render colours, apply_fixes
        self.report, self.issues, self.oks = None, [], []
        self.done = set()          # titles handled in this session (fixed or skipped)
        self.current = None
        self._units = None
        self.mode = "interactive"    # how the assistant tells the user to apply a fix
        self.at_home = False         # the menu is on screen; elsewhere the prompt offers m

    # ---------- the issue list ----------

    def scan(self, areas=None):
        t = time.time()
        print(self.c("2", "Checking..."), flush=True)
        if areas and self.report:
            self.report["findings"] = [f for f in self.report["findings"] if f["area"] not in areas] + run_checks(self.ctx, areas)
        else:
            self.report = self.cli.scan(self.ctx, quiet=True)
        self.report["took"] = round(time.time() - t, 1)
        self._number()

    def _number(self):
        fs = self.report["findings"]
        self.issues = sorted([f for f in fs if f["level"] in (CRIT, WARN, INFO)],
                             key=lambda f: (RANK[f["level"]], AREAS.index(f["area"]) if f["area"] in AREAS else 99))
        self.oks = [f for f in fs if f["level"] in (OK, SKIP)]

    def icon(self, f):
        return self.c(self.cli.COLOR[f["level"]], self.cli.ICON[f["level"]])

    def tag(self, f):
        if f["title"] in self.done:
            return self.c("2", "  (done)")
        if not f.get("fix"):
            return ""
        return self.c("32", "  [fix]") if f["fix"]["safe"] else self.c("33", "  [fix · review]")

    def row(self, n, f):
        print(f" {n:>3} {self.icon(f)} {f['title'][:112]}{self.tag(f)}")

    def show(self, everything=False):
        urgent = [(n, f) for n, f in enumerate(self.issues, 1) if f["level"] != INFO]
        extra = [(n, f) for n, f in enumerate(self.issues, 1) if f["level"] == INFO]
        crit = sum(f["level"] == CRIT for _, f in urgent)
        print()
        if urgent:
            print(self.c("1", "Needs attention") + self.c("2", f"  {crit} problem(s), {len(urgent) - crit} warning(s), {len(self.oks)} checks OK"))
            for n, f in urgent:
                self.row(n, f)
        else:
            print(self.c("32", f"Nothing needs attention. {len(self.oks)} checks OK."))
        if extra and everything:
            print(self.c("1", "\nSuggestions and FYI"))
            for n, f in extra:
                self.row(n, f)
        elif extra:
            print(self.c("2", f"  + {len(extra)} suggestions (services you may not need, FYI) — type more"))
        if everything:
            for f in self.oks:
                print(f"     {self.icon(f)} {self.c('2', f['title'])}")
        self.menu()

    def menu(self):
        left = sum(f["title"] not in self.done for f in self.issues)
        d = lambda t: self.c("2", t)
        print()
        if left:
            print(f"  {self.c('1', 'Enter')} {d('go through the issues')}   {self.c('1', '3')} {d('open issue 3')}   "
                  f"{self.c('1', 'more')} {d('suggestions too')}   {self.c('1', 'r')} {d('check again')}")
        else:
            print(f"  {self.c('1', 'r')} {d('check again')}   {self.c('1', 'more')} {d('everything that was checked')}")
        print(f"  {self.c('1', 'clean')} · {self.c('1', 'deep')} {d('free disk space')}   "
              f"{self.c('1', 'top · ports · net · temps · boot · kills · svc NAME')} {d('look closer')}")
        ask = f"{d('or just ask a question')}   " if agent.available() else ""
        print(f"  {ask}{self.c('1', 'help')} {d('everything')}   {self.c('1', 'm')} {d('back here')}   {self.c('1', 'q')} {d('quit')}")

    def home(self):
        """The main menu: what needs attention, and what you can do."""
        self.at_home = True
        self.show()

    def card(self, n):
        f = self.current = self.issues[n - 1]
        print(f"\n{self.c('2', f'[{n}/{len(self.issues)}]')} {self.icon(f)} {self.c('1', f['title'])}  {self.c('2', f['area'])}")
        for d in f["detail"]:
            print(f"      {d}")
        if f.get("fix"):
            x = f["fix"]
            notes = ", ".join(t for t, on in (("needs sudo", x["root"]), ("review first", not x["safe"])) if on)
            print(f"\n    {self.c('1', 'Fix: ' + x['label'])}" + (self.c("2", f"  ({notes})") if notes else ""))
            for line in x["cmd"].splitlines():
                print(self.c("2", f"        $ {line}"))
        return f

    # ---------- acting on issues ----------

    def walk(self, start=None):
        """Enter: step through what's left, one decision per issue. b goes back one, m returns to the menu."""
        order = list(range(1, len(self.issues) + 1))
        if start:
            order = order[start - 1:] + order[:start - 1]
        todo = [n for n in order if self.issues[n - 1]["title"] not in self.done or n == start]
        fixed = skipped = 0
        i = 0
        while i < len(todo):
            n = todo[i]
            if n > len(self.issues):
                i += 1
                continue
            f = self.card(n)
            while True:
                keys = ("Enter fix it" if f.get("fix") else "Enter next") + " · e explain · s skip · b back · m menu"
                if agent.available():
                    keys += " · or ask about it"
                a = self.input(self.c("2", f"    {keys} › "))
                if a is None or a.strip().lower() in ("m", "menu", "home", "q", "stop"):
                    self.summary(fixed, skipped, stopped=True)
                    return self.home()
                a = a.strip()
                if a.lower() in ("b", "back", "p", "prev"):
                    if i == 0:
                        print("    This is the first one.")
                        continue
                    i -= 1
                    break
                if a == "" and f.get("fix"):
                    self.fix([f], confirm=False)
                    fixed += 1
                    i += 1
                    break
                if a.lower() in ("", "s", "n", "skip", "next"):
                    self.done.add(f["title"])
                    skipped += 1
                    i += 1
                    break
                if a.lower() in ("e", "explain", "?"):
                    self.explain(n)
                elif a.isdigit():
                    return self.walk(int(a))
                elif agent.available():
                    self.ask(f"About issue {n} ({f['title']}): {a}")
                else:
                    print("    Enter, e, s, b or m.")
        self.summary(fixed, skipped)
        self.home()

    def summary(self, fixed, skipped, stopped=False):
        left = sum(f["title"] not in self.done for f in self.issues)
        print(self.c("1", f"\n{'Stopped' if stopped else 'Done'}.") + f" {fixed} fixed, {skipped} skipped, {left} left."
              )

    def choose(self, args):
        if args in (["safe"], ["all"]):
            chosen = [f for f in self.issues if f.get("fix") and f["fix"]["safe"] and f["title"] not in self.done]
            if not chosen:
                print("No safe fixes left. The [fix · review] ones are picked by number: f 3")
            return chosen
        try:
            return [self.issues[n - 1] for n in self.cli.parse_numbers(args, len(self.issues))]
        except ValueError as e:
            print(e)
            return []

    def fix(self, chosen, confirm=True):
        for f in [f for f in chosen if not f.get("fix")]:
            print(f"No automatic fix for: {f['title']}" + (" — e explains what to do" if agent.available() else ""))
        chosen = [f for f in chosen if f.get("fix")]
        if not chosen:
            return
        review = [f for f in chosen if not f["fix"]["safe"]]
        if confirm and review:
            print(self.c("33", "These change something you may rely on:"))
            for f in review:
                print(f"  - {f['fix']['label']}")
            if (self.input("Apply? [y/N] ") or "").strip().lower() not in ("y", "yes"):
                return
        for i, f in enumerate(chosen, 1):
            f["fix"]["n"] = i
        failed = self.cli.apply_fixes(chosen)
        names = sorted({f["check"] for f in chosen})
        fresh = run_checks(Ctx(), names=names)
        self.report["findings"] = [f for f in self.report["findings"] if f["check"] not in names] + fresh
        self.done |= {f["title"] for f in chosen}
        self._number()
        print(self.c("32" if not failed else "33", f"    {len(chosen) - failed} of {len(chosen)} applied.") + self.c("2", " Now:"))
        for f in fresh:
            print(f"      {self.icon(f)} {f['title']}")

    # ---------- the assistant ----------

    def explain(self, n=None):
        n = n or (self.issues.index(self.current) + 1 if self.current in self.issues else None)
        if not n or not 1 <= n <= len(self.issues):
            print("Which one? e 3")
            return
        self._agent(agent.explain_prompt(n, self.issues[n - 1], {"issues": self.issues, "findings": self.report["findings"]}, self.mode))

    def ask(self, question):
        self._agent(agent.ask_prompt(question, {"issues": self.issues, "findings": self.report["findings"]}, self.mode))

    def _agent(self, prompt):
        if not agent.available():
            print("The assistant needs Claude Code (the `claude` command). Install it, or read the details above.")
            return
        width = min(shutil.get_terminal_size((100, 20)).columns, 110) - 6
        state = {"buf": ""}

        def out(line):
            line = re.sub(r"\*\*(.+?)\*\*", lambda m: self.c("1", m.group(1)), line).replace("`", "")
            bullet = re.match(r"^(\s*[-*] )", line)
            for w in (textwrap.wrap(line, width, subsequent_indent=" " * len(bullet.group(1)) if bullet else "") or [""]):
                print("    " + w, flush=True)

        def on_text(t):
            state["buf"] += t
            while "\n" in state["buf"]:
                line, state["buf"] = state["buf"].split("\n", 1)
                out(line)

        def on_tool(what):
            if state["buf"].strip():   # "Let me check..." before a tool call stands on its own line
                out(state["buf"])
            state["buf"] = ""
            print(self.c("2", f"    · looking at: {str(what)[:90]}"), flush=True)

        print(self.c("36", "\n  Assistant") + self.c("2", "  read-only: it can look around, not change anything"), flush=True)
        err = agent.stream(prompt, on_text, on_tool, cwd=self.cli.state_dir())
        if state["buf"].strip():
            out(state["buf"])
        if err:
            print(self.c("33", f"    The assistant couldn't answer: {err}"))

    # ---------- looking closer ----------

    def top(self):
        d = probes.now(self.ctx)
        print(self.c("1", "\nRight now") + f"  RAM {human(d['ram_used'])} of {human(d['ram_total'])} · swap {human(d['swap_used'])} · "
              f"memory stall {d['mem_stall']:.1f}% · CPU stall {d['cpu_stall']:.1f}% · load {d['load']} on {d['cores']} cores")
        print(self.c("1", "\nMemory by app"))
        for name, b in d["apps"]:
            print(f"  {human(b):>7}  {name}")
        print(self.c("1", "\nBusiest right now") + self.c("2", f"   {'PID':>7} {'CPU%':>6} {'RAM':>7}  RUNNING FOR"))
        for p in d["procs"]:
            print(f"  {p['name'][:18]:18} {p['pid']:>7} {p['cpu']:>6} {human(p['rss']):>7}  {p['running']}")
        print(self.c("2", "\nStop one: !kill PID"))

    def ports(self):
        rows, full = probes.listeners(self.ctx)
        print(self.c("1", f"\n  {'PROTO':6}{'PORT':>6}  {'REACHABLE FROM':16}PROGRAM"))
        for public, proto, port, prog in rows:
            where = self.c("33", "the network     ") if public else self.c("2", "this computer   ")
            print(f"  {proto:6}{port:>6}  {where}{prog}")
        if not full:
            print(self.c("2", "Some program names need sudo."))

    def kills(self):
        rows = probes.memory_kills(self.ctx)
        if not rows:
            print("No apps killed for low memory in the last 30 days of logs.")
            return
        print(self.c("1", f"\n{len(rows)} app(s) killed for low memory"))
        for t, who, why in rows:
            print(f"  {t}  {who:28} {self.c('2', why)}")

    def temps(self):
        print(self.c("1", "\nSensors"))
        for chip, label, val in probes.sensors(self.ctx):
            print(f"  {chip[:14]:14} {label[:24]:24} {val}")
        print(self.c("2", "\nAbove ~90°C at light load usually means dust or a tired fan."))

    def net(self):
        d = probes.network(self.ctx)
        print(self.c("1", "\nConnection") + f"  via {d['dev'] or 'nothing'}" + (f", gateway {d['gateway']}" if d["gateway"] else ""))
        if d["wifi"]:
            print(f"  Wi-Fi {d['wifi'][0]}, signal {d['wifi'][1]}%")
        for label, ms, loss in d["checks"]:
            val = f"{ms:.0f} ms" if ms is not None else self.c("31", "FAILED")
            print(f"  {label:22} {val:>9}" + (self.c("33", f"  {loss}% lost") if ms is not None and loss else ""))

    def boot(self):
        print()
        subprocess.run("systemd-analyze 2>/dev/null | head -1", shell=True)
        print(self.c("1", "\nSlowest at startup"))
        subprocess.run("systemd-analyze blame --no-pager 2>/dev/null | head -10", shell=True)
        print(self.c("1", "\nYour own services"))
        subprocess.run("systemd-analyze --user blame --no-pager 2>/dev/null | head -5", shell=True)
        print(self.c("2", "\nTurn one off: svc NAME, then d"))

    def disk(self):
        clean.status()
        print(self.c("2", "\nFree space: clean (caches)   deep [storage|folder] (big things)   then pick 1 3"))

    def clean(self):
        clean.clean()
        self.scan(["disk"])

    def deep(self, where=""):
        if clean.deep(where or None) == 0 and (clean.last_scan() or {}).get("items"):
            print(self.c("2", "Delete some: pick 1 3 5-7 (asks first)"))

    def pick(self, args=""):
        if not args.split():
            print("Which items? pick 1 3 5-7   (numbers from the last deep scan)")
            return
        if clean.pick(args.split(), confirm=lambda q: (self.input(q) or "").strip().lower() in ("y", "yes")) == 0:
            self.scan(["disk"])

    def malware(self):
        scanner = "/usr/local/sbin/weekly-security-scan.sh"
        if not os.path.exists(scanner):
            print("The rootkit scanner isn't set up; one of the security issues offers to set it up.")
            return
        print("Running rkhunter + chkrootkit (a few minutes, Ctrl+C stops)...")
        subprocess.run(f"{'' if self.ctx.is_root else 'sudo '}bash {scanner}", shell=True)
        self.scan(["security"])
        self.home()

    def history(self):
        self.cli.show_history()

    def logs(self, name=""):
        if name:
            u, user = self.find_unit(name)
            if u:
                subprocess.run(f"journalctl {'--user-unit' if user else '-u'} {shlex.quote(u)} -n 50 --no-pager -o short", shell=True)
            return
        for f in run_checks(self.ctx, names=["app-errors", "kernel-errors"]):
            print("\n" + self.c("1", f["title"]))
            for d in f["detail"]:
                print(f"  {d}")

    def units(self):
        if self._units is None:
            names = set()
            for flag in ("", "--user "):
                for cmd in ("list-units --type=service --all --no-legend --plain", "list-unit-files --type=service --no-legend"):
                    names |= {l.split()[0] for l in self.ctx.run(f"systemctl {flag}{cmd}").splitlines() if l.split()}
            self._units = sorted(n for n in names if "@." not in n)
        return self._units

    def find_unit(self, name):
        if not name:
            print("Which service? e.g. svc docker")
            return None, None
        full = name if name.endswith((".service", ".timer", ".socket")) else name + ".service"
        cands = [full] if full in self.units() else [u for u in self.units() if name.lower() in u.lower()]
        if len(cands) != 1:
            print(f"No service matching '{name}'." if not cands else "Several match: " + ", ".join(cands[:12]))
            return None, None
        user = bool(self.ctx.run(f"systemctl --user cat {shlex.quote(cands[0])} 2>/dev/null | head -1").strip())
        return cands[0], user

    def svc(self, name=""):
        u, user = self.find_unit(name)
        if not u:
            return
        flag, q = ("--user " if user else ""), shlex.quote(u)
        print()
        subprocess.run(f"systemctl {flag}status {q} --no-pager -n 0 | head -10", shell=True)
        subprocess.run(f"journalctl {'--user-unit' if user else '-u'} {q} -n 12 --no-pager -o short-precise | cut -c1-200", shell=True)
        while True:
            a = (self.input(self.c("1", f"\n{u}: ") + "r restart · s stop · d disable · e enable · l more log · Enter back · m menu › ") or "").strip().lower()
            verb = {"r": "restart", "s": "stop", "d": "disable --now", "e": "enable --now"}.get(a)
            if verb:
                subprocess.run(f"{'' if user or self.ctx.is_root else 'sudo '}systemctl {flag}{verb} {q}; "
                               f"echo \"now: $(systemctl {flag}is-active {q}), $(systemctl {flag}is-enabled {q} 2>/dev/null) at boot\"", shell=True)
            elif a == "l":
                subprocess.run(f"journalctl {'--user-unit' if user else '-u'} {q} -n 80 --no-pager -o short", shell=True)
            elif a in ("m", "menu"):
                return self.home()
            else:
                return

    # ---------- the prompt ----------

    def input(self, prompt):
        try:
            return input(prompt)
        except KeyboardInterrupt:
            print()
            return ""
        except EOFError:
            print()
            return None

    def complete(self, text, state):
        try:
            import readline
            line = readline.get_line_buffer()
        except ImportError:
            line = text
        words = line.split()
        arg = words and (len(words) > 1 or line.endswith(" "))
        if arg and words[0] in ("svc", "logs"):
            opts = [u.replace(".service", "") for u in self.units()]
        elif arg and words[0] == "deep":
            opts = ["system"] + sorted(os.listdir(f"/media/{self.ctx.user}")) if os.path.isdir(f"/media/{self.ctx.user}") else ["system"]
        else:
            opts = COMMANDS
        matches = [o + " " for o in opts if o.startswith(text)]
        return matches[state] if state < len(matches) else None

    def handle(self, line):
        """One line from the prompt. Returns False to quit."""
        self.at_home = False
        if line.startswith("!"):
            subprocess.run(line[1:], shell=True)
            return True
        words = line.split()
        if not words:
            self.walk()
            return True
        cmd, args = words[0].lower(), words[1:]
        if cmd.isdigit() and not args:
            n = int(cmd)
            if 1 <= n <= len(self.issues):
                self.walk(n)
            else:
                print(f"There are {len(self.issues)} issues.")
        elif cmd in ("q", "quit", "exit"):
            return False
        elif cmd in ("m", "menu", "home", "back", "b"):
            self.home()
        elif cmd in ("h", "help"):
            print(HELP)
        elif cmd in ("more", "l", "list", "ls", "ok", "all"):
            self.show(everything=cmd in ("more", "ok", "all"))
        elif cmd in ("f", "fix"):
            self.fix(self.choose(args) if args else ([self.current] if self.current else []))
        elif cmd in ("e", "explain"):
            self.explain(int(args[0]) if args and args[0].isdigit() else None)
        elif cmd in ("r", "recheck", "rescan"):
            bad = [a for a in args if a not in AREAS]
            if bad:
                print(f"Areas: {' '.join(AREAS)}")
                return True
            self.scan(args or None)
            self.home()
        elif cmd in AREAS and not args:
            self.scan([cmd])
            for f in [f for f in self.report["findings"] if f["area"] == cmd]:
                n = self.issues.index(f) + 1 if f in self.issues else ""
                print(f" {n:>3} {self.icon(f)} {f['title']}{self.tag(f)}")
                for d in f["detail"][:3]:
                    print(self.c("2", f"       {d[:140]}"))
            if cmd == "disk":
                print()
                self.disk()
        elif cmd in FOCUSED + SPACE and (args == [] or cmd in TAKES_ARGS):
            getattr(self, cmd)(*([" ".join(args)] if cmd in TAKES_ARGS else []))
        elif agent.available():
            self.ask(line)          # anything else is a question
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
            readline = hist = None
        self.scan()
        print(self.c("1", f"doctor · {self.report['host']} · {'full' if self.ctx.sudo else 'limited (no sudo)'} · {self.report['took']}s"))
        self.home()
        while True:
            line = self.input("\n" + ("" if self.at_home else self.c("2", "m menu ")) + self.c("1", "› "))
            if line is None:
                break
            try:
                if not self.handle(line.strip()):
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
