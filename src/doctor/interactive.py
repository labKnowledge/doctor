"""doctor i: opens on a main menu of everything doctor can do (arrows or a letter). The check-up leads to the issue
list, where Enter walks through the issues (fix, explain, skip); m returns to the main menu from anywhere."""
import os, re, shlex, shutil, signal, subprocess, sys, textwrap, time

from . import agent, clean, knowledge, learn, menu, probes, procs
from .health import log_errors
from .menu import Column
from .core import AREAS, CRIT, INFO, OK, RANK, SKIP, WARN, Ctx, human, run_checks
from .health import meminfo, psi

FOCUSED = ["top", "ports", "svc", "logs", "boot", "kills", "temps", "net", "disk", "malware", "history"]
SPACE = ["clean", "deep", "pick"]   # free disk space (disk_clean)
TAKES_ARGS = ("svc", "logs", "deep", "pick")
COMMANDS = ["more", "menu", "kill", "f", "e", "r", "help", "q"] + FOCUSED + SPACE + AREAS

HELP = """
  On the issue list (after a check-up):
  Enter        go through the issues one by one: fix, explain or skip each (b back, m main menu)
  m            back to the main menu
  3            open issue 3            f 3 5   fix several            f safe   every safe fix
  e 3          the assistant explains issue 3 in plain words
  o 3          learn more: a full Claude session about issue 3 opens in a new window (doctor stays here)
  a question   ask the assistant anything: "is anydesk safe?", "why is the fan loud?"
  more         show the suggestions too                              r   check again
  history      what doctor changed on this computer, and how to undo it

  Free space   clean   caches that rebuild themselves    deep [storage|folder]   big things safe to remove
               pick 1 3   delete those from the last deep scan (asks first)
  services     every service in one list: open one to restart, stop, start, disable, enable, or explain it
  top          live list of what uses memory and CPU: open one, end it (k), force it (f), explain it (?)
  kill PID     the same for one process you know the number of
  Look closer  top · ports · svc NAME · logs [NAME] · boot · kills · temps · net · disk · malware · any area name
  !command runs a shell command · Tab completes · m main menu · Ctrl+X quits from anywhere, even mid-task"""


class Leave(Exception):
    """Ctrl+X: close doctor from wherever the user is."""


class ToMenu(Exception):
    """m: back to the main menu from wherever the user is."""


# The main menu: (letter, label, what it does). Hints that depend on this computer are filled in by Session.hint().
MAIN = [
    ("Check and fix", [
        ("c", "Check-up", "find what's wrong and fix it, one issue at a time"),
        ("l", "Last results", ""),
        ("a", "Ask the assistant", "any question about this computer, in plain words"),
        ("o", "Learn with Claude", "a full session in a new window, holding this computer's last check-up"),
    ]),
    ("Disk space", [
        ("f", "Free up space", "clear caches that rebuild themselves, safe"),
        ("b", "Big files and folders", "find what's safe to delete on a drive"),
    ]),
    ("Manage", [
        ("s", "Services", "start, stop, turn off at boot"),
        ("h", "History", "what doctor changed, and how to undo it"),
    ]),
    ("Look closer", [
        ("t", "Top apps", "what uses memory and CPU now · end what's stuck"),
        ("p", "Ports", "what listens, and who can reach it"),
        ("n", "Network", "router, internet and DNS speed"),
        ("e", "Temperatures", "sensors and fans"),
        ("u", "Startup", "what makes boot slow"),
        ("k", "App kills", "apps closed for low memory, last 30 days"),
        ("g", "Logs", "errors in the last 24 hours"),
        ("r", "Rootkit scan", "rkhunter + chkrootkit, a few minutes"),
    ]),
]


def ctrl_x_closes():
    """Make Ctrl+X close doctor at any prompt, even mid-task: while doctor runs, the terminal sends the quit signal
    for Ctrl+X (readline can't bind it, it's a prefix key). Returns a function that puts the terminal back."""
    try:
        import termios
        fd = sys.stdin.fileno()
        before = termios.tcgetattr(fd)
        mine = termios.tcgetattr(fd)
        mine[6][termios.VQUIT] = b"\x18"
        termios.tcsetattr(fd, termios.TCSANOW, mine)
    except Exception:  # no terminal (a pipe) or no termios: q still quits
        return lambda: None

    def leave(*_):
        raise Leave()
    previous = signal.signal(signal.SIGQUIT, leave)

    def restore():
        signal.signal(signal.SIGQUIT, previous)
        try:
            termios.tcsetattr(fd, termios.TCSANOW, before)
        except termios.error:
            pass
    return restore


def ago(t):
    """Seconds -> '5 min', '3h', '2 days'."""
    t = max(t if t < 1e9 else time.time() - t, 0)
    return f"{int(t // 60)} min" if t < 3600 else f"{int(t // 3600)}h" if t < 172800 else f"{int(t // 86400)} days"


class Session:
    def __init__(self, ctx, cli, no_sudo=False):
        self.ctx, self.cli, self.c = ctx, cli, cli.c   # cli = the cli module: scan, render colours, apply_fixes
        self.report, self.issues, self.oks = None, [], []
        self.done = set()          # titles handled in this session (fixed or skipped)
        self.current = None
        self._units = None
        self.mode = "interactive"    # how the assistant tells the user to apply a fix
        self.at_home = False         # the issue list is on screen; elsewhere the prompt offers m
        self.no_sudo = no_sudo
        self.glance = None

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

    # ---------- the main menu ----------

    def hint(self, key, default):
        g, last = self.glance or {}, self.cli.load_last()
        if key == "l":
            if not last:
                return "none yet"
            n = sum(f["level"] in (CRIT, WARN) for f in last["findings"])
            return f"{n} to look at, from {ago(last['time'])} ago" if n else f"all fine, {ago(last['time'])} ago"
        if key == "s" and g.get("failed"):
            return f"{g['failed']} failing · start, stop, turn off at boot"
        if key == "f":
            full = [n for n, pct in g.get("drives", []) if pct >= 90]
            return f"{', '.join(full)} {'is' if len(full) == 1 else 'are'} 90%+ full · {default}" if full else default
        return default

    def entries(self):
        hide = {"l"} if not self.cli.load_last() else set()
        hide |= {"a"} if not agent.available() else set()
        hide |= {"o"} if not learn.available() else set()
        return [(title, [e for e in items if e[0] not in hide]) for title, items in MAIN]

    def render_main(self, sel):
        k, d = (lambda t: self.c("1", t)), (lambda t: self.c("2", t))
        g = self.glance
        drives = "  ".join(self.c("33" if pct >= 90 else "0", f"{name} {pct}%") for name, pct in g["drives"])
        lines = [k("doctor") + d(f" · {self.ctx.user}@{os.uname().nodename} · up {ago(g['uptime'])} · ")
                 + f"RAM {human(g['ram_used'])} of {human(g['ram_total'])}" + d("  ·  disks ") + drives, ""]
        i = 0
        for title, items in self.entries():
            lines.append(d(title))
            for key, label, hint in items:
                mark = self.c("36;1", "›") if i == sel else " "
                text = self.c("7", f" {label:<22}") if i == sel else f" {label:<22}"
                lines.append(f"  {mark} {k(key)} {text} {d(self.hint(key, hint))}")
                i += 1
            lines.append("")
        lines.append(d("  ↑↓ move · Enter open · or press its letter · : type a command · q quit (Ctrl+X anywhere)" if sel >= 0
                       else "  type a letter and Enter · : type a command · q quit (Ctrl+X anywhere)"))
        return lines

    def main_menu(self):
        """Show everything doctor can do; run the chosen one; come back here. Returns when the user quits."""
        sel = 0
        while True:
            self.glance = probes.glance(self.ctx)
            flat = [e for _, items in self.entries() for e in items]
            print()
            key = menu.choose(flat, self.render_main, extra_keys=(":", "/", "?"), start=sel)
            if key == menu.QUIT:
                return
            if key == menu.BACK:
                continue
            sel = next((i for i, e in enumerate(flat) if e[0] == key), sel)
            try:
                if self.open(key) == menu.QUIT:
                    return
            except ToMenu:
                pass
            except KeyboardInterrupt:
                print("\nStopped.")

    def open(self, key):
        """Run one main-menu entry. Screens that only show something wait for a key before the menu comes back."""
        if key == "c":
            return self.checkup()
        if key == "l":
            self.report = self.cli.load_last()
            self._number()
            return self.results()
        if key in (":", "/", "?"):
            if key == "?":
                print(HELP)
            return self.results(prompt_only=True)
        if key == "s":
            return self.services()
        if key == "b":
            return self.big_files()
        screens = {"t": self.top_live, "p": self.look_ports, "n": self.look_net, "e": self.look_temps,
                   "u": self.look_boot, "k": self.look_kills, "g": self.look_logs}
        if key in screens:
            return screens[key]()
        if key == "o":
            report = self.report or self.cli.load_last()
            facts = agent.condensed({"findings": report["findings"]}) if report else "No check-up has run yet."
            return self.learn("this computer's health and how to keep it running well", facts) or None
        if key == "a":
            q = (self.input(self.c("1", "\nAsk › ")) or "").strip()
            if not q:
                return
            self.ask(q)
        elif {"f": self.clean, "h": self.history, "r": self.malware}[key]() == "quiet":
            return   # nothing was shown (declined): no need to wait for a key
        return menu.pause(self.c)

    def checkup(self):
        if not self.ctx.sudo and not self.no_sudo and sys.stdin.isatty() and self.may_sudo("The full check-up"):
            print(self.c("2", "\nSome checks need sudo (firewall, open ports, accounts, drive health). "
                              "Enter your password, or press Ctrl+C to skip them."))
            try:
                self.ctx.sudo = subprocess.run(["sudo", "-v"]).returncode == 0
            except KeyboardInterrupt:
                print()
        self.scan()
        print(self.c("1", f"\nCheck-up · {'full' if self.ctx.sudo else 'limited (no sudo)'} · {self.report['took']}s"))
        return self.results()

    def results(self, prompt_only=False):
        """The issue list and its prompt: Enter walks the issues, commands and questions work too. m goes back."""
        if not prompt_only:
            self.show()
        elif not self.report:
            self.report = self.cli.load_last()
            if self.report:
                self._number()
            print(self.c("2", "Type a command (help lists them), or m for the main menu."))
        while True:
            line = self.input("\n" + ("" if self.at_home else self.c("2", "m menu ")) + self.c("1", "› "))
            if line is None:
                return menu.QUIT
            try:
                if not self.handle(line.strip()):
                    return menu.QUIT
            except KeyboardInterrupt:
                print("\nStopped.")

    def big_files(self):
        """Pick a drive (or a folder), list what's big and safe to delete there, then delete by number."""
        drives = [("1" if n == "/" else str(i + 1), n, pct) for i, (n, pct) in enumerate(self.glance["drives"])]
        opts = [(key, "System drive" if n == "/" else n, f"{pct}% full") for key, n, pct in drives]
        opts.append(("o", "Another folder", "type its path"))

        def render(sel):
            lines = [self.c("1", "\nWhere should I look?") + self.c("2", "  a whole data drive can take 10-15 minutes"), ""]
            for i, (key, label, hint) in enumerate(opts):
                mark = self.c("36;1", "›") if i == sel else " "
                lines.append(f"  {mark} {self.c('1', key)} {self.c('7', f' {label:<16}') if i == sel else f' {label:<16}'} {self.c('2', hint)}")
            lines += ["", self.c("2", "  ↑↓ move · Enter look · Esc back" if sel >= 0 else "  type its number and Enter · Enter alone goes back")]
            return lines
        key = menu.choose(opts, render)
        if key in (menu.BACK, menu.QUIT):
            return
        if key == "o":
            where = (self.input("Folder › ") or "").strip()
            if not where:
                return
        else:
            name = next(n for k, n, _ in drives if k == key)
            where = None if name == "/" else name
        if clean.deep(where) != 0 or not (clean.last_scan() or {}).get("items"):
            return menu.pause(self.c)
        nums = (self.input(self.c("1", "\nDelete which? ") + self.c("2", "numbers like 1 3 5-7, Enter to keep everything › ")) or "").strip()
        if nums:
            self.pick(nums)
        return menu.pause(self.c)

    def menu(self):
        """The keys of the issue list, under it."""
        self.at_home = True
        left = sum(f["title"] not in self.done for f in self.issues)
        safe = sum(bool(f.get("fix")) and f["fix"]["safe"] and f["title"] not in self.done for f in self.issues)
        k, d = (lambda t: self.c("1", t)), (lambda t: self.c("2", t))
        print()
        if left:
            print(f"  {k('Enter')} {d('go through them')}   {k('3')} {d('open issue 3')}   "
                  + (f"{k('f safe')} {d(f'apply the {safe} safe fixes')}   " if safe else "") + f"{k('more')} {d('suggestions too')}")
        ask = f"   {d('or ask a question')}" if agent.available() else ""
        print(f"  {k('r')} {d('check again')}   {k('m')} {d('main menu')}   {k('help')} {d('all commands')}{ask}")

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
                keys = ("Enter fix it" if f.get("fix") else "Enter next") + " · e explain" + (" · o learn more" if learn.available() else "") + " · s skip · b back · q list · m menu"
                if agent.available():
                    keys += " · or ask about it"
                a = self.input(self.c("2", f"    {keys} › "))
                if a is None or a.strip().lower() in ("m", "menu", "home"):
                    self.summary(fixed, skipped, stopped=True)
                    raise ToMenu()
                if a.strip().lower() in ("q", "stop", "l", "list"):
                    self.summary(fixed, skipped, stopped=True)
                    return self.show()
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
                elif a.lower() in ("o", "learn"):
                    self.learn_issue(n)
                elif a.isdigit():
                    return self.walk(int(a))
                elif agent.available():
                    self.ask(f"About issue {n} ({f['title']}): {a}")
                else:
                    print("    Enter, e, s, b, q (issue list) or m (main menu).")
        self.summary(fixed, skipped)
        self.show()

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

    def learn_issue(self, n):
        f = self.issues[n - 1]
        fx = f.get("fix")
        facts = (f"Issue: ({f['level']}, {f['area']}) {f['title']}\n" + "\n".join(f"  {d}" for d in f["detail"])
                 + (f"\ndoctor offers a fix: {fx['label']} ({'safe' if fx['safe'] else 'review first'}); it runs:\n"
                    + "\n".join(f"  $ {l}" for l in fx["cmd"].splitlines()) if fx else "\nNo automatic fix is offered."))
        self.learn(f["title"], facts)

    def ask(self, question):
        if not self.report:
            self.report = self.cli.load_last() or {"findings": []}
            self._number()
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
        print(self.c("2", "\nEnd one: doctor i, then t"))

    # ---------- top apps, live: pick one, see what it is, end it ----------

    def process_card(self, pid):
        """One process: what it is and what it belongs to, then end it, force it, end its whole app, or ask about it."""
        while True:
            d = procs.detail(pid)
            if not d:
                print("It has already closed.")
                return
            k, dim = (lambda t: self.c("1", t)), (lambda t: self.c("2", t))
            kind = "app" if d["unit"].endswith(".scope") else "service" if d["unit"].endswith(".service") else "group"
            print("\n" + k(d["name"]) + dim(f"  PID {d['pid']} · {human(d['rss'])} · {d['threads']} threads · {d['state']}"))
            if d["unit"]:
                print(f"  part of   {d['app']}" + dim(f"  ({kind}: {d['unit']}, {d['group']} process{'es' if d['group'] != 1 else ''})"))
            print(f"  started by {d['parent'] or '-'}" + dim(f" (PID {d['ppid']})"))
            print(dim(f"  command   {d['cmd'][:300]}"))
            if d["warning"]:
                print(self.c("33", f"  ! Careful: {d['warning']}."))
            whole = ""
            if d["unit"] and d["group"] > 1 and kind == "app" and not d["has_doctor"]:
                whole = f" · a end the whole app ({d['group']} processes)"
            elif kind == "service":
                whole = f" · a stop the service {d['unit'].replace('.service', '')}"
            ask = (" · ? explain" if agent.available() else "") + (" · o learn more" if learn.available() else "")
            a = menu.key(dim(f"\n  k end it · f force it{whole}{ask} · Enter back › "))
            if a in ("k", "f"):
                self.end_process(d, force=a == "f")
                if not procs.detail(pid):
                    return
            elif a == "a" and whole:
                if self.confirm(f"{'Stop' if kind == 'service' else 'End'} all of {d['app']}?") and \
                        (d["user_unit"] or self.may_sudo(f"Stopping {d['unit']}")):
                    code = procs.end_group(d["unit"], d["user_unit"])
                    print(self.c("32", "  Done.") if code == 0 else self.c("31", "  It didn't stop (see above)."))
                    return
            elif a == "?":
                self._agent(agent.process_prompt(d, mode=self.mode))
            elif a == "o":
                self.learn(f"the process {d['name']} (PID {d['pid']})",
                           "\n".join(f"{k}: {v}" for k, v in d.items() if k not in ("has_doctor",)))
            elif a in (menu.QUIT, "m"):
                raise ToMenu()
            else:
                return

    def end_process(self, d, force=False):
        """End (or force) one process, explaining each outcome in plain words."""
        if d["pid"] == 1 or d["pid"] in (os.getpid(), os.getppid()):
            print(self.c("33", f"  Not ending it: {d['warning']}."))
            return
        if d["warning"]:
            print(self.c("33", f"  Careful: {d['warning']}."))
        verb = "Force-close" if force else "End"
        if not self.confirm(f"{verb} {d['name']} (PID {d['pid']}){', unsaved work in it is lost' if force else ''}?"):
            return
        result = procs.end(d["pid"], force)
        if result == "needs sudo":
            if not self.may_sudo(f"Ending {d['name']}") or not self.confirm(f"{d['name']} isn't yours (it runs as {'root' if d['uid'] == 0 else 'another user'}). Use sudo?"):
                return
            result = procs.end_as_root(d["pid"], force)
        if result == "still running" and not force:
            print(self.c("33", "  It's still running 3 seconds later (busy, or ignoring the request)."))
            if self.confirm("Force it closed? Unsaved work in it is lost."):
                result = procs.end(d["pid"], True) if d["uid"] == os.getuid() else \
                    procs.end_as_root(d["pid"], True) if self.may_sudo(f"Ending {d['name']}") else "not ended"
        print({"ended": self.c("32", f"  ✓ {d['name']} ended."), "gone": "  It had already closed.",
               "still running": self.c("31", "  It's still running."), "not ended": self.c("31", "  Not ended (sudo refused).")}
              .get(result, result))
        if result == "ended" and d["unit"].endswith(".service"):
            print(self.c("2", f"  It belongs to {d['unit']}, which may start it again. To stop it for good: s, then find the service."))

    def confirm(self, question):
        return menu.key(f"  {question} " + self.c("2", "y/N › "), flush=True) in ("y", "Y")

    def learn(self, topic, facts):
        """o: open a Claude Code session about `topic` in a new terminal window, holding `facts`; doctor stays here."""
        if not learn.available():
            print("Learning sessions need Claude Code (the `claude` command).")
            return
        script = learn.prepare(self.cli.state_dir(), topic, facts,
                               "If something needs fixing, doctor can do it: tell me which doctor screen or fix to use.")
        where = learn.open_window(script, "Learn: " + topic)
        if where:
            print(self.c("36", f"  ↗ Opened a Claude session in a new {where} window: ") + topic[:70]
                  + self.c("2", "  (doctor stays here)"))
            return
        if not self.confirm("No new window can open here (no desktop). Start the session in this terminal? doctor waits"):
            return
        self.in_plain_terminal(["bash", script])

    def in_plain_terminal(self, argv):
        """Run a full-screen program here with the terminal's normal keys (Ctrl+X is doctor's only while doctor reads)."""
        try:
            import termios
            fd = sys.stdin.fileno()
            mine = termios.tcgetattr(fd)
            plain = termios.tcgetattr(fd)
            plain[6][termios.VQUIT] = b"\x1c"
            termios.tcsetattr(fd, termios.TCSANOW, plain)
        except Exception:
            mine = None
        try:
            subprocess.run(argv)
        finally:
            if mine:
                termios.tcsetattr(fd, termios.TCSANOW, mine)

    def may_sudo(self, what):
        """Right before anything that can ask for the sudo password: honour --no-sudo, and drop keys typed ahead
        so they can never become password attempts."""
        if self.ctx.is_root:
            return True
        if self.no_sudo:
            print(self.c("33", f"  {what} needs sudo, and doctor was started with --no-sudo."))
            return False
        menu.flush_input()
        return True

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
        print(self.c("2", "\nTurn one off: services, then its number"))

    def disk(self):
        clean.status()
        print(self.c("2", "\nFree space: clean (caches)   deep [storage|folder] (big things)   then pick 1 3"))

    def clean(self):
        clean.clean()
        if self.report:
            self.scan(["disk"])

    def deep(self, where=""):
        if clean.deep(where or None) == 0 and (clean.last_scan() or {}).get("items"):
            print(self.c("2", "Delete some: pick 1 3 5-7 (asks first)"))

    def pick(self, args=""):
        if not args.split():
            print("Which items? pick 1 3 5-7   (numbers from the last deep scan)")
            return
        if clean.pick(args.split(), confirm=lambda q: (self.input(q) or "").strip().lower() in ("y", "yes")) == 0 and self.report:
            self.scan(["disk"])

    def malware(self):
        scanner = "/usr/local/sbin/weekly-security-scan.sh"
        if not os.path.exists(scanner):
            print("The rootkit scanner isn't set up; one of the security issues offers to set it up.")
            return
        if not self.confirm("The rootkit scan takes a few minutes and needs sudo. Start it?"):
            return "quiet"
        if not self.may_sudo("The rootkit scan"):
            return
        print("Running rkhunter + chkrootkit (a few minutes, Ctrl+C stops)...")
        subprocess.run(f"{'' if self.ctx.is_root else 'sudo '}bash {scanner}", shell=True)
        self.scan(["security"])
        print(self.c("1", "\nSecurity now"))
        for f in [f for f in self.report["findings"] if f["area"] == "security" and f["level"] in (CRIT, WARN)][:8]:
            print(f"  {self.icon(f)} {f['title']}")

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
        """svc NAME opens one service; svc alone (or `services`) manages them all."""
        if not name:
            return self.services()
        u, user = self.find_unit(name)
        if u:
            return self.manage(u, user)

    def manage(self, u, user):
        """One service: status and recent log, then act on it. Returns "menu" when the user asked for the menu."""
        flag, q = ("--user " if user else ""), shlex.quote(u)
        unit_log = f"journalctl {'--user-unit' if user else '-u'} {q} --no-pager"
        print()
        subprocess.run(f"systemctl {flag}status {q} --no-pager -n 0 | head -10", shell=True)
        subprocess.run(f"{unit_log} -n 12 -o short-precise | cut -c1-200", shell=True)
        ask = (" · ? explain, or ask about it" if agent.available() else "") + (" · o learn more" if learn.available() else "")
        while True:
            raw = (self.input(self.c("1", f"\n{u}: ") + "r restart · s stop · t start · d disable · e enable · l more log"
                              + ask + " · Enter back · m menu › ") or "").strip()
            a = raw.lower()
            if a in ("o", "learn"):
                self.learn(f"the {u} service", f"{'User' if user else 'System'} service {u}.\nStatus:\n"
                           + self.ctx.run(f"systemctl {flag}status {q} --no-pager -n 0 | head -15")
                           + "\nRecent log:\n" + self.ctx.run(f"{unit_log} -n 30 -o short"))
                continue
            if a in ("?", "x", "explain") or (len(raw) > 2 and agent.available() and a not in ("log", "menu", "back")):
                status = self.ctx.run(f"systemctl {flag}status {q} --no-pager -n 0 | head -15")
                log = self.ctx.run(f"{unit_log} -n 40 -o short")
                self._agent(agent.service_prompt(u, user, status, log, None if len(raw) <= 2 or a == "explain" else raw, self.mode))
                continue
            verb = {"r": "restart", "s": "stop", "t": "start", "d": "disable --now", "e": "enable --now"}.get(a)
            if verb and not user and not self.may_sudo(f"Changing {u}"):
                continue
            if verb:
                subprocess.run(f"{'' if user or self.ctx.is_root else 'sudo '}systemctl {flag}{verb} {q}; "
                               f"echo \"now: $(systemctl {flag}is-active {q}), $(systemctl {flag}is-enabled {q} 2>/dev/null) at boot\"", shell=True)
                self._units = None
            elif a == "l":
                subprocess.run(f"{unit_log} -n 80 -o short", shell=True)
            elif a in ("m", "menu"):
                raise ToMenu()
            else:
                return

    # ---------- look closer: every screen is a list you can move through; the selected row explains itself ----------

    def look(self, title, about, load, columns, **kw):
        """Show a list screen; m inside it (or in anything it opens) goes to the main menu."""
        row_text = lambda r: "  ".join(f"{c.header}: {c.cell(r).strip()}" for c in columns)
        kw.setdefault("explain", (lambda r: self._agent(agent.row_prompt(title, about, row_text(r),
                                                                         kw["note"](r) if kw.get("note") else "", self.mode)))
                      if agent.available() else None)
        topic = lambda r: f"{title}: " + " ".join(c.cell(r).strip() for c in columns[:3] if c.cell(r).strip())
        kw.setdefault("learn", (lambda r: self.learn(topic(r), f"Screen: {title} ({about})\nRow: {row_text(r)}\n"
                                                      + (f"doctor's note: {kw['note'](r)}" if kw.get("note") else "")))
                      if learn.available() else None)
        if menu.browse(self.c, title, about, load, columns, **kw) == "menu":
            raise ToMenu()

    def top_live(self):
        st = {"sort": "mem"}

        def sort(_):
            st["sort"] = "cpu" if st["sort"] == "mem" else "mem"
            return "quiet"

        def note(r):
            warn = procs.risk(r["pid"], r["name"])
            return (f"{r['name']} ({'part of ' + r['app'] if r['app'] else 'on its own'}) uses {human(r['rss'])} of memory and "
                    f"{r['cpu']:.1f}% CPU, running for {r['running']}." + (f" Careful: {warn}." if warn else " Enter for details, k ends it."))
        self.look("Top apps", "biggest first, live every 2s", lambda: procs.processes(self.ctx, st["sort"], 40), [
            Column("NAME", 20, lambda r: r["name"]), Column("APP", 18, lambda r: r["app"]),
            Column("PID", 7, lambda r: r["pid"], True), Column("CPU%", 5, lambda r: f"{r['cpu']:.1f}", True),
            Column("RAM", 6, lambda r: human(r["rss"]), True), Column("RUNNING", 11, lambda r: r["running"]),
            Column("OWNER", 10, lambda r: "" if r["mine"] else r["user"])],
            note=note, enter=("details", lambda r: self.process_card(r["pid"]) or "quiet"),
            actions=[("k", "end it", self._end_row), ("s", "sort by memory/CPU", sort)], refresh=2.0,
            explain=(lambda r: self._agent(agent.process_prompt(procs.detail(r["pid"]) or {}, mode=self.mode))
                     if procs.detail(r["pid"]) else print("It has already closed.")) if agent.available() else None)

    def _end_row(self, r):
        d = procs.detail(r["pid"])
        if not d:
            print("It has already closed.")
            return
        self.end_process(d)

    def look_ports(self):
        def pid_of(r):
            m = re.search(r"\((\d+)\)", r[3])
            return int(m.group(1)) if m else None

        def details(r):
            if not pid_of(r):
                print("Which program this is needs sudo to see. Run doctor's check-up with sudo, or: sudo ss -tulnp")
                return
            return self.process_card(pid_of(r)) or "quiet"

        def end(r):
            return self._end_row({"pid": pid_of(r)}) if pid_of(r) else print("Which program this is needs sudo to see.")
        self.look("Ports", "programs waiting for connections, and who can reach them", lambda: probes.listeners(self.ctx)[0], [
            Column("PORT", 6, lambda r: r[2], True), Column("PROTO", 5, lambda r: r[1]),
            Column("REACHABLE FROM", 14, lambda r: "the network" if r[0] else "this computer"),
            Column("PROGRAM", 34, lambda r: r[3])],
            note=lambda r: knowledge.port(*r), enter=("program details", details), actions=[("k", "end the program", end)],
            empty="Nothing is waiting for connections.")

    def look_net(self):
        cache = {}

        def load():
            if not cache or cache.get("stale"):
                d = probes.network(self.ctx)
                rows = [{"label": "connection", "value": f"{d['dev'] or 'none'}" + (f" via {d['gateway']}" if d["gateway"] else ""),
                         "note": "The network this computer uses right now." if d["dev"] else "No connection at all."}]
                if d["wifi"]:
                    rows.append({"label": "Wi-Fi", "value": f"{d['wifi'][0]}, signal {d['wifi'][1]}%",
                                 "note": "Under 50% signal makes everything slower and flakier; move closer to the router."})
                rows += [{"label": l, "value": f"{ms:.0f} ms" + (f", {loss}% lost" if loss else "") if ms is not None else "FAILED",
                          "note": knowledge.network(l, ms, loss)} for l, ms, loss in d["checks"]]
                cache.clear()
                cache["rows"] = rows
            return cache["rows"]

        def again(_):
            cache["stale"] = True
            return "quiet"
        print(self.c("2", "Measuring the connection..."), flush=True)
        self.look("Network", "each step from this computer to the internet", load,
                  [Column("STEP", 20, lambda r: r["label"]), Column("RESULT", 40, lambda r: r["value"])],
                  note=lambda r: r["note"], actions=[("t", "test again", again)])

    def look_temps(self):
        self.look("Temperatures", "sensors and fans, live every 3s", lambda: probes.sensors(self.ctx), [
            Column("PART", 14, lambda r: r[0]), Column("SENSOR", 24, lambda r: r[1]), Column("NOW", 40, lambda r: r[2])],
            note=lambda r: knowledge.sensor(*r), refresh=3.0, empty="No sensors found (in a VM, or the drivers aren't loaded).")

    def look_boot(self):
        total = self.ctx.run("systemd-analyze 2>/dev/null | head -1").strip().replace("Startup finished in ", "")
        self.look("Startup", f"slowest at the last startup ({total or 'time unknown'})", lambda: probes.boot_times(self.ctx), [
            Column("TOOK", 7, lambda r: f"{r[0]:.1f}s", True), Column("SERVICE", 44, lambda r: r[1]),
            Column("WHOSE", 6, lambda r: "you" if r[2] else "system")],
            note=lambda r: knowledge.boot(*r), enter=("open the service", lambda r: self.manage(r[1], r[2]) or "quiet"))

    def look_kills(self):
        self.look("App kills", "apps closed for low memory, last 30 days", lambda: probes.memory_kills(self.ctx), [
            Column("WHEN", 16, lambda r: r[0]), Column("APP", 28, lambda r: r[1]), Column("WHY", 24, lambda r: r[2])],
            note=lambda r: knowledge.kill(*r), empty="No apps were closed for low memory in the last 30 days. Good.")

    def look_logs(self):
        def full(g):
            sel = (f"{'--user-unit' if g['user_unit'] else '-u'} {shlex.quote(g['unit'])}" if g["unit"]
                   else f"-t {shlex.quote(g['ident'])}")
            subprocess.run(f"journalctl {sel} -p err --since '24 hours ago' -n 30 --no-pager -o short | cut -c1-220", shell=True)

        def service(g):
            if not g["unit"].endswith(".service"):
                print("This message doesn't come from a service.")
                return
            return self.manage(g["unit"], g["user_unit"]) or "quiet"
        self.look("Logs", "errors in the last 24 hours, most frequent first", lambda: log_errors(self.ctx), [
            Column("TIMES", 6, lambda g: g["count"], True), Column("FROM", 22, lambda g: g["app"]),
            Column("LAST", 5, lambda g: time.strftime("%H:%M", time.localtime(g["last"])) if g["last"] else ""),
            Column("MESSAGE", 70, lambda g: g["sample"])],
            note=knowledge.log, enter=("its log", full), actions=[("s", "open its service", service)],
            empty="No error messages in the last 24 hours.")

    def services(self):
        """Every service in one list: problems first, then what runs (biggest first)."""
        st = {"all": False, "who": None}

        def load():
            rows = probes.all_services(self.ctx)
            if st["who"] is not None:
                rows = [r for r in rows if r["user"] == st["who"]]
            bad = lambda r: r["active"] == "failed" or r["sub"] == "auto-restart"
            run = lambda r: r["sub"] == "running"
            order = sorted(rows, key=lambda r: (0 if bad(r) else 1 if run(r) else 2, -r["mem"], r["unit"]))
            return [r for r in order if st["all"] or bad(r) or run(r)]

        def note(r):
            state = ("It has failed or keeps restarting: Enter shows why, ? explains it" if r["active"] == "failed" or r["sub"] == "auto-restart"
                     else "Running now" if r["sub"] == "running" else "Not running")
            boot = {"enabled": "starts at boot", "disabled": "doesn't start at boot", "static": "starts when something needs it"}.get(r["boot"], r["boot"])
            return f"{r['desc'] or r['unit']}. {state}; {boot}. Enter opens it: restart, stop, start, turn off, explain."

        def toggle(_):
            st["all"] = not st["all"]
            return "quiet"

        def whose(_):
            st["who"] = {None: True, True: False, False: None}[st["who"]]
            return "quiet"
        self.look("Services", "problems first, then what runs, biggest first", load, [
            Column(" ", 1, lambda r: "✗" if r["active"] == "failed" or r["sub"] == "auto-restart" else "●" if r["sub"] == "running" else "○"),
            Column("SERVICE", 32, lambda r: r["unit"].replace(".service", "")), Column("WHOSE", 6, lambda r: "you" if r["user"] else "system"),
            Column("RAM", 6, lambda r: human(r["mem"]) if r["mem"] else "", True),
            Column("AT BOOT", 9, lambda r: {"enabled": "starts", "disabled": "off", "static": "on demand"}.get(r["boot"], r["boot"])),
            Column("WHAT IT IS", 44, lambda r: r["desc"])],
            note=note, enter=("open", lambda r: self.manage(r["unit"], r["user"]) or "quiet"),
            actions=[("a", "show all / running", toggle), ("w", "yours / system / both", whose)])

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
            if not self.report:
                print("No check-up yet: m for the main menu, then c.")
                return True
            self.walk()
            return True
        cmd, args = words[0].lower(), words[1:]
        if cmd.isdigit() and not args:
            n = int(cmd)
            if 1 <= n <= len(self.issues):
                self.walk(n)
            else:
                print(f"There are {len(self.issues)} issues.")
        elif cmd in ("quit", "exit"):
            return False
        elif cmd in ("q", "m", "menu", "home", "back", "b"):  # q goes up one level; from the main menu it quits
            raise ToMenu()
        elif cmd in ("h", "help"):
            print(HELP)
        elif cmd in ("more", "l", "list", "ls", "ok", "all"):
            self.show(everything=cmd in ("more", "ok", "all"))
        elif cmd in ("f", "fix"):
            self.fix(self.choose(args) if args else ([self.current] if self.current else []))
        elif cmd in ("o", "learn"):
            n = int(args[0]) if args and args[0].isdigit() else (self.issues.index(self.current) + 1 if self.current in self.issues else 0)
            if 1 <= n <= len(self.issues):
                self.learn_issue(n)
            else:
                print("Which one? o 3")
        elif cmd in ("e", "explain"):
            self.explain(int(args[0]) if args and args[0].isdigit() else None)
        elif cmd in ("r", "recheck", "rescan"):
            bad = [a for a in args if a not in AREAS]
            if bad:
                print(f"Areas: {' '.join(AREAS)}")
                return True
            self.scan(args or None)
            self.show()
        elif cmd in ("services", "service", "svcs") and not args:
            self.services()        # the area of the same name is re-checked with: r services
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
        elif cmd in ("top", "kill", "ports", "net", "temps", "boot", "kills", "logs") and not args and menu.can_redraw(12):
            {"top": self.top_live, "kill": self.top_live, "ports": self.look_ports, "net": self.look_net, "temps": self.look_temps,
             "boot": self.look_boot, "kills": self.look_kills, "logs": self.look_logs}[cmd]()
        elif cmd == "kill" and args and args[0].isdigit():
            self.process_card(int(args[0]))
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
        restore = ctrl_x_closes()
        try:
            self.main_menu()
        except Leave:
            print(self.c("2", "\nClosed (Ctrl+X)."))
        finally:
            restore()
        if readline and hist:
            try:
                readline.set_history_length(500)
                readline.write_history_file(hist)
            except OSError:
                pass
        return 0
