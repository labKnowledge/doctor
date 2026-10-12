"""Command line: doctor [area ...] | fix [n ...|all] | i | ask | clean | deep [where] | pick N | malware | last."""
import json, os, re, socket, subprocess, sys, tempfile, time

from . import health, review, security, vulns  # noqa: F401  (registers the checks)
from .core import AREAS, CHECKS, CRIT, INFO, OK, SKIP, WARN, Ctx, run_checks

USAGE = """doctor — find out what's wrong with this computer and fix it

  doctor               full check-up: crashes, memory, disks, hardware, services, logs, updates, security
  doctor fix           apply the safe fixes from the last check (asks for sudo once)
  doctor fix 2 4       apply specific fixes by number (also the ones marked "review"); "doctor 2 4" works too
  doctor i             interactive: a menu of everything doctor does (check-up, space, services, ...)
  doctor ask "..."     ask the assistant about this computer (uses the last report; read-only)

  Free disk space
  doctor clean         clear caches that rebuild themselves (safe, no questions)
  doctor deep [where]  list big things that are safe to remove; where = system (default), storage, a folder
  doctor pick 1 3 5-7  delete those items from the last deep scan

  doctor vulns         vulnerabilities that can actually hurt this computer, and what fixes them
  doctor guard on      stop API keys, passwords and private keys from being committed, in every git repository
                       level: doctor guard relaxed|normal|strict (add --here for this repository only) · off
  Look closer: top ports kills temps net boot logs [NAME] history · last (the last report again)
  doctor malware       check-up plus a full rootkit/malware scan (a few minutes)
  doctor memory disk   check only some areas: """ + " ".join(AREAS) + """

  Options: --json (machine-readable)  --no-sudo (skip root checks)  -y (no confirmation)
  The old names still work: system-check, disk-clean, deep, pick.
"""


ICON = {CRIT: "✗", WARN: "!", INFO: "i", OK: "✓", SKIP: "-"}
COLOR = {CRIT: "31", WARN: "33", INFO: "36", OK: "32", SKIP: "2"}
TTY = sys.stdout.isatty()


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if TTY else s


def state_dir():
    d = os.environ.get("DOCTOR_DATA") or os.path.join(Ctx().home, ".local/state/doctor")
    os.makedirs(os.path.join(d, "reports"), mode=0o700, exist_ok=True)
    return d


def get_sudo(no_sudo):
    """Ask for the sudo password once so root-only checks run; Ctrl+C skips them."""
    ctx = Ctx(use_sudo=not no_sudo)
    if ctx.sudo or no_sudo or not sys.stdin.isatty():
        return ctx
    print(c("2", "Some checks need sudo (firewall, open ports, accounts, drive health). "
                 "Enter your password, or press Ctrl+C to skip them."), file=sys.stderr)
    try:
        ok = subprocess.run(["sudo", "-v"]).returncode == 0
    except KeyboardInterrupt:
        ok = False
        print(file=sys.stderr)
    ctx.sudo = ok
    return ctx


def scan(ctx, areas=None, quiet=False):
    t = time.time()
    if not quiet and TTY:
        print(c("2", f"Checking {len([x for x in CHECKS if not areas or x[0] in areas])} things..."), end="\r", file=sys.stderr, flush=True)
    findings = run_checks(ctx, areas)
    n = 0
    for f in findings:
        if f.get("fix"):
            n += 1
            f["fix"]["n"] = n
    report = {"time": time.time(), "took": round(time.time() - t, 1), "host": socket.gethostname(),
              "sudo": ctx.sudo, "areas": areas or AREAS, "findings": findings}
    with open(os.path.join(state_dir(), "last.json"), "w") as fh:
        json.dump(report, fh)
    return report


def render(report, verbose=False):
    out = []
    when = time.strftime("%a %b %d %H:%M", time.localtime(report["time"]))
    mode = "full" if report["sudo"] else "limited (no sudo: some checks skipped)"
    out.append(c("1", f"doctor · {report['host']} · {when} · {mode} · {report['took']}s"))
    area = None
    for f in report["findings"]:
        if f["area"] != area:
            area = f["area"]
            out.append("\n" + c("1", area.upper()))
        tag = f"  [fix {f['fix']['n']}]" if f.get("fix") else ""
        out.append(f"  {c(COLOR[f['level']], ICON[f['level']])} {f['title']}{c('1', tag)}")
        if f["level"] in (CRIT, WARN, INFO) or verbose:
            out += [c("2", f"      {d if len(d) <= 150 or verbose else d[:147] + '...'}") for d in f["detail"]]
    fs = report["findings"]
    count = {lvl: sum(f["level"] == lvl for f in fs) for lvl in (CRIT, WARN, OK)}
    out.append("\n" + c("1", "SUMMARY ") + " · ".join(
        [c(COLOR[CRIT], f"{count[CRIT]} problem(s)"), c(COLOR[WARN], f"{count[WARN]} warning(s)"), c(COLOR[OK], f"{count[OK]} OK")]))
    fixes = [f["fix"] for f in fs if f.get("fix")]
    if fixes:
        out.append("\nFixes:")
        for x in fixes:
            notes = [n for n, on in (("sudo", x["root"]), ("review first", not x["safe"])) if on]
            out.append(f"  {x['n']:>2}. {x['label']}" + c("2", f"  ({', '.join(notes)})" if notes else ""))
        safe = [str(x["n"]) for x in fixes if x["safe"]]
        pick = " ".join([str(x["n"]) for x in fixes if not x["safe"]][:2]) or "1"
        if safe:
            out.append(f"\nRun {c('1', 'doctor fix')} to apply the safe ones ({', '.join(safe)}),"
                       f" or pick by number: {c('1', 'doctor fix ' + pick)}   From chat: !sysfix")
        else:
            out.append(f"\nThese need your decision; pick by number: {c('1', 'doctor fix ' + pick)}   From chat: !sysfix {pick}")
    elif count[CRIT] + count[WARN] == 0:
        out.append("Nothing needs attention.")
    return "\n".join(out)


def save_text(report, text):
    d = os.path.join(state_dir(), "reports")
    path = os.path.join(d, time.strftime("%Y-%m-%d_%H%M.txt", time.localtime(report["time"])))
    with open(path, "w") as fh:
        fh.write(re.sub(r"\033\[[\d;]*m", "", text) + "\n")
    for old in sorted(os.listdir(d))[:-30]:
        os.remove(os.path.join(d, old))
    return path


def load_last():
    try:
        with open(os.path.join(state_dir(), "last.json")) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def parse_numbers(args, maximum):
    picked = set()
    for a in args:
        for part in a.split(","):
            m = re.fullmatch(r"(\d+)(?:-(\d+))?", part.strip())
            if not m:
                raise ValueError(f"not a fix number: {part}")
            lo, hi = int(m.group(1)), int(m.group(2) or m.group(1))
            picked.update(range(lo, hi + 1))
    bad = [n for n in picked if not 1 <= n <= maximum]
    if bad:
        raise ValueError(f"no fix numbered {bad[0]} (there are {maximum})")
    return sorted(picked)


def log_fixes(group, ok):
    """Remember what was changed on this computer, so `history` can show it (and how to undo)."""
    with open(os.path.join(state_dir(), "fixes.log"), "a") as fh:
        for f in group:
            undo = next((d for d in f["detail"] if d.startswith("Undo")), "")
            fh.write(json.dumps({"time": time.time(), "label": f["fix"]["label"], "cmd": f["fix"]["cmd"],
                                 "ok": ok, "undo": undo}) + "\n")


def log_change(label, undo, ok=True):
    with open(os.path.join(state_dir(), "fixes.log"), "a") as fh:
        fh.write(json.dumps({"time": time.time(), "label": label, "cmd": "", "ok": ok, "undo": undo}) + "\n")


def do_guard(args, here=False):
    """doctor guard [on [level] | off | relaxed|normal|strict | ignore GLOB | unignore GLOB | clear] [--here]"""
    from . import guard
    what = args[0].lower() if args else ""
    level = next((a for a in args if a in guard.LEVELS), None)
    scope = "--local" if here else "--global"
    if here and not guard.git("rev-parse", "--git-dir"):
        print("--here works inside a git repository; cd into one first.")
        return 2
    if what in ("on", *guard.LEVELS) and not here:
        was = guard.is_on()
        print(guard.turn_on(level or (guard.level_global() if was else guard.DEFAULT_LEVEL)))
        if not was:
            log_change("Turned on the commit guard", "Undo: doctor guard off")
        print(c("2", "  Every commit is checked. To go ahead anyway: answer y, or DOCTOR_GUARD=allow git commit ... "
                     "(git commit --no-verify works too, and you are still told)."))
        return 0
    if what in ("off", *guard.LEVELS) and here:
        guard.git("config", "--local", "doctor.guard", what)
        print(f"This repository: commit guard {what}." + ("" if guard.is_on() else " (Turn it on first: doctor guard on)"))
        return 0
    if what == "off":
        was = guard.is_on()
        print(guard.turn_off())
        if was:
            log_change("Turned off the commit guard", "Undo: doctor guard on")
        return 0
    if what in ("ignore", "unignore"):
        globs = args[1:]
        if not globs:
            print(f"Which files? doctor guard {what} 'tests/fixtures/*'")
            return 2
        for g in globs:
            if what == "ignore":
                guard.git("config", scope, "--add", "doctor.guardIgnore", g)
            else:
                guard.git("config", scope, "--fixed-value", "--unset-all", "doctor.guardIgnore", g)
        print(("Not checked from now on: " if what == "ignore" else "Checked again: ") + "  ".join(globs))
        return 0
    if what == "clear":
        n = guard.clear()
        print(f"Cleared {n} committed secret{'s' * (n != 1)} from doctor's list." if n else "Nothing to clear.")
        return 0
    if what not in ("", "status"):
        print(guard.__doc__.split("Levels")[0].strip().splitlines()[0])
        print("Use: doctor guard [on|off|relaxed|normal|strict] [--here] · ignore GLOB · unignore GLOB · clear")
        return 2
    print("\n".join(guard.status_lines()))
    rows = guard.exposures()
    if rows:
        print(c("1", f"\nSecrets that went into commits (last 30 days)"))
        for r in rows[:15]:
            where = f"{r['path']}:{r['line']}" if r.get("line") else r["path"]
            print(f"  {c('31', '✗')} {os.path.basename(r.get('repo') or '?')}  {where}  {r['rule']}  {c('2', r['preview'])}")
            print(c("2", f"      {time.strftime('%b %d', time.localtime(r['time']))} · commit {r.get('commit', '')[:8]} · "
                         + {"bypassed": "check skipped (--no-verify)", "allowed": "let through", "warned": "warned only"}.get(r.get("how"), "")))
        print(c("2", "  Replace (rotate) each key, remove it from the code, then: doctor guard clear"))
    return 0


def show_history(limit=30):
    try:
        with open(os.path.join(state_dir(), "fixes.log")) as fh:
            rows = [json.loads(l) for l in fh if l.strip()][-limit:]
    except (OSError, ValueError):
        rows = []
    if not rows:
        print("doctor hasn't changed anything on this computer yet.")
        return
    print(c("1", "What doctor changed on this computer") + c("2", "  (newest last)"))
    for r in rows:
        when = time.strftime("%b %d %H:%M", time.localtime(r["time"]))
        print(f"  {when}  {c('32', '✓') if r['ok'] else c('31', '✗')} {r['label']}")
        if r.get("undo"):
            print(c("2", f"                {r['undo']}"))


def apply_fixes(chosen):
    """Run the chosen findings' fixes (root ones under one sudo prompt), streaming output. Returns how many failed."""
    ctx = Ctx()
    failed = 0
    for root in (True, False):
        group = [f for f in chosen if f["fix"]["root"] == root]
        if not group:
            continue
        body = "\n".join(  # each fix's own messages are shown indented right under it
            f"echo '==> {f['fix']['n']}. {f['fix']['label'].replace(chr(39), '')}'\n"
            f"( set -e\n{f['fix']['cmd']}\n) 2>&1 | sed -u 's/^/      /'\n"
            f"if [ ${{PIPESTATUS[0]}} -eq 0 ]; then echo '    done'; else echo '    FAILED'; fi"
            for f in group)
        with tempfile.NamedTemporaryFile("w", suffix=".sh", dir=state_dir(), delete=False) as fh:
            fh.write("#!/bin/bash\n" + body + "\n")
        os.chmod(fh.name, 0o700)
        if root and not ctx.is_root:
            if not ctx.sudo and not sys.stdin.isatty():
                print("These fixes need sudo, which needs a password: run `doctor fix` in a terminal.")
                failed += len(group)
                os.remove(fh.name)
                continue
            argv = ["sudo", "bash", fh.name]
        elif not root and ctx.is_root:
            argv = ["runuser", "-u", ctx.user, "--", "bash", fh.name]
        else:
            argv = ["bash", fh.name]
        done = 0
        with subprocess.Popen(argv, stdout=subprocess.PIPE, text=True, errors="replace") as proc:
            for line in proc.stdout:  # stream: apt and snap fixes can take a while
                print(c("31", line.rstrip()) if line.strip() == "FAILED" else line.rstrip(), flush=True)
                done += line.strip() == "done"
        if done < len(group) and argv[0] == "sudo" and proc.returncode:
            print(c("31", "    Not applied: sudo was refused (wrong password or cancelled)."))
        failed += len(group) - done  # a fix only counts once it printed "done"
        log_fixes(group, ok=done == len(group))
        os.remove(fh.name)

    return failed


def do_fix(args, yes, no_sudo):
    report = load_last()
    if not report or time.time() - report["time"] > 6 * 3600:
        print("Last check is missing or older than 6 hours; checking again first.\n")
        ctx = get_sudo(no_sudo)
        report = scan(ctx)
        print(render(report))
        if args:
            print("\nNumbers may have changed. Pick again with: doctor fix <numbers>")
            return 1
    fixes = [f for f in report["findings"] if f.get("fix")]
    if not fixes:
        print("No fixes to apply.")
        return 0
    if args == ["all"]:
        chosen = fixes
    elif args:
        try:
            nums = parse_numbers(args, len(fixes))
        except ValueError as e:
            print(f"doctor fix: {e}", file=sys.stderr)
            return 2
        chosen = [f for f in fixes if f["fix"]["n"] in nums]
    else:
        chosen = [f for f in fixes if f["fix"]["safe"]]
        if not chosen:
            print("No safe fixes; these need you to pick them by number:")
            for f in fixes:
                print(f"  {f['fix']['n']:>2}. {f['fix']['label']}")
            return 0
    print("Applying:")
    for f in chosen:
        print(f"  {f['fix']['n']:>2}. {f['fix']['label']}")
    if not yes and sys.stdin.isatty():
        try:
            if input("Go ahead? [Y/n] ").strip().lower() in ("n", "no"):
                return 0
        except (EOFError, KeyboardInterrupt):
            print()
            return 0

    failed = apply_fixes(chosen)

    names = {f["check"] for f in chosen}
    print("\nChecking again...")
    fresh = run_checks(Ctx(), names=names)
    for f in fresh:
        if f["check"] in names:
            print(f"  {c(COLOR[f['level']], ICON[f['level']])} {f['title']}")
    still = {f["key"] for f in fresh if f.get("key") and f["level"] in (CRIT, WARN, INFO)}
    for f in chosen:   # an issue that has a name must be gone afterwards, not just "the command ran"
        if f.get("key"):
            print(f"  {c('32', 'verified: fixed') if f['key'] not in still else c('33', 'still there')}: {f['title']}")
    print(f"\n{len(chosen) - failed} of {len(chosen)} fix(es) applied. Run doctor for the full picture.")
    return 1 if failed else 0


def do_malware(no_sudo):
    ctx = get_sudo(no_sudo)
    scanner = "/usr/local/sbin/weekly-security-scan.sh"
    if ctx.sudo and os.path.exists(scanner):
        print("Running the rootkit/malware scan (rkhunter + chkrootkit), a few minutes...")
        subprocess.run(["sudo", "-n", "bash", scanner] if not ctx.is_root else ["bash", scanner])
    elif ctx.sudo:
        print("Rootkit scanner not set up; run the fix offered under 'Weekly rootkit/malware scan'.")
    else:
        print("The rootkit scan needs sudo; skipping it.")
    report = scan(ctx)
    text = render(report)
    print(text)
    save_text(report, text)
    return exit_code(report)


def exit_code(report):
    levels = {f["level"] for f in report["findings"]}
    return 2 if CRIT in levels else 1 if WARN in levels else 0


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    flags = {a for a in argv if a.startswith("-")}
    args = [a for a in argv if not a.startswith("-")]
    as_json, no_sudo = "--json" in flags, "--no-sudo" in flags
    yes, verbose = bool(flags & {"-y", "--yes"}), bool(flags & {"-v", "--verbose"})
    if flags & {"-h", "--help"} or args[:1] == ["help"]:
        print(USAGE)
        return 0
    if args and re.fullmatch(r"[\d,\-]+|all", args[0]):
        args.insert(0, "fix")  # `doctor 2 4` means fix 2 and 4
    if args[:1] == ["guard"]:
        return do_guard(args[1:], "--here" in flags)
    LOOK = ("top", "ports", "kills", "temps", "net", "boot", "logs", "history", "vulns")
    SPACE = ("clean", "deep", "pick")
    cmd = args.pop(0) if args and args[0] in ("fix", "last", "malware", "rootkit", "i", "interactive", "ask", "explain") + LOOK + SPACE else "check"
    if cmd in SPACE:
        from . import clean
        if as_json:  # the library's own CLI already speaks JSON
            from disk_clean.cli import main as disk_main
            return disk_main([{"clean": "quick"}.get(cmd, cmd), *args, "--json"])
        if cmd == "pick" and not args:
            print("Which items? doctor pick 1 3 5-7   (numbers from doctor deep)")
            return 2
        return {"clean": clean.clean, "deep": lambda: clean.deep(" ".join(args) or None),
                "pick": lambda: clean.pick(args)}[cmd]()
    if cmd == "vulns" and flags & {"--refresh", "--offline"}:   # what the check-up starts in the background
        from . import vulns
        return vulns.refresh_cli(Ctx(use_sudo=False), quiet="--quiet" in flags, offline="--offline" in flags)
    if cmd in LOOK or cmd in ("ask", "explain"):
        from .interactive import Session
        s = Session(Ctx(use_sudo=not no_sudo), sys.modules[__name__])
        if cmd in LOOK:
            getattr(s, cmd)(*([" ".join(args)] if cmd == "logs" else []))
            return 0
        s.report = load_last() or scan(s.ctx, quiet=True)
        s.mode = "cli"
        s._number()
        if cmd == "explain":
            if not (args and args[0].isdigit()):
                print("Which issue? doctor explain 3   (numbers as in doctor i)")
                return 2
            s.explain(int(args[0]))
        elif args:
            s.ask(" ".join(args))
        else:
            print('Ask a question: doctor ask "why is my computer slow?"')
            return 2
        return 0
    if cmd in ("i", "interactive"):
        if not sys.stdin.isatty():
            print("Interactive mode needs a terminal. In chat use: doctor, then doctor fix 2 4", file=sys.stderr)
            return 2
        from .interactive import Session
        return Session(Ctx(use_sudo=not no_sudo), sys.modules[__name__], no_sudo).run()  # sudo is asked for at the check-up

    if cmd == "fix":
        return do_fix(args, yes, no_sudo)
    if cmd in ("malware", "rootkit"):
        return do_malware(no_sudo)
    if cmd == "last":
        report = load_last()
        if not report:
            print("No check has run yet. Run: doctor")
            return 1
    else:
        bad = [a for a in args if a not in AREAS]
        if bad:
            print(f"Unknown area '{bad[0]}'. Areas: {' '.join(AREAS)}", file=sys.stderr)
            return 2
        report = scan(get_sudo(no_sudo or as_json and not sys.stdin.isatty()), args or None, quiet=as_json)
    if as_json:
        print(json.dumps(report, indent=1))
        return exit_code(report)
    text = render(report, verbose)
    print(text)
    if cmd == "check":
        print(c("2", f"\nReport saved: {save_text(report, text).replace(os.path.expanduser('~'), '~')}"))
    return exit_code(report)
