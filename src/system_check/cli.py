"""Command line: system-check [area ...] | fix [n ...|all] | last | deep."""
import json, os, re, socket, subprocess, sys, tempfile, time

from . import health, review, security  # noqa: F401  (registers the checks)
from .core import AREAS, CHECKS, CRIT, INFO, OK, SKIP, WARN, Ctx, run_checks

USAGE = """system-check — find out what's wrong with this computer and fix it

  system-check               full check-up: crashes, memory, disks, hardware, services, logs, updates, security
  system-check fix           apply the safe fixes from the last check (asks for sudo once)
  system-check fix 2 4       apply specific fixes by number (also the ones marked "review"); "system-check 2 4" works too
  system-check fix all       apply every fix, including the "review" ones
  system-check i             interactive: check, open issues, fix on the go, plus focused checks
                             (top, ports, svc NAME, logs, boot, kills, temps, net, disk, deep)
  system-check last          show the last report again
  system-check deep          check-up plus a full rootkit/malware scan (a few minutes)
  system-check memory disk   check only some areas: """ + " ".join(AREAS) + """

  Options: --json (machine-readable)  --no-sudo (skip root checks)  -y (no confirmation)
"""

ICON = {CRIT: "✗", WARN: "!", INFO: "i", OK: "✓", SKIP: "-"}
COLOR = {CRIT: "31", WARN: "33", INFO: "36", OK: "32", SKIP: "2"}
TTY = sys.stdout.isatty()


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if TTY else s


def state_dir():
    d = os.environ.get("SYSTEM_CHECK_DATA") or os.path.join(Ctx().home, ".local/state/system-check")
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
    out.append(c("1", f"system-check · {report['host']} · {when} · {mode} · {report['took']}s"))
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
            out.append(f"\nRun {c('1', 'system-check fix')} to apply the safe ones ({', '.join(safe)}),"
                       f" or pick by number: {c('1', 'system-check fix ' + pick)}   From chat: !sysfix")
        else:
            out.append(f"\nThese need your decision; pick by number: {c('1', 'system-check fix ' + pick)}   From chat: !sysfix {pick}")
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
                print("These fixes need sudo, which needs a password: run `system-check fix` in a terminal.")
                failed += len(group)
                os.remove(fh.name)
                continue
            argv = ["sudo", "bash", fh.name]
        elif not root and ctx.is_root:
            argv = ["runuser", "-u", ctx.user, "--", "bash", fh.name]
        else:
            argv = ["bash", fh.name]
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, text=True, errors="replace")
        for line in proc.stdout:  # stream: apt and snap fixes can take a while
            print(c("31", line.rstrip()) if line.strip() == "FAILED" else line.rstrip(), flush=True)
            failed += line.strip() == "FAILED"
        proc.wait()
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
            print("\nNumbers may have changed. Pick again with: system-check fix <numbers>")
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
            print(f"system-check fix: {e}", file=sys.stderr)
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
    print(f"\n{len(chosen) - failed} of {len(chosen)} fix(es) applied. Run system-check for the full picture.")
    return 1 if failed else 0


def do_deep(no_sudo):
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
        args.insert(0, "fix")  # `system-check 2 4` means fix 2 and 4
    cmd = args.pop(0) if args and args[0] in ("fix", "last", "deep", "i", "interactive") else "check"
    if cmd in ("i", "interactive"):
        if not sys.stdin.isatty():
            print("Interactive mode needs a terminal. In chat use: system-check, then system-check fix 2 4", file=sys.stderr)
            return 2
        from .interactive import Session
        return Session(get_sudo(no_sudo), sys.modules[__name__]).run()

    if cmd == "fix":
        return do_fix(args, yes, no_sudo)
    if cmd == "deep":
        return do_deep(no_sudo)
    if cmd == "last":
        report = load_last()
        if not report:
            print("No check has run yet. Run: system-check")
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
