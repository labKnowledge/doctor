"""Commit guard: stops API keys, passwords and private keys from leaving in a git commit, on every repository.

`doctor guard on` points git's global hooks folder at doctor's own hooks. Each one runs the guard (pre-commit and
post-commit only) and then passes through to whatever ran before: the hooks folder that was set before doctor, else
the repository's own .git/hooks. `doctor guard off` puts the previous setting back.

- pre-commit scans what is about to be committed (added lines and added files) and blocks or warns, by level.
- post-commit runs even after `git commit --no-verify`: a commit the pre-commit didn't approve is scanned again
  and any secret in it is reported (terminal, desktop notification, and the next doctor check-up).

Levels (git config doctor.guard; a repository can override the global one):
  relaxed  warn about secrets, never block
  normal   block known key formats, private keys and secret files (.env, id_rsa, *.pem); warn about the rest
  strict   block anything that looks like a secret, including passwords and tokens written into code

This file only uses the standard library and runs as a plain script from the hooks, so a commit never waits on the
rest of doctor and never breaks when doctor is missing.
"""
import fnmatch, json, math, os, re, shlex, subprocess, sys, time

LEVELS = ("relaxed", "normal", "strict")
DEFAULT_LEVEL = "normal"
SURE, LIKELY = "sure", "likely"   # how certain a match is a real secret
ALLOW_MARK = re.compile(r"doctor:allow|pragma: allowlist secret|gitleaks:allow")

# (name, pattern, certainty). Patterns for known formats are specific enough to be trusted on sight.
RULES = [
    ("private key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----", SURE),
    ("AWS access key", r"\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b", SURE),
    ("AWS secret key", r"(?i)aws.{0,20}(?:secret|key).{0,20}['\"=:\s]([A-Za-z0-9/+=]{40})\b", SURE),
    ("GitHub token", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b", SURE),
    ("GitLab token", r"\bglpat-[A-Za-z0-9_-]{20,}\b", SURE),
    ("Slack token", r"\bxox[abposr]-[A-Za-z0-9-]{10,}\b", SURE),
    ("Slack webhook", r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+", SURE),
    ("Discord webhook", r"https://(?:ptb\.|canary\.)?discord(?:app)?\.com/api/webhooks/\d+/[\w-]{20,}", SURE),
    ("Stripe live key", r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b", SURE),
    ("Stripe test key", r"\b(?:sk|rk)_test_[A-Za-z0-9]{20,}\b", LIKELY),
    ("Anthropic API key", r"\bsk-ant-[a-z]+\d*-[A-Za-z0-9_-]{60,}", SURE),
    ("OpenAI API key", r"\bsk-(?:proj-|svcacct-|admin-)?[A-Za-z0-9_-]{20,}T3BlbkFJ[A-Za-z0-9_-]{20,}|\bsk-proj-[A-Za-z0-9_-]{40,}", SURE),
    ("Google API key", r"\bAIza[0-9A-Za-z_-]{35}\b", SURE),
    ("Google OAuth secret", r"\bGOCSPX-[A-Za-z0-9_-]{28}\b", SURE),
    ("Hugging Face token", r"\bhf_[A-Za-z0-9]{34,}\b", SURE),
    ("npm token", r"\bnpm_[A-Za-z0-9]{36}\b", SURE),
    ("PyPI token", r"\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}", SURE),
    ("SendGrid key", r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b", SURE),
    ("Telegram bot token", r"\b\d{8,10}:AA[A-Za-z0-9_-]{33}\b", SURE),
    ("DigitalOcean token", r"\bdo[por]_v1_[a-f0-9]{64}\b", SURE),
    ("Shopify token", r"\bshp(?:at|ca|pa|ss)_[a-fA-F0-9]{32}\b", SURE),
    ("Azure storage key", r"AccountKey=[A-Za-z0-9+/]{86}==", SURE),
    ("Twilio key", r"\bSK[0-9a-f]{32}\b", LIKELY),
    ("Mailgun key", r"\bkey-[0-9a-f]{32}\b", LIKELY),
    ("JSON web token", r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}", LIKELY),
    ("password in a URL", r"\b[a-z][a-z0-9+.-]{1,20}://[^\s/:@'\"]{1,64}:([^\s/:@'\"]{3,128})@[\w.-]+", LIKELY),
]
RULES = [(n, re.compile(p), c) for n, p, c in RULES]

# A value assigned to a secret-sounding name: password = "...", "api_key": "...", TOKEN=...
GENERIC = re.compile(
    r"(?i)\b([\w.-]{0,30}(?:password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|private[_-]?key|"
    r"client[_-]?secret|auth[_-]?key|credentials?)[\w.-]{0,20})['\"]?\s*(?:[:=]|:=|=>)\s*['\"]?([^\s'\"`,;)]{8,})")
NOT_A_VALUE = re.compile(
    r"(?i)^(?:true|false|null|none|nil|undefined)$|example|sample|dummy|placeholder|your[_-]|changeme|change_me|xxx|"
    r"\*{3}|redacted|<[^>]*>|^\$|^\{|\$\{|\$\(|%\(|^process\.|^os\.|^env\.|getenv|environ|^config\.|^settings\.|"
    r"^self\.|^this\.|^props\.|^req\.|^args\.|^[A-Z_]+$|^[a-z]+(?:[A-Z][a-z0-9]+)+$|^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+$|"
    r"[\[\](){}]|^/|^https?://")

# Files that are secret by nature. (glob on the file name, what it is, certainty)
SECRET_FILES = [
    (".env", "environment file", SURE), (".env.*", "environment file", SURE),
    ("id_rsa", "SSH private key", SURE), ("id_dsa", "SSH private key", SURE),
    ("id_ecdsa", "SSH private key", SURE), ("id_ed25519", "SSH private key", SURE),
    ("*.pem", "key or certificate file", LIKELY), ("*.key", "private key file", LIKELY),
    ("*.p12", "certificate bundle with private key", SURE), ("*.pfx", "certificate bundle with private key", SURE),
    ("*.jks", "Java keystore", SURE), ("*.keystore", "keystore", SURE), ("*.kdbx", "password database", SURE),
    (".netrc", "saved logins", SURE), (".pgpass", "saved database passwords", SURE),
    ("credentials", "saved credentials", LIKELY), ("*.tfstate", "Terraform state (often holds secrets)", LIKELY),
]
NOT_SECRET_FILES = re.compile(r"(?i)\.env\.(?:example|sample|template|dist|defaults?)$|\.pub$|example|sample")
SKIP_FILES = re.compile(r"(?:^|/)(?:package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Cargo\.lock|go\.sum|"
                        r"composer\.lock|Gemfile\.lock|uv\.lock|bun\.lockb)$|\.min\.(?:js|css)$|\.map$")
MAX_LINE = 4000

HOOK_NAMES = ["applypatch-msg", "pre-applypatch", "post-applypatch", "pre-commit", "pre-merge-commit",
              "prepare-commit-msg", "commit-msg", "post-commit", "pre-rebase", "post-checkout", "post-merge",
              "pre-push", "pre-receive", "update", "proc-receive", "post-receive", "post-update",
              "reference-transaction", "push-to-checkout", "pre-auto-gc", "post-rewrite", "sendemail-validate",
              "fsmonitor-watchman", "post-index-change"]


# ---------- scanning ----------

def entropy(s):
    if not s:
        return 0.0
    counts = {ch: s.count(ch) for ch in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def mask(secret):
    """Enough to recognise it, never enough to use it."""
    s = secret.strip()
    return s[:4] + "…" + s[-2:] if len(s) > 10 else s[:2] + "…"


def scan_line(text):
    """[(rule name, certainty, matched secret)] in one added line."""
    if len(text) > MAX_LINE or ALLOW_MARK.search(text):
        return []
    hits, spans = [], []
    for name, rx, certainty in RULES:
        for m in rx.finditer(text):
            secret = m.group(m.lastindex or 0)
            if "EXAMPLE" in secret.upper() or (name == "password in a URL" and NOT_A_VALUE.search(secret)):
                continue
            hits.append((name, certainty, secret))
            spans.append(m.span())
    for m in GENERIC.finditer(text):
        value = m.group(2)
        if any(a <= m.start(2) < b for a, b in spans) or NOT_A_VALUE.search(value) or entropy(value) < 3.0:
            continue
        hits.append((f"secret in {m.group(1)[:30]}", LIKELY, value))
    return hits


def secret_file(path):
    """(what it is, certainty) when the file itself is a secret, else None."""
    name = os.path.basename(path)
    if NOT_SECRET_FILES.search(name):
        return None
    for pattern, what, certainty in SECRET_FILES:
        if fnmatch.fnmatch(name, pattern):
            return what, certainty
    return None


def parse_diff(diff):
    """Yield (path, line number or None, text) for each added line, and (path, None, None) for each added file."""
    path, new_file, lineno = None, False, 0
    for line in diff.splitlines():
        if line.startswith("diff --git "):
            path, new_file = None, False
        elif line.startswith("new file mode"):
            new_file = True
        elif line.startswith("+++ "):
            path = line[4:].strip()
            path = path[2:] if path.startswith("b/") else None if path == "/dev/null" else path
            if path and new_file:
                yield path, None, None
        elif line.startswith("@@"):
            m = re.search(r"\+(\d+)", line)
            lineno = int(m.group(1)) if m else 0
        elif path and line.startswith("+"):
            yield path, lineno, line[1:]
            lineno += 1


def scan_diff(diff, ignore=()):
    """Every exposed secret in a unified diff: [{"path", "line", "rule", "certainty", "preview"}]."""
    found, seen = [], set()
    for path, lineno, text in parse_diff(diff):
        if SKIP_FILES.search(path) or any(fnmatch.fnmatch(path, g) for g in ignore):
            continue
        if text is None:
            kind = secret_file(path)
            if kind:
                found.append({"path": path, "line": None, "rule": kind[0], "certainty": kind[1], "preview": "the whole file"})
            continue
        for rule, certainty, secret in scan_line(text):
            if (path, secret) in seen:
                continue
            seen.add((path, secret))
            found.append({"path": path, "line": lineno, "rule": rule, "certainty": certainty, "preview": mask(secret)})
    return found


def blocks(f, level):
    return level == "strict" or (level == "normal" and f["certainty"] == SURE)


# ---------- git ----------

def git(*args, cwd=None):
    try:
        p = subprocess.run(["git", *args], capture_output=True, text=True, errors="replace", cwd=cwd, timeout=60)
        return p.stdout if p.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def config(key, scope=None):
    return git("config", *([f"--{scope}"] if scope else []), "--get", key).strip()


def level_here():
    """The level for the current repository: its own setting, else the global one."""
    lv = config("doctor.guard").lower()
    return lv if lv in LEVELS + ("off",) else DEFAULT_LEVEL


def ignores():
    return [g for g in git("config", "--get-all", "doctor.guardIgnore").splitlines() if g.strip()]


def state_dir():
    d = os.environ.get("DOCTOR_DATA") or os.path.expanduser("~/.local/state/doctor")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def record(findings, how):
    """Remember secrets that went into a commit, so the check-up keeps showing them until they're dealt with."""
    top = git("rev-parse", "--show-toplevel").strip()
    sha = git("rev-parse", "HEAD").strip()
    with open(os.path.join(state_dir(), "guard.log"), "a") as fh:
        for f in findings:
            fh.write(json.dumps({"time": time.time(), "repo": top, "commit": sha, "how": how, **f}) + "\n")


# ---------- output ----------

def paint(code, s, on):
    return f"\033[{code}m{s}\033[0m" if on else s


def describe(findings, level, out, color):
    w = max(len(f"{f['path']}:{f['line']}" if f["line"] else f["path"]) for f in findings)
    for f in findings:
        where = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
        sign = paint("31", "✗", color) if blocks(f, level) else paint("33", "!", color)
        print(f"  {sign} {where:<{min(w, 50)}}  {f['rule']}  {paint('2', f['preview'], color)}", file=out)


def notify(title, body):
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        try:
            subprocess.Popen(["notify-send", "-u", "critical", "-a", "doctor", title, body],
                             stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except OSError:
            pass


def marker():
    return git("rev-parse", "--git-path", "doctor-guard-checked").strip()


# ---------- the hooks ----------

def pre_commit():
    level = level_here()
    if level == "off" or git("rev-parse", "-q", "--verify", "MERGE_HEAD").strip():
        return 0   # a merge brings in commits that were already checked where they were made
    findings = scan_diff(git("diff", "--cached", "--no-color", "--no-ext-diff", "-U0", "--diff-filter=ACMR"), ignores())
    tree = git("write-tree").strip()
    approve = lambda: open(marker(), "w").write(tree) if tree else None   # noqa: E731  (post-commit skips approved trees)
    if not findings:
        approve()
        return 0
    stopping = [f for f in findings if blocks(f, level)]
    out = sys.stderr
    color = out.isatty()
    n = len(findings)
    head = f"doctor guard: this commit would expose {n} secret{'s' * (n > 1)}"
    print(paint("1;31" if stopping else "1;33", head, color), file=out)
    describe(findings, level, out, color)
    if any(f["line"] is None for f in findings):
        files = " ".join(shlex.quote(f["path"]) for f in findings if f["line"] is None)
        print(paint("2", f"  Keep secret files out of git: git rm --cached {files} && echo the name >> .gitignore", color), file=out)
    print(paint("2", "  Move secrets to an environment variable or a file in .gitignore. False alarm? Add doctor:allow on "
                     "that line, or: doctor guard ignore 'path/*'", color), file=out)
    if not stopping:
        print(paint("2", f"  Level {level}: warning only, the commit goes ahead.", color), file=out)
        approve()
        _pending(findings, "warned")   # recorded with its commit hash once the commit exists
        return 0
    if os.environ.get("DOCTOR_GUARD", "").lower() == "allow":
        print(paint("33", "  DOCTOR_GUARD=allow: committing anyway. It stays on doctor's list until you deal with it.", color), file=out)
        approve()
        _pending(findings, "allowed")
        return 0
    answer = ask_tty("  Commit anyway? y/N › ")
    if answer == "y":
        approve()
        _pending(findings, "allowed")
        return 0
    if answer is None:   # no terminal (an editor's commit button): explain how to go ahead
        print(paint("2", "  Commit anyway: DOCTOR_GUARD=allow git commit ...   (or git commit --no-verify; "
                         "you'll still be told)", color), file=out)
    print(paint("31", "  Commit stopped.", color), file=out)
    return 1


def _pending(findings, how):
    """A let-through commit gets its hash in post-commit; keep the findings until then."""
    with open(marker() + ".pending", "w") as fh:
        json.dump({"how": how, "findings": findings}, fh)


def ask_tty(prompt):
    """y/n from the user's terminal even though git gives hooks no stdin; None when there is no terminal."""
    try:   # two handles: a terminal can't be opened read-write in text mode (it isn't seekable)
        with open("/dev/tty", "w") as out, open("/dev/tty") as inp:
            out.write(prompt)
            out.flush()
            return inp.readline().strip().lower()[:1] or "n"
    except OSError:
        return None


def post_commit():
    level = level_here()
    mk = marker()
    checked = ""
    try:
        with open(mk) as fh:
            checked = fh.read().strip()
        os.unlink(mk)
    except OSError:
        pass
    pending = None
    try:
        with open(mk + ".pending") as fh:
            pending = json.load(fh)
        os.unlink(mk + ".pending")
    except (OSError, ValueError):
        pass
    if level == "off":
        return 0
    if checked and checked == git("rev-parse", "HEAD^{tree}").strip():
        if pending:   # let through on purpose at pre-commit: remember it with its commit
            record(pending["findings"], pending["how"])
        return 0
    if len(git("rev-list", "--parents", "-n1", "HEAD").split()) > 2:
        return 0   # merge commit
    gd = git("rev-parse", "--git-dir").strip()
    if any(os.path.exists(os.path.join(gd, d)) for d in ("rebase-merge", "rebase-apply")):
        return 0   # replaying commits that were checked when first made
    findings = scan_diff(git("show", "--no-color", "--no-ext-diff", "-U0", "--format=", "HEAD"), ignores())
    if not findings:
        return 0
    record(findings, "bypassed")
    out = sys.stderr
    color = out.isatty()
    n = len(findings)
    print(paint("1;31", f"doctor guard: the commit you just made exposes {n} secret{'s' * (n > 1)} (pre-commit check was skipped)", color), file=out)
    describe(findings, "strict", out, color)
    print(paint("2", "  Before you push: remove it and git commit --amend, then replace (rotate) the key; "
                     "it is on doctor's check-up until then.", color), file=out)
    repo = os.path.basename(git("rev-parse", "--show-toplevel").strip())
    notify("Secret committed", f"{repo}: {findings[0]['rule']} in {findings[0]['path']}" + (f" and {n - 1} more" if n > 1 else ""))
    return 0


def hook(name):
    try:
        return {"pre-commit": pre_commit, "post-commit": post_commit}[name]()
    except Exception as e:   # the guard must never make git unusable
        print(f"doctor guard: skipped ({type(e).__name__}: {e})", file=sys.stderr)
        return 0


# ---------- turning it on and off ----------

def hooks_dir():
    return os.path.join(os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share"), "doctor", "git-hooks")


def is_on():
    return os.path.realpath(os.path.expanduser(config("core.hooksPath", "global") or "/nonexistent")) == os.path.realpath(hooks_dir())


def write_hooks(prev):
    """One script per hook name: the guard where it applies, then whatever ran before doctor."""
    d = hooks_dir()
    os.makedirs(d, exist_ok=True)
    for old in os.listdir(d):
        os.unlink(os.path.join(d, old))
    me = os.path.realpath(__file__)
    names = HOOK_NAMES
    if prev:   # don't add hooks the previous folder didn't have (each one costs a little on every git command)
        names = sorted({n for n in os.listdir(prev) if os.access(os.path.join(prev, n), os.X_OK)} | {"pre-commit", "post-commit"})
    # The repository's own hook lives in its .git/hooks. (Not `git rev-parse --git-path hooks/...`: with a global
    # core.hooksPath that names this folder again, and the hook would call itself forever.)
    own = 'own="$(git rev-parse --git-common-dir 2>/dev/null)/hooks/{name}"\n'
    for name in names:
        guard = ""
        if name in ("pre-commit", "post-commit"):
            guard = (f'if [ -f {shlex.quote(me)} ]; then\n'
                     f'  /usr/bin/python3 -I {shlex.quote(me)} {name} || exit $?\n'
                     f'fi\n')
        # A previous hook that looks up "the repository's hook" through core.hooksPath lands back here:
        # the second time round, go straight to the repository's own hook.
        reentry = (own.format(name=name) +
                   f'if [ "$DOCTOR_GUARD_IN" = {name} ]; then [ -x "$own" ] && exec "$own" "$@"; exit 0; fi\n'
                   f'DOCTOR_GUARD_IN={name}; export DOCTOR_GUARD_IN\n')
        nxt = f'next={shlex.quote(os.path.join(prev, name))}\n' if prev else 'next="$own"\n'
        with open(os.path.join(d, name), "w") as fh:
            fh.write("#!/bin/sh\n# doctor guard: checks commits for secrets, then runs the hook that was here before.\n"
                     f"# Turn off: doctor guard off\n{reentry}{guard}{nxt}"
                     '[ -x "$next" ] && exec "$next" "$@"\nexit 0\n')
        os.chmod(os.path.join(d, name), 0o755)


def turn_on(level=DEFAULT_LEVEL):
    """Returns a line saying what happened."""
    if not git("--version"):
        return "git isn't installed, so there are no commits to guard."
    if not is_on():
        prev = config("core.hooksPath", "global")
        if prev:
            git("config", "--global", "doctor.guardPrevHooks", prev)
        else:
            git("config", "--global", "--unset", "doctor.guardPrevHooks")
    prev = config("doctor.guardPrevHooks", "global")
    write_hooks(os.path.expanduser(prev) if prev else "")
    git("config", "--global", "core.hooksPath", hooks_dir())
    git("config", "--global", "doctor.guard", level)
    return f"Commit guard on, level {level}" + (f" (your hooks in {prev} still run)" if prev else "") + "."


def turn_off():
    if not is_on():
        return "Commit guard is already off."
    prev = config("doctor.guardPrevHooks", "global")
    if prev:
        git("config", "--global", "core.hooksPath", prev)
    else:
        git("config", "--global", "--unset", "core.hooksPath")
    for key in ("doctor.guardPrevHooks", "doctor.guard"):
        git("config", "--global", "--unset", key)
    for f in os.listdir(hooks_dir()):
        os.unlink(os.path.join(hooks_dir(), f))
    return "Commit guard off" + (f"; git uses {prev} again." if prev else "; git hooks are back to each repository's own.")


def exposures(days=30):
    """Secrets that went into commits in the last `days` and haven't been cleared: newest first, one per secret."""
    try:
        with open(os.path.join(state_dir(), "guard.log")) as fh:
            rows = [json.loads(l) for l in fh if l.strip()]
    except (OSError, ValueError):
        return []
    cut = time.time() - days * 86400
    seen, out = set(), []
    for r in reversed(rows):
        key = (r.get("repo"), r.get("path"), r.get("preview"))
        if r["time"] < cut or key in seen:
            continue
        seen.add(key)
        if r.get("how") == "cleared":
            continue
        out.append(r)
    return out


def clear():
    rows = exposures()
    with open(os.path.join(state_dir(), "guard.log"), "a") as fh:
        for r in rows:
            fh.write(json.dumps({**r, "time": time.time(), "how": "cleared"}) + "\n")
    return len(rows)


def pushed(r):
    """Whether the commit already reached a remote (then the key must be replaced, not just removed)."""
    if not (r.get("repo") and r.get("commit")) or not os.path.isdir(r["repo"]):
        return None
    return bool(git("branch", "-r", "--contains", r["commit"], cwd=r["repo"]).strip())


def status_lines():
    on = is_on()
    lines = [f"Commit guard: {'on' if on else 'off'}" + (f", level {level_global()}" if on else "")]
    if on:
        prev = config("doctor.guardPrevHooks", "global")
        lines.append(f"  Checks every commit in every repository on this computer" + (f"; then runs your hooks in {prev}" if prev else "") + ".")
        here = config("doctor.guard", "local")
        if here:
            lines.append(f"  This repository: {here}.")
        ig = [g for g in git("config", "--global", "--get-all", "doctor.guardIgnore").splitlines() if g]
        if ig:
            lines.append("  Not checked: " + "  ".join(ig))
    else:
        lines.append("  Turn on: doctor guard on   (stops API keys, passwords and private keys from being committed)")
    return lines


def level_global():
    lv = config("doctor.guard", "global").lower()
    return lv if lv in LEVELS else DEFAULT_LEVEL


if __name__ == "__main__":
    sys.exit(hook(sys.argv[1] if len(sys.argv) > 1 else ""))
