"""Plumbing shared by every check: running commands (as user or root), findings, the check registry."""
import concurrent.futures as cf
import os, pwd, re, shlex, subprocess, time

OK, INFO, WARN, CRIT, SKIP = "ok", "info", "warn", "crit", "skip"
RANK = {CRIT: 0, WARN: 1, INFO: 2, SKIP: 3, OK: 4}

AREAS = ["stability", "memory", "disk", "hardware", "services", "logs", "updates", "network", "security"]

CHECKS = []  # (area, name, fn)


def check(area, name):
    def deco(fn):
        CHECKS.append((area, name, fn))
        return fn
    return deco


def finding(level, title, detail=(), fix=None, key=None):
    """fix = {"label", "cmd" (bash), "root": bool, "safe": bool}. safe fixes run with plain `fix`."""
    return {"level": level, "title": title, "detail": [d for d in detail if d], "fix": fix, "key": key}


def fix(label, cmd, root=True, safe=True):
    return {"label": label, "cmd": cmd, "root": root, "safe": safe}


class Ctx:
    """Who we are, whether root commands work, and how to run things."""

    def __init__(self, use_sudo=True):
        self.is_root = os.geteuid() == 0
        name = os.environ.get("SUDO_USER") if self.is_root else None
        pw = pwd.getpwnam(name) if name else pwd.getpwuid(os.getuid())
        self.user, self.uid, self.home = pw.pw_name, pw.pw_uid, pw.pw_dir
        self.sudo = self.is_root or (use_sudo and _sudo_cached())
        self.ncpu = os.cpu_count() or 1
        self._cache = {}

    def run(self, cmd, root=False, timeout=25):
        """Run a bash command; returns its stdout ("" on failure). root=True returns None when no root is available."""
        if root and not self.is_root:
            if not self.sudo:
                return None
            argv = ["sudo", "-n", "bash", "-c", cmd]
        elif not root and self.is_root and self.user != "root":
            rt = f"/run/user/{self.uid}"
            argv = ["runuser", "-u", self.user, "--", "env", f"XDG_RUNTIME_DIR={rt}",
                    f"DBUS_SESSION_BUS_ADDRESS=unix:path={rt}/bus", f"HOME={self.home}", "bash", "-c", cmd]
        else:
            argv = ["bash", "-c", cmd]
        try:
            p = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, errors="replace",
                               env={**os.environ, "LC_ALL": "C", "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": ""})
            return p.stdout
        except (subprocess.TimeoutExpired, OSError):
            return "" if not root else None

    def cached(self, key, cmd, root=False, timeout=25):
        if key not in self._cache:
            self._cache[key] = self.run(cmd, root=root, timeout=timeout)
        return self._cache[key]

    def has(self, prog):
        return bool(self.run(f"command -v {shlex.quote(prog)}").strip())


def _sudo_cached():
    try:
        return subprocess.run(["sudo", "-n", "true"], capture_output=True, timeout=5).returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def read(path, default=""):
    try:
        with open(path, errors="replace") as f:
            return f.read()
    except OSError:
        return default


def human(n):
    n = float(n)
    for unit in ("B", "K", "M", "G", "T"):
        if abs(n) < 1024 or unit == "T":
            return f"{n:.0f}{unit}" if unit in ("B", "K") or n >= 10 else f"{n:.1f}{unit}"
        n /= 1024


def normalize(msg):
    """Collapse numbers/hex/ids so repeats of one message group together."""
    msg = re.sub(r"0x[0-9a-fA-F]+|\b[0-9a-f]{8,}\b", "#", msg)
    return re.sub(r"\d+", "N", msg).strip()[:160]


def run_checks(ctx, areas=None, progress=None, names=None):
    todo = [c for c in CHECKS if (not areas or c[0] in areas) and (not names or c[1] in names)]
    results = []
    with cf.ThreadPoolExecutor(max_workers=8) as pool:
        futs = {pool.submit(_safe_call, fn, ctx): (area, name) for area, name, fn in todo}
        for fut in cf.as_completed(futs):
            area, name = futs[fut]
            for f in fut.result():
                f.update(area=area, check=name)
                results.append(f)
            if progress:
                progress(len(results))
    order = {a: i for i, a in enumerate(AREAS)}
    results.sort(key=lambda f: (order.get(f["area"], 99), RANK[f["level"]], f["title"]))
    return results


def _safe_call(fn, ctx):
    t = time.time()
    try:
        out = fn(ctx) or []
    except Exception as e:  # one broken check must never sink the whole report
        out = [finding(INFO, f"Check '{fn.__name__}' could not run", [f"{type(e).__name__}: {e}"])]
    if time.time() - t > 20:
        for f in out:
            f.setdefault("slow", True)
    return out
