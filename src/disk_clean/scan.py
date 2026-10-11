"""Deep scan: find big things that are safe to remove because they rebuild, re-download, or are unused.

Nothing is deleted here. A scan returns numbered items; `actions.remove` deletes the ones picked.
Anything a running process holds (open file, cwd, binary, mapped file, command-line path, active swap)
is never listed.
"""
import hashlib, json, os, re, shutil, subprocess, time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

HOME = Path.home()
DATA_DIR = Path(os.environ.get("DISK_CLEAN_DATA", HOME / ".cache" / "disk-clean"))
STATE = DATA_DIR / "last-scan.json"
REFS = DATA_DIR / "refs.json"

IDLE_DAYS = 30          # projects, conda envs, emulators
BIG_FILE = 1 << 30      # 1 GB
BIG_FILE_DAYS = 90
MIN_ITEM = 50 << 20     # hide items under 50 MB
MAX_ITEMS = 40
TIME_BUDGET = 20 * 60   # stop walking after 20 min (chat commands time out at 30)
DAY = 86400

# Folders under $HOME that tools manage themselves; covered by their own rules or by the quick clean.
MANAGED = [".cache", "miniconda3", "anaconda3", "Android", ".android", ".var", "snap", ".local/share/Trash",
           ".npm", ".gradle", ".cargo", ".rustup", "go/pkg", ".nvm", ".bun", ".pnpm-store", ".vscode",
           ".cursor", ".config", ".unsloth", ".whatslive", ".omnish", ".claude", ".local/lib", ".local/share/pnpm"]
SKIP_NAMES = {".git", ".hg", ".svn", "proc", "sys", "dev", "run", "lost+found", ".Trash-1000"}
OS_ROOT_DIRS = {"bin", "boot", "cdrom", "dev", "etc", "lib", "lib32", "lib64", "libx32", "media", "mnt", "opt",
                "proc", "root", "run", "sbin", "snap", "srv", "sys", "tmp", "usr", "var"}

# artifact dir -> sibling files that prove it's generated output for that project
ARTIFACTS = {
    "node_modules": ["package.json"],
    ".next": ["package.json"], ".nuxt": ["package.json"], ".turbo": ["package.json"],
    ".parcel-cache": ["package.json"], ".angular": ["package.json"], ".svelte-kit": ["package.json"],
    ".expo": ["package.json"], "dist": ["package.json", "pyproject.toml", "setup.py"],
    "build": ["build.gradle", "build.gradle.kts", "settings.gradle", "settings.gradle.kts", "package.json",
              "CMakeLists.txt", "pyproject.toml", "setup.py", "pubspec.yaml"],
    ".gradle": ["settings.gradle", "settings.gradle.kts", "build.gradle", "build.gradle.kts"],
    ".kotlin": ["settings.gradle", "settings.gradle.kts", "build.gradle.kts"],
    ".cxx": ["build.gradle", "build.gradle.kts"],
    "target": ["Cargo.toml", "pom.xml"],
    ".dart_tool": ["pubspec.yaml"], "Pods": ["Podfile"],
    ".venv": [], "venv": [], "env": [],   # only when they contain pyvenv.cfg
}


class DiskCleanError(Exception):
    """A user-facing problem (bad target, no scan yet, bad pick). The message is safe to show as-is."""


def human(n):
    for unit in ("B", "K", "M", "G", "T"):
        if n < 1024 or unit == "T":
            return f"{n:.1f}{unit}" if unit in "GT" else f"{int(n)}{unit}"
        n /= 1024


def age(ts, now=None):
    d = int(((now or time.time()) - ts) / DAY)
    if d < 1: return "today"
    if d < 60: return f"{d}d"
    if d < 730: return f"{d // 30}mo"
    return f"{d // 365}y"


def disk_usage(path):
    u = shutil.disk_usage(path)
    return {"total": u.total, "used": u.used, "free": u.free, "percent": round(u.used / u.total * 100)}


def disk_line(path):
    u = disk_usage(path)
    return f"{u['percent']}% used, {human(u['free'])} free"


def du(paths):
    try:
        out = subprocess.run(["du", "-sbc", "--", *paths], capture_output=True, text=True).stdout
        return int(out.strip().splitlines()[-1].split()[0])
    except Exception:
        return 0


def mounts():
    out = subprocess.run(["findmnt", "-rn", "-o", "TARGET"], capture_output=True, text=True).stdout
    return [m.replace("\\x20", " ") for m in out.split()]


def held_paths():
    """Every path a running process depends on, plus swap files. These are never listed or deleted."""
    held = set()
    try:  # active swap files never show up as open files
        for line in Path("/proc/swaps").read_text().splitlines()[1:]:
            held.add(line.split()[0])
    except OSError: pass
    try:  # configured swap files, even if swapped off right now
        for line in Path("/etc/fstab").read_text().splitlines():
            f = line.split()
            if len(f) >= 3 and f[2] == "swap" and f[0].startswith("/"): held.add(f[0])
    except OSError: pass
    for pid in os.listdir("/proc"):
        if not pid.isdigit():
            continue
        base = f"/proc/{pid}"
        try:
            with open(f"{base}/cmdline", "rb") as f:
                held.update(a for a in f.read().decode(errors="ignore").split("\0") if a.startswith("/"))
        except OSError: pass
        for link in ("cwd", "exe"):
            try: held.add(os.readlink(f"{base}/{link}"))
            except OSError: pass
        try:
            for fd in os.listdir(f"{base}/fd"):
                try: held.add(os.readlink(f"{base}/fd/{fd}"))
                except OSError: pass
        except OSError: pass
        try:
            with open(f"{base}/maps") as f:
                for line in f:
                    p = line.split(None, 5)
                    if len(p) == 6 and p[5].startswith("/"): held.add(p[5].strip())
        except OSError: pass
    return held


def in_use(paths, held):
    return any(h == p or h.startswith(p.rstrip("/") + "/") for p in paths for h in held)


def resolve_target(arg=None):
    """'/', 'system' or nothing -> /;  a folder path -> that folder;  a drive name ('storage') -> its mount."""
    if not arg or arg in ("/", "system", "root"):
        return Path("/")
    p = Path(os.path.expanduser(arg))
    if p.is_dir():
        return p.resolve()
    ms = mounts()
    hits = [m for m in ms if Path(m).name.lower() == arg.lower()] or \
           [m for m in ms if arg.lower() in Path(m).name.lower() and m.startswith("/media")]
    if hits:
        return Path(hits[0])
    drives = ", ".join(Path(m).name for m in ms if m.startswith(("/media", "/mnt")))
    raise DiskCleanError(f"Can't find '{arg}'. Use a folder path or a drive name ({drives}).")


def load_refs():
    try: return json.loads(REFS.read_text())
    except Exception: return {}


def parse_size(s):
    m = re.match(r"([\d.]+)\s*([KMGT]?)B", s)
    if not m: return 0
    return int(float(m.group(1)) * 1024 ** "_KMGT".index(m.group(2) or "_"))


class Scan:
    def __init__(self, target, time_budget=TIME_BUDGET, on_progress=None):
        self.target = Path(target)
        self.now = time.time()
        self.time_budget = time_budget
        self.on_progress = on_progress
        self.dev = os.stat(self.target).st_dev
        # On "/", the user's data is $HOME; system dirs are package-managed.
        self.walk_root = HOME if self.target == Path("/") and os.stat(HOME).st_dev == self.dev else self.target
        self.items = []
        self.newest = {}        # dir -> newest mtime in its subtree (artifacts excluded)
        self.artifacts = {}     # project root -> [artifact paths]
        self.big_files = []
        self.skip = {str(HOME / m) for m in MANAGED}
        self.git_root_cache = {}
        self.partial = False
        self.notes = []
        self.refs = {"ndk": set(), "gradle": set()}
        # an old OS install on a data drive: its system folders aren't user data
        root = str(self.walk_root)
        self.os_root = root != "/" and os.path.isdir(f"{root}/etc") and os.path.isdir(f"{root}/usr")

    def on_drive(self, p):
        try: return os.stat(p).st_dev == self.dev and str(p).startswith(str(self.target))
        except OSError: return False

    def idle(self, ts):
        return self.now - ts >= IDLE_DAYS * DAY

    def add(self, kind, label, paths, size, ts, note="", when="idle"):
        if size >= MIN_ITEM:
            paths = [str(p) for p in paths]
            self.items.append({"id": hashlib.sha1("\0".join(paths).encode()).hexdigest()[:10],
                               "kind": kind, "label": label, "paths": paths, "size": size,
                               "age": f"{when} {age(ts, self.now)}" if ts else "", "last_used": ts or None,
                               "note": note})

    # ---------- filesystem walk: project build output + big old files ----------
    def bump(self, d, ts):
        while d and self.newest.get(d, 0) < ts:
            self.newest[d] = ts
            parent = os.path.dirname(d)
            d = parent if parent != d else None

    def git_root(self, d):
        cur, seen, root = d, [], None
        while cur and cur != "/":
            if cur in self.git_root_cache:
                root = self.git_root_cache[cur]; break
            seen.append(cur)
            if os.path.isdir(os.path.join(cur, ".git")):
                root = cur; break
            cur = os.path.dirname(cur)
        for s in seen: self.git_root_cache[s] = root
        return root

    def walk(self):
        root = str(self.walk_root)
        stack = [root]
        start = time.time()
        dirs = 0
        while stack:
            if time.time() - start > self.time_budget:
                self.partial = True; break
            d = stack.pop()
            dirs += 1
            if self.on_progress and dirs % 5000 == 0:
                self.on_progress({"dirs": dirs, "elapsed": time.time() - start, "current": d})
            try: entries = list(os.scandir(d))
            except OSError: continue
            names = {e.name for e in entries}
            newest = 0
            for e in entries:
                try:
                    if e.is_symlink(): continue
                    if e.is_dir():
                        if e.name in SKIP_NAMES or e.path in self.skip: continue
                        if self.os_root and d == root and e.name in OS_ROOT_DIRS: continue
                        if e.stat().st_dev != self.dev: continue
                        if self.is_artifact(d, e.name, names) and self.is_project(d):
                            proj = self.git_root(d) or d
                            self.artifacts.setdefault(proj, []).append(e.path)
                            continue
                        if e.name == "node_modules": continue   # stray, never descend
                        stack.append(e.path)
                    elif e.is_file():
                        st = e.stat()
                        if e.name.startswith(("build.gradle", "gradle-wrapper.properties")) and st.st_size < 1 << 20:
                            self.read_refs(e.path)
                        newest = max(newest, st.st_mtime)
                        if st.st_size >= BIG_FILE and self.now - st.st_mtime > BIG_FILE_DAYS * DAY:
                            self.big_files.append((e.path, st.st_size, st.st_mtime))
                except OSError:
                    continue
            if newest: self.bump(d, newest)

    def is_project(self, d):
        """Real source projects only: not installed extensions/packages inside hidden app folders."""
        rel = os.path.relpath(d, self.walk_root)
        if any(part.startswith(".") for part in rel.split(os.sep) if part != "."):
            return False
        return self.git_root(d) is not None or os.path.isdir(os.path.join(d, "src"))

    def read_refs(self, path):
        try: text = Path(path).read_text(errors="ignore")
        except OSError: return
        self.refs["ndk"].update(re.findall(r'ndkVersion\s*=?\s*"([0-9.]+)"', text))
        self.refs["gradle"].update(re.findall(r"gradle-([0-9.]+)-(?:all|bin)\.zip", text))

    @staticmethod
    def is_artifact(parent, name, siblings):
        if name not in ARTIFACTS: return False
        if name in (".venv", "venv", "env"):
            return os.path.isfile(os.path.join(parent, name, "pyvenv.cfg"))
        return any(s in siblings for s in ARTIFACTS[name])

    @staticmethod
    def git_tracked(proj, art):
        if Path(art).name not in ("build", "dist", "env", "target"): return False
        try:
            out = subprocess.run(["git", "-C", proj, "ls-files", "--", os.path.relpath(art, proj)],
                                 capture_output=True, text=True, timeout=10).stdout
            return bool(out.strip())
        except Exception: return False

    def projects(self, held):
        jobs = []
        for proj, arts in self.artifacts.items():
            last = self.newest.get(proj, 0)
            try:
                ct = subprocess.run(["git", "-C", proj, "log", "-1", "--format=%ct"],
                                    capture_output=True, text=True, timeout=10).stdout.strip()
                if ct: last = max(last, int(ct))
            except Exception: pass
            if not self.idle(last): continue
            arts = [a for a in arts if not self.git_tracked(proj, a)]
            if arts and not in_use(arts, held):
                jobs.append((proj, arts, last))
        with ThreadPoolExecutor(8) as pool:
            sizes = list(pool.map(lambda j: du(j[1]), jobs))
        for (proj, arts, last), size in zip(jobs, sizes):
            kinds = sorted({Path(a).name for a in arts})
            venv = any(k in (".venv", "venv", "env") for k in kinds)
            self.add("build", f"{self.short(proj)}: {'+'.join(kinds)}", arts, size, last,
                     "Python env: reinstall packages to use again" if venv else "rebuilds on next build/install")

    def short(self, p):
        p = str(p)
        for base, tag in ((str(self.walk_root), ""), (str(HOME), "~")):
            if p.startswith(base + "/"):
                return (tag + "/" if tag else "") + p[len(base) + 1:]
        return p

    def big(self, claimed, held):
        files = [f for f in self.big_files
                 if not any(f[0].startswith(c + "/") for c in claimed) and not in_use([f[0]], held)]
        for path, size, mtime in sorted(files, key=lambda f: -f[1])[:15]:
            unfinished = path.endswith((".incomplete", ".part", ".crdownload", ".partial"))
            self.add("file", self.short(path), [path], size, mtime,
                     "unfinished download" if unfinished else "single file, not touched in 90+ days")

    # ---------- managed stores (only when they live on this drive) ----------
    def hf_models(self, held):
        hub = HOME / ".cache/huggingface/hub"
        if not self.on_drive(hub): return
        for m in sorted(hub.glob("models--*")):
            if in_use([str(m)], held): continue
            name = m.name[len("models--"):].replace("--", "/")
            snaps = list(m.glob("snapshots/*"))
            ts = max((s.stat().st_mtime for s in snaps), default=m.stat().st_mtime)
            self.add("model", f"AI model {name}", [m], du([str(m)]), ts, "downloads again if needed",
                     when="downloaded")

    def conda_envs(self, held):
        for base in (HOME / "miniconda3", HOME / "anaconda3"):
            envs = base / "envs"
            if not envs.is_dir() or not self.on_drive(envs): continue
            for env in sorted(envs.iterdir()):
                hist = env / "conda-meta" / "history"
                if not hist.exists() or in_use([str(env)], held): continue
                ts = max(hist.stat().st_mtime, env.stat().st_mtime)
                if not self.idle(ts): continue
                self.add("conda", f"conda env {env.name}", [env], du([str(env)]), ts,
                         "must be recreated to use again")

    def project_refs(self):
        """ndkVersion / Gradle versions any project uses: $HOME now, other drives from their last deep scan.
        Returns None unless every mounted data drive has been deep-scanned once."""
        cache = load_refs()
        missing = [d for d in mounts() if d.startswith(("/media/", "/mnt/")) and d not in cache]
        if missing:
            self.notes.append("NDK/Gradle cleanup needs a deep scan of "
                              + ", ".join(Path(d).name for d in missing) + " first")
            return None
        ndk, gradle = set(self.refs["ndk"]), set(self.refs["gradle"])
        for v in cache.values():
            ndk.update(v["ndk"]); gradle.update(v["gradle"])
        try:
            out = subprocess.run(["rg", "-oIN", "--no-messages", "-g", "*.gradle*", "-g", "gradle-wrapper.properties",
                                  r'ndkVersion\s*=?\s*"[0-9.]+"|gradle-[0-9.]+-(?:all|bin)\.zip', str(HOME)],
                                 capture_output=True, text=True, timeout=60).stdout
        except Exception:
            return None
        ndk.update(re.findall(r'"([0-9.]+)"', out))
        gradle.update(re.findall(r"gradle-([0-9.]+)-", out))
        return ndk, gradle

    def android_gradle(self, held):
        sdk = HOME / "Android/Sdk"
        dists = HOME / ".gradle/wrapper/dists"
        if not (self.on_drive(sdk) or self.on_drive(dists)): return
        refs = self.project_refs()
        if refs is None: return     # can't tell what's referenced: list nothing
        ndk_refs, gradle_refs = refs
        ndks = sorted((sdk / "ndk").glob("*"), key=lambda p: [int(x) for x in re.findall(r"\d+", p.name)])
        for ndk in ndks[:-1]:       # always keep the newest (AGP default)
            if ndk.name not in ndk_refs and not in_use([str(ndk)], held):
                self.add("android", f"Android NDK {ndk.name}", [ndk], du([str(ndk)]), ndk.stat().st_mtime,
                         "no project's ndkVersion uses it")
        avd_config = "".join(ini.read_text(errors="ignore") for ini in (HOME / ".android/avd").glob("*.avd/config.ini"))
        for img in (sdk / "system-images").glob("*/*/*"):
            rel = str(img.relative_to(sdk))
            if rel not in avd_config:
                self.add("android", f"emulator image {rel}", [img], du([str(img)]), img.stat().st_mtime,
                         "no AVD uses it")
        for avd in (HOME / ".android/avd").glob("*.avd"):
            ts = max((f.stat().st_mtime for f in avd.iterdir()), default=avd.stat().st_mtime)
            if self.idle(ts) and not in_use([str(avd)], held):
                self.add("android", f"emulator {avd.stem}", [avd, avd.with_suffix(".ini")], du([str(avd)]), ts,
                         "emulator and its data")
        if gradle_refs:
            for dist in sorted(dists.glob("gradle-*")):
                ver = re.sub(r"^gradle-|-(all|bin)$", "", dist.name)
                if ver in gradle_refs or in_use([str(dist)], held): continue
                cache = HOME / ".gradle/caches" / ver
                paths = [dist] + ([cache] if cache.is_dir() else [])
                self.add("gradle", f"Gradle {ver}", paths, du([str(p) for p in paths]), dist.stat().st_mtime,
                         "no project's wrapper uses it")

    def docker_volumes(self):
        if not self.on_drive(Path("/var/lib/docker")): return
        try:
            names = subprocess.run(["docker", "volume", "ls", "-qf", "dangling=true"],
                                   capture_output=True, text=True, timeout=30).stdout.split()
            if not names: return
            vols = json.loads(subprocess.run(["docker", "system", "df", "-v", "--format", "{{json .Volumes}}"],
                                             capture_output=True, text=True, timeout=60).stdout or "[]")
        except Exception:
            return
        size_of = {v["Name"]: v.get("Size", "0B") for v in vols}
        for n in names:
            anon = re.fullmatch(r"[0-9a-f]{64}", n) is not None
            self.add("docker", f"docker volume {n[:12]}…" if anon else f"docker volume {n}",
                     [f"docker-volume:{n}"], parse_size(size_of.get(n, "0B")), 0,
                     "anonymous, unattached" if anon else "named, unattached: may hold a stopped stack's data")

    def run(self):
        held = held_paths()
        self.walk()
        self.projects(held)
        self.hf_models(held)
        self.conda_envs(held)
        self.android_gradle(held)
        self.docker_volumes()
        self.big([p for it in self.items for p in it["paths"]], held)
        if not self.partial and os.path.ismount(self.target) and self.target != Path("/"):
            cache = load_refs()
            cache[str(self.target)] = {k: sorted(v) for k, v in self.refs.items()}
            REFS.parent.mkdir(parents=True, exist_ok=True)
            REFS.write_text(json.dumps(cache))
        self.items.sort(key=lambda i: -i["size"])
        return self.items[:MAX_ITEMS]
