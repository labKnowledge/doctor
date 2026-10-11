"""Vulnerabilities that can actually hurt this computer, and the fewest actions that remove them.

Ubuntu's CVE data × installed versions × exploited in the wild (CISA KEV, EPSS) × what really runs here (as root,
reachable from the network) gives a short, fixable list instead of thousands of CVEs ranked by CVSS, which
predicts real attacks poorly (Allodi & Massacci 2014; EPSS, Jacobs et al.). Feeds download in the background at
most once a day; a check-up only reads a small index of rules for the installed packages (~20 ms).
Also here: CPU flaws, firmware protection (fwupd HSI), and packages installed without a signature check.
Design and validation: docs/research/2026-10-11-vulnerability-triage.md"""
import bz2, csv, glob, gzip, json, os, re, shlex, subprocess, time, urllib.request
import xml.etree.ElementTree as ET

from .core import CRIT, INFO, LAUNCHER, OK, SKIP, WARN, check, finding, fix, read

FEEDS = {
    "oval.xml.bz2": "https://security-metadata.canonical.com/oval/com.ubuntu.{release}.cve.oval.xml.bz2",
    "kev.json": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
    "epss.csv.gz": "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
}
FRESH = 20 * 3600          # re-download after this
OLD = 7 * 86400            # warn that results may be out of date
EPSS_LIKELY = 0.1          # "likely to be exploited" (EPSS: probability of exploitation in the next 30 days)
UNUSED_DAYS = 60           # a package nobody ran for this long can go, if nothing needs it
PROTECTED = re.compile(r"^(linux-|systemd|libc6|libc-bin|dpkg|apt|ubuntu-|gnome-shell|gdm3|sudo|openssh|grub|shim|init)")
# Words in CISA's vendor/product names that say nothing about which package is meant.
GENERIC = {"server", "linux", "kernel", "library", "the", "and", "for", "open", "source", "project", "software", "inc",
           "foundation", "corporation", "enterprise", "edition", "platform", "framework", "manager", "client", "core", "multiple"}


def data_dir(ctx):
    d = os.path.join(os.environ.get("DOCTOR_DATA") or os.path.join(ctx.home, ".local/state/doctor"), "vuln")
    os.makedirs(d, mode=0o700, exist_ok=True)
    return d


def release():
    """Ubuntu codename (noble, ...) or None: the feeds are Ubuntu's."""
    osr = dict(re.findall(r'^(\w+)="?([^"\n]*)"?', read("/etc/os-release"), re.M))
    return osr.get("VERSION_CODENAME") if osr.get("ID") == "ubuntu" else None


# ---------- feeds and index ----------

def refresh(ctx, download=True, say=lambda s: None):
    """Download the feeds when stale, then compile the index of rules that name an installed package."""
    d, rel = data_dir(ctx), release()
    if not rel:
        return "Vulnerability data exists for Ubuntu only."
    lock = os.path.join(d, "refresh.lock")
    if os.path.exists(lock) and time.time() - os.path.getmtime(lock) < 900:
        return "Already refreshing."
    open(lock, "w").close()
    try:
        status = _load(os.path.join(d, "status.json")) or {}
        if download and time.time() - status.get("fetched", 0) > FRESH:
            try:
                for name, url in FEEDS.items():
                    say(f"Downloading {name.split('.')[0].upper()}...")
                    with urllib.request.urlopen(url.format(release=rel), timeout=60) as r:
                        data = r.read()
                    with open(os.path.join(d, name + ".part"), "wb") as fh:
                        fh.write(data)
                for name in FEEDS:
                    os.replace(os.path.join(d, name + ".part"), os.path.join(d, name))
                status.update(fetched=time.time(), error="")
            except OSError as e:
                status["error"] = str(e)[:200]
            _save(os.path.join(d, "status.json"), status)
        if not all(os.path.exists(os.path.join(d, n)) for n in FEEDS):
            return "Couldn't download the vulnerability data: " + (status.get("error") or "no network")
        say("Building the index for the installed packages...")
        _save(os.path.join(d, "index.json"), compile_index(d, installed()[0], status.get("fetched", 0)))
        return ""
    finally:
        os.remove(lock)


def compile_index(d, pkgs, fetched):
    """OVAL definition -> test -> object (binary package names) + state (fixed version), kept for installed packages."""
    tag = lambda el: el.tag.rsplit("}", 1)[-1]
    defs, tests, objects, states, variables = [], {}, {}, {}, {}
    for _, el in ET.iterparse(bz2.open(os.path.join(d, "oval.xml.bz2")), events=("end",)):
        t = tag(el)
        if t == "definition":
            cve = el.find(".//{*}cve")
            if cve is not None:
                defs.append((cve.text, float(cve.get("cvss_score") or 0),
                             [c.get("test_ref") for c in el.iter() if tag(c) == "criterion"]))
            el.clear()
        elif t == "dpkginfo_test":
            o, s = el.find("{*}object"), el.find("{*}state")
            tests[el.get("id")] = (o.get("object_ref") if o is not None else None, s.get("state_ref") if s is not None else None)
        elif t == "dpkginfo_object":
            n = el.find("{*}name")
            objects[el.get("id")] = n.get("var_ref") if n is not None else None
        elif t == "dpkginfo_state":
            evr = el.find("{*}evr")
            states[el.get("id")] = evr.text if evr is not None else None
        elif t == "constant_variable":
            variables[el.get("id")] = [v.text for v in el.findall("{*}value")]
            el.clear()
    rules = []
    for cve, cvss, refs in defs:
        for ref in refs:
            obj, state = tests.get(ref, (None, None))
            for p in variables.get(objects.get(obj), []):
                if p in pkgs:
                    rules.append([cve, p, states.get(state), cvss])
    cves = {r[0] for r in rules}
    kev = {v["cveID"]: [v.get("vendorProject", ""), v.get("product", "")]
           for v in json.load(open(os.path.join(d, "kev.json")))["vulnerabilities"] if v["cveID"] in cves}
    with gzip.open(os.path.join(d, "epss.csv.gz"), "rt") as fh:
        epss = {r["cve"]: float(r["epss"]) for r in csv.DictReader(l for l in fh if not l.startswith("#")) if r["cve"] in cves}
    return {"built": time.time(), "fetched": fetched, "release": release(), "dpkg": _dpkg_mtime(),
            "rules": rules, "kev": kev, "epss": epss}


def ensure_fresh(ctx, index):
    """Start a background refresh when the feeds are old or packages changed since the index was built."""
    stale = not index or time.time() - index.get("fetched", 0) > FRESH or index.get("dpkg") != _dpkg_mtime()
    if not stale or os.environ.get("DOCTOR_NO_REFRESH"):
        return
    argv = [LAUNCHER, "vulns", "--refresh", "--quiet"] + (["--offline"] if os.environ.get("DOCTOR_OFFLINE") else [])
    if ctx.is_root and ctx.user != "root":   # the index belongs to the user, not to root
        argv = ["runuser", "-u", ctx.user, "--"] + argv
    try:
        subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    except OSError:
        pass


def installed():
    """{package: version} and {package: (source, essential, priority)} for installed packages."""
    out = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${db:Status-Abbrev}\t${source:Package}\t"
                          "${Essential}\t${Priority}\n"], capture_output=True, text=True).stdout
    vers, meta = {}, {}
    for line in out.splitlines():
        p = line.split("\t")
        if len(p) == 6 and p[2].startswith("ii"):
            vers[p[0]] = p[1]
            meta[p[0]] = (p[3] or p[0], p[4] == "yes", p[5])
    return vers, meta


# ---------- what runs here ----------

# Runs as root when possible (a separate interpreter, so it sees every process): for every file a process maps or
# executes, whether a process runs it at all (1), as root (2), or while listening on a non-loopback address (4);
# the oldest such process's start time; and for deleted (since updated) files the programs still using them.
EXPOSURE = r'''
import json, os
def listening():
    out = set()
    for name in ("tcp", "tcp6", "udp", "udp6"):
        try:
            lines = open("/proc/net/" + name).read().splitlines()[1:]
        except OSError:
            continue
        for l in lines:
            p = l.split()
            addr, port = p[1].split(":")
            if p[3] != ("0A" if name.startswith("tcp") else "07") or name.startswith("udp") and int(port, 16) >= 32768:
                continue
            loop = addr[-2:] == "7F" if len(addr) == 8 else addr == "0" * 24 + "01000000" or addr[:24] == "0" * 16 + "FFFF0000" and addr[-2:] == "7F"
            if not loop:
                out.add(p[9])
    return out
inodes, paths = listening(), {}
boot = int(next(l for l in open("/proc/stat") if l.startswith("btime")).split()[1])
for pid in filter(str.isdigit, os.listdir("/proc")):
    try:
        uid = int(open(f"/proc/{pid}/status").read().split("\nUid:")[1].split()[0])
        start = boot + int(open(f"/proc/{pid}/stat").read().rsplit(")", 1)[1].split()[19]) / os.sysconf("SC_CLK_TCK")
        comm = open(f"/proc/{pid}/comm").read().strip()
        public = False
        for fd in os.listdir(f"/proc/{pid}/fd") if inodes else ():
            try:
                link = os.readlink(f"/proc/{pid}/fd/{fd}")
            except OSError:
                continue
            if link.startswith("socket:[") and link[8:-1] in inodes:
                public = True
                break
        files = {line[line.index("/"):].rstrip("\n") for line in open(f"/proc/{pid}/maps") if "/" in line}
        files.add(os.readlink(f"/proc/{pid}/exe"))
    except (OSError, IndexError, ValueError):
        continue
    for f in files:
        e = paths.setdefault(f, [0, start, []])
        e[0] |= 1 | (2 if uid == 0 else 0) | (4 if public else 0)
        e[1] = min(e[1], start)
        if f.endswith(" (deleted)") and comm not in e[2] and len(e[2]) < 6:
            e[2].append(comm)
print(json.dumps(paths))
'''


def exposure(ctx):
    cmd = "/usr/bin/python3 -I -c " + shlex.quote(EXPOSURE)
    out = ctx.run(cmd, root=True, timeout=40)
    full = bool(out)
    try:
        return json.loads(out if full else ctx.run(cmd, timeout=40)), full
    except ValueError:
        return {}, False


_LISTS, _FILES = {}, {}


def _list_path(pkg):
    """dpkg's file list for a package (name.list or name:arch.list); the folder is listed once, it holds thousands."""
    if not _LISTS:
        for name in os.listdir("/var/lib/dpkg/info"):
            if name.endswith(".list"):
                _LISTS.setdefault(name[:-5].split(":")[0], os.path.join("/var/lib/dpkg/info", name))
    return _LISTS.get(pkg)


def package_files(pkg):
    if pkg not in _FILES:
        path = _list_path(pkg)
        _FILES[pkg] = [l for l in read(path).splitlines() if l.startswith(("/usr/", "/bin/", "/sbin/", "/lib", "/opt/"))] if path else []
    return _FILES[pkg]


def updated_at(pkg):
    path = _list_path(pkg)
    try:
        return os.path.getmtime(path) if path else 0
    except OSError:
        return 0


# ---------- matching and scoring (pure) ----------

def match(rules, vers, compare):
    """Rules whose package is installed at a version below the fix (or with no fix released yet)."""
    return [r for r in rules if r[1] in vers and (r[2] is None or compare(vers[r[1]], r[2]) < 0)]


def _order(c):
    """Sort weight of one character in the non-digit part of a Debian version; "" is the end of the part."""
    return -1 if c == "~" else 0 if not c else ord(c) if c.isalpha() else ord(c) + 256


def _cmp_part(a, b):
    """Debian Policy 5.6.12: alternate non-digit runs (letters before other characters, ~ before everything, even
    the end) and digit runs compared as numbers."""
    while a or b:
        na, nb = re.match(r"\D*", a).group(), re.match(r"\D*", b).group()
        a, b = a[len(na):], b[len(nb):]
        for i in range(max(len(na), len(nb))):
            oa, ob = _order(na[i:i + 1]), _order(nb[i:i + 1])
            if oa != ob:
                return -1 if oa < ob else 1
        da, db = re.match(r"\d*", a).group(), re.match(r"\d*", b).group()
        a, b = a[len(da):], b[len(db):]
        if int(da or 0) != int(db or 0):
            return -1 if int(da or 0) < int(db or 0) else 1
    return 0


def version_compare(a, b):
    """Same answer as apt_pkg.version_compare (sign only), for interpreters without python3-apt."""
    def split(v):
        epoch, _, rest = v.rpartition(":") if ":" in v else ("0", "", v)
        up, _, rev = rest.rpartition("-") if "-" in rest else (rest, "", "")
        return int(epoch or 0), up, rev
    (ea, ua, ra), (eb, ub, rb) = split(a), split(b)
    if ea != eb:
        return -1 if ea < eb else 1
    return _cmp_part(ua, ub) or _cmp_part(ra, rb)


def kev_matches(vendor, product, pkg, src):
    """CISA lists exploits per product; Ubuntu's mapping sometimes lands on another package (e.g. a WebLogic exploit
    on openjdk). Count a KEV entry as exploited here only when the product names this package."""
    words = [w for w in re.split(r"[^a-z0-9]+", f"{vendor} {product}".lower()) if len(w) >= 3 and w not in GENERIC]
    hay = f"{pkg} {src}".lower()
    return not words or any(w in hay for w in words)


def score(h):
    """Chance of exploitation × how reachable it is here. Only the order reaches the user."""
    p = 1.0 if h["kev"] else max(h["epss"], 5e-4)
    return p * (8 if h["flags"] & 4 else 1) * (3 if h["flags"] & 2 else 1) * (2 if h["flags"] & 1 else 0.25)


def worth_acting(h):
    return h["kev"] or h["epss"] >= EPSS_LIKELY or (h["flags"] & 4 and h["epss"] >= 0.01)


# ---------- analysis ----------

def analyze(ctx):
    """Everything the check, the fixes and `doctor vulns` need; cached for the run."""
    if "vulns" in ctx._cache:
        return ctx._cache["vulns"]
    res = ctx._cache["vulns"] = _analyze(ctx)
    return res


def _analyze(ctx):
    try:
        import apt_pkg
        apt_pkg.init_system()
        compare = apt_pkg.version_compare
    except ImportError:
        compare = version_compare
    if not release():
        return {"skip": "The vulnerability check uses Ubuntu's security data; this isn't Ubuntu"}
    d = data_dir(ctx)
    index = _load(os.path.join(d, "index.json"))
    ensure_fresh(ctx, index)
    if not index or index.get("release") != release():
        status = _load(os.path.join(d, "status.json")) or {}
        return {"pending": status.get("error") or ""}
    vers, meta = installed()
    hits = match(index["rules"], vers, compare)
    paths, full = exposure(ctx)
    kernel = os.uname().release
    flags_of, rows = {}, []
    for c, p, fixed, cvss in hits:
        if re.search(r"\d+\.\d+\.\d+-\d+", p) and kernel not in p:
            continue                      # an older kernel that isn't running: not reachable
        if p not in flags_of:
            fl = 0
            for f in package_files(p):
                fl |= paths.get(f, [0])[0] | paths.get(f + " (deleted)", [0])[0]
            flags_of[p] = fl | (3 if kernel in p else 0)
        src = meta.get(p, (p,))[0]
        k = index["kev"].get(c)
        rows.append({"cve": c, "pkg": p, "src": src, "have": vers[p], "fixed": fixed, "cvss": cvss,
                     "kev": bool(k) and kev_matches(*k, p, src), "kev_other": k[1] if k and not kev_matches(*k, p, src) else "",
                     "epss": index["epss"].get(c, 0.0), "flags": flags_of[p]})
    rows.sort(key=score, reverse=True)
    return {"rows": rows, "vers": vers, "meta": meta, "paths": paths, "full": full, "index": index,
            "pro": _pro_attached(ctx), "residue": residue(index["rules"], vers, paths, compare)}


def residue(rules, vers, paths, compare):
    """Packages updated with security fixes while programs kept running the old code: {pkg: [programs]}."""
    if not any(k.endswith(" (deleted)") for k in paths):
        return {}
    fixed_pkgs = {p for c, p, f, _ in rules if f and p in vers and compare(vers[p], f) >= 0}
    out = {}
    for p in fixed_pkgs:
        when = updated_at(p)
        for f in package_files(p):
            e = paths.get(f + " (deleted)")
            if e and e[1] < when:
                out.setdefault(p, []).extend(x for x in e[2] if x not in out.get(p, []))
    return out


def plan(ctx, a):
    """The fewest actions that remove the most risk: each covers many (CVE, package) pairs."""
    rows, actions = a["rows"], []
    urgent_free = sorted({r["pkg"] for r in rows if r["fixed"] and "esm" not in r["fixed"] and worth_acting(r)})
    if urgent_free:
        actions.append(("update", urgent_free, len({r["cve"] for r in rows if r["pkg"] in urgent_free and r["fixed"]})))
    pro = sorted({r["pkg"] for r in rows if r["fixed"] and "esm" in r["fixed"]})
    if pro:
        n = len({r["cve"] for r in rows if r["fixed"] and "esm" in r["fixed"]})
        actions.append(("update" if a["pro"] else "pro", pro, n))
    for src, pkgs, n, last in removable(ctx, a):
        actions.append(("remove", pkgs, n, src, last))
    return actions


def removable(ctx, a):
    """Software with unpatched flaws that nobody uses: not running, untouched for UNUSED_DAYS, and removing it takes
    nothing else with it (checked with apt's own simulation, cached until packages change)."""
    if "noatime" in ctx.run("findmnt -no OPTIONS --target /usr"):
        return []                      # no record of when programs were last used
    by_src = {}
    for r in a["rows"]:
        if not r["fixed"]:
            by_src.setdefault(r["src"], []).append(r)
    cands = []
    for src, rs in by_src.items():
        risky = any(r["kev"] or r["epss"] >= 0.01 for r in rs) or len({r["cve"] for r in rs}) >= 10
        family = sorted(p for p, m in a["meta"].items() if m[0] == src)
        if not risky or any(a["meta"][p][1] or a["meta"][p][2] in ("required", "important") or PROTECTED.match(p) for p in family):
            continue
        files = [f for p in family for f in package_files(p)]
        if any(f in a["paths"] or f + " (deleted)" in a["paths"] for f in files):
            continue
        # Last use = when one of its programs last ran; plugins and libraries get read by scanners too, so they only
        # count for packages without programs.
        progs = [f for f in files if re.search(r"/s?bin/", f)] or [f for f in files if ".so" in f]
        used = max((_atime(f) for f in progs), default=0)
        if not used or time.time() - used < UNUSED_DAYS * 86400:
            continue
        cands.append((src, family, len({r["cve"] for r in rs}), used))
    cache_path = os.path.join(data_dir(ctx), "removal.json")
    cache = _load(cache_path) or {}
    if cache.get("dpkg") != _dpkg_mtime():
        cache = {"dpkg": _dpkg_mtime(), "sim": {}}
    out = []
    for src, family, n, used in sorted(cands, key=lambda c: -c[2])[:3]:
        if src not in cache["sim"]:
            sim = ctx.run("apt-get -s remove " + " ".join(family), timeout=60)
            cache["sim"][src] = re.findall(r"^Remv (\S+)", sim, re.M)
        if cache["sim"][src] and set(cache["sim"][src]) <= set(family):
            out.append((src, family, n, used))
    _save(cache_path, cache)
    return out


# ---------- checks ----------

@check("security", "vulnerabilities")
def vulnerabilities(ctx):
    a = analyze(ctx)
    if "skip" in a:
        return [finding(SKIP, a["skip"])]
    if "pending" in a:
        why = f" (last try failed: {a['pending']})" if a["pending"] else ""
        return [finding(INFO, "Vulnerability data is downloading in the background (about 15 MB, once a day)" + why,
                        ["Results appear on the next check-up. Or now: doctor vulns"])]
    rows, res, planned = a["rows"], [], set()
    age = time.time() - a["index"].get("fetched", 0)
    stale = [f"The vulnerability data is {age / 86400:.0f} days old: it couldn't be updated."] if age > OLD else []
    for act in plan(ctx, a):
        planned.update(act[1])
        if act[0] == "update":
            pkgs, n = act[1], act[2]
            res.append(finding(CRIT if any(r["kev"] for r in rows if r["pkg"] in pkgs) else WARN,
                               f"Security fixes ready for {len(pkgs)} package(s) with flaws that matter here",
                               [f"{n} known flaw(s): " + ", ".join(pkgs[:8])] + stale,
                               fix(f"Install the fixes for {', '.join(pkgs[:3])}{' and more' if len(pkgs) > 3 else ''}",
                                   "apt-get update -qq\nDEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade "
                                   + " ".join(pkgs)), key="vuln-update"))
        elif act[0] == "pro":
            pkgs, n = act[1], act[2]
            serious = [r for r in rows if r["fixed"] and "esm" in r["fixed"] and worth_acting(r)]
            res.append(finding(WARN if serious else INFO,
                               f"Ubuntu Pro would fix {n} known flaw(s) in {len(pkgs)} package(s); it's free for personal use",
                               ["Only Ubuntu Pro ships these fixes: " + ", ".join(sorted({r['src'] for r in rows if r['pkg'] in pkgs})[:8]),
                                "The fix shows a short code: enter it at ubuntu.com/pro/attach (sign in, free for up to 5 computers).",
                                "Undo: sudo pro detach"] + stale,
                               fix("Attach Ubuntu Pro (free for personal use) and install its security fixes",
                                   "PYTHONUNBUFFERED=1 pro attach\napt-get update -qq\n"
                                   "DEBIAN_FRONTEND=noninteractive apt-get install -y --only-upgrade " + " ".join(pkgs), safe=False),
                               key="vuln-pro"))
        elif act[0] == "remove":
            pkgs, n, src, used = act[1], act[2], act[3], act[4]
            res.append(finding(WARN, f"{src} has {n} unpatched flaw(s) and hasn't been used since "
                                     f"{time.strftime('%b %d', time.localtime(used))}: remove it",
                               ["No fix exists yet, and nothing else on this computer needs it (checked with apt).",
                                "Undo: sudo apt-get install " + " ".join(pkgs)],
                               fix(f"Remove {src} ({len(pkgs)} package(s))",
                                   "DEBIAN_FRONTEND=noninteractive apt-get remove -y " + " ".join(pkgs), safe=False),
                               key=f"vuln-remove:{src}"))
    watch = {}
    for r in rows:
        if worth_acting(r) and r["pkg"] not in planned and r["src"] not in watch:
            watch[r["src"]] = r
    if watch:
        res.append(finding(INFO, f"{len(watch)} exploited or likely-exploited flaw(s) with no fix yet; keep an eye on them",
                           [_why(r) for r in list(watch.values())[:4]] + ["The full list: doctor vulns"], key="vuln-watch"))
    if a["residue"]:
        names = sorted({x for v in a["residue"].values() for x in v})
        res.append(finding(INFO, f"Security updates are installed, but {len(names)} program(s) still run the old code",
                           [", ".join(names[:10]), "Restart them, or log out and back in, to finish updating "
                            + ", ".join(sorted(a["residue"])[:5])], key="vuln-residue"))
    if not [f for f in res if f["level"] in (WARN, CRIT)]:
        known = len({r["cve"] for r in rows})
        res.append(finding(OK, f"No vulnerabilities worth acting on ({known} known flaw(s) in installed software, "
                               "none exploited or reachable here)" if known else "No known vulnerabilities in installed software",
                           stale + ([] if a["full"] else ["Only your own programs were checked (sudo checks all)."])))
    return res


def _why(r):
    what = ("exploited in the wild" if r["kev"] else f"exploited in {r['kev_other']}, not this package"
            if r["kev_other"] else f"{r['epss']:.0%} chance of exploitation within a month")
    where = ("open to the network" if r["flags"] & 4 else "running as root" if r["flags"] & 2 else "running"
             if r["flags"] & 1 else "installed, not running")
    return f"{r['pkg']}: {r['cve']}, {what}; {where}. No fix yet: remove it if unused, keep it off the network"


CPU_NAMES = {"gather_data_sampling": "Downfall (GDS)", "spectre_v1": "Spectre v1", "spectre_v2": "Spectre v2",
             "meltdown": "Meltdown", "mds": "MDS (ZombieLoad)", "retbleed": "Retbleed", "srbds": "SRBDS (CrossTalk)",
             "mmio_stale_data": "MMIO stale data", "l1tf": "L1TF (Foreshadow)", "spec_store_bypass": "Speculative Store Bypass",
             "tsx_async_abort": "TAA", "itlb_multihit": "iTLB multihit", "reg_file_data_sampling": "RFDS",
             "spec_rstack_overflow": "Inception (SRSO)", "indirect_target_selection": "ITS", "tsa": "TSA"}
# Kernel switches that mitigate a flaw when the CPU maker shipped no microcode for it, and what they cost.
CPU_PARAMS = {"gather_data_sampling": ("gather_data_sampling=force",
                                       "turns off AVX: video encoding, AI and some games get slower")}
GRUB_DROPIN = "/etc/default/grub.d/90-doctor-cpu.cfg"


@check("security", "cpu-flaws")
def cpu_flaws(ctx):
    base = "/sys/devices/system/cpu/vulnerabilities"
    if not os.path.isdir(base):
        return [finding(SKIP, "CPU flaw status not available from the kernel")]
    bad = {n: read(os.path.join(base, n)).strip() for n in sorted(os.listdir(base))}
    bad = {n: s for n, s in bad.items() if s.startswith("Vulnerable")}
    if not bad:
        return [finding(OK, "CPU flaws (Spectre, Meltdown and others) mitigated")]
    vendor = "intel" if "GenuineIntel" in read("/proc/cpuinfo") else "amd64"
    has_ucode = bool(ctx.run(f"dpkg-query -W -f '${{Status}}' {vendor}-microcode 2>/dev/null").startswith("install ok"))
    cmdline, res = read("/proc/cmdline"), []
    for n, s in bad.items():
        name = CPU_NAMES.get(n, n.replace("_", " "))
        if "microcode" in s.lower() and not has_ucode:
            res.append(finding(WARN, f"CPU flaw {name} is not mitigated: the CPU maker's fix isn't installed", [s],
                               fix(f"Install {vendor}-microcode (takes effect after a reboot)",
                                   f"DEBIAN_FRONTEND=noninteractive apt-get install -y {vendor}-microcode"), key=f"cpu:{n}"))
        elif n in CPU_PARAMS and CPU_PARAMS[n][0] in read(GRUB_DROPIN) and CPU_PARAMS[n][0] not in cmdline:
            res.append(finding(INFO, f"CPU flaw {name}: the mitigation is set up and starts after a reboot", [], key=f"cpu:{n}"))
        elif n in CPU_PARAMS and os.path.isdir(os.path.dirname(GRUB_DROPIN)) and ctx.has("update-grub"):
            param, cost = CPU_PARAMS[n]
            res.append(finding(WARN, f"CPU flaw {name} is not mitigated; the CPU maker released no fix for this processor",
                               [s, f"Linux can block it, but that {cost}. Worth it if others use this computer or you run "
                                   "untrusted code (VMs, downloads).", f"Undo: sudo rm {GRUB_DROPIN} && sudo update-grub"],
                               fix(f"Mitigate {name} at boot ({cost.split(':')[0]})",
                                   f"printf 'GRUB_CMDLINE_LINUX_DEFAULT=\"$GRUB_CMDLINE_LINUX_DEFAULT {param}\"\\n' > {GRUB_DROPIN}\n"
                                   "update-grub 2>&1 | tail -1\necho 'Takes effect after a reboot.'", safe=False), key=f"cpu:{n}"))
        else:
            res.append(finding(WARN, f"CPU flaw {name} is not mitigated", [s, "A BIOS update from the computer maker may fix it."],
                               key=f"cpu:{n}"))
    return res


HSI_WORDS = {"Spi": "the firmware chip can be rewritten from the system", "BootGuard": "the firmware isn't verified at power-on",
             "Mei": "the Intel management engine is outdated or unlocked", "SecureBoot": "Secure Boot is off",
             "Tpm": "the TPM security chip is missing or off", "Iommu": "devices can read memory directly (no IOMMU)",
             "Prebootdma": "devices can read memory during boot", "Uefi": "a UEFI setting is weak"}


def hsi_level(attrs):
    """fwupd's Host Security ID: the highest level 1-4 at which every check passes."""
    level = 0
    for lvl in range(1, 5):
        at = [x for x in attrs if x.get("HsiLevel") == lvl]
        if at and all("success" in x.get("Flags", []) for x in at):
            level = lvl
        else:
            break
    return level


@check("hardware", "firmware")
def firmware(ctx):
    if not ctx.has("fwupdmgr"):
        return [finding(SKIP, "Firmware security check needs fwupd (sudo apt install fwupd)")]
    try:
        attrs = json.loads(ctx.run("fwupdmgr security --json 2>/dev/null", timeout=20) or "{}").get("SecurityAttributes", [])
    except ValueError:
        attrs = []
    res = []
    try:
        devs = json.loads(ctx.run("fwupdmgr get-updates --json 2>/dev/null", timeout=20) or "{}").get("Devices", [])
    except ValueError:
        devs = []
    if devs:
        names = [d.get("Name", "?") for d in devs]
        res.append(finding(WARN, f"Firmware update(s) available for {', '.join(names[:3])}",
                           ["Firmware updates often fix security flaws. Keep the computer plugged in while it updates."],
                           fix("Install firmware updates (may restart the computer)", "fwupdmgr update -y --no-reboot-check",
                               safe=False), key="fw-updates"))
    if attrs:
        lvl = hsi_level(attrs)
        failing = [x for x in attrs if x.get("HsiLevel") == lvl + 1 and "success" not in x.get("Flags", [])]
        words = sorted({w for x in failing for k, w in HSI_WORDS.items() if k.lower() in x.get("AppstreamId", "").lower()})
        res.append(finding(INFO if lvl < 2 else OK, f"Firmware protection level HSI:{lvl} of 4",
                           (["Below the next level: " + "; ".join(words or [x.get("Name", "") for x in failing][:3]) + "."]
                            if failing else []) +
                           (["This is set by the computer maker (BIOS settings or update), not by software: "
                             "common on older or consumer boards. Details: fwupdmgr security"] if lvl < 2 else []),
                           key="fw-hsi"))
    return res or [finding(OK, "No firmware updates waiting")]


def unsigned_installs(history):
    """Packages installed with apt's signature check switched off, from apt history text: [(date, [pkgs])]."""
    out, when = [], ""
    for line in history.splitlines():
        if line.startswith("Start-Date:"):
            when = line.split(": ", 1)[1].split()[0]
        elif line.startswith("Commandline:") and re.search(r"--allow-unauthenticated|--allow-insecure-repositories|"
                                                           r"AllowUnauthenticated=(1|true)", line):
            words = line.split()[1:]
            if "install" in words:
                out.append((when, [w for w in words[words.index("install") + 1:] if not w.startswith("-")]))
    return out


@check("security", "package-trust")
def package_trust(ctx):
    history = ""
    for path in sorted(glob.glob("/var/log/apt/history.log*")):
        try:
            with (gzip.open(path, "rt", errors="replace") if path.endswith(".gz") else open(path, errors="replace")) as fh:
                history += fh.read()
        except OSError:
            pass
    vers = set(ctx.run("dpkg-query -W -f '${Package}\\n' 2>/dev/null").split())
    res, seen = [], {}
    for when, pkgs in unsigned_installs(history):
        for p in pkgs:
            if p.split("=")[0].split(":")[0] in vers:
                seen.setdefault(p.split("=")[0].split(":")[0], when)
    if seen:
        res.append(finding(WARN, f"{len(seen)} package(s) were installed with the signature check turned off",
                           [", ".join(f"{p} ({w})" for p, w in list(seen.items())[:6]),
                            "Anyone between you and the server could have swapped them. If they come from Ubuntu, "
                            "reinstall to verify: sudo apt-get install --reinstall " + " ".join(list(seen)[:6])],
                           key="unsigned-installs"))
    loose = []
    for path in glob.glob("/etc/apt/sources.list") + glob.glob("/etc/apt/sources.list.d/*"):
        txt = read(path)
        if re.search(r"trusted=yes|allow-insecure=yes|^Trusted:\s*yes|^Allow-Insecure:\s*yes", txt, re.M | re.I):
            loose.append(path)
    if loose:
        res.append(finding(WARN, f"{len(loose)} software source(s) skip the signature check", loose[:5] +
                           ["Packages from them are installed without proof of who made them. Add the source's signing key, "
                            "or remove the source if you no longer use it."], key="trusted-sources"))
    return res or [finding(OK, "All installed packages came with a verified signature")]


# ---------- doctor vulns ----------

def show(ctx, c=lambda code, s: s):
    a = analyze(ctx)
    if "skip" in a:
        print(a["skip"] + ".")
        return 0
    if "pending" in a:
        print("Getting the vulnerability data (about 15 MB, once a day)...")
        msg = refresh(ctx, download=not os.environ.get("DOCTOR_OFFLINE"), say=lambda s: print(c("2", "  " + s)))
        if msg:
            print(msg)
            return 1
        ctx._cache.pop("vulns", None)
        a = analyze(ctx)
    rows, idx = a["rows"], a["index"]
    cves = {r["cve"] for r in rows}
    when = time.strftime("%b %d", time.localtime(idx.get("fetched", 0)))
    print(c("1", f"\nVulnerabilities") + c("2", f"  ·  data from {when} (Ubuntu, CISA, EPSS)  ·  {len(a['vers'])} packages"
                                            + ("" if a["full"] else "  ·  your programs only (sudo checks all)")))
    if not rows:
        print("  No known vulnerabilities in installed software.")
        return 0
    fixed = [r for r in rows if r["fixed"]]
    print(f"  {len(cves)} known flaw(s) affect installed software:")
    free = {r["cve"] for r in fixed if "esm" not in r["fixed"]}
    pro = {r["cve"] for r in fixed if "esm" in r["fixed"]} - free
    print(c("2", f"    {len(free)} fixed by a normal update · {len(pro)} fixed by Ubuntu Pro · "
                 f"{len(cves - free - pro)} with no fix yet"))
    print(c("2", f"    {len({r['cve'] for r in rows if r['kev']})} exploited in the wild · "
                 f"{len({r['cve'] for r in rows if r['epss'] >= EPSS_LIKELY})} likely to be · "
                 f"{len({r['cve'] for r in rows if r['flags'] & 1})} in software that is running now"))
    acts = [f for f in vulnerabilities(ctx) if f.get("fix")]
    if acts:
        print(c("1", "\nWhat to do") + c("2", "  (run doctor, then doctor fix with the number shown)"))
        for f in acts:
            print(f"  • {f['fix']['label']}")
            print(c("2", f"      {f['title']}"))
    print(c("1", "\nMost at risk here") + c("2", "  (likelihood of attack × how reachable it is)"))
    print(c("2", f"  {'CVE':16} {'PACKAGE':26} {'WHY':38} FIX"))
    shown = set()
    for r in rows:
        if (r["cve"], r["src"]) in shown:
            continue
        shown.add((r["cve"], r["src"]))
        why = ("exploited" if r["kev"] else f"EPSS {r['epss']:.0%}") + (", network" if r["flags"] & 4 else ", root" if r["flags"] & 2
                                                                        else ", running" if r["flags"] & 1 else "")
        how = "Ubuntu Pro" if r["fixed"] and "esm" in r["fixed"] else "update" if r["fixed"] else "none yet"
        print(f"  {r['cve']:16} {r['pkg'][:26]:26} {why[:38]:38} {how}")
        if len(shown) >= 15:
            break
    return 0


def refresh_cli(ctx, quiet=False, offline=False):
    msg = refresh(ctx, download=not offline, say=(lambda s: None) if quiet else print)
    if not quiet:
        print(msg or "Vulnerability data up to date.")
    return 1 if msg else 0


# ---------- helpers ----------

def _dpkg_mtime():
    try:
        return int(os.path.getmtime("/var/lib/dpkg/status"))
    except OSError:
        return 0


def _atime(path):
    try:
        return os.stat(path).st_atime
    except OSError:
        return 0


def _pro_attached(ctx):
    try:
        return json.loads(ctx.run("pro api u.pro.status.is_attached.v1 2>/dev/null", timeout=20) or "{}")[
            "data"]["attributes"]["is_attached"]
    except (ValueError, KeyError, TypeError):
        return False


def _load(path):
    try:
        with open(path) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def _save(path, data):
    with open(path + ".tmp", "w") as fh:
        json.dump(data, fh)
    os.replace(path + ".tmp", path)
