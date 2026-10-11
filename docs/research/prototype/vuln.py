"""Prototype: exposure-aware vulnerability triage for one Ubuntu host.
Ubuntu CVE OVAL (what is vulnerable + fixed version) × dpkg (what is installed) × KEV/EPSS (is it exploited)
× runtime exposure (is it running, as root, reachable from the network)  →  ranked, fixable list."""
import bz2, csv, gzip, json, os, re, subprocess, sys, time
import xml.etree.ElementTree as ET
import apt_pkg

apt_pkg.init_system()
FEEDS = sys.argv[1] if len(sys.argv) > 1 else "feeds"
T = {}


def tick(name, t0):
    T[name] = time.perf_counter() - t0


# ---------- 1. parse OVAL: definition -> [(binary pkgs, fixed_version|None)] ----------
def parse_oval(path):
    t0 = time.perf_counter()
    ns_strip = lambda tag: tag.rsplit("}", 1)[-1]
    defs, tests, objects, states, variables = {}, {}, {}, {}, {}
    for _, el in ET.iterparse(bz2.open(path), events=("end",)):
        tag = ns_strip(el.tag)
        if tag == "definition":
            md = next(c for c in el if ns_strip(c.tag) == "metadata")
            cve = md.find(".//{*}cve")
            adv = md.find(".//{*}advisory")
            crits = [c.get("test_ref") for c in el.iter() if ns_strip(c.tag) == "criterion"]
            desc = (md.findtext("{*}description") or "")
            defs[el.get("id")] = {
                "cve": cve.text if cve is not None else md.findtext("{*}title", "").split()[0],
                "priority": cve.get("priority") if cve is not None else "",
                "cvss": float(cve.get("cvss_score") or 0) if cve is not None else 0.0,
                "av_network": "AV:N" in (cve.get("cvss_vector") or "") if cve is not None else False,
                "pro_only": "Available with Ubuntu Pro" in desc,
                "tests": crits}
            el.clear()
        elif tag == "dpkginfo_test":
            o, s = el.find("{*}object"), el.find("{*}state")
            tests[el.get("id")] = (o.get("object_ref") if o is not None else None, s.get("state_ref") if s is not None else None)
        elif tag == "dpkginfo_object":
            n = el.find("{*}name")
            objects[el.get("id")] = n.get("var_ref") if n is not None else None
        elif tag == "dpkginfo_state":
            evr = el.find("{*}evr")
            states[el.get("id")] = evr.text if evr is not None else None
        elif tag == "constant_variable":
            variables[el.get("id")] = [v.text for v in el.findall("{*}value")]
            el.clear()
    out = []
    for d in defs.values():
        for tid in d["tests"]:
            if tid not in tests:
                continue
            oid, sid = tests[tid]
            pkgs = variables.get(objects.get(oid), [])
            out.append((d, pkgs, states.get(sid)))   # fixed=None -> no fix released yet
    tick("parse OVAL", t0)
    return out


# ---------- 2. installed packages ----------
def installed():
    t0 = time.perf_counter()
    out = subprocess.run(["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${db:Status-Abbrev}\n"],
                         capture_output=True, text=True).stdout
    pk = {p: v for p, v, st in (l.split("\t") for l in out.splitlines()) if st.startswith("ii")}
    tick("dpkg-query", t0)
    return pk


# ---------- 3. threat intel ----------
def kev():
    d = json.load(open(os.path.join(FEEDS, "known_exploited_vulnerabilities.json")))
    return {v["cveID"]: v for v in d["vulnerabilities"]}


def epss():
    with gzip.open(os.path.join(FEEDS, "epss_scores-current.csv.gz"), "rt") as fh:
        rows = (l for l in fh if not l.startswith("#"))
        return {r["cve"]: float(r["epss"]) for r in csv.DictReader(rows)}


# ---------- 4. runtime exposure: package -> running? as root? listening on network? ----------
def exposure():
    t0 = time.perf_counter()
    exe_pids = {}
    for pid in filter(str.isdigit, os.listdir("/proc")):
        try:
            exe = os.readlink(f"/proc/{pid}/exe").replace(" (deleted)", "")
            uid = int(open(f"/proc/{pid}/status").read().split("\nUid:")[1].split()[0])
        except (OSError, IndexError, ValueError):
            continue
        exe_pids.setdefault(exe, []).append((int(pid), uid))
    # Mapped shared libraries matter too (a vulnerable libssl is "running" inside every process using it).
    libs = set()
    for pid in [p for v in exe_pids.values() for p, _ in v][:400]:
        try:
            for line in open(f"/proc/{pid}/maps"):
                if ".so" in line:
                    libs.add(line.split()[-1])
        except OSError:
            pass
    listen = subprocess.run(["ss", "-Hltnup"], capture_output=True, text=True).stdout
    public_pids = {int(p) for l in listen.splitlines()
                   if not re.search(r"\s(127\.\d+\.\d+\.\d+|\[::1\]|\[::ffff:127[^\]]*\]):\d+", l)
                   for p in re.findall(r"pid=(\d+)", l)}
    paths = sorted(set(exe_pids) | libs)
    owner = {}
    for i in range(0, len(paths), 500):
        out = subprocess.run(["dpkg", "-S", *paths[i:i + 500]], capture_output=True, text=True).stdout
        for l in out.splitlines():
            if ": " in l:
                pk, path = l.split(": ", 1)
                for p in pk.split(", "):
                    owner.setdefault(path, set()).add(p.split(":")[0])
    pkg = {}
    for path in paths:
        for p in owner.get(path, ()):
            e = pkg.setdefault(p, {"running": False, "root": False, "public": False, "lib": False})
            procs = exe_pids.get(path, [])
            e["running"] = True
            e["lib"] |= path in libs and not procs
            e["root"] |= any(uid == 0 for _, uid in procs)
            e["public"] |= any(pid in public_pids for pid, _ in procs)
    tick("runtime exposure", t0)
    return pkg


# ---------- 5. join + rank ----------
def triage():
    rules = parse_oval(os.path.join(FEEDS, "com.ubuntu.noble.cve.oval.xml.bz2"))
    pk = installed()
    t0 = time.perf_counter()
    K, E = kev(), epss()
    tick("load KEV+EPSS", t0)
    ex = exposure()
    t0 = time.perf_counter()
    hits = {}
    for d, pkgs, fixed in rules:
        for p in pkgs:
            v = pk.get(p)
            if v is None:
                continue
            if fixed is not None and apt_pkg.version_compare(v, fixed) >= 0:
                continue
            h = hits.setdefault((d["cve"], p), {**d, "pkg": p, "have": v, "fixed": fixed})
    tick("match", t0)
    kernel = os.uname().release
    rows = []
    for (cve, p), h in hits.items():
        x = ex.get(p, {})
        if p.startswith("linux-") and kernel not in p and re.search(r"\d+\.\d+\.\d+-\d+", p):
            continue                       # an older, non-running kernel package: removal, not patching
        h.update(kev=cve in K, epss=E.get(cve, 0.0), **{k: x.get(k, False) for k in ("running", "root", "public", "lib")})
        rows.append(h)
    return rows, pk


def score(h):
    """Likelihood of exploitation here (EPSS / KEV) × how reachable it is on THIS machine.
    Exposure multipliers are [conjecture]; ordering, not absolute value, is what's shown to the user."""
    p = 1.0 if h["kev"] else max(h["epss"], 0.0005)
    reach = (8 if h["public"] else 1) * (3 if h["root"] else 1) * (2 if h["running"] else 0.25)
    return p * reach


if __name__ == "__main__":
    t_all = time.perf_counter()
    rows, pk = triage()
    total = time.perf_counter() - t_all
    fixable = [r for r in rows if r["fixed"]]
    unfixed = [r for r in rows if not r["fixed"]]
    esm = [r for r in fixable if "esm" in r["fixed"]]
    print(f"installed packages: {len(pk)}   vulnerable (cve,pkg) pairs: {len(rows)}   distinct CVEs: {len({r['cve'] for r in rows})}")
    print(f"  fix available: {len(fixable)} (of which Ubuntu Pro/ESM-only: {len(esm)})   no fix yet: {len(unfixed)}")
    print(f"  in CISA KEV: {sum(r['kev'] for r in rows)}   EPSS>=0.1: {sum(r['epss'] >= 0.1 for r in rows)}")
    print(f"  in running code: {sum(r['running'] for r in rows)}   as root: {sum(r['root'] for r in rows)}   network-reachable: {sum(r['public'] for r in rows)}")
    by_cvss = sorted(rows, key=lambda r: -r["cvss"])[:10]
    by_ours = sorted(rows, key=lambda r: -score(r))[:10]
    print("\nTop 10 by CVSS (what most scanners show):")
    for r in by_cvss:
        print(f"  {r['cve']:<16} {r['pkg']:<28} cvss {r['cvss']:<4} epss {r['epss']:.3f} kev {int(r['kev'])} run {int(r['running'])} pub {int(r['public'])}  fix {r['fixed'] or '-'}")
    print("\nTop 10 by exploit-likelihood × exposure:")
    for r in by_ours:
        print(f"  {r['cve']:<16} {r['pkg']:<28} cvss {r['cvss']:<4} epss {r['epss']:.3f} kev {int(r['kev'])} run {int(r['running'])} root {int(r['root'])} pub {int(r['public'])}  fix {r['fixed'] or '-'}")
    overlap = len({(r['cve'], r['pkg']) for r in by_cvss} & {(r['cve'], r['pkg']) for r in by_ours})
    print(f"\noverlap of the two top-10s: {overlap}/10")
    # How many apt actions fix everything fixable? (fixes collapse onto source/binary package upgrades)
    print(f"distinct packages to upgrade to clear all {len(fixable)} fixable pairs: {len({r['pkg'] for r in fixable})}")
    print("timings: " + ", ".join(f"{k} {v:.2f}s" for k, v in T.items()) + f", total {total:.2f}s")
    # Free fixes the user can apply right now vs. those behind Ubuntu Pro (free for personal use, 5 machines).
    free = [r for r in fixable if "esm" not in r["fixed"]]
    print(f"\nfixable without Pro: {len(free)} pairs in {len({r['pkg'] for r in free})} packages; "
          f"Pro-only: {len(esm)} pairs in {len({r['pkg'] for r in esm})} packages")
    for r in sorted(free, key=lambda r: -score(r))[:5]:
        print(f"  free fix: {r['cve']} {r['pkg']} {r['have']} -> {r['fixed']} epss {r['epss']:.3f} run {int(r['running'])}")
    for r in sorted(esm, key=lambda r: -score(r))[:5]:
        print(f"  pro fix:  {r['cve']} {r['pkg']} {r['have']} -> {r['fixed']} epss {r['epss']:.3f} run {int(r['running'])}")
    kevs = sorted({(r['cve'], r['pkg'].split('-')[0]) for r in rows if r['kev']})
    print("KEV hits:", kevs)
    hi = [r for r in unfixed if r["kev"] or r["epss"] >= 0.1]
    print(f"no-fix-yet but actively exploited/likely: {len(hi)} pairs; of 'might be affected' total {len(unfixed)}")
