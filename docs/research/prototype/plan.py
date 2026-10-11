"""Precompiled index cost + greedy weighted set cover of fix actions."""
import json, os, sys, time
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
sys.argv = ["vuln.py", "feeds"]
import vuln
rules = vuln.parse_oval("feeds/com.ubuntu.noble.cve.oval.xml.bz2")
pk = vuln.installed()
# Compile once per feed update: keep only rules naming an installed package.
idx = [[d["cve"], d["cvss"], d["av_network"], p, fixed] for d, pkgs, fixed in rules for p in pkgs if p in pk]
json.dump(idx, open("index.json", "w"))
t = time.perf_counter()
idx2 = json.load(open("index.json"))
import apt_pkg
hits = [r for r in idx2 if r[4] is None or apt_pkg.version_compare(pk[r[3]], r[4]) < 0]
print(f"compiled index: {os.path.getsize('index.json')/1e6:.1f} MB, {len(idx2)} rules; load+match {1e3*(time.perf_counter()-t):.0f} ms -> {len(hits)} hits")
# Fix actions: each action covers a set of (cve,pkg) risks. Greedy weighted set cover (Chvátal 1979).
E = vuln.epss(); K = vuln.kev()
risk = {(c, p): (1.0 if c in K else max(E.get(c, 0), 5e-4)) for c, _, _, p, f in hits}
actions = {}
for c, _, _, p, f in hits:
    if f and "esm" in f:
        actions.setdefault("pro attach + apt upgrade (free for personal use)", set()).add((c, p))
    elif f:
        actions.setdefault(f"apt upgrade {p}", set()).add((c, p))
    else:
        actions.setdefault(f"remove {p} (no fix exists)", set()).add((c, p))
total = sum(risk.values()); left = dict(risk); plan = []
while left and len(plan) < 6:
    name, cov = max(actions.items(), key=lambda a: sum(left.get(x, 0) for x in a[1]))
    gain = sum(left.pop(x, 0) for x in cov)
    if gain <= 0: break
    plan.append((name, gain / total, len(cov)))
for n, g, k in plan:
    print(f"  {g:6.1%} of expected-exploit mass  {k:5d} pairs  {n}")
