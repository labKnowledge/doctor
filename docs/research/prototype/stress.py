import random, statistics, time, sys
sys.path.insert(0, ".")
from proto import attribute, onset, time_to_full
day = 86400
def trial(run_every_days, evidence, seed):
    r = random.Random(seed); t0 = 0
    boots = [d*day + 3600 for d in range(365)]
    changes = []
    for d in range(365):               # upgrade batches ~2x/week of 40 pkgs, plus ad-hoc installs
        if r.random() < 0.3:
            changes += [{"t": d*day+50000+k, "kind":"upgrade", "what": f"lib{r.randrange(3000)}"} for k in range(40)]
        if r.random() < 0.2:
            changes.append({"t": d*day+r.random()*day, "kind":"install", "what": f"app{r.randrange(500)}"})
    tc = r.uniform(100, 300) * day
    culprit = {"t": tc, "kind": "upgrade", "what": "foo"}
    changes = sorted(changes + [culprit], key=lambda c: c["t"])
    times = [c["t"] for c in changes]
    runs = [d*day + 40000 for d in range(0, 365, run_every_days)]
    snaps = [(t, {"X"} if t > tc else set()) for t in runs]
    w = onset(snaps, "X")
    issue = {"check":"failed-units","area":"services","title":"Service keeps failing","detail":[]}
    ranked = attribute(issue, w, changes, times, boots, owners={"foo"} if evidence else set())
    names = [c["what"] for _, c, _ in ranked]
    rank = names.index("foo") + 1 if "foo" in names else None
    return rank, len(ranked)
for every in (1, 7, 30):
    for ev in (True, False):
        res = [trial(every, ev, s) for s in range(500)]
        top1 = sum(r == 1 for r, _ in res) / len(res)
        top3 = sum(r is not None and r <= 3 for r, _ in res) / len(res)
        incl = sum(r is not None for r, _ in res) / len(res)
        n = statistics.median(c for _, c in res)
        print(f"runs every {every:>2}d  ownership-evidence={ev!s:5}  culprit in set {incl:.0%}  top1 {top1:.0%}  top3 {top3:.0%}  median candidates {n:.0f}  (search space ~{12000+70} changes/yr)")
