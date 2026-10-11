"""Prototype: onset detection + change attribution + exhaustion forecast. Benchmarks the critical path."""
import bisect, gzip, glob, hashlib, math, random, re, statistics, time


def normalize(msg):
    msg = re.sub(r"0x[0-9a-fA-F]+|\b[0-9a-f]{8,}\b", "#", msg)
    return re.sub(r"\d+", "N", msg).strip()[:160]


def fingerprint(f):
    """Stable identity of an issue across runs: check + explicit key, else check + normalized title."""
    basis = f"{f['check']}|{f.get('key') or normalize(f['title'])}"
    return hashlib.blake2s(basis.encode(), digest_size=6).hexdigest()


# ---------- onset: interval in which an issue first appeared ----------
def onset(snapshots, fp):
    """snapshots: [(t, set(fps))] sorted. Returns (t_last_absent|None, t_first_present) of the CURRENT episode."""
    first = last_absent = None
    for t, fps in reversed(snapshots):
        if fp in fps:
            first = t
        else:
            last_absent = t
            break
    return last_absent, first


# ---------- change ledger ----------
def apt_changes():
    out = []
    for path in sorted(glob.glob("/var/log/apt/history.log*")):
        op = gzip.open if path.endswith(".gz") else open
        try:
            text = op(path, "rt", errors="replace").read()
        except OSError:
            continue
        t = None
        for line in text.splitlines():
            if line.startswith("Start-Date:"):
                t = time.mktime(time.strptime(line.split(": ", 1)[1].strip(), "%Y-%m-%d  %H:%M:%S"))
            elif t and re.match(r"(Install|Upgrade|Remove|Purge): ", line):
                kind, rest = line.split(": ", 1)
                for pkg in re.findall(r"([a-z0-9][\w.+-]*):\w+ \(", rest):
                    out.append({"t": t, "kind": kind.lower(), "what": pkg})
    return sorted(out, key=lambda c: c["t"])


# Changes that only take effect after a reboot: their effective time is the next boot, not the install.
NEEDS_BOOT = re.compile(r"^(linux-(image|modules|firmware)|nvidia-|firmware-|systemd$|libc6$|intel-microcode|amd64-microcode)")


def effective(c, boots):
    if NEEDS_BOOT.match(c["what"]):
        i = bisect.bisect_right(boots, c["t"])
        return boots[i] if i < len(boots) else None   # not yet in effect
    return c["t"]


# ---------- attribution ----------
# Likelihood ratios for evidence linking a change to an issue [conjecture: hand-set, to be calibrated on episodes].
LR_OWNS = 20.0      # the changed package owns the failing unit's binary / the crashing executable
LR_NAME = 6.0       # the package name appears in the issue's title/detail
LR_AREA = 2.0       # change kind matches the area (kernel pkg ↔ hardware/stability, ufw ↔ security, ...)
LR_HISTORY = 4.0    # this pair co-occurred in a past episode (NetMedic-style history)


def attribute(issue, window, changes, times, boots, owners=frozenset(), history=frozenset()):
    """Rank changes whose effect lands inside the onset window. Uniform prior over admissible candidates
    (Strider: anything present while still healthy is excluded), multiplied by evidence likelihood ratios."""
    lo, hi = window
    i0 = bisect.bisect_left(times, (lo or hi - 30 * 86400) - 30 * 86400)  # boot-gated changes may predate lo
    i1 = bisect.bisect_right(times, hi)
    text = (issue["title"] + " " + " ".join(issue.get("detail", []))).lower()
    cands = []
    for c in changes[i0:i1]:
        te = effective(c, boots)
        if te is None or te > hi or (lo is not None and te <= lo):
            continue
        w = 1.0
        if c["what"] in owners:
            w *= LR_OWNS
        if len(c["what"]) > 3 and c["what"].split("-")[0] in text:
            w *= LR_NAME
        if NEEDS_BOOT.match(c["what"]) and issue["area"] in ("hardware", "stability"):
            w *= LR_AREA
        if (fingerprint(issue), c["what"]) in history:
            w *= LR_HISTORY
        cands.append((w, c, te))
    z = sum(w for w, _, _ in cands) or 1
    # Posterior mass; window width tells how sharp the answer can be.
    return sorted(((w / z, c, te) for w, c, te in cands), key=lambda x: -x[0])


# ---------- exhaustion forecast: Theil-Sen slope + Mann-Kendall gate ----------
def theil_sen(ts, ys):
    slopes = [(ys[j] - ys[i]) / (ts[j] - ts[i]) for i in range(len(ts)) for j in range(i + 1, len(ts)) if ts[j] != ts[i]]
    m = statistics.median(slopes)
    b = statistics.median(y - m * t for t, y in zip(ts, ys))
    return m, b


def mann_kendall_z(ys):
    n = len(ys)
    s = sum((ys[j] > ys[i]) - (ys[j] < ys[i]) for i in range(n) for j in range(i + 1, n))
    var = n * (n - 1) * (2 * n + 5) / 18
    return 0 if s == 0 else (s - (1 if s > 0 else -1)) / math.sqrt(var)


def time_to_full(ts, used, capacity, z_min=2.33):   # one-sided p<0.01
    if len(ts) < 8 or mann_kendall_z(used) < z_min:
        return None
    m, b = theil_sen(ts, used)
    return None if m <= 0 else (capacity - (m * ts[-1] + b)) / m


# ---------- benchmark ----------
if __name__ == "__main__":
    random.seed(1)
    real = apt_changes()
    print(f"real apt ledger: {len(real)} package changes parsed")

    # Synthetic year: 2 runs/day, 60 stable findings + issue X appearing on day 200 after pkg 'foo' upgrade.
    day = 86400
    t0 = time.time() - 365 * day
    boots = [t0 + d * day + 3600 for d in range(365)]
    changes = sorted([{"t": t0 + random.random() * 365 * day, "kind": "upgrade", "what": f"lib{k}"} for k in range(2000)]
                     + [{"t": t0 + 199.8 * day, "kind": "upgrade", "what": "foo"},
                        {"t": t0 + 199.7 * day, "kind": "upgrade", "what": "linux-image-7.0.0-40-generic"}],
                     key=lambda c: c["t"])
    times = [c["t"] for c in changes]
    base = {f"fp{k}" for k in range(60)}
    snaps = [(t0 + d * day + h * 43200, base | ({"X"} if d >= 200 else set())) for d in range(365) for h in (0, 1)]
    issue = {"check": "failed-units", "area": "services", "title": "foo.service keeps failing", "detail": []}

    t = time.perf_counter()
    for _ in range(100):
        w = onset(snaps, "X")
        ranked = attribute(issue, w, changes, times, boots, owners={"foo"})
    dt = (time.perf_counter() - t) / 100
    print(f"onset window: {(w[1]-w[0])/3600:.0f} h wide; candidates {len(ranked)}; "
          f"top: {ranked[0][1]['what']} p={ranked[0][0]:.2f}; per-issue {dt*1e3:.2f} ms")
    nobw = attribute(issue, w, changes, times, boots)
    print(f"without ownership evidence: top p={nobw[0][0]:.2f} over {len(nobw)} candidates (uniform = {1/len(nobw):.2f})")

    # Forecast: disk filling 0.4 GB/day with noise + a cleanup dip.
    ts = [d * day for d in range(30)]
    used = [400e9 + 0.4e9 * d + random.gauss(0, 2e9) - (15e9 if d == 12 else 0) for d in range(30)]
    t = time.perf_counter()
    eta = time_to_full(ts, used, 500e9)
    print(f"disk ETA {eta/day:.0f} days (truth ~{(500-400-0.4*29)/0.4:.0f}); {(time.perf_counter()-t)*1e3:.2f} ms")
    flat = [400e9 + random.gauss(0, 2e9) for _ in range(30)]
    print(f"flat noisy disk -> ETA {time_to_full(ts, flat, 500e9)} (MK gate suppresses false alarm)")
