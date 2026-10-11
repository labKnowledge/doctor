"""The three things an app needs: scan(), remove(), quick_clean(). All return plain dicts (JSON-ready)."""
import json, os, re, shutil, subprocess, time
from importlib import resources

from .scan import (DAY, STATE, TIME_BUDGET, DiskCleanError, Scan, disk_usage, held_paths, human, in_use,
                   resolve_target)

PICK_EXPIRES = DAY


def scan(target=None, *, time_budget=TIME_BUDGET, on_progress=None, save=True):
    """Deep-scan a drive or folder. Nothing is deleted. The result is saved so `remove()` can act on it.

    target: None/'/'/'system' for the system partition, a drive name like 'storage', or a folder path.
    on_progress: optional callback(dict) called every few thousand folders during the walk.
    """
    path = resolve_target(target)
    t0 = time.time()
    s = Scan(path, time_budget=time_budget, on_progress=on_progress)
    items = s.run()
    result = {"target": str(path), "time": s.now, "took": round(time.time() - t0, 1),
              "disk": disk_usage(path), "partial": s.partial, "notes": s.notes,
              "total": sum(i["size"] for i in items), "items": items}
    if save:
        STATE.parent.mkdir(parents=True, exist_ok=True)
        STATE.write_text(json.dumps(result))
    return result


def last_scan():
    """The most recent saved scan, or None."""
    try: return json.loads(STATE.read_text())
    except Exception: return None


def parse_picks(spec, count):
    """'1 3 5-7', '1,3', 'all', [1, 3] or item ids -> sorted 1-based numbers."""
    if isinstance(spec, (list, tuple)):
        spec = " ".join(str(x) for x in spec)
    picks = set()
    for tok in re.split(r"[\s,]+", str(spec).strip()):
        if not tok: continue
        if tok == "all": return list(range(1, count + 1))
        m = re.fullmatch(r"(\d+)(?:-(\d+))?", tok)
        if not m: raise DiskCleanError(f"Don't understand '{tok}'. Use numbers like: pick 1 3 5-7")
        a, b = int(m.group(1)), int(m.group(2) or m.group(1))
        picks.update(range(a, b + 1))
    bad = [p for p in sorted(picks) if not 1 <= p <= count]
    if bad: raise DiskCleanError(f"No item {bad[0]}: the last scan has {count} items.")
    if not picks: raise DiskCleanError("Say which items, e.g.: pick 1 3 5-7")
    return sorted(picks)


def remove(picks, *, ids=None):
    """Delete items from the last scan, by number ('1 3 5-7', 'all', [1, 3]) or by item id (ids=[...]).
    Each item is re-checked: anything now in use is skipped."""
    state = last_scan()
    if not state: raise DiskCleanError("No scan yet. Run a deep scan first.")
    if time.time() - state["time"] > PICK_EXPIRES:
        raise DiskCleanError("The last scan is over a day old. Run a deep scan again first.")
    items = state["items"]
    if ids:
        by_id = {it.get("id"): n for n, it in enumerate(items, 1)}
        unknown = [i for i in ids if i not in by_id]
        if unknown: raise DiskCleanError(f"Unknown item id {unknown[0]}.")
        numbers = sorted(by_id[i] for i in ids)
    else:
        numbers = parse_picks(picks, len(items))
    target = state["target"]
    before = shutil.disk_usage(target).free
    held = held_paths()
    results = []
    for n in numbers:
        it = items[n - 1]
        res = {"n": n, "id": it.get("id"), "label": it["label"], "size": it["size"]}
        local = [p for p in it["paths"] if not p.startswith("docker-volume:")]
        if not it["paths"]:
            res["status"] = "already removed"
        elif local and in_use(local, held):
            res["status"] = "skipped: in use"
        else:
            errors = []
            for p in it["paths"]:
                if p.startswith("docker-volume:"):
                    r = subprocess.run(["docker", "volume", "rm", p.split(":", 1)[1]], capture_output=True, text=True)
                    if r.returncode: errors.append((r.stderr.strip().splitlines() or ["docker error"])[-1])
                elif os.path.lexists(p):
                    try:
                        shutil.rmtree(p) if os.path.isdir(p) and not os.path.islink(p) else os.remove(p)
                    except OSError as e:
                        errors.append(f"{e.strerror}: {e.filename}")
            # keep whatever is left so a retry can finish the job
            it["paths"] = [p for p in it["paths"]
                           if (p.startswith("docker-volume:") and errors) or
                              (not p.startswith("docker-volume:") and os.path.lexists(p))]
            res["status"] = "removed" if not errors else "partly removed"
            if errors: res["error"] = errors[0]
        results.append(res)
    STATE.write_text(json.dumps(state))
    after = shutil.disk_usage(target).free
    return {"target": target, "freed": max(after - before, 0), "disk": disk_usage(target), "results": results}


def quick_clean(on_line=None):
    """Clear caches that rebuild themselves (package managers, Docker leftovers, app caches).
    on_line: optional callback(str) for each progress line. Returns freed bytes and disk usage of /."""
    before = shutil.disk_usage("/").free
    script = resources.files("disk_clean") / "quick.sh"
    with resources.as_file(script) as path:
        proc = subprocess.Popen(["bash", str(path)], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
        lines = []
        for line in proc.stdout:
            line = line.rstrip("\n")
            lines.append(line)
            if on_line: on_line(line)
        proc.wait()
    after = shutil.disk_usage("/").free
    return {"freed": max(after - before, 0), "disk": disk_usage("/"), "log": lines}


__all__ = ["scan", "last_scan", "remove", "quick_clean", "parse_picks", "DiskCleanError", "human"]
