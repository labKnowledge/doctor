"""Command line: disk-clean [quick|status|deep|pick] — also runs as `deep` / `pick` when invoked by those names."""
import json, os, subprocess, sys

from .api import last_scan, quick_clean, remove, scan
from .scan import TIME_BUDGET, DiskCleanError, disk_line, human

USAGE = """disk-clean — free disk space safely

  disk-clean                  quick clean: caches that rebuild themselves
  disk-clean status           disk usage and the biggest caches, deletes nothing
  disk-clean deep [where]     list big removable things; where = system (default), a drive name, or a folder
  disk-clean pick 1 3 5-7     delete those items from the last deep scan ("pick all" for everything)
  disk-clean last             show the last deep scan again

  Short forms: deep [where], pick 1 3
  Add --json to deep, pick, last or quick for machine-readable output.
"""


def print_scan(r):
    print(f"Deep scan of {r['target']} ({disk_line(r['target'])}) took {int(r.get('took', 0))}s")
    if r.get("partial"):
        print(f"Stopped after {TIME_BUDGET // 60} min: this list covers part of the drive. "
              "Run it again to go further (it's faster the second time).")
    for note in r.get("notes", []):
        print(f"Note: {note}.")
    items = r["items"]
    if not items:
        print("Nothing big and safe to remove found.")
        return
    print(f"{len(items)} items, {human(r.get('total') or sum(i['size'] for i in items))} total:\n")
    for n, it in enumerate(items, 1):
        meta = " · ".join(x for x in (it["age"], it["note"]) if x)
        print(f"{n:>2}. {human(it['size']):>6}  {it['label']}\n      {meta}")
    print("\nDelete with: pick 1 3 5-7   (or: pick all)   from chat: !pick 1 3")


def print_remove(r):
    for res in r["results"]:
        extra = f" ({res['error']})" if res.get("error") else ""
        print(f"{res['n']:>2}. {res['status']}: {res['label']}{extra}")
    print(f"\nFreed {human(r['freed'])} on {r['target']}. Now: {disk_line(r['target'])}")


def status():
    print(f"/: {disk_line('/')}", flush=True)
    home = os.path.expanduser("~")
    subprocess.run(f"du -sh {home}/.cache/* {home}/.npm {home}/miniconda3/pkgs 2>/dev/null | sort -rh | head -10",
                   shell=True)
    subprocess.run("command -v docker >/dev/null && docker system df 2>/dev/null", shell=True)


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    as_json = "--json" in argv
    argv = [a for a in argv if a != "--json"]
    invoked = os.path.basename(sys.argv[0])
    if invoked in ("deep", "pick") and not (argv and argv[0] in ("help", "-h", "--help", "last")):
        argv.insert(0, invoked)
    cmd = argv.pop(0).lstrip("-") if argv else "quick"
    out = (lambda r: print(json.dumps(r, indent=2))) if as_json else None
    try:
        if cmd == "quick":
            r = quick_clean(on_line=None if as_json else print)
            if as_json: out(r)
        elif cmd == "status":
            status()
        elif cmd == "deep":
            r = scan(argv[0] if argv else None)
            (out or print_scan)(r)
        elif cmd == "pick":
            r = remove(argv)
            (out or print_remove)(r)
        elif cmd == "last":
            r = last_scan()
            if not r: raise DiskCleanError("No scan yet. Run: deep [where]")
            (out or print_scan)(r)
        elif cmd in ("help", "h"):
            print(USAGE)
        else:
            raise DiskCleanError(f"Unknown command '{cmd}'.\n\n{USAGE}")
    except DiskCleanError as e:
        if as_json:
            print(json.dumps({"error": str(e)}))
        else:
            print(e, file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())
