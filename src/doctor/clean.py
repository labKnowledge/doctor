"""Disk space, through the disk_clean library: quick cache clean, deep scan of a drive or folder, delete picked items.
Shared by `doctor clean|deep|pick` and the same words in interactive mode."""
import sys, time

from disk_clean import DiskCleanError, human, last_scan, parse_picks, quick_clean, remove, scan
from disk_clean.cli import print_remove, print_scan, status


def clean():
    try:
        r = quick_clean(on_line=print)
    except DiskCleanError as e:
        print(e)
        return 1
    print(f"\nFreed {human(r['freed'])}. Bigger things: doctor deep (system drive) or doctor deep storage")
    return 0


def deep(where=None):
    """Scan, showing progress on a terminal. Ctrl+C stops the walk; nothing is ever deleted here."""
    t = time.time()
    tty = sys.stdout.isatty()

    def progress(p):
        if tty:
            print(f"\r  {p['dirs']:,} folders looked at, {int(time.time() - t)}s (Ctrl+C stops)", end="", flush=True)
    try:
        if tty:
            print("Looking for big things that are safe to remove. A whole data drive can take 10-15 minutes.")
        r = scan(where, on_progress=progress)
    except DiskCleanError as e:
        print(e)
        return 1
    except KeyboardInterrupt:
        print("\nStopped. Nothing was deleted.")
        return 130
    if tty:
        print("\r" + " " * 70 + "\r", end="")
    print_scan(r)
    return 0


def pick(args, confirm=None):
    """Delete items from the last deep scan. confirm(prompt) -> bool asks first (interactive)."""
    r = last_scan()
    if not r:
        print("No deep scan yet. Run: deep [system|storage|folder]")
        return 1
    if confirm:
        try:
            nums = parse_picks(args, len(r["items"]))
        except DiskCleanError as e:
            print(e)
            return 1
        total = sum(r["items"][n - 1]["size"] for n in nums)
        for n in nums:
            print(f"  {n:>2}. {human(r['items'][n - 1]['size']):>6}  {r['items'][n - 1]['label']}")
        if not confirm(f"Delete these ({human(total)})? [y/N] "):
            return 0
    try:
        print_remove(remove(args))
    except DiskCleanError as e:
        print(e)
        return 1
    return 0


__all__ = ["clean", "deep", "pick", "status"]
