"""disk-clean: free disk space safely.

    from disk_clean import scan, remove, quick_clean

    result = scan("storage")            # nothing deleted; numbered items
    remove("1 3 5-7")                   # or remove(None, ids=[item["id"], ...])
    quick_clean(on_line=print)          # caches that rebuild themselves
"""
from .api import last_scan, parse_picks, quick_clean, remove, scan
from .scan import DiskCleanError, human

__version__ = "1.0.0"
__all__ = ["scan", "remove", "quick_clean", "last_scan", "parse_picks", "DiskCleanError", "human", "__version__"]
