"""doctor: one command to diagnose and fix common Linux desktop problems."""
from .core import CHECKS, Ctx, run_checks
from . import health, review, security  # noqa: F401  (registers the checks)

__all__ = ["CHECKS", "Ctx", "run_checks"]
