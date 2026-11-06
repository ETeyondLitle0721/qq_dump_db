"""Backward-compatible launcher for the modular Python package."""
from __future__ import annotations

import sys
from pathlib import Path


PACKAGE_ROOT = Path(__file__).resolve().parent / "python"
if str(PACKAGE_ROOT) not in sys.path:
    sys.path.insert(0, str(PACKAGE_ROOT))

from qq_dump_db.cli import main  # noqa: E402


if __name__ == "__main__":
    raise SystemExit(main())
