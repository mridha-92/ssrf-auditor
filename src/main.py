#!/usr/bin/env python3
"""SSRF Auditor v2.0 - Main entry point."""

from __future__ import annotations

import sys
from pathlib import Path


sys.path.insert(0, str(Path(__file__).parent.parent))


def entry_point() -> None:
    from src.cli import main
    main()


if __name__ == "__main__":
    entry_point()
