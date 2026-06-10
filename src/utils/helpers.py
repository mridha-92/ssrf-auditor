"""Helper utilities for the SSRF Auditor framework."""

from __future__ import annotations

import asyncio
import json
import os
import re
import time
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urlparse


def ensure_directory(path: str) -> Path:
    dir_path = Path(path)
    dir_path.mkdir(parents=True, exist_ok=True)
    return dir_path


def read_file_lines(path: str) -> list[str]:
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f if line.strip() and not line.strip().startswith("#")]


def write_json(data: Any, path: str) -> None:
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, default=str)


def read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def chunk_list(lst: list, size: int):
    for i in range(0, len(lst), size):
        yield lst[i : i + size]


def domain_from_url(url: str) -> str:
    return urlparse(url).netloc or urlparse(url).path.split("/")[0]


class Timer:
    """Simple context manager for timing operations."""

    def __init__(self) -> None:
        self.start_time: float = 0.0
        self.elapsed: float = 0.0

    def __enter__(self) -> "Timer":
        self.start_time = time.time()
        return self

    def __exit__(self, *args) -> None:
        self.elapsed = time.time() - self.start_time


class AsyncCounter:
    """Thread-safe async counter."""

    def __init__(self, initial: int = 0) -> None:
        self._value = initial
        self._lock = asyncio.Lock()

    async def increment(self, amount: int = 1) -> int:
        async with self._lock:
            self._value += amount
            return self._value

    async def decrement(self, amount: int = 1) -> int:
        async with self._lock:
            self._value -= amount
            return self._value

    async def value(self) -> int:
        async with self._lock:
            return self._value


class SigmoidConfidence:
    """Calculate confidence scores using sigmoid function."""

    @staticmethod
    def calculate(
        evidence_count: int,
        source_reliability: float,
        pattern_match_strength: float,
    ) -> float:
        import math
        raw = (evidence_count * 0.3 + source_reliability * 0.4 + pattern_match_strength * 0.3)
        return 1.0 / (1.0 + math.exp(-raw + 3))
