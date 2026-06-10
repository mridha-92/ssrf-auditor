"""Rate limiting engine for asynchronous requests."""

from __future__ import annotations

import asyncio
import time
from typing import Optional

from src.config import Config
from src.utils.logger import AuditLogger


class RateLimiter:
    """Token-bucket rate limiter for async HTTP requests."""

    def __init__(self, config: Config) -> None:
        self.logger = AuditLogger.get_instance()
        rate_config = config.rate_limiting
        self.enabled = rate_config.get("enabled", True)
        self.rate = rate_config.get("requests_per_second", 50)
        self.burst = rate_config.get("burst_size", 10)
        self.delay = rate_config.get("delay_between_requests", 0.05)

        self._tokens = float(self.burst)
        self._last_refill = time.monotonic()
        self._lock = asyncio.Lock()
        self._request_times: list[float] = []

    async def acquire(self) -> None:
        if not self.enabled:
            return

        async with self._lock:
            now = time.monotonic()
            elapsed = now - self._last_refill
            self._tokens = min(
                float(self.burst),
                self._tokens + elapsed * self.rate,
            )
            self._last_refill = now

            if self._tokens < 1.0:
                wait_time = (1.0 - self._tokens) / self.rate
                self.logger.debug(f"Rate limit waiting {wait_time:.3f}s")
                self._tokens = 0.0
                self._lock.release()
                try:
                    await asyncio.sleep(wait_time)
                finally:
                    await self._lock.acquire()
                self._tokens = min(float(self.burst), self.delay * self.rate)
            else:
                self._tokens -= 1.0

        if self.delay > 0:
            await asyncio.sleep(self.delay)

    async def __aenter__(self) -> "RateLimiter":
        await self.acquire()
        return self

    async def __aexit__(self, *args) -> None:
        pass


class HostRateLimiter:
    """Per-host rate limiting."""

    def __init__(self, config: Config) -> None:
        self.global_limiter = RateLimiter(config)
        self._host_limiters: dict[str, RateLimiter] = {}
        self._lock = asyncio.Lock()
        self.per_host_rate = max(1, config.rate_limiting.get("requests_per_second", 50) // 5)

    async def acquire(self, host: str) -> None:
        await self.global_limiter.acquire()
        async with self._lock:
            if host not in self._host_limiters:
                limiter_config = type("obj", (object,), {
                    "rate_limiting": {
                        "enabled": True,
                        "requests_per_second": self.per_host_rate,
                        "burst_size": 3,
                        "delay_between_requests": 0.1,
                    }
                })
                self._host_limiters[host] = RateLimiter(limiter_config)
        await self._host_limiters[host].acquire()

    async def __aenter__(self) -> "HostRateLimiter":
        return self

    async def __aexit__(self, *args) -> None:
        pass
