"""HTTP utilities for the SSRF Auditor framework."""

from __future__ import annotations

import asyncio
import ssl
from typing import Any, Optional

import aiohttp
from aiohttp import ClientTimeout, TCPConnector
from yarl import URL

from src.config import Config
from src.exceptions import NetworkError, TimeoutError
from src.models import ScanResult
from src.utils.logger import AuditLogger


class HTTPClient:
    """Async HTTP client with proxy support and rate limiting."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = AuditLogger.get_instance()
        self._session: Optional[aiohttp.ClientSession] = None
        self._timeout = ClientTimeout(
            total=config.general.get("request_timeout", 30)
        )

        ssl_context = None
        if not config.general.get("verify_ssl", True):
            ssl_context = ssl.create_default_context()
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE

        proxy_config = config.proxy
        proxy_url = proxy_config.get("http") or proxy_config.get("https") or ""

        connector = TCPConnector(
            ssl=ssl_context,
            limit=config.general.get("max_threads", 20),
            limit_per_host=config.rate_limiting.get("max_concurrent_hosts", 10),
            force_close=False,
            enable_cleanup_closed=True,
        )

        headers = {
            "User-Agent": config.general.get(
                "user_agent", "SSRFAudit/2.0 (Security Assessment Tool)"
            ),
            "Accept": "text/html,application/json,application/xml,application/graphql+json,*/*",
            "Accept-Language": "en-US,en;q=0.9",
        }
        user_headers = config.general.get("headers", {})
        if user_headers:
            headers.update(user_headers)

        self._session = aiohttp.ClientSession(
            connector=connector,
            timeout=self._timeout,
            headers=headers,
            cookies=config.general.get("cookies", {}),
        )

    async def close(self) -> None:
        if self._session and not self._session.closed:
            await self._session.close()

    async def request(
        self,
        method: str,
        url: str,
        params: Optional[dict[str, str]] = None,
        data: Any = None,
        json_data: Any = None,
        headers: Optional[dict[str, str]] = None,
        allow_redirects: Optional[bool] = None,
        timeout: Optional[int] = None,
    ) -> ScanResult:
        if not self._session:
            raise NetworkError("HTTP session not initialized")

        if allow_redirects is None:
            allow_redirects = self.config.general.get("follow_redirects", True)

        max_redirects = self.config.general.get("max_redirects", 5)

        try:
            async with self._session.request(
                method=method,
                url=url,
                params=params,
                data=data,
                json=json_data,
                headers=headers,
                allow_redirects=allow_redirects,
                max_redirects=max_redirects,
                timeout=ClientTimeout(total=timeout or self.config.general.get("request_timeout", 30)),
            ) as response:
                body = await response.text()
                result = ScanResult(
                    url=str(response.url),
                    status_code=response.status,
                    headers=dict(response.headers),
                    body=body,
                    content_type=response.content_type or "",
                    size=len(body.encode("utf-8")),
                )
                return result

        except asyncio.TimeoutError:
            raise TimeoutError(f"Request timed out for {url}")
        except aiohttp.ClientError as e:
            raise NetworkError(f"HTTP request failed for {url}: {e}")

    async def get(
        self,
        url: str,
        params: Optional[dict[str, str]] = None,
        headers: Optional[dict[str, str]] = None,
    ) -> ScanResult:
        return await self.request("GET", url, params=params, headers=headers)

    async def post(
        self,
        url: str,
        data: Any = None,
        json_data: Any = None,
        headers: Optional[dict[str, str]] = None,
    ) -> ScanResult:
        return await self.request("POST", url, data=data, json_data=json_data, headers=headers)

    async def head(self, url: str, headers: Optional[dict[str, str]] = None) -> ScanResult:
        return await self.request("HEAD", url, headers=headers)

    async def options(self, url: str, headers: Optional[dict[str, str]] = None) -> ScanResult:
        return await self.request("OPTIONS", url, headers=headers)
