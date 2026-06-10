"""Web crawler for SSRF Auditor with async support."""

from __future__ import annotations

import asyncio
from typing import Optional, Set
from urllib.parse import urlparse, urljoin

from src.config import Config
from src.engine.rate_limiter import HostRateLimiter
from src.exceptions import CrawlerError
from src.utils.http import HTTPClient
from src.utils.logger import AuditLogger
from src.utils.parsers import HTMLParser


class Crawler:
    """Async web crawler with depth control and URL filtering."""

    def __init__(self, config: Config, http_client: HTTPClient) -> None:
        self.config = config
        self.http = http_client
        self.logger = AuditLogger.get_instance()
        self.rate_limiter = HostRateLimiter(config)
        self.parser = HTMLParser()

        crawler_config = config.crawler
        self.max_depth = crawler_config.get("max_depth", 3)
        self.max_pages = crawler_config.get("max_pages", 500)
        self.same_domain = crawler_config.get("same_domain_only", True)
        self.excluded_exts = crawler_config.get("excluded_extensions", [])
        self.include_paths = crawler_config.get("include_paths", [])
        self.exclude_paths = crawler_config.get("exclude_paths", [])

        self._visited: Set[str] = set()
        self._base_domain: str = ""
        self._page_count = 0

    def _should_exclude(self, url: str) -> bool:
        parsed = urlparse(url)
        path = parsed.path.lower()

        for ext in self.excluded_exts:
            if path.endswith(ext):
                return True

        for exclude in self.exclude_paths:
            if exclude in path:
                return True

        if self.include_paths:
            return not any(inc in path for inc in self.include_paths)

        return False

    def _is_same_domain(self, url: str) -> bool:
        if not self.same_domain:
            return True
        domain = urlparse(url).netloc
        return domain == self._base_domain or domain.endswith("." + self._base_domain)

    async def crawl(
        self, start_url: str, max_depth: Optional[int] = None
    ) -> list[str]:
        if max_depth is not None:
            original_depth = self.max_depth
            self.max_depth = max_depth

        self._base_domain = urlparse(start_url).netloc
        self._visited.clear()
        self._page_count = 0

        found_urls = await self._crawl_recursive(start_url, 0)

        if max_depth is not None:
            self.max_depth = original_depth

        return found_urls

    async def _crawl_recursive(self, url: str, depth: int) -> list[str]:
        if depth > self.max_depth:
            return []
        if self._page_count >= self.max_pages:
            return []
        if url in self._visited:
            return []
        if self._should_exclude(url):
            return []

        self._visited.add(url)
        found_urls = [url]

        try:
            host = urlparse(url).netloc
            await self.rate_limiter.acquire(host)
            response = await self.http.get(url)
            self._page_count += 1

            if not response.is_success:
                return found_urls

            links = self.parser.extract_links(response.body, url)

            crawl_tasks = []
            for link in links:
                if (
                    link not in self._visited
                    and self._is_same_domain(link)
                    and not self._should_exclude(link)
                ):
                    crawl_tasks.append(self._crawl_recursive(link, depth + 1))

            if crawl_tasks:
                results = await asyncio.gather(*crawl_tasks, return_exceptions=True)
                for result in results:
                    if isinstance(result, list):
                        found_urls.extend(result)

        except Exception as e:
            self.logger.debug(f"Crawl error for {url}: {e}")

        return found_urls

    async def get_page(self, url: str) -> Optional[str]:
        try:
            host = urlparse(url).netloc
            await self.rate_limiter.acquire(host)
            response = await self.http.get(url)
            if response.is_success:
                return response.body
            return None
        except Exception as e:
            self.logger.debug(f"Failed to get page {url}: {e}")
            return None
