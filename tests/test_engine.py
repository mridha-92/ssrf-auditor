"""Tests for the audit engine components."""

import pytest
from unittest.mock import AsyncMock, Mock, patch, MagicMock

from src.engine.crawler import Crawler
from src.engine.rate_limiter import RateLimiter, HostRateLimiter
from src.engine.scanner import Scanner
from src.models import ScanResult


@pytest.fixture
def mock_config():
    config = Mock()
    config.general = {
        "max_threads": 20,
        "request_timeout": 30,
        "user_agent": "TestAgent",
        "follow_redirects": True,
        "max_redirects": 5,
        "verify_ssl": False,
        "cookies": {},
        "headers": {},
        "resume": True,
        "state_file": "test_state.json",
        "output_dir": "results",
    }
    config.crawler = {
        "max_depth": 3,
        "max_pages": 500,
        "same_domain_only": True,
        "excluded_extensions": [".jpg", ".png", ".gif"],
        "include_paths": [],
        "exclude_paths": [],
    }
    config.rate_limiting = {
        "enabled": True,
        "requests_per_second": 50,
        "burst_size": 10,
        "delay_between_requests": 0.01,
        "max_concurrent_hosts": 10,
    }
    config.modules = {}
    config.proxy = {"http": "", "https": "", "socks5": "", "no_proxy": []}
    config.exploit = {"enabled": False, "dry_run": True}
    config.reporting = {"formats": ["json"], "executive_summary": True, "technical_report": True, "color_scheme": "dark"}
    config.logging = {"level": "INFO", "file": ""}
    return config


class TestRateLimiter:
    @pytest.mark.asyncio
    async def test_acquire_release(self, mock_config):
        limiter = RateLimiter(mock_config)
        await limiter.acquire()
        assert limiter._tokens < limiter.burst

    @pytest.mark.asyncio
    async def test_host_rate_limiter(self, mock_config):
        limiter = HostRateLimiter(mock_config)
        await limiter.acquire("test.com")
        assert limiter._host_limiters is not None


class TestCrawler:
    @pytest.mark.asyncio
    async def test_exclude_extensions(self, mock_config):
        mock_http = AsyncMock()
        crawler = Crawler(mock_config, mock_http)
        assert crawler._should_exclude("https://example.com/image.jpg")
        assert not crawler._should_exclude("https://example.com/page.html")

    def test_same_domain(self, mock_config):
        mock_http = AsyncMock()
        crawler = Crawler(mock_config, mock_http)
        crawler._base_domain = "example.com"
        assert crawler._is_same_domain("https://example.com/page")
        assert not crawler._is_same_domain("https://evil.com/page")


class TestScanner:
    @pytest.mark.asyncio
    async def test_scanner_initialization(self, mock_config):
        scanner = Scanner(mock_config)
        await scanner.initialize()
        assert scanner.http is not None
        assert scanner.crawler is not None
