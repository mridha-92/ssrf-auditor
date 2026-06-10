"""Main scanner engine orchestrating all audit modules."""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from src.config import Config
from src.engine.crawler import Crawler
from src.engine.plugin_loader import PluginLoader
from src.engine.rate_limiter import HostRateLimiter
from src.exceptions import ScannerError, StateError
from src.models import AuditReport, Finding, RiskLevel, ScanState
from src.utils.http import HTTPClient
from src.utils.logger import AuditLogger
from src.utils.helpers import Timer, ensure_directory, write_json


class Scanner:
    """Orchestrates the full security audit process."""

    def __init__(self, config: Config) -> None:
        self.config = config
        self.logger = AuditLogger.get_instance()
        self.http = HTTPClient(config)
        self.crawler = Crawler(config, self.http)
        self.plugin_loader = PluginLoader()
        self.rate_limiter = HostRateLimiter(config)
        self.report = AuditReport(target="")
        self.state = ScanState()
        self._modules: dict = {}
        self._stop_requested = False

    async def initialize(self) -> None:
        self.plugin_loader.discover()
        module_config = self.config.modules
        for module_name, module_class in self.plugin_loader._module_classes.items():
            module_config_entry = module_config.get(module_name, {})
            if isinstance(module_config_entry, dict) and module_config_entry.get("enabled", True):
                try:
                    module = self.plugin_loader.load_module(
                        module_name, config=self.config, http_client=self.http
                    )
                    self._modules[module_name] = module
                    self.logger.info(f"Initialized module: {module_name}")
                except Exception as e:
                    self.logger.error(f"Failed to initialize module {module_name}: {e}")

        if self.config.general.get("resume", True):
            self._load_state()

    async def run(self, target: str) -> AuditReport:
        self.report = AuditReport(target=target)
        self.report.modules_run = list(self._modules.keys())
        timer = Timer()
        timer.__enter__()

        try:
            self.logger.info(f"Starting audit of: {target}")

            urls = [target]

            crawl_config = self.config.crawler
            if crawl_config.get("max_depth", 3) > 0:
                self.logger.info("Crawling target...")
                crawled = await self.crawler.crawl(
                    target,
                    max_depth=crawl_config.get("max_depth", 3),
                )
                urls = crawled
                self.logger.info(f"Crawled {len(urls)} URLs")

            self.report.urls_scanned = len(urls)

            for module_name, module in self._modules.items():
                if self._stop_requested:
                    break
                try:
                    self.logger.info(f"Running module: {module_name}")
                    findings = await module.run(urls)
                    if findings:
                        self.report.findings.extend(findings)
                        self.logger.info(
                            f"Module {module_name} found {len(findings)} issues"
                        )
                    self.state.completed_modules.append(module_name)
                    self._save_state()
                except Exception as e:
                    error_msg = f"Module {module_name} failed: {e}"
                    self.logger.error(error_msg)
                    self.report.errors.append(error_msg)

            self.logger.info(
                f"Audit complete. Found {self.report.total_findings} findings"
            )

        except Exception as e:
            error_msg = f"Scanner failed: {e}"
            self.logger.error(error_msg)
            self.report.errors.append(error_msg)
            raise ScannerError(error_msg) from e
        finally:
            timer.__exit__(None, None, None)
            self.report.duration = timer.elapsed
            await self._cleanup()

        return self.report

    async def _cleanup(self) -> None:
        await self.http.close()
        self._save_state()

    def _load_state(self) -> None:
        state_file = self.config.general.get("state_file", "audit_state.json")
        if os.path.exists(state_file):
            try:
                with open(state_file, "r") as f:
                    data = json.load(f)
                self.state.scanned_urls = set(data.get("scanned_urls", []))
                self.state.completed_modules = data.get("completed_modules", [])
                self.state.findings_count = data.get("findings_count", 0)
                self.logger.info(f"Resumed state from {state_file}")
            except Exception as e:
                self.logger.warning(f"Failed to load state file: {e}")

    def _save_state(self) -> None:
        if not self.config.general.get("resume", True):
            return
        state_file = self.config.general.get("state_file", "audit_state.json")
        try:
            data = {
                "scanned_urls": list(self.state.scanned_urls),
                "pending_urls": list(self.state.pending_urls),
                "failed_urls": self.state.failed_urls,
                "completed_modules": self.state.completed_modules,
                "findings_count": len(self.report.findings),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            with open(state_file, "w") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            self.logger.warning(f"Failed to save state: {e}")

    def stop(self) -> None:
        self._stop_requested = True
        self.logger.info("Stop requested, finishing current module...")
