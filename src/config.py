"""Configuration management for SSRF Auditor."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Optional

import yaml

from src.exceptions import ConfigurationError


class Config:
    """Central configuration manager with YAML support."""

    DEFAULTS = {
        "general": {
            "max_threads": 20,
            "request_timeout": 30,
            "user_agent": "SSRFAudit/2.0 (Security Assessment Tool)",
            "follow_redirects": True,
            "max_redirects": 5,
            "verify_ssl": False,
            "cookies": {},
            "headers": {},
            "resume": True,
            "state_file": "audit_state.json",
            "output_dir": "results",
        },
        "rate_limiting": {
            "enabled": True,
            "requests_per_second": 50,
            "burst_size": 10,
            "delay_between_requests": 0.05,
            "max_concurrent_hosts": 10,
        },
        "modules": {
            "ssrf_discovery": {"enabled": True},
            "cloud_metadata": {"enabled": True},
            "infra_disclosure": {"enabled": True},
            "sensitive_files": {"enabled": True},
            "js_analysis": {"enabled": True},
            "cloud_assets": {"enabled": True},
            "security_headers": {"enabled": True},
            "api_surface": {"enabled": True},
        },
        "exploit": {
            "enabled": False,
            "dry_run": True,
        },
        "reporting": {
            "formats": ["html", "json", "csv"],
            "executive_summary": True,
            "technical_report": True,
            "color_scheme": "dark",
        },
        "logging": {
            "level": "INFO",
            "file": "logs/ssrf-auditor.log",
        },
    }

    def __init__(self, config_path: Optional[str] = None) -> None:
        self._data: dict[str, Any] = self._deep_copy(self.DEFAULTS)
        if config_path:
            self._load_file(config_path)
        self._validate()

    def _deep_copy(self, data: dict) -> dict:
        """Deep copy a dictionary."""
        import copy
        return copy.deepcopy(data)

    def _load_file(self, path: str) -> None:
        path_obj = Path(path)
        if not path_obj.exists():
            raise ConfigurationError(f"Configuration file not found: {path}")
        try:
            with open(path_obj, "r", encoding="utf-8") as f:
                user_config = yaml.safe_load(f)
            if user_config:
                self._merge(self._data, user_config)
        except yaml.YAMLError as e:
            raise ConfigurationError(f"Invalid YAML configuration: {e}")

    def _merge(self, base: dict, override: dict) -> None:
        for key, value in override.items():
            if key in base and isinstance(base[key], dict) and isinstance(value, dict):
                self._merge(base[key], value)
            else:
                base[key] = value

    def _validate(self) -> None:
        general = self._data.get("general", {})
        if not general.get("output_dir"):
            raise ConfigurationError("output_dir must be specified")
        rate = self._data.get("rate_limiting", {})
        if rate.get("requests_per_second", 50) < 1:
            raise ConfigurationError("requests_per_second must be >= 1")

    @property
    def general(self) -> dict[str, Any]:
        return self._data.get("general", {})

    @property
    def rate_limiting(self) -> dict[str, Any]:
        return self._data.get("rate_limiting", {})

    @property
    def modules(self) -> dict[str, Any]:
        return self._data.get("modules", {})

    @property
    def exploit(self) -> dict[str, Any]:
        return self._data.get("exploit", {})

    @property
    def reporting(self) -> dict[str, Any]:
        return self._data.get("reporting", {})

    @property
    def logging(self) -> dict[str, Any]:
        return self._data.get("logging", {})

    @property
    def crawler(self) -> dict[str, Any]:
        return self._data.get("crawler", {})

    @property
    def proxy(self) -> dict[str, Any]:
        return self._data.get("proxy", {})

    def get(self, key: str, default: Any = None) -> Any:
        keys = key.split(".")
        data = self._data
        for k in keys:
            if isinstance(data, dict):
                data = data.get(k)
            else:
                return default
        return data if data is not None else default

    def set(self, key: str, value: Any) -> None:
        keys = key.split(".")
        data = self._data
        for k in keys[:-1]:
            if k not in data:
                data[k] = {}
            data = data[k]
        data[keys[-1]] = value

    def module_enabled(self, module_name: str) -> bool:
        module_config = self.modules.get(module_name, {})
        if isinstance(module_config, dict):
            return module_config.get("enabled", True)
        return bool(module_config)

    def to_dict(self) -> dict[str, Any]:
        return self._deep_copy(self._data)
