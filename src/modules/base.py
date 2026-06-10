"""Base module class for all audit modules."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any, Optional

from src.config import Config
from src.models import Finding, RiskLevel
from src.utils.http import HTTPClient
from src.utils.logger import AuditLogger


class BaseModule(ABC):
    """Abstract base class for all security audit modules."""

    module_name: str = "base"
    module_description: str = ""
    module_version: str = "1.0.0"

    def __init__(self, config: Config, http_client: HTTPClient) -> None:
        self.config = config
        self.http = http_client
        self.logger = AuditLogger.get_instance()
        self.findings: list[Finding] = []
        self._module_config: dict[str, Any] = config.modules.get(self.module_name, {})

    @abstractmethod
    async def run(self, urls: list[str]) -> list[Finding]:
        """Execute the module's audit logic."""
        ...

    def create_finding(
        self,
        title: str,
        description: str,
        risk_level: RiskLevel = RiskLevel.INFORMATIONAL,
        confidence: float = 0.0,
        url: str = "",
        parameter: str = "",
        evidence: str = "",
        detection_source: str = "",
        remediation: str = "",
        tags: Optional[list[str]] = None,
        raw_data: Optional[dict] = None,
    ) -> Finding:
        finding = Finding(
            title=title,
            description=description,
            risk_level=risk_level,
            confidence=confidence,
            module=self.module_name,
            url=url,
            parameter=parameter,
            evidence=evidence,
            detection_source=detection_source,
            remediation=remediation,
            tags=tags or [],
        )
        if raw_data:
            finding.raw_data = raw_data
        return finding

    def add_finding(self, finding: Finding) -> None:
        self.findings.append(finding)

    def get_config(self, key: str, default: Any = None) -> Any:
        if isinstance(self._module_config, dict):
            return self._module_config.get(key, default)
        return default

    def is_enabled(self) -> bool:
        if isinstance(self._module_config, dict):
            return self._module_config.get("enabled", True)
        return bool(self._module_config)

    @property
    def name(self) -> str:
        return self.module_name

    @property
    def description(self) -> str:
        return self.module_description
