"""Data models for the SSRF Auditor framework."""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any, Optional
from uuid import uuid4


class RiskLevel(Enum):
    INFORMATIONAL = auto()
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()

    @classmethod
    def from_string(cls, value: str) -> "RiskLevel":
        mapping = {
            "informational": cls.INFORMATIONAL,
            "low": cls.LOW,
            "medium": cls.MEDIUM,
            "high": cls.HIGH,
            "critical": cls.CRITICAL,
        }
        return mapping.get(value.lower(), cls.INFORMATIONAL)

    def __str__(self) -> str:
        return self.name.title()

    @property
    def score(self) -> int:
        return {
            RiskLevel.INFORMATIONAL: 1,
            RiskLevel.LOW: 2,
            RiskLevel.MEDIUM: 3,
            RiskLevel.HIGH: 4,
            RiskLevel.CRITICAL: 5,
        }[self]

    @property
    def color(self) -> str:
        return {
            RiskLevel.INFORMATIONAL: "#808080",
            RiskLevel.LOW: "#00cc00",
            RiskLevel.MEDIUM: "#ffcc00",
            RiskLevel.HIGH: "#ff6600",
            RiskLevel.CRITICAL: "#ff0000",
        }[self]


class ModuleType(Enum):
    SSRF_DISCOVERY = "ssrf_discovery"
    CLOUD_METADATA = "cloud_metadata"
    INFRA_DISCLOSURE = "infra_disclosure"
    SENSITIVE_FILES = "sensitive_files"
    JS_ANALYSIS = "js_analysis"
    CLOUD_ASSETS = "cloud_assets"
    SECURITY_HEADERS = "security_headers"
    API_SURFACE = "api_surface"
    RISK_ENGINE = "risk_engine"
    EXPLOIT = "exploit"


@dataclass
class Finding:
    """Represents a single security finding."""

    id: str = field(default_factory=lambda: str(uuid4())[:8])
    title: str = ""
    description: str = ""
    risk_level: RiskLevel = RiskLevel.INFORMATIONAL
    confidence: float = 0.0
    module: str = ""
    url: str = ""
    parameter: str = ""
    evidence: str = ""
    evidence_type: str = ""
    detection_source: str = ""
    remediation: str = ""
    cve: Optional[str] = None
    cwe: Optional[str] = None
    raw_data: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["risk_level"] = str(self.risk_level)
        result["risk_score"] = self.risk_level.score
        result["timestamp"] = self.timestamp.isoformat()
        result["id"] = self.id
        return result

    def to_csv_row(self) -> list[str]:
        return [
            self.id,
            str(self.timestamp),
            self.title,
            self.description,
            str(self.risk_level),
            str(self.confidence),
            self.module,
            self.url,
            self.parameter,
            self.evidence,
            self.detection_source,
            self.remediation,
            "|".join(self.tags),
        ]

    @staticmethod
    def csv_headers() -> list[str]:
        return [
            "ID",
            "Timestamp",
            "Title",
            "Description",
            "Risk Level",
            "Confidence",
            "Module",
            "URL",
            "Parameter",
            "Evidence",
            "Detection Source",
            "Remediation",
            "Tags",
        ]


@dataclass
class ScanTarget:
    url: str
    depth: int = 0
    method: str = "GET"
    params: dict[str, str] = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    content_type: Optional[str] = None


@dataclass
class ScanResult:
    url: str
    status_code: int
    headers: dict[str, str]
    body: str
    content_type: str
    redirect_url: Optional[str] = None
    elapsed: float = 0.0
    size: int = 0
    server_ip: Optional[str] = None

    @property
    def is_redirect(self) -> bool:
        return 300 <= self.status_code < 400

    @property
    def is_success(self) -> bool:
        return 200 <= self.status_code < 300

    @property
    def is_error(self) -> bool:
        return self.status_code >= 400


@dataclass
class AuditReport:
    target: str
    scan_date: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    duration: float = 0.0
    urls_scanned: int = 0
    findings: list[Finding] = field(default_factory=list)
    modules_run: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.risk_level == RiskLevel.INFORMATIONAL)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    @property
    def risk_score(self) -> float:
        if not self.findings:
            return 0.0
        total = sum(f.risk_level.score * f.confidence for f in self.findings)
        return round(total / len(self.findings), 2)

    def to_dict(self) -> dict[str, Any]:
        return {
            "target": self.target,
            "scan_date": self.scan_date.isoformat(),
            "duration": round(self.duration, 2),
            "urls_scanned": self.urls_scanned,
            "total_findings": self.total_findings,
            "risk_score": self.risk_score,
            "critical": self.critical_count,
            "high": self.high_count,
            "medium": self.medium_count,
            "low": self.low_count,
            "info": self.info_count,
            "findings": [f.to_dict() for f in self.findings],
            "modules_run": self.modules_run,
            "errors": self.errors,
            "metadata": self.metadata,
        }

    def findings_by_risk(self, level: RiskLevel) -> list[Finding]:
        return [f for f in self.findings if f.risk_level == level]

    def findings_by_module(self, module: str) -> list[Finding]:
        return [f for f in self.findings if f.module == module]


@dataclass
class Endpoint:
    path: str
    method: str
    params: list[str] = field(default_factory=list)
    headers: dict[str, str] = field(default_factory=dict)
    content_type: str = ""
    response_code: int = 0
    source: str = ""


@dataclass
class JSFile:
    url: str
    content: str
    size: int = 0
    endpoints: list[str] = field(default_factory=list)
    api_refs: list[str] = field(default_factory=list)
    internal_urls: list[str] = field(default_factory=list)
    cloud_refs: list[str] = field(default_factory=list)
    secrets: list[str] = field(default_factory=list)


@dataclass
class CloudAsset:
    asset_type: str
    url: str
    provider: str
    publicly_accessible: bool = False
    evidence: str = ""
    confidence: float = 0.0


class ScanState:
    """Manages scan state for resume capability."""

    def __init__(self) -> None:
        self.scanned_urls: set[str] = set()
        self.pending_urls: set[str] = set()
        self.failed_urls: dict[str, str] = {}
        self.current_depth: int = 0
        self.completed_modules: list[str] = []
        self.findings_count: int = 0
