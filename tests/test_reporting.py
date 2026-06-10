"""Tests for reporting module."""

import json
import csv
import os
import pytest
from pathlib import Path
from unittest.mock import Mock, patch

from src.modules.reporting import HTMLRenderer, JSONRenderer, CSVRenderer
from src.models import AuditReport, Finding, RiskLevel


@pytest.fixture
def sample_report():
    report = AuditReport(target="https://example.com")
    report.duration = 45.67
    report.urls_scanned = 100
    report.findings = [
        Finding(
            title="SSRF Parameter Found",
            description="Test description",
            risk_level=RiskLevel.CRITICAL,
            confidence=0.95,
            module="ssrf_discovery",
            url="https://example.com/page?url=http://evil.com",
            parameter="url",
            evidence="Parameter 'url' = 'http://evil.com'",
            detection_source="URL parameter analysis",
            remediation="Validate URL inputs",
            tags=["ssrf", "test"],
        ),
        Finding(
            title="Cloud Metadata Reference",
            description="AWS metadata IP found",
            risk_level=RiskLevel.HIGH,
            confidence=0.9,
            module="cloud_metadata",
            url="https://example.com",
            evidence="169.254.169.254",
            detection_source="Content analysis",
            remediation="Remove metadata references",
            tags=["cloud", "aws"],
        ),
    ]
    report.modules_run = ["ssrf_discovery", "cloud_metadata"]
    return report


class TestJSONRenderer:
    def test_render(self, tmp_path, sample_report):
        renderer = JSONRenderer(sample_report, str(tmp_path), {})
        filepath = renderer.render()
        assert Path(filepath).exists()

        with open(filepath) as f:
            data = json.load(f)
        assert data["target"] == "https://example.com"
        assert data["total_findings"] == 2
        assert data["critical"] == 1
        assert data["high"] == 1


class TestCSVRenderer:
    def test_render(self, tmp_path, sample_report):
        renderer = CSVRenderer(sample_report, str(tmp_path), {})
        filepath = renderer.render()
        assert Path(filepath).exists()

        with open(filepath, newline="") as f:
            reader = csv.reader(f)
            rows = list(reader)
        assert len(rows) == 3
        assert rows[0] == Finding.csv_headers()


class TestHTMLRenderer:
    def test_render(self, tmp_path, sample_report):
        renderer = HTMLRenderer(sample_report, str(tmp_path), {})
        filepath = renderer.render()
        assert Path(filepath).exists()

        with open(filepath) as f:
            content = f.read()
        assert "SSRF Auditor Report" in content
        assert "Critical" in content
        assert "https://example.com" in content
