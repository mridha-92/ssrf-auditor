"""Module 9: Risk Engine - Classify, score, and prioritize security findings."""

from __future__ import annotations

import math
from typing import Any

from src.models import AuditReport, Finding, RiskLevel
from src.modules.base import BaseModule


class RiskClassifier:
    CVSS_VECTORS = {
        "ssrf": {
            "critical": {
                "desc": "Direct SSRF to cloud metadata service with full control",
                "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
            },
            "high": {
                "desc": "SSRF capable of accessing internal services or cloud metadata",
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
            },
            "medium": {
                "desc": "URL parameter injection point without confirmed access",
                "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:L/A:N",
            },
            "low": {
                "desc": "URL-like parameter pattern without clear exploit path",
                "vector": "AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:L/A:N",
            },
        },
        "info_disclosure": {
            "critical": {
                "desc": "Hardcoded credentials or keys exposed",
                "vector": "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
            },
            "high": {
                "desc": "Internal infrastructure details exposed",
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
            },
            "medium": {
                "desc": "Technology stack or configuration details",
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
            },
            "low": {
                "desc": "Informational disclosure with limited impact",
                "vector": "AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N",
            },
        },
    }

    SSRF_KEYWORDS = {
        "ssrf", "url-parameter", "endpoint-pattern", "url-input",
        "ssrf-vector", "ssrf-mitigation", "cloud-metadata",
    }
    DISCLOSURE_KEYWORDS = {
        "credentials", "secrets", "internal-urls", "internal",
        "cloud-storage", "header-leak", "information-leak",
        "infra-disclosure", "infra_disclosure",
    }

    @classmethod
    def classify(cls, finding: Finding) -> tuple[RiskLevel, float]:
        base_score = cls._calculate_base_score(finding)
        context_modifier = cls._calculate_context_modifier(finding)
        final_score = min(base_score * context_modifier, 10.0)

        if final_score >= 9.0:
            return RiskLevel.CRITICAL, round(final_score, 1)
        elif final_score >= 7.0:
            return RiskLevel.HIGH, round(final_score, 1)
        elif final_score >= 4.0:
            return RiskLevel.MEDIUM, round(final_score, 1)
        elif final_score >= 1.0:
            return RiskLevel.LOW, round(final_score, 1)
        return RiskLevel.INFORMATIONAL, round(final_score, 1)

    @classmethod
    def _calculate_base_score(cls, finding: Finding) -> float:
        severity_map = {
            RiskLevel.CRITICAL: 9.5,
            RiskLevel.HIGH: 7.5,
            RiskLevel.MEDIUM: 5.5,
            RiskLevel.LOW: 2.5,
            RiskLevel.INFORMATIONAL: 0.5,
        }
        base = severity_map.get(finding.risk_level, 2.5)
        confidence_modifier = 0.5 + (finding.confidence * 0.5)
        return base * confidence_modifier

    @classmethod
    def _calculate_context_modifier(cls, finding: Finding) -> float:
        modifier = 1.0

        tags_lower = {t.lower() for t in finding.tags}

        if any(ssrf in tags_lower for ssrf in cls.SSRF_KEYWORDS):
            modifier *= 1.4

        if any(disc in tags_lower for disc in cls.DISCLOSURE_KEYWORDS):
            modifier *= 1.3

        if "critical" in [t.lower() for t in finding.tags]:
            modifier *= 1.3

        if "cloud-metadata" in tags_lower:
            modifier *= 1.5

        if any(tag in tags_lower for tag in ["ssrf", "url-input", "proxy-headers"]):
            modifier *= 1.3

        return modifier


class RiskEngineModule(BaseModule):
    """Evaluates, scores, and prioritizes all findings for risk-based reporting."""

    module_name = "risk_engine"
    module_description = "Risk Engine - Classifies findings with CVSS-based scoring and prioritization"

    async def run(self, urls: list[str]) -> list[Finding]:
        self.findings.clear()
        return self.findings

    def analyze_report(self, report: AuditReport) -> AuditReport:
        self.logger.info(f"Analyzing {len(report.findings)} findings for risk scoring")

        for finding in report.findings:
            classified_risk, cvss_score = RiskClassifier.classify(finding)
            finding.risk_level = classified_risk
            if "cvss_score" not in finding.raw_data:
                finding.raw_data["cvss_score"] = cvss_score
            else:
                finding.raw_data["cvss_score"] = max(
                    float(finding.raw_data.get("cvss_score", 0)), cvss_score
                )

        report.findings.sort(
            key=lambda f: (f.risk_level.score * -1, f.confidence * -1)
        )

        self._add_summary_findings(report)
        return report

    def _add_summary_findings(self, report: AuditReport) -> None:
        risk_counts = {}
        for finding in report.findings:
            level = str(finding.risk_level)
            risk_counts[level] = risk_counts.get(level, 0) + 1

        if report.critical_count > 0:
            finding = self.create_finding(
                title=f"Critical Risk Summary: {report.critical_count} Critical Findings",
                description=(
                    f"Audit identified {report.critical_count} critical security issues "
                    f"that require immediate attention. Total findings across all "
                    f"severities: {report.total_findings}"
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=1.0,
                evidence=f"Critical: {report.critical_count}, High: {report.high_count}, "
                         f"Medium: {report.medium_count}, Low: {report.low_count}, "
                         f"Info: {report.info_count}",
                detection_source="Risk engine analysis",
                remediation=(
                    "Address critical and high-risk findings immediately. "
                    "Prioritize based on CVSS scores and exploitability."
                ),
                tags=["risk-summary", "critical"],
            )
            report.findings.insert(0, finding)

        overall_risk = self.create_finding(
            title=f"Overall Risk Score: {report.risk_score}/5.0",
            description=(
                f"Overall weighted risk score for {report.target}: "
                f"{report.risk_score}/5.0 based on {report.total_findings} findings "
                f"across {len(report.modules_run)} modules."
            ),
            risk_level=RiskLevel.INFORMATIONAL,
            confidence=1.0,
            evidence=f"Risk Score: {report.risk_score}/5.0",
            detection_source="Risk engine aggregation",
            remediation="Review all findings and implement recommended remediations.",
            tags=["risk-summary", "overall-score"],
        )
        report.findings.insert(0, overall_risk)
