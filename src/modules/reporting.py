"""Module 10: Reporting - Generate comprehensive audit reports in multiple formats."""

from __future__ import annotations

import csv
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from jinja2 import Environment, FileSystemLoader

from src.models import AuditReport, Finding, RiskLevel
from src.modules.base import BaseModule
from src.utils.helpers import ensure_directory, write_json


class ReportRenderer:
    """Base report renderer."""

    def __init__(self, report: AuditReport, output_dir: str, config: dict) -> None:
        self.report = report
        self.output_dir = output_dir
        self.config = config

    def render(self) -> str:
        raise NotImplementedError


class JSONRenderer(ReportRenderer):
    """Render audit report as JSON."""

    def render(self) -> str:
        data = self.report.to_dict()
        data["report_metadata"] = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "tool_name": "SSRF Auditor",
            "tool_version": "2.0.0",
            "report_format": "json",
        }
        filename = f"ssrf-audit-report-{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        filepath = os.path.join(self.output_dir, filename)
        write_json(data, filepath)
        return filepath


class CSVRenderer(ReportRenderer):
    """Render audit report as CSV."""

    def render(self) -> str:
        filename = f"ssrf-audit-report-{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        filepath = os.path.join(self.output_dir, filename)

        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(Finding.csv_headers())
            for finding in self.report.findings:
                writer.writerow(finding.to_csv_row())

        return filepath


class HTMLRenderer(ReportRenderer):
    """Render audit report as HTML with interactive elements."""

    TEMPLATE = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SSRF Auditor Report - {{ report.target }}</title>
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0e17; color: #e0e0e0; line-height: 1.6; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.header { background: linear-gradient(135deg, #0d1b2a 0%, #1b2838 100%); padding: 40px; border-radius: 12px; margin-bottom: 30px; border: 1px solid #1e3a5f; }
.header h1 { color: #ff4757; font-size: 2.2em; margin-bottom: 8px; }
.header .subtitle { color: #8a9db5; font-size: 1.1em; }
.stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin-bottom: 30px; }
.stat-card { background: #141e30; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #1e3a5f; }
.stat-card .value { font-size: 2em; font-weight: bold; }
.stat-card .label { color: #8a9db5; font-size: 0.85em; text-transform: uppercase; margin-top: 4px; }
.critical .value { color: #ff4757; }
.high .value { color: #ff6348; }
.medium .value { color: #ffa502; }
.low .value { color: #2ed573; }
.info .value { color: #747d8c; }
.risk-bar { background: #1e3a5f; border-radius: 4px; height: 8px; margin: 10px 0; }
.risk-bar-fill { height: 100%; border-radius: 4px; }
.summary { background: #141e30; padding: 25px; border-radius: 8px; margin-bottom: 30px; border: 1px solid #1e3a5f; }
.summary h2 { color: #ff4757; margin-bottom: 15px; }
.summary p { color: #8a9db5; margin-bottom: 8px; }
.findings-count { display: flex; gap: 10px; flex-wrap: wrap; }
.finding-card { background: #141e30; padding: 20px; border-radius: 8px; margin-bottom: 15px; border-left: 4px solid; }
.finding-card.critical { border-color: #ff4757; }
.finding-card.high { border-color: #ff6348; }
.finding-card.medium { border-color: #ffa502; }
.finding-card.low { border-color: #2ed573; }
.finding-card.info { border-color: #747d8c; }
.finding-card h3 { color: #e0e0e0; margin-bottom: 8px; }
.finding-card .meta { color: #8a9db5; font-size: 0.85em; margin-bottom: 8px; }
.finding-card .evidence { background: #0d1b2a; padding: 10px; border-radius: 4px; font-family: monospace; font-size: 0.85em; margin: 8px 0; word-break: break-all; }
.finding-card .remediation { border-top: 1px solid #1e3a5f; margin-top: 10px; padding-top: 10px; }
.finding-card .remediation h4 { color: #2ed573; margin-bottom: 4px; }
.tag { display: inline-block; background: #1e3a5f; padding: 2px 8px; border-radius: 3px; font-size: 0.75em; margin: 2px; }
.module-list { display: flex; gap: 10px; flex-wrap: wrap; margin: 15px 0; }
.module-badge { background: #1e3a5f; padding: 5px 12px; border-radius: 15px; font-size: 0.85em; }
.footer { text-align: center; color: #747d8c; font-size: 0.85em; margin-top: 40px; padding: 20px; border-top: 1px solid #1e3a5f; }
</style>
</head>
<body>
<div class="container">
<div class="header">
<h1>SSRF Auditor Report</h1>
<div class="subtitle">
  <strong>Target:</strong> {{ report.target }} |
  <strong>Date:</strong> {{ report.scan_date }} |
  <strong>Duration:</strong> {{ "%.2f"|format(report.duration) }}s |
  <strong>URLs Scanned:</strong> {{ report.urls_scanned }}
</div>
</div>

<div class="stats">
<div class="stat-card critical"><div class="value">{{ report.critical_count }}</div><div class="label">Critical</div></div>
<div class="stat-card high"><div class="value">{{ report.high_count }}</div><div class="label">High</div></div>
<div class="stat-card medium"><div class="value">{{ report.medium_count }}</div><div class="label">Medium</div></div>
<div class="stat-card low"><div class="value">{{ report.low_count }}</div><div class="label">Low</div></div>
<div class="stat-card info"><div class="value">{{ report.info_count }}</div><div class="label">Info</div></div>
<div class="stat-card"><div class="value">{{ report.total_findings }}</div><div class="label">Total</div></div>
</div>

<div class="summary">
<h2>Executive Summary</h2>
<p><strong>Risk Score:</strong> {{ report.risk_score }}/5.0</p>
<p><strong>Assessment Target:</strong> {{ report.target }}</p>
<p><strong>Scan Date:</strong> {{ report.scan_date }}</p>
<p><strong>Pages Analyzed:</strong> {{ report.urls_scanned }}</p>
<p><strong>Modules Executed:</strong> {{ report.modules_run|length }}</p>
<div class="module-list">
{% for module in report.modules_run %}
<span class="module-badge">{{ module }}</span>
{% endfor %}
</div>
</div>

<h2>Findings ({{ report.total_findings }})</h2>
{% for finding in report.findings %}
{% if finding.risk_level.value >= 3 %}
<div class="finding-card {{ finding.risk_level.name|lower }}">
<h3>{{ finding.title }}</h3>
<div class="meta">
  <strong>Risk:</strong> {{ finding.risk_level }} |
  <strong>Confidence:</strong> {{ "%.0f"|format(finding.confidence * 100) }}% |
  <strong>Module:</strong> {{ finding.module }} |
  <strong>Source:</strong> {{ finding.detection_source }}
  {% if finding.parameter %}| <strong>Parameter:</strong> {{ finding.parameter }}{% endif %}
</div>
<p>{{ finding.description }}</p>
{% if finding.evidence %}<div class="evidence">{{ finding.evidence }}</div>{% endif %}
{% if finding.remediation %}
<div class="remediation">
  <h4>Remediation</h4>
  <p>{{ finding.remediation }}</p>
</div>
{% endif %}
<div>{% for tag in finding.tags %}<span class="tag">{{ tag }}</span>{% endfor %}</div>
</div>
{% endif %}
{% endfor %}

{% if report.errors %}
<h2>Errors</h2>
<ul>
{% for error in report.errors %}
<li style="color: #ff4757;">{{ error }}</li>
{% endfor %}
</ul>
{% endif %}

<div class="footer">
  <p>Generated by SSRF Auditor v2.0 | {{ report.scan_date }}</p>
  <p>Authorized security testing only. Unauthorized use is prohibited.</p>
</div>
</div>
</body>
</html>"""

    def render(self) -> str:
        filename = f"ssrf-audit-report-{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        filepath = os.path.join(self.output_dir, filename)

        jinja_env = Environment(autoescape=True)
        template = jinja_env.from_string(self.TEMPLATE)
        html_content = template.render(report=self.report)

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        alt_filename = f"ssrf-audit-report-executive-{datetime.now().strftime('%Y%m%d_%H%M%S')}.html"
        alt_filepath = os.path.join(self.output_dir, alt_filename)

        with open(alt_filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath


class ReportingModule(BaseModule):
    """Generates comprehensive audit reports in HTML, JSON, and CSV formats."""

    module_name = "reporting"
    module_description = "Reporting - Generates HTML, JSON, and CSV audit reports"

    async def run(self, urls: list[str]) -> list[Finding]:
        self.findings.clear()
        return self.findings

    def generate_reports(self, report: AuditReport) -> dict[str, str]:
        output_dir = self.config.general.get("output_dir", "results")
        ensure_directory(output_dir)

        reporting_config = self.config.reporting
        formats = reporting_config.get("formats", ["html", "json", "csv"])
        generated_files: dict[str, str] = {}

        renderers = {
            "html": HTMLRenderer,
            "json": JSONRenderer,
            "csv": CSVRenderer,
        }

        config_dict = {
            "executive_summary": reporting_config.get("executive_summary", True),
            "technical_report": reporting_config.get("technical_report", True),
            "color_scheme": reporting_config.get("color_scheme", "dark"),
        }

        for fmt in formats:
            renderer_class = renderers.get(fmt.lower())
            if renderer_class:
                try:
                    renderer = renderer_class(report, output_dir, config_dict)
                    filepath = renderer.render()
                    generated_files[fmt] = filepath
                    self.logger.info(f"Generated {fmt.upper()} report: {filepath}")
                except Exception as e:
                    self.logger.error(f"Failed to generate {fmt} report: {e}")

        return generated_files
