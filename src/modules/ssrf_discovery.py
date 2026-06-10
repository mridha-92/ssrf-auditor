"""Module 1: SSRF Exposure Discovery - Detect potential SSRF attack surfaces."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urlparse, parse_qs

from src.models import Finding, RiskLevel
from src.modules.base import BaseModule
from src.utils.parsers import URLParser


class SSRFFindingParams:
    RELEVANT_PARAMS = {
        "callback", "redirect", "return_url", "return_url", "returnurl",
        "feed_url", "feedurl", "image_url", "imageurl", "img_url",
        "webhook", "webhook_url", "webhookurl", "import_url", "importurl",
        "avatar_url", "avatarurl", "api_url", "apiurl", "endpoint",
        "proxy", "fetch", "download", "upload_url", "uploadurl",
        "next", "prev", "to", "goto", "url", "link", "href",
        "src", "source", "target", "page", "file", "path",
        "redirect_uri", "redirecturi", "return_to", "returnto",
        "continue", "cont", "dest", "destination", "out",
        "view", "dir", "show", "document", "folder", "root",
        "load", "read", "process", "handle", "execute", "run",
        "uri", "resource", "request", "include", "require",
        "template", "theme", "style", "css", "custom",
    }

    URL_VALUE_PATTERN = re.compile(
        r"https?://[^\s'\"<>(){}|\\^`\[\]]+", re.IGNORECASE
    )


class SSRFFormAnalyzer:
    @staticmethod
    def analyze_form(action: str, method: str, inputs: list[dict]) -> list[dict]:
        findings = []
        for inp in inputs:
            name = inp.get("name", "").lower()
            for target in SSRFFindingParams.RELEVANT_PARAMS:
                if target in name or name == target:
                    findings.append({
                        "param": inp["name"],
                        "type": inp.get("type", "text"),
                        "method": method,
                        "action": action,
                    })
        return findings


class SSRFDiscoveryModule(BaseModule):
    """Detects potential SSRF vulnerabilities through parameter analysis."""

    module_name = "ssrf_discovery"
    module_description = "SSRF Exposure Discovery - Detects URL-related inputs across various attack surfaces"

    async def run(self, urls: list[str]) -> list[Finding]:
        self.findings.clear()
        urls_analyzed = set()

        for url in urls:
            if url in urls_analyzed:
                continue
            urls_analyzed.add(url)

            await self._analyze_url_params(url)
            await self._analyze_path_patterns(url)

        return self.findings

    async def _analyze_url_params(self, url: str) -> None:
        findings = URLParser.find_ssrf_params(url)
        seen_params = set()

        for param, value in findings:
            param_lower = param.lower()
            if param_lower in seen_params:
                continue
            seen_params.add(param_lower)

            is_url = bool(re.match(r"^https?://", value, re.IGNORECASE))
            confidence = 0.9 if is_url else 0.6
            risk = RiskLevel.HIGH if is_url else RiskLevel.MEDIUM

            finding = self.create_finding(
                title=f"Potential SSRF parameter: {param}",
                description=(
                    f"Parameter '{param}' in URL '{url}' accepts URL-like input "
                    f"({'URL value detected' if is_url else 'suspicious value format'}). "
                    f"This could be used for SSRF attacks if not properly validated."
                ),
                risk_level=risk,
                confidence=confidence,
                url=url,
                parameter=param,
                evidence=f"Parameter '{param}' = '{value}'",
                detection_source="URL parameter analysis",
                remediation=(
                    "Validate and sanitize all URL inputs. Use allowlist validation. "
                    "Restrict outbound requests. Implement network segmentation. "
                    "Use URL parsing libraries to validate scheme, host, and path."
                ),
                tags=["ssrf", "url-parameter", f"confidence-{int(confidence * 10)}"],
            )
            self.add_finding(finding)

    async def _analyze_path_patterns(self, url: str) -> None:
        path_patterns = [
            (r"/proxy\b", "Proxy endpoint", RiskLevel.HIGH),
            (r"/fetch\b", "Fetch/resource loader endpoint", RiskLevel.HIGH),
            (r"/download\b", "Download endpoint", RiskLevel.MEDIUM),
            (r"/redirect\b", "Redirect endpoint", RiskLevel.MEDIUM),
            (r"/webhook\b", "Webhook endpoint", RiskLevel.HIGH),
            (r"/callback\b", "Callback endpoint", RiskLevel.HIGH),
            (r"/import\b", "Import endpoint", RiskLevel.HIGH),
            (r"/upload\b", "Upload endpoint (potential file URL)", RiskLevel.MEDIUM),
            (r"/api/proxy\b", "API proxy endpoint", RiskLevel.HIGH),
            (r"/api/v\d+/proxy\b", "Versioned API proxy", RiskLevel.HIGH),
            (r"/external\b", "External resource loader", RiskLevel.HIGH),
            (r"/remote\b", "Remote resource loader", RiskLevel.HIGH),
            (r"/load\b", "Resource loader", RiskLevel.MEDIUM),
        ]

        parsed = urlparse(url)
        path = parsed.path.lower()

        for pattern, description, risk in path_patterns:
            if re.search(pattern, path):
                finding = self.create_finding(
                    title=f"SSRF-susceptible endpoint: {description}",
                    description=(
                        f"Endpoint pattern '{pattern[1:-1]}' found at {url}. "
                        f"This endpoint may accept and process URL inputs, "
                        f"potentially enabling SSRF attacks."
                    ),
                    risk_level=risk,
                    confidence=0.7,
                    url=url,
                    evidence=f"Path matches pattern: {pattern[1:-1]}",
                    detection_source="URL path pattern analysis",
                    remediation=(
                        "Audit this endpoint for URL input handling. "
                        "Implement strict validation of all URL inputs. "
                        "Use network segmentation to restrict outbound traffic."
                    ),
                    tags=["ssrf", "endpoint-pattern", "url-input"],
                )
                self.add_finding(finding)
