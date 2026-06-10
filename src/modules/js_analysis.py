"""Module 5: JavaScript Analysis - Extract sensitive information from JavaScript files."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse, urljoin

from bs4 import BeautifulSoup

from src.models import Finding, JSFile, RiskLevel
from src.modules.base import BaseModule


class JSAnalyzer:
    ENDPOINT_PATTERN = re.compile(
        r"""['"`]((?:/[a-zA-Z0-9_\-./?=&%${}]+){2,})['"`]""",
        re.IGNORECASE
    )

    API_PATTERN = re.compile(
        r"""['"`]((?:https?://)?(?:api|v[12]/|rest|graphql|endpoint)[a-zA-Z0-9_\-./?=&%${}]+)['"`]""",
        re.IGNORECASE
    )

    INTERNAL_URL_PATTERN = re.compile(
        r"""['"`]((?:https?://)?(?:localhost|127\.0\.0\.1|10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3}|[a-zA-Z0-9-]+\.(?:internal|local|corp|lan|intranet|private))(?::\d+)?(?:/[\w\-./?=&%]*)?)['"`]""",
        re.IGNORECASE
    )

    CLOUD_STORAGE_PATTERN = re.compile(
        r"""['"`]((?:https?://)?(?:[a-zA-Z0-9._-]+\.s3[.\-][\w.-]+\.amazonaws\.com|[a-zA-Z0-9._-]+\.s3[.\-][\w.-]+\.amazonaws\.com\.cn|storage\.googleapis\.com/[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+\.storage\.googleapis\.com|[a-zA-Z0-9._-]+\.blob\.core\.windows\.net|[a-zA-Z0-9._-]+\.azureedge\.net|[a-zA-Z0-9._-]+\.cloudfront\.net|[a-zA-Z0-9._-]+\.r2\.cloudflarestorage\.com)(?:/[^\s'"]*)?)['"`]""",
        re.IGNORECASE
    )

    ENV_INDICATOR_PATTERN = re.compile(
        r"""['"`]?(process\.env\.\w+|import\.meta\.env\.\w+|
            __ENV\.\w+|window\.__ENV|_env\.[A-Z_]+|
            ENV_[A-Z_]+|REACT_APP_[A-Z_]+|
            VUE_APP_[A-Z_]+|NEXT_PUBLIC_[A-Z_]+|
            GATSBY_[A-Z_]+|SANITY_STUDIO_[A-Z_]+|
            CRAWLER_[A-Z_]+|NG_APP_[A-Z_]+)['"`]?""",
        re.IGNORECASE
    )

    HARDCODED_SECRET_PATTERN = re.compile(
        r"""(?i)(?:['"`](?:AKIA[0-9A-Z]{16}|[A-Za-z0-9+/]{40})['"`]|
            ['"`](?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}['"`]|
            ['"`](?:xox[bpsar]-[A-Za-z0-9-]{10,})['"`]|
            ['"`]sk_live_[0-9a-zA-Z]{24,}['"`]|
            ['"`]pk_live_[0-9a-zA-Z]{24,}['"`]|
            ['"`]SG\.[\w\-.]{22,}['"`])"""
    )

    @classmethod
    def analyze(cls, js_content: str, js_url: str) -> JSFile:
        js_file = JSFile(url=js_url, content=js_content, size=len(js_content))

        js_file.endpoints = list(set(cls.ENDPOINT_PATTERN.findall(js_content)))
        js_file.api_refs = list(set(cls.API_PATTERN.findall(js_content)))
        js_file.internal_urls = list(set(cls.INTERNAL_URL_PATTERN.findall(js_content)))
        js_file.cloud_refs = list(set(cls.CLOUD_STORAGE_PATTERN.findall(js_content)))

        env_matches = cls.ENV_INDICATOR_PATTERN.findall(js_content)
        js_file.secrets = list(set(env_matches))

        secret_matches = cls.HARDCODED_SECRET_PATTERN.findall(js_content)
        if secret_matches:
            js_file.secrets.extend(list(set(secret_matches)))

        return js_file


class JSAnalysisModule(BaseModule):
    """Analyzes JavaScript files for endpoints, secrets, and infrastructure references."""

    module_name = "js_analysis"
    module_description = "JavaScript Analysis - Extracts endpoints, API refs, secrets, and infrastructure data from JS"

    async def run(self, urls: list[str]) -> list[Finding]:
        self.findings.clear()
        js_files: list[JSFile] = []
        analyzed_js = set()

        for url in urls:
            try:
                response = await self.http.get(url)
                if not response.is_success:
                    continue

                js_urls = self._extract_js_urls(response.body, url)
                for js_url in js_urls:
                    if js_url in analyzed_js:
                        continue
                    analyzed_js.add(js_url)
                    try:
                        js_response = await self.http.get(js_url)
                        if js_response.is_success:
                            js_file = JSAnalyzer.analyze(js_response.body, js_url)
                            js_files.append(js_file)
                    except Exception:
                        continue

            except Exception:
                continue

        for js_file in js_files:
            self._process_js_file(js_file)

        return self.findings

    def _extract_js_urls(self, html: str, base_url: str) -> list[str]:
        urls = []
        soup = BeautifulSoup(html, "lxml")
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                full_url = urljoin(base_url, src)
                if any(full_url.endswith(ext) for ext in [".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"]):
                    urls.append(full_url)

        for script in soup.find_all("script"):
            content = script.string
            if content:
                inline_js_matches = re.findall(r'''['"`]([^'"`]+\.(?:js|mjs|cjs)\?[^'"`]*)['"`]''', content)
                for match in inline_js_matches:
                    full_url = urljoin(base_url, match)
                    urls.append(full_url)

        return list(set(urls))

    def _process_js_file(self, js_file: JSFile) -> None:
        min_size = self.get_config("min_js_file_size", 1024)
        max_size = self.get_config("max_js_file_size", 5242880)
        if js_file.size < min_size or js_file.size > max_size:
            return

        if js_file.endpoints and self.get_config("extract_endpoints", True):
            finding = self.create_finding(
                title="JavaScript Endpoint Discovery",
                description=(
                    f"Found {len(js_file.endpoints)} endpoint(s) in JS file "
                    f"at {js_file.url}"
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.8,
                url=js_file.url,
                evidence="; ".join(js_file.endpoints[:10]),
                detection_source="JavaScript endpoint extraction",
                remediation="Review exposed endpoints and implement access controls.",
                tags=["js-analysis", "endpoints"],
            )
            self.add_finding(finding)

        if js_file.api_refs and self.get_config("extract_api_refs", True):
            finding = self.create_finding(
                title="JavaScript API Reference Discovery",
                description=(
                    f"Found {len(js_file.api_refs)} API reference(s) in JS file "
                    f"at {js_file.url}"
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.85,
                url=js_file.url,
                evidence="; ".join(js_file.api_refs[:10]),
                detection_source="JavaScript API reference extraction",
                remediation="Review exposed API endpoints for proper authentication.",
                tags=["js-analysis", "api-refs"],
            )
            self.add_finding(finding)

        if js_file.internal_urls and self.get_config("extract_internal_urls", True):
            finding = self.create_finding(
                title="JavaScript Internal URL Exposure",
                description=(
                    f"Found {len(js_file.internal_urls)} internal URL(s) in JS file "
                    f"at {js_file.url}"
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.95,
                url=js_file.url,
                evidence="; ".join(js_file.internal_urls[:10]),
                detection_source="JavaScript internal URL extraction",
                remediation=(
                    "Remove internal URL references from client-side JavaScript. "
                    "Use server-side configuration for internal service URLs."
                ),
                tags=["js-analysis", "internal-urls"],
            )
            self.add_finding(finding)

        if js_file.cloud_refs and self.get_config("extract_cloud_refs", True):
            finding = self.create_finding(
                title="JavaScript Cloud Storage Reference",
                description=(
                    f"Found {len(js_file.cloud_refs)} cloud storage reference(s) "
                    f"in JS file at {js_file.url}"
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                url=js_file.url,
                evidence="; ".join(js_file.cloud_refs[:10]),
                detection_source="JavaScript cloud storage extraction",
                remediation=(
                    "Ensure cloud storage buckets are properly configured with "
                    "appropriate access controls."
                ),
                tags=["js-analysis", "cloud-storage"],
            )
            self.add_finding(finding)

        if js_file.secrets and self.get_config("extract_env_indicators", True):
            finding = self.create_finding(
                title="JavaScript Potential Secret/Environment Variable",
                description=(
                    f"Found {len(js_file.secrets)} potential secret or environment "
                    f"variable reference(s) in JS file at {js_file.url}"
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=0.9,
                url=js_file.url,
                evidence="; ".join(js_file.secrets[:10]),
                detection_source="JavaScript secret pattern detection",
                remediation=(
                    "Remove hardcoded secrets and environment variable references "
                    "from client-side JavaScript. Use proper secret management."
                ),
                tags=["js-analysis", "secrets", "env-vars"],
            )
            self.add_finding(finding)
