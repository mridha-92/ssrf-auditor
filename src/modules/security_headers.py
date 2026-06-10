"""Module 7: Security Header Analysis - Evaluate security headers for SSRF-related misconfigurations."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from src.models import Finding, RiskLevel
from src.modules.base import BaseModule


class SecurityHeaderChecks:
    CSP_WEAKNESSES = [
        (r"unsafe-inline", "Unsafe inline scripts allowed in CSP", RiskLevel.HIGH),
        (r"unsafe-eval", "Unsafe eval allowed in CSP", RiskLevel.HIGH),
        (r"\*\.?\\'", "Wildcard in CSP", RiskLevel.MEDIUM),
        (r"https?://\*", "Protocol wildcard in CSP", RiskLevel.MEDIUM),
        (r"http://", "HTTP protocol allowed in CSP", RiskLevel.MEDIUM),
        (r"data:", "Data: URI scheme allowed in CSP", RiskLevel.MEDIUM),
    ]

    CORS_WEAKNESSES = [
        (r"\*", "Wildcard origin in CORS", RiskLevel.HIGH),
        (r"null", "Null origin allowed in CORS", RiskLevel.HIGH),
        (r"http://", "HTTP origins allowed in CORS", RiskLevel.MEDIUM),
        (r"https?://\*", "Wildcard protocol in CORS", RiskLevel.MEDIUM),
    ]

    HSTS_WEAKNESSES = [
        ("max-age=", "HSTS configured but needs review", RiskLevel.LOW),
        ("max-age=0", "HSTS disabled", RiskLevel.HIGH),
        ("includesubdomains", "HSTS includes subdomains (correct)", RiskLevel.INFORMATIONAL),
        ("preload", "HSTS preload enabled (recommended)", RiskLevel.INFORMATIONAL),
    ]


class SecurityHeadersModule(BaseModule):
    """Analyzes HTTP security headers for misconfigurations."""

    module_name = "security_headers"
    module_description = "Security Header Analysis - Evaluates CSP, CORS, HSTS, and other security headers"

    async def run(self, urls: list[str]) -> list[Finding]:
        self.findings.clear()
        analyzed_urls = set()

        for url in urls:
            parsed = urlparse(url)
            base_url = f"{parsed.scheme}://{parsed.netloc}"
            if base_url in analyzed_urls:
                continue
            analyzed_urls.add(base_url)

            try:
                response = await self.http.get(base_url)
                if response.is_success or response.is_error:
                    self._analyze_csp(response.headers, base_url)
                    self._analyze_cors(response.headers, base_url)
                    self._analyze_hsts(response.headers, base_url)
                    self._analyze_referrer_policy(response.headers, base_url)
                    self._analyze_permissions_policy(response.headers, base_url)
                    self._analyze_other_headers(response.headers, base_url)
                    self._check_missing_headers(response.headers, base_url)
            except Exception:
                continue

        return self.findings

    def _analyze_csp(self, headers: dict, url: str) -> None:
        if not self.get_config("check_csp", True):
            return

        csp = headers.get("content-security-policy", "")
        if not csp:
            self.add_finding(self.create_finding(
                title="Missing Content-Security-Policy Header",
                description=(
                    f"URL {url} does not include a Content-Security-Policy header. "
                    f"This increases SSRF risk as there is no restriction on "
                    f"resources that can be loaded or connected to."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                url=url,
                evidence="Missing CSP header",
                detection_source="HTTP response header analysis",
                remediation=(
                    "Implement a Content-Security-Policy header that restricts "
                    "connect-src, script-src, and frame-src directives to "
                    "prevent SSRF and data exfiltration."
                ),
                tags=["security-headers", "csp", "ssrf-mitigation"],
            ))
            return

        csp_lower = csp.lower()
        for pattern, desc, risk in SecurityHeaderChecks.CSP_WEAKNESSES:
            if re.search(pattern, csp_lower, re.IGNORECASE):
                risk_adj = risk
                if "script-src" not in csp_lower:
                    pass
                self.add_finding(self.create_finding(
                    title=f"CSP Weakness: {desc}",
                    description=(
                        f"CSP header at {url} has weakness: {desc}. "
                        f"Full CSP: {csp[:200]}"
                    ),
                    risk_level=risk_adj,
                    confidence=0.9,
                    url=url,
                    evidence=desc,
                    detection_source="CSP header analysis",
                    remediation=(
                        "Remove unsafe directives from CSP. Use strict-dynamic "
                        "and nonce-based script loading. Restrict connect-src "
                        "to prevent SSRF via fetch/XMLHttpRequest."
                    ),
                    tags=["security-headers", "csp"],
                ))

    def _analyze_cors(self, headers: dict, url: str) -> None:
        if not self.get_config("check_cors", True):
            return

        acao = headers.get("access-control-allow-origin", "")
        acac = headers.get("access-control-allow-credentials", "")

        if not acao:
            return

        acao_lower = acao.lower()
        for pattern, desc, risk in SecurityHeaderChecks.CORS_WEAKNESSES:
            if re.search(pattern, acao_lower, re.IGNORECASE):
                credentials_info = f" Credentials enabled." if acac.lower() == "true" else ""
                self.add_finding(self.create_finding(
                    title=f"CORS Misconfiguration: {desc}",
                    description=(
                        f"CORS header at {url}: Access-Control-Allow-Origin: {acao}.{credentials_info} "
                        f"This can enable SSRF through cross-origin requests."
                    ),
                    risk_level=risk,
                    confidence=0.95,
                    url=url,
                    evidence=f"ACAO: {acao}, Credentials: {acac}",
                    detection_source="CORS header analysis",
                    remediation=(
                        "Restrict CORS to specific trusted origins. "
                        "Avoid using wildcard or null origins. "
                        "Only enable credentials when necessary."
                    ),
                    tags=["security-headers", "cors", "ssrf-vector"],
                ))

    def _analyze_hsts(self, headers: dict, url: str) -> None:
        if not self.get_config("check_hsts", True):
            return

        hsts = headers.get("strict-transport-security", "")
        if not hsts:
            self.add_finding(self.create_finding(
                title="Missing Strict-Transport-Security Header",
                description=(
                    f"URL {url} does not include HSTS header. "
                    f"Without HSTS, SSL stripping attacks are possible."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.8,
                url=url,
                evidence="Missing HSTS header",
                detection_source="HTTP response header analysis",
                remediation="Implement HSTS with a long max-age and includeSubDomains.",
                tags=["security-headers", "hsts"],
            ))
            return

        hsts_lower = hsts.lower()
        for pattern, desc, risk in SecurityHeaderChecks.HSTS_WEAKNESSES:
            if pattern in hsts_lower:
                self.add_finding(self.create_finding(
                    title=f"HSTS: {desc}",
                    description=f"HSTS header at {url}: {hsts[:200]}",
                    risk_level=risk,
                    confidence=0.9,
                    url=url,
                    evidence=desc,
                    detection_source="HSTS header analysis",
                    remediation="Ensure HSTS has adequate max-age and includes subdomains.",
                    tags=["security-headers", "hsts"],
                ))

    def _analyze_referrer_policy(self, headers: dict, url: str) -> None:
        if not self.get_config("check_referrer_policy", True):
            return

        rp = headers.get("referrer-policy", "")
        if not rp:
            self.add_finding(self.create_finding(
                title="Missing Referrer-Policy Header",
                description=(
                    f"URL {url} does not include a Referrer-Policy header. "
                    f"This may leak internal URLs in the Referer header."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.7,
                url=url,
                evidence="Missing Referrer-Policy",
                detection_source="HTTP response header analysis",
                remediation=(
                    "Set Referrer-Policy to 'strict-origin-when-cross-origin' "
                    "or 'no-referrer' to prevent URL leakage."
                ),
                tags=["security-headers", "referrer-policy", "information-leak"],
            ))

    def _analyze_permissions_policy(self, headers: dict, url: str) -> None:
        if not self.get_config("check_permissions_policy", True):
            return

        pp = headers.get("permissions-policy", "")
        if not pp:
            self.add_finding(self.create_finding(
                title="Missing Permissions-Policy Header",
                description=(
                    f"URL {url} does not include a Permissions-Policy header."
                ),
                risk_level=RiskLevel.LOW,
                confidence=0.5,
                url=url,
                evidence="Missing Permissions-Policy",
                detection_source="HTTP response header analysis",
                remediation="Implement Permissions-Policy to restrict browser features.",
                tags=["security-headers", "permissions-policy"],
            ))

    def _analyze_other_headers(self, headers: dict, url: str) -> None:
        checks = [
            ("x-frame-options", "X-Frame-Options", "Missing clickjacking protection", RiskLevel.MEDIUM),
            ("x-xss-protection", "X-XSS-Protection", "Missing XSS filter header", RiskLevel.LOW),
            ("x-content-type-options", "X-Content-Type-Options", "Missing MIME type sniffing protection", RiskLevel.MEDIUM),
        ]

        for check_key in ["check_xframe", "check_xxss", "check_xcontent"]:
            idx = ["check_xframe", "check_xxss", "check_xcontent"].index(check_key)
            header_name, display_name, desc, risk = checks[idx]
            if not self.get_config(check_key, True):
                continue

            if header_name not in headers:
                self.add_finding(self.create_finding(
                    title=f"Missing {display_name} Header",
                    description=f"{desc} at {url}.",
                    risk_level=risk,
                    confidence=0.8,
                    url=url,
                    evidence=f"Missing {display_name} header",
                    detection_source="HTTP response header analysis",
                    remediation=f"Add the {display_name} header to responses.",
                    tags=["security-headers", header_name.lower()],
                ))

    def _check_missing_headers(self, headers: dict, url: str) -> None:
        important_headers = {
            "content-security-policy": "CSP",
            "strict-transport-security": "HSTS",
            "x-frame-options": "XFO",
            "x-content-type-options": "XCTO",
        }

        missing = [name for name in important_headers if name not in headers]
        if len(missing) >= 3:
            self.add_finding(self.create_finding(
                title="Multiple Missing Security Headers",
                description=(
                    f"URL {url} is missing {len(missing)} important security headers: "
                    f"{', '.join(important_headers[h] for h in missing)}"
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.9,
                url=url,
                evidence="Missing headers: " + ", ".join(missing),
                detection_source="Security header inventory",
                remediation=(
                    "Implement all recommended security headers: "
                    "CSP, HSTS, X-Frame-Options, X-Content-Type-Options"
                ),
                tags=["security-headers", "missing-headers"],
            ))
