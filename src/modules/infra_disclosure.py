"""Module 3: Infrastructure Disclosure - Detect exposed internal infrastructure references."""

from __future__ import annotations

import re
from typing import Any

from src.models import Finding, RiskLevel
from src.modules.base import BaseModule


class InfrastructurePatterns:
    PRIVATE_IPS = re.compile(
        r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3}|"
        r"127\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"169\.254\.\d{1,3}\.\d{1,3})\b"
    )

    INTERNAL_HOSTNAMES = re.compile(
        r"\b([a-zA-Z0-9-]+\.internal\."
        r"|[a-zA-Z0-9-]+\.local\."
        r"|[a-zA-Z0-9-]+\.corp\."
        r"|[a-zA-Z0-9-]+\.lan\."
        r"|[a-zA-Z0-9-]+\.intranet\."
        r"|[a-zA-Z0-9-]+\.private\."
        r"|[a-zA-Z0-9-]+-internal\.)"
        r"[a-zA-Z0-9.-]+", re.IGNORECASE
    )

    KUBERNETES = re.compile(
        r"\b(k8s|kubernetes|kube-[a-z]+|\.k8s\.local|"
        r"\.svc\.cluster\.local|kube-system|kube-public|"
        r"kube-node-lease|etcd|api-server|kubelet|"
        r"kube-controller|kube-scheduler|kube-proxy|"
        r"clusterIP|ClusterIP|NodePort|kubectl)\b", re.IGNORECASE
    )

    DOCKER = re.compile(
        r"\b(docker|container[d]?|docker-compose|dockerfile|"
        r"dockerhub|Docker Hub|/var/run/docker|"
        r"docker\.sock|com\.docker|moby|"
        r"registry\.docker|docker\.io)\b", re.IGNORECASE
    )

    SERVICE_MESH = re.compile(
        r"\b(istio|envoy|linkerd|consul|"
        r"service-mesh|sidecar|ambassador|"
        r"kong|traefik|nginx-ingress|"
        r"haproxy-ingress|contour|gloo)\b", re.IGNORECASE
    )

    INTERNAL_DNS = re.compile(
        r"\b([a-zA-Z0-9-]+\.ec2\.internal|"
        r"[a-zA-Z0-9-]+\.compute\.internal|"
        r"[a-zA-Z0-9-]+\.azur?e\.com|"
        r"[a-zA-Z0-9-]+\.appservice\.com|"
        r"[a-zA-Z0-9-]+\.cloudapp\.net|"
        r"[a-zA-Z0-9-]+\.internal\.cloudapp\.net|"
        r"[a-zA-Z0-9-]+\.rds\.amazonaws\.com|"
        r"[a-zA-Z0-9-]+\.elasticache\.amazonaws\.com|"
        r"[a-zA-Z0-9-]+\.docdb\.amazonaws\.com|"
        r"[a-zA-Z0-9-]+\.neptune\.amazonaws\.com|"
        r"[a-zA-Z0-9-]+\.es\.amazonaws\.com)\b", re.IGNORECASE
    )

    INTERNAL_URLS = re.compile(
        r"(https?://(?:localhost|127\.0\.0\.1|0\.0\.0\.0|"
        r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3})"
        r"(?::\d+)?(?:/[\w\-./?=&%]*)?)", re.IGNORECASE
    )

    PROXY_HEADERS = re.compile(
        r"\b(X-Forwarded-For|X-Real-IP|X-Forwarded-Proto|"
        r"X-Forwarded-Host|X-Original-URL|X-Rewrite-URL|"
        r"X-Forwarded-Server|X-HTTP-Method-Override|"
        r"X-HTTP-Method|X-Method-Override|"
        r"Front-End-Https|True-Client-IP|"
        r"CLUSTER-IP|X-Forwarded|Via)\b", re.IGNORECASE
    )

    BACKEND_TECH = re.compile(
        r"\b(Apache|Nginx|IIS|Tomcat|Jetty|JBoss|"
        r"WebLogic|WebSphere|Gunicorn|uWSGI|"
        r"Node\.js|Express|Django|Flask|Rails|"
        r"Spring|Play|Netty|vert\.x|FastAPI|"
        r"php|ASP\.NET|Kestrel|Caddy|"
        r"OpenResty|Tengine|Caddy)\b", re.IGNORECASE
    )

    CICD = re.compile(
        r"\b(Jenkins|GitLab CI|GitHub Actions|CircleCI|"
        r"Travis CI|TeamCity|Bamboo|Buildkite|"
        r"Drone CI|Concourse|Spinnaker|ArgoCD|"
        r"FluxCD|Tekton|CodePipeline|"
        r"Docker Hub|ECR|GCR|ACR|"
        r"k8s-deploy|helm|helmfile|"
        r".gitlab-ci.yml|.github/workflows|"
        r"jenkinsfile|Dockerfile|docker-compose)\b", re.IGNORECASE
    )


class InfrastructureDisclosureModule(BaseModule):
    """Detects exposed internal infrastructure information."""

    module_name = "infra_disclosure"
    module_description = "Infrastructure Disclosure Detection - Identifies exposed internal system information"

    async def run(self, urls: list[str]) -> list[Finding]:
        self.findings.clear()
        analyzed_content = set()

        for url in urls:
            try:
                response = await self.http.get(url)
                if not response.is_success:
                    continue
                content_hash = hash(response.body[:500])
                if content_hash in analyzed_content:
                    continue
                analyzed_content.add(content_hash)

                self._analyze_content(response.body, url)
                self._analyze_headers(response.headers, url)

            except Exception:
                continue

        return self.findings

    def _analyze_content(self, content: str, url: str) -> None:
        checks = [
            ("private_ips", InfrastructurePatterns.PRIVATE_IPS, RiskLevel.HIGH,
             "Private IP Address Exposure", 0.9),
            ("hostnames", InfrastructurePatterns.INTERNAL_HOSTNAMES, RiskLevel.MEDIUM,
             "Internal Hostname Exposure", 0.8),
            ("k8s", InfrastructurePatterns.KUBERNETES, RiskLevel.HIGH,
             "Kubernetes Reference Detected", 0.85),
            ("docker", InfrastructurePatterns.DOCKER, RiskLevel.MEDIUM,
             "Docker Reference Detected", 0.8),
            ("service_mesh", InfrastructurePatterns.SERVICE_MESH, RiskLevel.LOW,
             "Service Mesh Reference Detected", 0.7),
            ("dns", InfrastructurePatterns.INTERNAL_DNS, RiskLevel.HIGH,
             "Internal DNS Name Exposure", 0.9),
            ("internal_urls", InfrastructurePatterns.INTERNAL_URLS, RiskLevel.CRITICAL,
             "Internal URL Exposure", 0.95),
            ("backend_tech", InfrastructurePatterns.BACKEND_TECH, RiskLevel.LOW,
             "Backend Technology Fingerprint", 0.6),
            ("cicd", InfrastructurePatterns.CICD, RiskLevel.MEDIUM,
             "CI/CD Reference Detected", 0.75),
        ]

        for check_key, pattern, risk, title, confidence in checks:
            if not self.get_config(f"check_{check_key}", True):
                continue

            matches = pattern.findall(content)
            if matches:
                unique_matches = list(set(match[0] if isinstance(match, tuple) else match
                                          for match in matches))[:5]
                evidence = "; ".join(unique_matches)

                finding = self.create_finding(
                    title=title,
                    description=(
                        f"Found {len(unique_matches)} instance(s) of {title.lower()} "
                        f"in content at {url}. This information can be used to "
                        f"map internal infrastructure and plan targeted attacks."
                    ),
                    risk_level=risk,
                    confidence=confidence,
                    url=url,
                    evidence=evidence,
                    detection_source=f"Pattern matching for {check_key}",
                    remediation=(
                        "Remove internal infrastructure references from publicly accessible "
                        "content. Implement proper information disclosure controls. "
                        "Review error handling to prevent internal details from leaking."
                    ),
                    tags=["infra-disclosure", check_key],
                )
                self.add_finding(finding)

        proxy_matches = InfrastructurePatterns.PROXY_HEADERS.findall(content)
        if proxy_matches:
            unique_proxy = list(set(proxy_matches))
            finding = self.create_finding(
                title="Reverse Proxy Header Reference",
                description=(
                    f"Found reverse proxy header references in content at {url}: "
                    f"{', '.join(unique_proxy)}. These headers can be manipulated "
                    f"for SSRF and internal network access."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.85,
                url=url,
                evidence="; ".join(unique_proxy),
                detection_source="HTTP header pattern analysis",
                remediation=(
                    "Ensure reverse proxies strip incoming headers from client requests. "
                    "Configure backend services to trust only specific proxy IPs."
                ),
                tags=["infra-disclosure", "proxy-headers", "ssrf-vector"],
            )
            self.add_finding(finding)

    def _analyze_headers(self, headers: dict, url: str) -> None:
        sensitive_headers = {
            "x-powered-by": "Technology stack information",
            "x-aspnet-version": "ASP.NET version disclosure",
            "x-aspnetmvc-version": "ASP.NET MVC version disclosure",
            "server": "Web server software and version",
            "x-backend-server": "Backend server identifier",
            "x-real-ip": "Client IP reflected by proxy",
            "x-forwarded-for": "Forwarded IP tracking header",
            "x-forwarded-host": "Forwarded host header",
            "x-forwarded-proto": "Forwarded protocol header",
            "x-originating-ip": "Originating IP address",
            "x-runtime": "Application runtime information",
            "x-request-id": "Request tracking ID (can leak infrastructure)",
            "x-varnish": "Varnish cache information",
            "x-cache": "Cache status information",
            "x-served-by": "Server identifier",
            "via": "Proxy gateway information",
        }

        for header, description in sensitive_headers.items():
            if header in headers:
                value = headers[header]
                risk = RiskLevel.LOW
                if header.startswith("x-forwarded-") or header == "via":
                    risk = RiskLevel.MEDIUM

                finding = self.create_finding(
                    title=f"Information Disclosure via '{header}' Header",
                    description=(
                        f"Response header '{header}: {value[:100]}' reveals "
                        f"{description} at {url}."
                    ),
                    risk_level=risk,
                    confidence=0.9,
                    url=url,
                    evidence=f"{header}: {value[:200]}",
                    detection_source="HTTP response header analysis",
                    remediation=(
                        f"Configure the web server to remove or obfuscate the "
                        f"'{header}' header in responses."
                    ),
                    tags=["infra-disclosure", "header-leak"],
                )
                self.add_finding(finding)
