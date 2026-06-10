"""Module 2: Cloud Metadata Exposure - Identify references to cloud metadata services."""

from __future__ import annotations

import re
from typing import Any

from src.models import Finding, RiskLevel
from src.modules.base import BaseModule


class CloudMetadataPatterns:
    AWS = {
        "ips": ["169.254.169.254", "169.254.170.2"],
        "urls": [
            r"http://169\.254\.169\.254/latest/meta-data",
            r"http://169\.254\.169\.254/latest/user-data",
            r"http://169\.254\.169\.254/latest/iam/",
            r"http://169\.254\.170\.2/v2/credentials/",
            r"http://169\.254\.169\.254/latest/dynamic/instance-identity/",
        ],
        "patterns": [
            r"ec2.internal",
            r"compute\.amazonaws\.com",
            r"amazonaws\.com",
            r"AWS_ACCESS_KEY_ID",
            r"AWS_SECRET_ACCESS_KEY",
            r"AWS_SESSION_TOKEN",
            r"aws:iam",
            r"amazonaws\.com\.cn",
        ],
        "documentation": [
            "docs.aws.amazon.com/AWSEC2/latest/UserGuide/instance-metadata.html",
        ],
    }

    AZURE = {
        "ips": ["169.254.169.254"],
        "urls": [
            r"http://169\.254\.169\.254/metadata/instance",
            r"http://169\.254\.169\.254/metadata/identity/oauth2/token",
            r"http://169\.254\.169\.254/metadata/scheduledevents",
        ],
        "patterns": [
            r"metadata\.azure\.com",
            r"azure\.com",
            r"windows\.net",
            r"core\.windows\.net",
            r"AZURE_CLIENT_ID",
            r"AZURE_TENANT_ID",
            r"AZURE_CLIENT_SECRET",
            r"azurefd\.net",
            r"azureedge\.net",
            r"azurewebsites\.net",
        ],
        "documentation": [
            "docs.microsoft.com/en-us/azure/virtual-machines/instance-metadata-service",
        ],
    }

    GCP = {
        "ips": ["169.254.169.254", "metadata.google.internal"],
        "urls": [
            r"http://metadata\.google\.internal/computeMetadata/v1",
            r"http://metadata\.google\.internal/computeMetadata/v1/instance",
            r"http://metadata\.google\.internal/computeMetadata/v1/project",
        ],
        "patterns": [
            r"metadata\.google\.internal",
            r"googleapis\.com",
            r"gcp\.api",
            r"GOOGLE_APPLICATION_CREDENTIALS",
            r"GOOGLE_API_KEY",
            r"compute\.google\.com",
            r"cloudfunctions\.net",
            r"appspot\.com",
            r"storage\.googleapis\.com",
        ],
        "documentation": [
            "cloud.google.com/compute/docs/storing-retrieving-metadata",
        ],
    }

    OCI = {
        "ips": ["169.254.169.254"],
        "urls": [
            r"http://169\.254\.169\.254/opc/v1/",
            r"http://169\.254\.169\.254/opc/v2/",
        ],
        "patterns": [
            r"oraclecloud\.com",
            r"oracle\.com",
            r"ocid\.",
            r"oke\.oracle\.com",
        ],
        "documentation": [
            "docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm",
        ],
    }

    ALIYUN = {
        "ips": ["100.100.100.200"],
        "urls": [
            r"http://100\.100\.100\.200/latest/meta-data",
            r"http://100\.100\.100\.200/latest/user-data",
        ],
        "patterns": [
            r"aliyuncs\.com",
            r"aliyun\.com",
            r"ALIBABA_CLOUD_ACCESS_KEY_ID",
            r"ALIBABA_CLOUD_ACCESS_KEY_SECRET",
        ],
    }

    OPENSTACK = {
        "ips": ["169.254.169.254"],
        "urls": [
            r"http://169\.254\.169\.254/openstack",
        ],
        "patterns": [
            r"openstack",
        ],
    }

    @classmethod
    def all_patterns(cls) -> dict:
        return {
            "AWS": cls.AWS,
            "Azure": cls.AZURE,
            "GCP": cls.GCP,
            "OCI": cls.OCI,
            "Alibaba Cloud": cls.ALIYUN,
            "OpenStack": cls.OPENSTACK,
        }


class CloudMetadataModule(BaseModule):
    """Identifies cloud metadata service references and exposure indicators."""

    module_name = "cloud_metadata"
    module_description = "Cloud Metadata Exposure - Detects references to cloud metadata services"

    async def run(self, urls: list[str]) -> list[Finding]:
        self.findings.clear()
        analyzed_content = set()

        for url in urls:
            try:
                response = await self.http.get(url)
                if not response.is_success:
                    continue
                content_hash = hash(response.body[:1000])
                if content_hash in analyzed_content:
                    continue
                analyzed_content.add(content_hash)

                self._analyze_content(response.body, url)
                self._analyze_headers(response.headers, url)

            except Exception:
                continue

        return self.findings

    def _analyze_content(self, content: str, url: str) -> None:
        for provider, patterns in CloudMetadataPatterns.all_patterns().items():
            enabled_key = f"check_{provider.lower().replace(' ', '_').replace('-', '_')}"
            if not self.get_config(enabled_key.replace("alibaba_cloud", "aliyun"), True):
                continue

            for ip in patterns["ips"]:
                if ip in content:
                    finding = self.create_finding(
                        title=f"{provider} Metadata Service IP Reference",
                        description=(
                            f"Found reference to {provider} metadata service IP '{ip}' "
                            f"in content at {url}. This indicates cloud metadata service "
                            f"exposure or documentation leaks."
                        ),
                        risk_level=RiskLevel.HIGH,
                        confidence=0.95,
                        url=url,
                        evidence=f"Found IP '{ip}' in content",
                        detection_source=f"Cloud metadata IP reference in {provider}",
                        remediation=(
                            "Remove references to cloud metadata service IPs from "
                            "publicly accessible content. Ensure metadata service is "
                            "not exposed to unauthorized users."
                        ),
                        tags=["cloud-metadata", provider.lower(), "ip-reference"],
                    )
                    self.add_finding(finding)

            for pattern in patterns["urls"]:
                if re.search(pattern, content, re.IGNORECASE):
                    finding = self.create_finding(
                        title=f"{provider} Metadata URL Reference",
                        description=(
                            f"Found URL pattern matching {provider} metadata service "
                            f"in content at {url}. This could expose metadata service "
                            f"endpoints to attackers."
                        ),
                        risk_level=RiskLevel.HIGH,
                        confidence=0.9,
                        url=url,
                        evidence=f"Pattern matched: {pattern[:60]}...",
                        detection_source=f"Cloud metadata URL pattern in {provider}",
                        remediation=(
                            "Remove metadata service URLs from publicly accessible content. "
                            "Implement proper access controls on metadata service endpoints."
                        ),
                        tags=["cloud-metadata", provider.lower(), "url-reference"],
                    )
                    self.add_finding(finding)

            for pattern in patterns["patterns"]:
                if re.search(pattern, content, re.IGNORECASE):
                    finding = self.create_finding(
                        title=f"{provider} Cloud Identifier Found",
                        description=(
                            f"Found {provider}-specific pattern in content at {url}. "
                            f"This may indicate cloud environment references that could "
                            f"aid in targeted attacks."
                        ),
                        risk_level=RiskLevel.MEDIUM,
                        confidence=0.7,
                        url=url,
                        evidence=f"Pattern matched: {pattern[:60]}...",
                        detection_source=f"Cloud identifier pattern in {provider}",
                        remediation=(
                            "Review and remove unnecessary cloud infrastructure "
                            "references from publicly accessible content."
                        ),
                        tags=["cloud-identifier", provider.lower()],
                    )
                    self.add_finding(finding)

    def _analyze_headers(self, headers: dict, url: str) -> None:
        header_content = str(headers)
        cloud_header_patterns = [
            (r"x-amz-", "AWS", RiskLevel.LOW),
            (r"x-azure-", "Azure", RiskLevel.LOW),
            (r"x-gcp-", "GCP", RiskLevel.LOW),
            (r"x-oci-", "OCI", RiskLevel.LOW),
            (r"x-alibaba-", "Alibaba", RiskLevel.LOW),
            (r"x-cloud-", "Generic Cloud", RiskLevel.INFORMATIONAL),
        ]

        for pattern, provider, risk in cloud_header_patterns:
            for header_name, header_value in headers.items():
                if re.search(pattern, header_name, re.IGNORECASE):
                    finding = self.create_finding(
                        title=f"{provider} Cloud Header Detected",
                        description=(
                            f"HTTP header '{header_name}' suggests {provider} "
                            f"infrastructure at {url}."
                        ),
                        risk_level=risk,
                        confidence=0.8,
                        url=url,
                        evidence=f"Header: {header_name}: {header_value[:100]}",
                        detection_source="HTTP header analysis",
                        remediation="Review header exposure in proxy/load balancer configuration.",
                        tags=["cloud-header", provider.lower()],
                    )
                    self.add_finding(finding)
