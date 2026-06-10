"""Module 6: Cloud Asset Enumeration - Detect publicly referenced cloud storage and services."""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlparse

from src.models import CloudAsset, Finding, RiskLevel
from src.modules.base import BaseModule


class CloudAssetPatterns:
    S3_BUCKET = re.compile(
        r"""['"`]?(?:https?://)?([a-zA-Z0-9._-]+\.s3[.\-][\w.-]+\.amazonaws\.com|[a-zA-Z0-9._-]+\.s3[.\-][\w.-]+\.amazonaws\.com\.cn|s3[.\-][\w.-]+\.amazonaws\.com/[a-zA-Z0-9._-]+|s3[.\-][\w.-]+\.amazonaws\.com\.cn/[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+\.s3-website[.\-][\w.-]+\.amazonaws\.com)['"`]?""",
        re.IGNORECASE
    )

    S3_BUCKET_NAME = re.compile(
        r"""['"`]([a-zA-Z0-9._-]{3,63})['"`]\s*[:=]\s*['"`]([a-zA-Z0-9._-]+\.s3)""",
        re.IGNORECASE
    )

    AZURE_STORAGE = re.compile(
        r"""['"`]?(?:https?://)?([a-zA-Z0-9]{3,24}\.blob\.core\.windows\.net|[a-zA-Z0-9]{3,24}\.table\.core\.windows\.net|[a-zA-Z0-9]{3,24}\.queue\.core\.windows\.net|[a-zA-Z0-9]{3,24}\.file\.core\.windows\.net|[a-zA-Z0-9]{3,24}\.dfs\.core\.windows\.net|[a-zA-Z0-9]+\.azureedge\.net|[a-zA-Z0-9]+\.azurefd\.net|[a-zA-Z0-9]+\.azurewebsites\.net|[a-zA-Z0-9]+\.scm\.azurewebsites\.net)['"`]?""",
        re.IGNORECASE
    )

    GCS_BUCKET = re.compile(
        r"""['"`]?(?:https?://)?([a-zA-Z0-9._-]+\.storage\.googleapis\.com|storage\.googleapis\.com/[a-zA-Z0-9._-]+|[a-zA-Z0-9._-]+\.appspot\.com|www\.googleapis\.com/storage)['"`]?""",
        re.IGNORECASE
    )

    CDN_ENDPOINTS = re.compile(
        r"""['"`]?(?:https?://)?([a-zA-Z0-9-]+\.cloudfront\.net|[a-zA-Z0-9-]+\.cdn\.cloudflare\.net|[a-zA-Z0-9-]+\.fastly\.net|[a-zA-Z0-9-]+\.edgesuite\.net|[a-zA-Z0-9-]+\.akamaihd\.net|[a-zA-Z0-9-]+\.akamaiedge\.net|[a-zA-Z0-9-]+\.imgix\.net|[a-zA-Z0-9-]+\.stackpathcdn\.com|[a-zA-Z0-9-]+\.keycdn\.com|[a-zA-Z0-9-]+\.bunnycdn\.com|d[0-9a-z]+\.cloudfront\.net)['"`]?""",
        re.IGNORECASE
    )

    PUBLIC_SERVICES = re.compile(
        r"""['"`]?(?:https?://)?([a-zA-Z0-9-]+\.(?:lambda-url\.[\w-]+\.on\.aws|execute-api\.[\w-]+\.amazonaws\.com|amplifyapp\.com|firebaseapp\.com|web\.app|netlify\.app|vercel\.app|pages\.dev|gitlab\.io|github\.io|herokuapp\.com|onrender\.com|fly\.dev|railway\.app|adaptable\.app|koyeb\.app|stormkit\.dev|surge\.sh|glitch\.me|codepen\.io|repl\.co|hugo\.app|cloud\.typeform\.com|typeform\.com/to|notion\.site|squarespace\.com)(?:/[\w\-./?=&%]*)?)['"`]?""",
        re.IGNORECASE
    )


class CloudAssetsModule(BaseModule):
    """Detects publicly referenced cloud assets and services."""

    module_name = "cloud_assets"
    module_description = "Cloud Asset Enumeration - Detects S3 buckets, Azure storage, GCS, CDNs, and public cloud services"

    async def run(self, urls: list[str]) -> list[Finding]:
        self.findings.clear()
        analyzed_content = set()
        all_found_assets: list[CloudAsset] = []

        for url in urls:
            try:
                response = await self.http.get(url)
                if not response.is_success:
                    continue
                content_hash = hash(response.body[:500])
                if content_hash in analyzed_content:
                    continue
                analyzed_content.add(content_hash)

                assets = self._extract_assets(response.body, url)
                all_found_assets.extend(assets)

            except Exception:
                continue

        for asset in all_found_assets:
            self._create_finding(asset)

        return self.findings

    def _extract_assets(self, content: str, url: str) -> list[CloudAsset]:
        assets = []

        if self.get_config("check_s3", True):
            for match in CloudAssetPatterns.S3_BUCKET.finditer(content):
                assets.append(CloudAsset(
                    asset_type="S3 Bucket",
                    url=match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0),
                    provider="AWS",
                    confidence=0.9,
                    evidence=f"S3 URL: {match.group(0)[:100]}",
                ))

        if self.get_config("check_azure_storage", True):
            for match in CloudAssetPatterns.AZURE_STORAGE.finditer(content):
                assets.append(CloudAsset(
                    asset_type="Azure Storage",
                    url=match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0),
                    provider="Azure",
                    confidence=0.9,
                    evidence=f"Azure URL: {match.group(0)[:100]}",
                ))

        if self.get_config("check_gcs", True):
            for match in CloudAssetPatterns.GCS_BUCKET.finditer(content):
                assets.append(CloudAsset(
                    asset_type="GCS Bucket",
                    url=match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0),
                    provider="GCP",
                    confidence=0.9,
                    evidence=f"GCS URL: {match.group(0)[:100]}",
                ))

        if self.get_config("check_cdn", True):
            for match in CloudAssetPatterns.CDN_ENDPOINTS.finditer(content):
                assets.append(CloudAsset(
                    asset_type="CDN Endpoint",
                    url=match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0),
                    provider="CDN",
                    confidence=0.85,
                    evidence=f"CDN URL: {match.group(0)[:100]}",
                ))

        if self.get_config("check_public_services", True):
            for match in CloudAssetPatterns.PUBLIC_SERVICES.finditer(content):
                assets.append(CloudAsset(
                    asset_type="Public Cloud Service",
                    url=match.group(1) if match.lastindex and match.lastindex >= 1 else match.group(0),
                    provider="Multi-Cloud",
                    confidence=0.8,
                    evidence=f"Service URL: {match.group(0)[:100]}",
                ))

        return assets

    def _create_finding(self, asset: CloudAsset) -> None:
        risk_map = {
            "S3 Bucket": RiskLevel.HIGH,
            "Azure Storage": RiskLevel.HIGH,
            "GCS Bucket": RiskLevel.HIGH,
            "CDN Endpoint": RiskLevel.MEDIUM,
            "Public Cloud Service": RiskLevel.LOW,
        }

        remediation_map = {
            "S3 Bucket": "Ensure S3 buckets have appropriate access policies. Use bucket policies and IAM roles. Enable block public access.",
            "Azure Storage": "Use Azure RBAC and managed identities. Ensure storage firewalls are configured properly.",
            "GCS Bucket": "Use IAM conditions and uniform bucket-level access. Review public access settings.",
            "CDN Endpoint": "Implement origin access identity and signed URLs. Restrict origin access to CDN only.",
            "Public Cloud Service": "Review service deployment for proper authentication and authorization.",
        }

        finding = self.create_finding(
            title=f"Cloud Asset Discovered: {asset.asset_type}",
            description=(
                f"Found reference to {asset.asset_type} ({asset.provider}) "
                f"in scanned content. Asset: {asset.url}"
            ),
            risk_level=risk_map.get(asset.asset_type, RiskLevel.MEDIUM),
            confidence=asset.confidence,
            evidence=asset.evidence,
            detection_source="Cloud asset pattern matching",
            remediation=remediation_map.get(asset.asset_type, "Review cloud asset security configuration."),
            tags=["cloud-assets", asset.provider.lower(), asset.asset_type.lower().replace(" ", "-")],
        )
        self.add_finding(finding)
