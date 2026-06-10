"""Tests for audit modules."""

import pytest
from unittest.mock import AsyncMock, Mock, patch

from src.modules.ssrf_discovery import SSRFDiscoveryModule
from src.modules.cloud_metadata import CloudMetadataModule
from src.modules.infra_disclosure import InfrastructureDisclosureModule
from src.modules.sensitive_files import SensitiveFilesModule
from src.modules.js_analysis import JSAnalysisModule, JSAnalyzer, JSFile
from src.modules.cloud_assets import CloudAssetsModule
from src.modules.security_headers import SecurityHeadersModule
from src.modules.api_surface import APISurfaceModule
from src.modules.risk_engine import RiskEngineModule, RiskClassifier
from src.models import AuditReport, Finding, RiskLevel
from tests.fixtures.sample_response import (
    SAMPLE_HTML, SAMPLE_JSON, SAMPLE_JS, SAMPLE_HEADERS, SAMPLE_URLS
)


@pytest.fixture
def mock_config():
    config = Mock()
    config.modules = {
        "ssrf_discovery": {"enabled": True},
        "cloud_metadata": {"enabled": True, "check_aws": True, "check_azure": True, "check_gcp": True, "check_oci": True, "check_aliyun": True, "check_openstack": True, "check_digitalocean": True, "check_cloudflare": True},
        "infra_disclosure": {"enabled": True, "check_private_ips": True, "check_hostnames": True, "check_k8s": True, "check_docker": True, "check_service_mesh": True, "check_dns": True, "check_proxy_headers": True, "check_backend_tech": True, "check_cloud_identifiers": True, "check_cicd": True},
        "sensitive_files": {"enabled": True, "check_config": True, "check_backups": True, "check_logs": True, "check_env": True, "check_manifests": True, "check_debug": True},
        "js_analysis": {"enabled": True, "extract_endpoints": True, "extract_api_refs": True, "extract_internal_urls": True, "extract_cloud_refs": True, "extract_env_indicators": True, "min_js_file_size": 10, "max_js_file_size": 99999999},
        "cloud_assets": {"enabled": True, "check_s3": True, "check_azure_storage": True, "check_gcs": True, "check_cdn": True, "check_public_services": True},
        "security_headers": {"enabled": True, "check_csp": True, "check_cors": True, "check_hsts": True, "check_referrer_policy": True, "check_permissions_policy": True, "check_xframe": True, "check_xxss": True, "check_xcontent": True},
        "api_surface": {"enabled": True, "check_rest": True, "check_graphql": True, "check_openapi": True, "check_swagger": True, "check_versioned_apis": True, "check_websocket_endpoints": True, "param_discovery": True},
    }
    return config


@pytest.fixture
def mock_http():
    http = AsyncMock()

    async def mock_request(url, **kwargs):
        from src.models import ScanResult
        if "api" in url:
            body = SAMPLE_JSON
        elif "js" in url:
            body = SAMPLE_JS
        else:
            body = SAMPLE_HTML
        return ScanResult(
            url=url,
            status_code=200,
            headers=dict(SAMPLE_HEADERS),
            body=body,
            content_type="text/html",
            size=len(body),
        )

    http.request = mock_request
    http.get = lambda url, **kw: mock_request(url, **kw)
    return http


class TestSSRFDiscoveryModule:
    @pytest.mark.asyncio
    async def test_detects_ssrf_params(self, mock_config, mock_http):
        module = SSRFDiscoveryModule(mock_config, mock_http)
        findings = await module.run(SAMPLE_URLS)
        assert len(findings) > 0
        ssrf_titles = [f.title for f in findings]
        assert any("SSRF" in t for t in ssrf_titles)

    @pytest.mark.asyncio
    async def test_detects_url_params(self, mock_config, mock_http):
        module = SSRFDiscoveryModule(mock_config, mock_http)
        findings = await module.run(["https://example.com?redirect_url=http://evil.com"])
        assert len(findings) > 0
        assert any(f.parameter == "redirect_url" for f in findings)
        assert any(f.confidence > 0.8 for f in findings)

    @pytest.mark.asyncio
    async def test_path_patterns(self, mock_config, mock_http):
        module = SSRFDiscoveryModule(mock_config, mock_http)
        findings = await module.run(["https://example.com/proxy/fetch"])
        assert len(findings) > 0


class TestCloudMetadataModule:
    @pytest.mark.asyncio
    async def test_detects_aws_metadata(self, mock_config, mock_http):
        module = CloudMetadataModule(mock_config, mock_http)
        findings = await module.run(["https://example.com"])
        aws_findings = [f for f in findings if "AWS" in f.title]
        assert len(aws_findings) > 0

    @pytest.mark.asyncio
    async def test_content_analysis(self, mock_config, mock_http):
        module = CloudMetadataModule(mock_config, mock_http)
        content = "http://169.254.169.254/latest/meta-data/ is referenced"
        module._analyze_content(content, "https://test.com")
        assert len(module.findings) > 0
        assert any("169.254.169.254" in f.evidence for f in module.findings)

    def test_header_analysis(self, mock_config, mock_http):
        module = CloudMetadataModule(mock_config, mock_http)
        module._analyze_headers({"x-amz-request-id": "test"}, "https://test.com")
        assert len(module.findings) > 0


class TestInfrastructureDisclosureModule:
    @pytest.mark.asyncio
    async def test_private_ip_detection(self, mock_config, mock_http):
        module = InfrastructureDisclosureModule(mock_config, mock_http)
        findings = await module.run(["https://example.com"])
        ip_findings = [f for f in findings if "IP" in f.title]
        assert len(ip_findings) > 0

    def test_content_analysis(self, mock_config, mock_http):
        module = InfrastructureDisclosureModule(mock_config, mock_http)
        content = "Internal server at 10.0.0.1:8080, k8s cluster running"
        module._analyze_content(content, "https://test.com")
        assert len(module.findings) >= 2


class TestSensitiveFilesModule:
    @pytest.mark.asyncio
    async def test_config_detection(self, mock_config, mock_http):
        module = SensitiveFilesModule(mock_config, mock_http)
        module._check_patterns("Found file: wp-config.php backup.sql dump.tar.gz",
                              "https://test.com", {})
        assert len(module.findings) > 0
        config_titles = [f.title for f in module.findings]
        assert any("Configuration" in t or "Backup" in t for t in config_titles)

    def test_secret_patterns(self, mock_config, mock_http):
        module = SensitiveFilesModule(mock_config, mock_http)
        content = 'password = "supersecret123!"; AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
        module._check_patterns(content, "https://test.com", {})
        assert len(module.findings) > 0
        assert any("Secret" in f.title or "Credential" in f.title for f in module.findings)


class TestJSAnalysisModule:
    def test_js_analyzer_endpoints(self):
        js_file = JSAnalyzer.analyze(SAMPLE_JS, "https://example.com/app.js")
        assert len(js_file.endpoints) > 0, f"No endpoints found, got: {js_file}"
        assert any("api" in ep.lower() for ep in js_file.endpoints)

    def test_js_analyzer_api_refs(self):
        js_file = JSAnalyzer.analyze(SAMPLE_JS, "https://example.com/app.js")
        assert len(js_file.api_refs) > 0
        assert any("api.internal.com" in ref for ref in js_file.api_refs)

    def test_js_analyzer_internal_urls(self):
        js_file = JSAnalyzer.analyze(SAMPLE_JS, "https://example.com/app.js")
        assert len(js_file.internal_urls) > 0, f"No internal URLs found, got: {js_file}"
        assert any("admin.internal" in url for url in js_file.internal_urls)

    def test_js_analyzer_cloud_refs(self):
        js_file = JSAnalyzer.analyze(SAMPLE_JS, "https://example.com/app.js")
        assert len(js_file.cloud_refs) > 0, f"No cloud refs found, got: {js_file}"

    def test_js_analyzer_secrets(self):
        js_file = JSAnalyzer.analyze(SAMPLE_JS, "https://example.com/app.js")
        assert len(js_file.secrets) > 0


class TestCloudAssetsModule:
    @pytest.mark.asyncio
    async def test_s3_detection(self, mock_config, mock_http):
        module = CloudAssetsModule(mock_config, mock_http)
        assets = module._extract_assets(
            'Found bucket at https://my-bucket.s3.us-east-1.amazonaws.com',
            "https://test.com"
        )
        assert len(assets) > 0
        assert any("S3" in a.asset_type for a in assets)


class TestSecurityHeadersModule:
    @pytest.mark.asyncio
    async def test_csp_analysis(self, mock_config, mock_http):
        module = SecurityHeadersModule(mock_config, mock_http)
        findings = await module.run(["https://example.com"])
        csp_findings = [f for f in findings if "CSP" in f.title or "Content-Security" in f.title]
        assert len(csp_findings) > 0

    @pytest.mark.asyncio
    async def test_cors_analysis(self, mock_config, mock_http):
        module = SecurityHeadersModule(mock_config, mock_http)
        findings = await module.run(["https://example.com"])
        cors_findings = [f for f in findings if "CORS" in f.title]
        assert len(cors_findings) > 0


class TestAPISurfaceModule:
    @pytest.mark.asyncio
    async def test_endpoint_discovery(self, mock_config, mock_http):
        module = APISurfaceModule(mock_config, mock_http)
        findings = await module.run(["https://example.com"])
        api_findings = [f for f in findings if "API" in f.title or "Endpoint" in f.title]
        assert len(api_findings) > 0


class TestRiskEngine:
    def test_classify_critical(self):
        finding = Finding(
            title="Test", risk_level=RiskLevel.CRITICAL,
            confidence=0.95, tags=["ssrf", "cloud-metadata"],
        )
        level, score = RiskClassifier.classify(finding)
        assert level == RiskLevel.CRITICAL
        assert score >= 9.0

    def test_classify_high(self):
        finding = Finding(
            title="Test", risk_level=RiskLevel.HIGH,
            confidence=0.8, tags=["infra-disclosure"],
        )
        level, score = RiskClassifier.classify(finding)
        assert level in (RiskLevel.HIGH, RiskLevel.CRITICAL)
        assert score >= 7.0

    def test_classify_low(self):
        finding = Finding(
            title="Test", risk_level=RiskLevel.LOW,
            confidence=0.3, tags=[],
        )
        level, score = RiskClassifier.classify(finding)
        assert level in (RiskLevel.LOW, RiskLevel.INFORMATIONAL)


class TestModels:
    def test_finding_to_dict(self):
        finding = Finding(
            title="Test Finding",
            risk_level=RiskLevel.HIGH,
            confidence=0.85,
            module="test",
        )
        data = finding.to_dict()
        assert data["title"] == "Test Finding"
        assert data["risk_level"] == "High"
        assert data["risk_score"] == 4

    def test_finding_csv(self):
        finding = Finding(title="Test", risk_level=RiskLevel.MEDIUM, module="test")
        row = finding.to_csv_row()
        assert len(row) == len(Finding.csv_headers())

    def test_audit_report_risk_score(self):
        report = AuditReport(target="https://test.com")
        report.findings = [
            Finding(title="A", risk_level=RiskLevel.CRITICAL, confidence=0.9, module="t"),
            Finding(title="B", risk_level=RiskLevel.HIGH, confidence=0.8, module="t"),
        ]
        assert report.risk_score > 0
        assert report.critical_count == 1
        assert report.high_count == 1
        assert report.total_findings == 2
