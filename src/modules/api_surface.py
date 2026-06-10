"""Module 8: API Surface Mapping - Discover and catalog API endpoints."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup

from src.models import Endpoint, Finding, RiskLevel
from src.modules.base import BaseModule


class APIPatterns:
    REST_ENDPOINTS = re.compile(
        r"""['"`]?(?:/api/|/rest/|/v\d+/|/api/v\d+/)"""
        r"""[\w\-./{}]+['"`]?""",
        re.IGNORECASE
    )

    GRAPHQL_PATTERNS = re.compile(
        r"""['"`]?(?:/graphql|/gql|/graphiql|/graphql/console|"""
        r"""/v\d+/graphql|/api/graphql|/query)['"`]?""",
        re.IGNORECASE
    )

    OPENAPI_PATTERNS = re.compile(
        r"""['"`]?(?:/swagger|/api-docs|/v\d+/api-docs|"""
        r"""/openapi\.json|/openapi\.yaml|/swagger\.json|"""
        r"""/swagger\.yaml|/swagger-ui\.html|/swagger-resources|"""
        r"""/v2/api-docs|/v3/api-docs|/api/swagger)['"`]?""",
        re.IGNORECASE
    )

    SWAGGER_PATTERNS = re.compile(
        r"""['"`]?(?:swagger|openapi|api-docs)['"`]?""",
        re.IGNORECASE
    )

    VERSIONED_API = re.compile(
        r"""(?:/api/)?v(\d+)/""",
        re.IGNORECASE
    )

    WEBSOCKET = re.compile(
        r"""['"`]?(?:wss?://[^\s'"]+|/ws/|/wss/|"""
        r"""/socket\.io/|/websocket|/sockjs/)['"`]?""",
        re.IGNORECASE
    )


class APISurfaceModule(BaseModule):
    """Maps API surfaces including REST, GraphQL, WebSocket endpoints."""

    module_name = "api_surface"
    module_description = "API Surface Mapping - Discovers REST, GraphQL, WebSocket, OpenAPI, and Swagger endpoints"

    async def run(self, urls: list[str]) -> list[Finding]:
        self.findings.clear()
        endpoints: list[Endpoint] = []
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

                page_endpoints = self._analyze_content(response.body, url)
                endpoints.extend(page_endpoints)

                page_endpoints = self._check_common_paths(url, url)
                endpoints.extend(page_endpoints)

            except Exception:
                continue

        self._catalog_endpoints(endpoints)
        return self.findings

    def _analyze_content(self, content: str, url: str) -> list[Endpoint]:
        endpoints = []

        if self.get_config("check_rest", True):
            for match in APIPatterns.REST_ENDPOINTS.finditer(content):
                endpoint_path = match.group(0).strip("'\"`")
                endpoints.append(Endpoint(
                    path=endpoint_path,
                    method="GET",
                    source=url,
                    content_type="REST",
                ))

            api_refs = re.finditer(
                r"""["'`]((?:get|post|put|patch|delete|head|options)\s+(/[\w\-./{}]+))["'`]""",
                content, re.IGNORECASE
            )
            for match in api_refs:
                method_str = match.group(1).split()[0].upper()
                path = match.group(2)
                endpoints.append(Endpoint(
                    path=path,
                    method=method_str,
                    source=url,
                    content_type="REST",
                ))

        if self.get_config("check_graphql", True):
            for match in APIPatterns.GRAPHQL_PATTERNS.finditer(content):
                endpoints.append(Endpoint(
                    path=match.group(0).strip("'\"`"),
                    method="POST",
                    source=url,
                    content_type="GraphQL",
                ))

        if self.get_config("check_openapi", True):
            for match in APIPatterns.OPENAPI_PATTERNS.finditer(content):
                endpoints.append(Endpoint(
                    path=match.group(0).strip("'\"`"),
                    method="GET",
                    source=url,
                    content_type="OpenAPI",
                ))

        if self.get_config("check_websocket_endpoints", True):
            for match in APIPatterns.WEBSOCKET.finditer(content):
                endpoints.append(Endpoint(
                    path=match.group(0).strip("'\"`"),
                    method="WS",
                    source=url,
                    content_type="WebSocket",
                ))

        return endpoints

    def _check_common_paths(self, base_url: str, source_url: str) -> list[Endpoint]:
        endpoints = []
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        common_paths = [
            "/api", "/api/", "/api/v1", "/api/v2", "/api/v3",
            "/graphql", "/gql", "/graphiql",
            "/swagger-ui.html", "/swagger-resources", "/v2/api-docs", "/v3/api-docs",
            "/openapi.json", "/swagger.json",
            "/actuator", "/actuator/health", "/actuator/info",
            "/health", "/healthz", "/readyz",
            "/ws", "/websocket",
            "/.well-known/openid-configuration",
        ]

        if self.get_config("param_discovery", True):
            common_params = ["/api?wsdl", "/api?disco"]
            common_paths.extend(common_params)

        for path in common_paths:
            full_url = base + path
            endpoints.append(Endpoint(
                path=path,
                method="GET",
                source=source_url,
                content_type="Common",
            ))

        return endpoints

    def _catalog_endpoints(self, endpoints: list[Endpoint]) -> None:
        if not endpoints:
            return

        unique_endpoints: dict[str, Endpoint] = {}
        for ep in endpoints:
            key = f"{ep.method}:{ep.path}"
            if key not in unique_endpoints:
                unique_endpoints[key] = ep

        endpoint_list = list(unique_endpoints.values())

        rest_count = sum(1 for e in endpoint_list if e.content_type == "REST")
        graphql_count = sum(1 for e in endpoint_list if e.content_type == "GraphQL")
        openapi_count = sum(1 for e in endpoint_list if e.content_type == "OpenAPI")
        ws_count = sum(1 for e in endpoint_list if e.content_type == "WebSocket")

        finding = self.create_finding(
            title=f"API Surface: {len(endpoint_list)} Endpoints Discovered",
            description=(
                f"Discovered {len(endpoint_list)} API endpoints: "
                f"{rest_count} REST, {graphql_count} GraphQL, "
                f"{openapi_count} OpenAPI/Swagger, {ws_count} WebSocket. "
                f"Review these endpoints for proper access controls."
            ),
            risk_level=RiskLevel.MEDIUM,
            confidence=0.8,
            evidence=(
                f"REST: {rest_count}, GraphQL: {graphql_count}, "
                f"OpenAPI: {openapi_count}, WebSocket: {ws_count}"
            ),
            detection_source="API surface pattern analysis",
            remediation=(
                "Catalog all API endpoints and ensure proper authentication is in place. "
                "Implement rate limiting and input validation on all API endpoints."
            ),
            tags=["api-surface", "endpoint-discovery"],
            raw_data={"endpoints": [e.__dict__ for e in endpoint_list[:50]]},
        )
        self.add_finding(finding)

        if graphql_count > 0:
            finding = self.create_finding(
                title="GraphQL Endpoint Detected",
                description=(
                    f"Found {graphql_count} GraphQL endpoint(s). "
                    f"GraphQL endpoints should be reviewed for proper "
                    f"query depth limiting, authentication, and introspection control."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.9,
                evidence=f"{graphql_count} GraphQL endpoint(s) discovered",
                detection_source="GraphQL pattern analysis",
                remediation=(
                    "Disable GraphQL introspection in production. "
                    "Implement query depth limiting and rate limiting. "
                    "Ensure proper authentication on all GraphQL endpoints."
                ),
                tags=["api-surface", "graphql"],
            )
            self.add_finding(finding)

        if openapi_count > 0:
            finding = self.create_finding(
                title="OpenAPI/Swagger Documentation Endpoint",
                description=(
                    f"Found {openapi_count} OpenAPI/Swagger documentation "
                    f"endpoint(s). API documentation can reveal attack surface."
                ),
                risk_level=RiskLevel.MEDIUM,
                confidence=0.9,
                evidence=f"{openapi_count} OpenAPI endpoint(s) discovered",
                detection_source="OpenAPI pattern analysis",
                remediation=(
                    "Restrict access to API documentation in production. "
                    "Use authentication for documentation endpoints."
                ),
                tags=["api-surface", "openapi", "swagger"],
            )
            self.add_finding(finding)
