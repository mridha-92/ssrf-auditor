"""Parsing utilities for HTML, JSON, XML, and other formats."""

from __future__ import annotations

import json
import re
from typing import Any, Optional
from urllib.parse import urlparse, parse_qs, urljoin

from bs4 import BeautifulSoup, Comment


class HTMLParser:
    """Parse HTML content for links, forms, scripts, and comments."""

    @staticmethod
    def extract_links(html: str, base_url: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        links = []
        for tag in soup.find_all(["a", "link", "area"], href=True):
            href = tag.get("href", "")
            if href and not href.startswith("#") and not href.startswith("javascript:"):
                full_url = urljoin(base_url, href)
                links.append(full_url)
        return list(set(links))

    @staticmethod
    def extract_forms(html: str, base_url: str) -> list[dict[str, Any]]:
        soup = BeautifulSoup(html, "lxml")
        forms = []
        for form in soup.find_all("form"):
            action = form.get("action", "")
            method = form.get("method", "GET").upper()
            inputs = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name")
                if name:
                    input_type = inp.get("type", "text")
                    inputs.append({
                        "name": name,
                        "type": input_type,
                        "value": inp.get("value", ""),
                    })
            forms.append({
                "action": urljoin(base_url, action) if action else base_url,
                "method": method,
                "inputs": inputs,
            })
        return forms

    @staticmethod
    def extract_scripts(html: str, base_url: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        scripts = []
        for script in soup.find_all("script"):
            src = script.get("src", "")
            if src:
                full_url = urljoin(base_url, src)
                scripts.append(full_url)
        return list(set(scripts))

    @staticmethod
    def extract_comments(html: str) -> list[str]:
        soup = BeautifulSoup(html, "lxml")
        comments = []
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            text = str(comment).strip()
            if text:
                comments.append(text)
        return comments

    @staticmethod
    def extract_meta_tags(html: str) -> dict[str, str]:
        soup = BeautifulSoup(html, "lxml")
        meta = {}
        for tag in soup.find_all("meta"):
            name = tag.get("name") or tag.get("property", "")
            content = tag.get("content", "")
            if name and content:
                meta[name] = content
        return meta


class JSONParser:
    """Parse JSON content for URLs and sensitive data."""

    URL_PATTERN = re.compile(
        r"https?://[^\s'\"<>(){}|\\^`[\]]*", re.IGNORECASE
    )

    SENSITIVE_KEYS = {
        "password", "secret", "token", "api_key", "apikey", "api-key",
        "access_key", "accesskey", "auth", "authorization", "bearer",
        "aws_access_key_id", "aws_secret_access_key", "private_key",
        "ssh_key", "connection_string", "conn_string",
    }

    @staticmethod
    def flatten_json(obj: Any, prefix: str = "") -> list[tuple[str, Any]]:
        items = []
        if isinstance(obj, dict):
            for k, v in obj.items():
                new_key = f"{prefix}.{k}" if prefix else k
                if isinstance(v, (dict, list)):
                    items.extend(JSONParser.flatten_json(v, new_key))
                else:
                    items.append((new_key, v))
        elif isinstance(obj, list):
            for i, v in enumerate(obj):
                new_key = f"{prefix}[{i}]"
                if isinstance(v, (dict, list)):
                    items.extend(JSONParser.flatten_json(v, new_key))
                else:
                    items.append((new_key, v))
        return items

    @staticmethod
    def extract_urls(data: str) -> list[str]:
        return list(set(JSONParser.URL_PATTERN.findall(data)))

    @staticmethod
    def find_sensitive_keys(data: str) -> list[tuple[str, str]]:
        try:
            parsed = json.loads(data)
        except json.JSONDecodeError:
            return []

        findings = []
        for key, value in JSONParser.flatten_json(parsed):
            key_lower = key.lower()
            for sensitive_key in JSONParser.SENSITIVE_KEYS:
                if sensitive_key in key_lower and value:
                    findings.append((key, str(value)[:100]))
        return findings


class XMLParser:
    """Parse XML content for URLs and entity references."""

    @staticmethod
    def extract_urls(xml_content: str) -> list[str]:
        url_pattern = re.compile(r"https?://[^\s'\"<>]+", re.IGNORECASE)
        return list(set(url_pattern.findall(xml_content)))

    @staticmethod
    def check_external_entities(xml_content: str) -> list[str]:
        entities = []
        pattern = re.compile(r'<!ENTITY\s+(\S+)\s+(SYSTEM|PUBLIC)\s+"([^"]+)"', re.IGNORECASE)
        for match in pattern.finditer(xml_content):
            entities.append(f"Entity '{match.group(1)}' references: {match.group(3)}")
        return entities


class URLParser:
    """Parse and analyze URLs."""

    SSRF_PARAMETERS = {
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

    @staticmethod
    def extract_params(url: str) -> dict[str, list[str]]:
        parsed = urlparse(url)
        return parse_qs(parsed.query)

    @staticmethod
    def find_ssrf_params(url: str) -> list[tuple[str, str]]:
        params = URLParser.extract_params(url)
        findings = []
        for param, values in params.items():
            param_lower = param.lower()
            for ssrf_param in URLParser.SSRF_PARAMETERS:
                if ssrf_param in param_lower or param_lower == ssrf_param:
                    for value in values:
                        if value and URLParser.looks_like_url(value):
                            findings.append((param, value))
                        elif value and not value.isdigit():
                            findings.append((param, value))
        return findings

    @staticmethod
    def looks_like_url(value: str) -> bool:
        return bool(re.match(r"^https?://", value, re.IGNORECASE))

    @staticmethod
    def is_private_ip(hostname: str) -> bool:
        import ipaddress
        try:
            ip = ipaddress.ip_address(hostname)
            return ip.is_private
        except ValueError:
            private_patterns = [
                r"^10\.",
                r"^172\.(1[6-9]|2\d|3[01])\.",
                r"^192\.168\.",
                r"^127\.",
                r"^169\.254\.",
                r"^0\.0\.0\.0$",
                r"^::1$",
                r"^fc00:",
                r"^fe80:",
                r"^fd",
            ]
            return any(re.match(p, hostname) for p in private_patterns)

    @staticmethod
    def is_internal_hostname(hostname: str) -> bool:
        internal_suffixes = [
            ".internal", ".local", ".corp", ".lan", ".intranet",
            ".private", ".cloud", ".ec2.internal", ".compute.internal",
            ".amazonaws.com", ".azure.com", ".appservice.com",
            ".k8s.local", ".svc.cluster.local", ".cluster.local",
            ".consul", ".service", ".pod", ".namespace",
        ]
        hostname_lower = hostname.lower()
        for suffix in internal_suffixes:
            if hostname_lower.endswith(suffix):
                return True
        return hostname_lower in {"localhost", "localhost.localdomain", "broadcasthost"}


class GraphQLParser:
    """Parse GraphQL content for endpoints and operations."""

    @staticmethod
    def extract_operations(body: str) -> list[dict[str, str]]:
        operations = []
        patterns = [
            r"(query|mutation|subscription)\s+(\w+)\s*[\(({]",
            r'"(query|mutation|subscription)"\s*:\s*"(\w+)',
        ]
        for pattern in patterns:
            for match in re.finditer(pattern, body, re.IGNORECASE):
                operations.append({
                    "type": match.group(1),
                    "name": match.group(2),
                })
        return operations

    @staticmethod
    def extract_introspection(body: str) -> bool:
        return "__schema" in body or "__type" in body
