"""Input validation and sanitization utilities."""

from __future__ import annotations

import re
from typing import Optional
from urllib.parse import urlparse


class InputValidator:
    """Validates and sanitizes user inputs."""

    URL_PATTERN = re.compile(
        r"^https?://[^\s/$.?#].[^\s]*$", re.IGNORECASE
    )

    @staticmethod
    def validate_url(url: str) -> bool:
        if not url or len(url) > 8192:
            return False
        if not InputValidator.URL_PATTERN.match(url):
            return False
        try:
            parsed = urlparse(url)
            return bool(parsed.netloc) and bool(parsed.scheme)
        except Exception:
            return False

    @staticmethod
    def validate_target(target: str) -> bool:
        if not target:
            return False
        if not target.startswith(("http://", "https://")):
            target = f"https://{target}"
        return InputValidator.validate_url(target)

    @staticmethod
    def normalize_url(url: str) -> str:
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        return url.rstrip("/")

    @staticmethod
    def sanitize_output(text: str) -> str:
        sensitive_patterns = {
            r'(?i)(password|secret|token|api[_-]?key)[=:]\s*\S+': r'\1=***REDACTED***',
            r'(?i)(bearer|basic)\s+\S+': r'\1 ***REDACTED***',
            r'(?i)aws[_-]?access[_-]?key[_-]?id[=:]\s*\S+': r'\1=***REDACTED***',
            r'(?i)aws[_-]?secret[_-]?access[_-]?key[=:]\s*\S+': r'\1=***REDACTED***',
        }
        result = text
        for pattern, replacement in sensitive_patterns.items():
            result = re.sub(pattern, replacement, result)
        return result

    @staticmethod
    def validate_output_dir(path: str) -> bool:
        import os
        try:
            return os.path.isabs(path) or bool(path.strip())
        except Exception:
            return False

    @staticmethod
    def extract_domain(url: str) -> Optional[str]:
        try:
            parsed = urlparse(url)
            return parsed.netloc or None
        except Exception:
            return None
