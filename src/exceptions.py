"""Custom exceptions for the SSRF Auditor framework."""

from typing import Optional


class SSRFAuditorError(Exception):
    """Base exception for all SSRF Auditor errors."""

    def __init__(self, message: str, original: Optional[Exception] = None) -> None:
        self.original = original
        super().__init__(message)


class ConfigurationError(SSRFAuditorError):
    """Raised when configuration is invalid or missing."""


class ScannerError(SSRFAuditorError):
    """Raised when scanner encounters a fatal error."""


class CrawlerError(SSRFAuditorError):
    """Raised when crawler encounters a fatal error."""


class NetworkError(SSRFAuditorError):
    """Raised on network-related failures."""


class RateLimitExceeded(SSRFAuditorError):
    """Raised when rate limit is exceeded."""


class ModuleError(SSRFAuditorError):
    """Raised when a module encounters an error."""


class PluginLoadError(SSRFAuditorError):
    """Raised when a plugin fails to load."""


class ReportError(SSRFAuditorError):
    """Raised when report generation fails."""


class ExploitError(SSRFAuditorError):
    """Raised when exploitation module encounters an error."""


class ValidationError(SSRFAuditorError):
    """Raised when input validation fails."""


class StateError(SSRFAuditorError):
    """Raised when state management fails."""


class TimeoutError(SSRFAuditorError):
    """Raised when operation times out."""
