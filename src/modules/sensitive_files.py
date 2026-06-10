"""Module 4: Sensitive File Discovery - Passive detection of sensitive file references."""

from __future__ import annotations

import re
from typing import Optional

from src.models import Finding, RiskLevel
from src.modules.base import BaseModule


class SensitiveFilePatterns:
    CONFIG_FILES = re.compile(
        r"\b(config\.(json|yaml|yml|xml|ini|env|php|py|rb|js|ts|go)"
        r"|app\.config|web\.config|database\.yml"
        r"|settings\.json|settings\.py|settings\.rb"
        r"|application\.yml|application\.yaml|application\.properties"
        r"|bootstrap\.json|parameters\.yml|parameters\.json"
        r"|db\.config|database\.config"
        r"|connectionstrings\.config|connectionstrings\.json"
        r"|aws\.config|aws\.json|credentials\.json"
        r"|database\.php|config\.php|db\.php"
        r"|wp-config\.php|configuration\.php)\b", re.IGNORECASE
    )

    BACKUP_FILES = re.compile(
        r"\b(.*\.(bak|backup|old|orig|copy|swp|swo|~"
        r"|sql\.bak|db\.bak|tar\.gz|tgz|zip\.bak"
        r"|dump|sql\.dump|backup\.sql"
        r"|202\d\d\d\d\d\d\d\d\d\d\d\d"
        r"|\.[0-9]{4}-[0-9]{2}-[0-9]{2}"
        r"|\.previous|\.current\.bak"
        r"))\b", re.IGNORECASE
    )

    LOG_FILES = re.compile(
        r"\b(.*\.(log|logs|trace|out|err|error|debug|audit"
        r"|access\.log|error\.log|server\.log|app\.log"
        r"|syslog|messages|auth\.log|cron\.log"
        r"|nginx\.log|apache\.log|mysql\.log|php\.log"
        r"|application\.log|stdout|stderr"
        r"))\b", re.IGNORECASE
    )

    ENV_FILES = re.compile(
        r"\b(\.env|\.env\.(local|production|development|staging|prod|dev|test)"
        r"|\.env\.example|env\.json|env\.yaml|env\.yml"
        r"|\.envrc|environment\.ts|environment\.js"
        r"|environment\.json|environment\.yaml"
        r"|\.flaskenv|\.dbenv|settings\.env"
        r"|env\.php|env\.py|env\.rb"
        r"|docker\.env|compose\.env)\b", re.IGNORECASE
    )

    MANIFEST_FILES = re.compile(
        r"\b(manifest\.json|manifest\.yaml|manifest\.yml|package\.json"
        r"|composer\.json|composer\.lock|package-lock\.json"
        r"|yarn\.lock|Gemfile|Gemfile\.lock|Podfile"
        r"|Cargo\.toml|Cargo\.lock|go\.mod|go\.sum"
        r"|requirements\.txt|Pipfile|Pipfile\.lock"
        r"|setup\.py|setup\.cfg|pyproject\.toml"
        r"|build\.gradle|pom\.xml|project\.json"
        r"|chart\.yaml|Chart\.yaml|values\.yaml"
        r"|kustomization\.yaml|Kustomization"
        r"|terraform\.tf|terragrunt\.hcl"
        r"|Dockerfile|docker-compose\.yaml|docker-compose\.yml"
        r")\b", re.IGNORECASE
    )

    DEBUG_ENDPOINTS = re.compile(
        r"\b(/debug|/debug\.php|/info\.php|/phpinfo\.php"
        r"|/status|/health|/healthz|/readyz|/livez"
        r"|/metrics|/prometheus|/actuator|/actuator/health"
        r"|/actuator/info|/actuator/env|/actuator/beans"
        r"|/heapdump|/threaddump|/dump"
        r"|/console|/admin/console|/h2-console"
        r"|/swagger-ui\.html|/swagger-resources|/v2/api-docs|/v3/api-docs"
        r"|/graphiql|/graphql-playground"
        r"|/actuator/prometheus|/debug/pprof"
        r"|/__debug__|/\.git|/\.svn"
        r")\b", re.IGNORECASE
    )

    SECRET_PATTERNS = re.compile(
        r"(?i)(?:password|passwd|pwd|secret|token|api[_-]?key|apikey"
        r"|access[_-]?key|secret[_-]?key|auth[_-]?token"
        r"|bearer|jwt|session[_-]?id|sid|ssid"
        r"|private[_-]?key|public[_-]?key|ssh[_-]?key"
        r"|connection[_-]?string|conn[_-]?string"
        r"|db[_-]?password|db[_-]?user(?:name)?"
        r"|redis[_-]?password|mysql[_-]?password"
        r"|postgres[_-]?password|mongo[_-]?password"
        r"|slack[_-]?token|discord[_-]?token"
        r"|github[_-]?token|gitlab[_-]?token"
        r"|aws[_-]?access[_-]?key[_-]?id"
        r"|aws[_-]?secret[_-]?access[_-]?key"
        r"|google[_-]?api[_-]?key"
        r"|azure[_-]?client[_-]?(?:id|secret)"
        r"|firebase[_-]?api[_-]?key"
        r"|stripe[_-]?(?:api|secret|publishable)[_-]?key"
        r")\s*[:=]\s*['\"]?(?:[A-Za-z0-9_\-+/]{16,})['\"]?"
    )


class SensitiveFilesModule(BaseModule):
    """Passively identifies references to sensitive files and configurations."""

    module_name = "sensitive_files"
    module_description = "Sensitive File Discovery - Identifies references to config files, backups, logs, and debug endpoints"

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

                self._check_patterns(response.body, url, response.headers)
                self._check_urls(url)

            except Exception:
                continue

        return self.findings

    def _check_urls(self, url: str) -> None:
        path_matches = SensitiveFilePatterns.DEBUG_ENDPOINTS.findall(url)
        for match in path_matches:
            path = match.rstrip("/")
            finding = self.create_finding(
                title=f"Debug/Sensitive Endpoint Reference: {path}",
                description=(
                    f"URL path contains reference to potentially sensitive "
                    f"endpoint '{path}' at {url}. This endpoint may expose "
                    f"sensitive system information."
                ),
                risk_level=RiskLevel.HIGH,
                confidence=0.8,
                url=url,
                evidence=f"URL path: {path}",
                detection_source="URL path pattern analysis",
                remediation=(
                    "Remove or protect debug/admin endpoints in production. "
                    "Implement authentication and network access controls."
                ),
                tags=["sensitive-endpoint", "debug"],
            )
            self.add_finding(finding)

    def _check_patterns(self, content: str, url: str, headers: dict) -> None:
        checks = [
            ("config", SensitiveFilePatterns.CONFIG_FILES, RiskLevel.HIGH,
             "Configuration File Reference", 0.85,
             "Remove configuration file references from public content."),
            ("backups", SensitiveFilePatterns.BACKUP_FILES, RiskLevel.CRITICAL,
             "Backup File Reference", 0.9,
             "Remove backup file references and ensure backups are not accessible."),
            ("logs", SensitiveFilePatterns.LOG_FILES, RiskLevel.HIGH,
             "Log File Reference", 0.85,
             "Ensure log files are not publicly accessible."),
            ("env", SensitiveFilePatterns.ENV_FILES, RiskLevel.CRITICAL,
             "Environment File Reference", 0.95,
             "Ensure .env files are excluded from version control and not publicly accessible."),
            ("manifests", SensitiveFilePatterns.MANIFEST_FILES, RiskLevel.MEDIUM,
             "Manifest/Config File Reference", 0.8,
             "Review manifest files for sensitive information."),
        ]

        for check_key, pattern, risk, title, confidence, remediation in checks:
            if not self.get_config(f"check_{check_key}", True):
                continue

            matches = pattern.findall(content)
            if matches:
                unique_matches = list(set(m[0] if isinstance(m, tuple) else m
                                          for m in matches))[:5]
                evidence = "; ".join(unique_matches)

                finding = self.create_finding(
                    title=title,
                    description=(
                        f"Found {len(unique_matches)} reference(s) to {title.lower()}s "
                        f"in content at {url}: {evidence}. This may expose sensitive "
                        f"system configuration."
                    ),
                    risk_level=risk,
                    confidence=confidence,
                    url=url,
                    evidence=evidence,
                    detection_source=f"Pattern matching for {check_key}",
                    remediation=remediation,
                    tags=["sensitive-files", check_key],
                )
                self.add_finding(finding)

        secret_matches = SensitiveFilePatterns.SECRET_PATTERNS.findall(content)
        if secret_matches:
            evidences = []
            for match in secret_matches[:5]:
                match_str = match[0] if isinstance(match, tuple) else match
                match_str = re.sub(r"['\"]", "", match_str)
                key_part = match_str.split("=")[0].split(":")[0].strip() if "=" in match_str or ":" in match_str else match_str[:30]
                evidences.append(key_part)

            finding = self.create_finding(
                title="Potential Secret/Key Exposure",
                description=(
                    f"Found {len(secret_matches)} potential secret/credential "
                    f"pattern(s) in content at {url}. This represents a critical "
                    f"security risk if real credentials are exposed."
                ),
                risk_level=RiskLevel.CRITICAL,
                confidence=min(0.5 + len(secret_matches) * 0.1, 0.95),
                url=url,
                evidence="; ".join(evidences),
                detection_source="Credential pattern detection",
                remediation=(
                    "Immediately rotate any exposed credentials. "
                    "Use secrets management solutions. "
                    "Implement secret scanning in CI/CD pipeline."
                ),
                tags=["sensitive-files", "credentials", "secrets"],
            )
            self.add_finding(finding)
