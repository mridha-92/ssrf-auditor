"""Command-line interface for SSRF Auditor."""

from __future__ import annotations

import argparse
import asyncio
import sys
from pathlib import Path
from typing import Optional

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from tqdm import tqdm

from src.config import Config
from src.engine.scanner import Scanner
from src.exceptions import ConfigurationError, SSRFAuditorError
from src.modules.reporting import ReportingModule
from src.modules.risk_engine import RiskEngineModule
from src.utils.logger import AuditLogger
from src.utils.validators import InputValidator
from src.utils.helpers import read_file_lines, ensure_directory


console = Console()


class CLI:
    """Command-line interface handler."""

    BANNER = """
    ╔══════════════════════════════════════════════╗
    ║         SSRF AUDITOR v2.0                    ║
    ║   SSRF & Infrastructure Disclosure Scanner   ║
    ║   Authorized Security Testing Only           ║
    ╚══════════════════════════════════════════════╝
    """

    def __init__(self) -> None:
        self.args: argparse.Namespace
        self.config: Optional[Config] = None
        self.scanner: Optional[Scanner] = None

    def parse_args(self) -> argparse.Namespace:
        parser = argparse.ArgumentParser(
            description="SSRF Auditor v2.0 - Production-grade SSRF & Infrastructure Disclosure Framework",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
Examples:
  %(prog)s -u https://target.com
  %(prog)s -l urls.txt
  %(prog)s -u https://target.com --js-analysis
  %(prog)s -u https://target.com --infra-leaks
  %(prog)s -u https://target.com --report html
  %(prog)s -u https://target.com --output results/
  %(prog)s -u https://target.com --exploit --dry-run
  %(prog)s -u https://target.com --all-modules
            """,
        )

        target_group = parser.add_mutually_exclusive_group(required=True)
        target_group.add_argument(
            "-u", "--url", help="Single target URL to scan"
        )
        target_group.add_argument(
            "-l", "--list", help="File containing list of target URLs"
        )

        parser.add_argument(
            "-c", "--config", default="config.yaml",
            help="Path to configuration file (default: config.yaml)"
        )
        parser.add_argument(
            "-o", "--output", default="results",
            help="Output directory for reports (default: results)"
        )

        module_group = parser.add_argument_group("Module Controls")
        module_group.add_argument(
            "--ssrf-discovery", action="store_true",
            help="Enable SSRF exposure discovery module"
        )
        module_group.add_argument(
            "--cloud-metadata", action="store_true",
            help="Enable cloud metadata exposure checks"
        )
        module_group.add_argument(
            "--infra-leaks", action="store_true",
            help="Enable infrastructure disclosure detection"
        )
        module_group.add_argument(
            "--sensitive-files", action="store_true",
            help="Enable sensitive file discovery"
        )
        module_group.add_argument(
            "--js-analysis", action="store_true",
            help="Enable JavaScript analysis module"
        )
        module_group.add_argument(
            "--cloud-assets", action="store_true",
            help="Enable cloud asset enumeration"
        )
        module_group.add_argument(
            "--security-headers", action="store_true",
            help="Enable security header analysis"
        )
        module_group.add_argument(
            "--api-surface", action="store_true",
            help="Enable API surface mapping"
        )
        module_group.add_argument(
            "--all-modules", action="store_true",
            help="Enable all audit modules"
        )

        exploit_group = parser.add_argument_group("Exploitation Controls")
        exploit_group.add_argument(
            "--exploit", action="store_true",
            help="Enable exploitation engine (authorized testing only)"
        )
        exploit_group.add_argument(
            "--no-dry-run", action="store_true",
            help="Disable dry-run mode for exploitation (allows actual exploitation)"
        )
        exploit_group.add_argument(
            "--ssrf-exploit", action="store_true",
            help="Enable SSRF exploitation"
        )
        exploit_group.add_argument(
            "--auth-bypass", action="store_true",
            help="Enable authentication bypass"
        )
        exploit_group.add_argument(
            "--privilege-esc", action="store_true",
            help="Enable privilege escalation"
        )
        exploit_group.add_argument(
            "--data-extract", action="store_true",
            help="Enable data extraction"
        )
        exploit_group.add_argument(
            "--rce", action="store_true",
            help="Enable remote code execution"
        )
        exploit_group.add_argument(
            "--destructive", action="store_true",
            help="Enable destructive actions assessment"
        )

        report_group = parser.add_argument_group("Reporting Options")
        report_group.add_argument(
            "-r", "--report", nargs="+", choices=["html", "json", "csv", "all"],
            default=["html", "json", "csv"],
            help="Report format(s) to generate (default: html json csv)"
        )
        report_group.add_argument(
            "--executive-summary", action="store_true", default=True,
            help="Include executive summary in report"
        )
        report_group.add_argument(
            "--no-executive-summary", action="store_false", dest="executive_summary",
            help="Exclude executive summary"
        )

        general_group = parser.add_argument_group("General Options")
        general_group.add_argument(
            "--threads", type=int, default=20,
            help="Maximum number of concurrent threads (default: 20)"
        )
        general_group.add_argument(
            "--depth", type=int, default=3,
            help="Crawling depth (default: 3)"
        )
        general_group.add_argument(
            "--timeout", type=int, default=30,
            help="Request timeout in seconds (default: 30)"
        )
        general_group.add_argument(
            "--rate-limit", type=int, default=50,
            help="Max requests per second (default: 50)"
        )
        general_group.add_argument(
            "--proxy", help="HTTP proxy URL (e.g., http://127.0.0.1:8080)"
        )
        general_group.add_argument(
            "--user-agent", default="SSRFAudit/2.0 (Security Assessment Tool)",
            help="Custom User-Agent string"
        )
        general_group.add_argument(
            "--no-resume", action="store_true",
            help="Disable resume capability"
        )
        general_group.add_argument(
            "--quiet", action="store_true",
            help="Minimal output"
        )
        general_group.add_argument(
            "--debug", action="store_true",
            help="Enable debug logging"
        )
        general_group.add_argument(
            "--version", action="version",
            version="SSRF Auditor v2.0",
            help="Show version and exit"
        )

        return parser.parse_args()

    def _apply_args_to_config(self) -> None:
        args = self.args

        if args.all_modules:
            for module_name in [
                "ssrf_discovery", "cloud_metadata", "infra_disclosure",
                "sensitive_files", "js_analysis", "cloud_assets",
                "security_headers", "api_surface",
            ]:
                self.config.set(f"modules.{module_name}.enabled", True)
        else:
            module_map = {
                "ssrf_discovery": "ssrf_discovery",
                "cloud_metadata": "cloud_metadata",
                "infra_disclosure": "infra_leaks",
                "sensitive_files": "sensitive_files",
                "js_analysis": "js_analysis",
                "cloud_assets": "cloud_assets",
                "security_headers": "security_headers",
                "api_surface": "api_surface",
            }
            for module_name, arg_name in module_map.items():
                if getattr(args, arg_name.replace("-", "_"), False):
                    self.config.set(f"modules.{module_name}.enabled", True)

        self.config.set("general.max_threads", args.threads)
        self.config.set("crawler.max_depth", args.depth)
        self.config.set("general.request_timeout", args.timeout)
        self.config.set("rate_limiting.requests_per_second", args.rate_limit)
        self.config.set("general.output_dir", args.output)
        self.config.set("general.resume", not args.no_resume)
        self.config.set("logging.level", "DEBUG" if args.debug else "INFO")

        if args.proxy:
            self.config.set("proxy.http", args.proxy)
            self.config.set("proxy.https", args.proxy)

        if args.user_agent:
            self.config.set("general.user_agent", args.user_agent)

        if args.exploit:
            self.config.set("exploit.enabled", True)
            self.config.set("exploit.dry_run", not args.no_dry_run)
            self.config.set("exploit.ssrf_exploit", args.ssrf_exploit or args.all_modules)
            self.config.set("exploit.auth_bypass", args.auth_bypass or args.all_modules)
            self.config.set("exploit.privilege_esc", args.privilege_esc or args.all_modules)
            self.config.set("exploit.data_extraction", args.data_extract or args.all_modules)
            self.config.set("exploit.rce", args.rce or args.all_modules)
            self.config.set("exploit.destructive", args.destructive or args.all_modules)

        self.config.set("reporting.formats", args.report if "all" not in args.report else ["html", "json", "csv"])
        self.config.set("reporting.executive_summary", args.executive_summary)

    def _validate_args(self) -> None:
        args = self.args
        if args.list and not Path(args.list).exists():
            console.print(f"[red]Error: URL list file not found: {args.list}[/red]")
            sys.exit(1)

        if not InputValidator.validate_output_dir(args.output):
            console.print(f"[red]Error: Invalid output directory: {args.output}[/red]")
            sys.exit(1)

        if args.exploit and args.no_dry_run:
            console.print(Panel(
                "[bold red]WARNING: Exploitation Engine in LIVE MODE[/bold red]\n\n"
                "Dry-run is disabled. Actual exploitation will be performed.\n"
                "Only use on systems you own or have explicit written authorization to test.\n"
                "Unauthorized testing may violate computer fraud and abuse laws.",
                title="[bold red]LEGAL WARNING[/bold red]",
                border_style="red",
            ))
            response = input("Type 'I ACKNOWLEDGE THE RISKS' to continue: ")
            if response != "I ACKNOWLEDGE THE RISKS":
                console.print("[red]Aborted.[/red]")
                sys.exit(1)

    def _get_targets(self) -> list[str]:
        if self.args.url:
            url = InputValidator.normalize_url(self.args.url)
            if not InputValidator.validate_url(url):
                console.print(f"[red]Error: Invalid URL: {self.args.url}[/red]")
                sys.exit(1)
            return [url]
        else:
            targets = read_file_lines(self.args.list)
            valid_targets = []
            for t in targets:
                url = InputValidator.normalize_url(t)
                if InputValidator.validate_url(url):
                    valid_targets.append(url)
                else:
                    console.print(f"[yellow]Warning: Skipping invalid URL: {t}[/yellow]")
            if not valid_targets:
                console.print("[red]Error: No valid URLs found in list[/red]")
                sys.exit(1)
            return valid_targets

    def _print_findings_table(self, findings: list) -> None:
        if not findings:
            return

        table = Table(title="Finding Summary (High & Critical)")
        table.add_column("Risk", style="bold")
        table.add_column("Title", style="white")
        table.add_column("Module", style="dim")
        table.add_column("Confidence", justify="right")

        for finding in findings:
            if finding.risk_level.name in ("HIGH", "CRITICAL"):
                risk_style = "red" if finding.risk_level.name == "CRITICAL" else "orange1"
                table.add_row(
                    f"[{risk_style}]{finding.risk_level.name}[/{risk_style}]",
                    finding.title[:60],
                    finding.module,
                    f"{finding.confidence:.0%}",
                )

        if table.row_count > 0:
            console.print(table)

    async def _run_async(self) -> None:
        targets = self._get_targets()
        logger = AuditLogger.get_instance(
            level="DEBUG" if self.args.debug else "INFO",
            log_file=self.config.logging.get("file"),
        )

        ensure_directory(self.args.output)

        scanner = Scanner(self.config)
        await scanner.initialize()

        combined_report = None

        for target in targets:
            console.print(f"\n[bold]Scanning:[/bold] {target}")
            try:
                report = await scanner.run(target)
                combined_report = report

                risk_engine = RiskEngineModule(self.config, scanner.http)
                report = risk_engine.analyze_report(report)

                reporting = ReportingModule(self.config, scanner.http)
                generated = reporting.generate_reports(report)

                console.print(f"\n[bold green]Scan Complete for:[/bold green] {target}")
                console.print(f"  [bold]Total Findings:[/bold] {report.total_findings}")
                console.print(f"  [red]Critical:[/red] {report.critical_count} | "
                            f"[orange1]High:[/orange1] {report.high_count} | "
                            f"[yellow]Medium:[/yellow] {report.medium_count} | "
                            f"[green]Low:[/green] {report.low_count}")

                self._print_findings_table(report.findings)

                console.print("\n[bold]Reports Generated:[/bold]")
                for fmt, path in generated.items():
                    console.print(f"  [{fmt.upper()}] {path}")

            except Exception as e:
                console.print(f"[red]Error scanning {target}: {e}[/red]")
                if self.args.debug:
                    import traceback
                    console.print(traceback.format_exc())

        if scanner.exploit_enabled:
            console.print(Panel(
                "[bold yellow]Exploitation modules are ready for use.\n"
                "Run with --exploit and specific exploit flags to activate.[/bold yellow]",
                title="Exploitation",
                border_style="yellow",
            ))

    def run(self) -> None:
        self.args = self.parse_args()

        if not self.args.quiet:
            console.print(self.BANNER, style="bold cyan")
            console.print(
                "[dim]Authorized Security Testing Only[/dim]\n"
            )

        try:
            self.config = Config(self.args.config)
        except ConfigurationError as e:
            console.print(f"[red]Configuration Error: {e}[/red]")
            sys.exit(1)

        self._apply_args_to_config()
        self._validate_args()

        try:
            asyncio.run(self._run_async())
        except KeyboardInterrupt:
            console.print("\n[yellow]Scan interrupted by user[/yellow]")
            if self.scanner:
                self.scanner.stop()
            sys.exit(1)
        except SSRFAuditorError as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)
        except Exception as e:
            console.print(f"[red]Unexpected error: {e}[/red]")
            if self.args.debug:
                import traceback
                console.print(traceback.format_exc())
            sys.exit(1)


def main() -> None:
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()
