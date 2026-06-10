# SSRF Auditor v2.0

**Production-grade SSRF & Infrastructure Information Disclosure Auditing Framework for Kali Linux**

A comprehensive security assessment framework designed to identify Server-Side Request Forgery (SSRF) attack surfaces, cloud metadata exposure risks, infrastructure information disclosure, and sensitive configuration leaks. Built for authorized security teams to assess assets they own or are explicitly authorized to test.

## ⚠️ Legal & Authorization

**IMPORTANT:** This tool is designed for **authorized security testing only**. You must:
- Only test systems you own or have **explicit written authorization** to test
- Comply with all applicable laws and regulations
- Obtain proper authorization before scanning or exploiting any system
- The exploitation engine requires explicit flag activation (`--exploit --no-dry-run`)

Unauthorized use may violate computer fraud and abuse laws. The developers assume no liability for unauthorized use.

## Architecture

```
ssrf-auditor/
├── src/
│   ├── main.py                    # Entry point
│   ├── cli.py                     # CLI interface (argparse + Rich)
│   ├── config.py                  # YAML configuration manager
│   ├── models.py                  # Data models (Finding, Report, etc.)
│   ├── exceptions.py              # Custom exceptions
│   ├── engine/
│   │   ├── scanner.py             # Main scan orchestrator
│   │   ├── crawler.py             # Async web crawler
│   │   ├── rate_limiter.py        # Token-bucket rate limiter
│   │   └── plugin_loader.py       # Module discovery system
│   ├── modules/
│   │   ├── base.py                # Abstract base module
│   │   ├── ssrf_discovery.py      # Module 1: SSRF discovery
│   │   ├── cloud_metadata.py      # Module 2: Cloud metadata checks
│   │   ├── infra_disclosure.py    # Module 3: Infrastructure leaks
│   │   ├── sensitive_files.py     # Module 4: Sensitive files
│   │   ├── js_analysis.py         # Module 5: JavaScript analysis
│   │   ├── cloud_assets.py        # Module 6: Cloud asset enumeration
│   │   ├── security_headers.py    # Module 7: Security headers
│   │   ├── api_surface.py         # Module 8: API surface mapping
│   │   ├── risk_engine.py         # Module 9: Risk classification
│   │   └── reporting.py           # Module 10: Report generation
│   ├── exploit/
│   │   ├── engine.py              # Exploitation orchestrator
│   │   ├── ssrf_exploit.py        # SSRF exploitation
│   │   ├── auth_bypass.py         # Authentication bypass
│   │   ├── privilege_esc.py       # Privilege escalation
│   │   ├── data_extract.py        # Data extraction
│   │   ├── rce.py                 # Remote code execution
│   │   └── destruct.py            # Destructive actions assessment
│   ├── utils/
│   │   ├── http.py                # Async HTTP client
│   │   ├── parsers.py             # HTML/JSON/XML/URL parsers
│   │   ├── validators.py          # Input validation
│   │   ├── logger.py              # Rotating file logger
│   │   └── helpers.py             # Utility functions
│   └── reports/
│       └── templates/             # Report templates
├── tests/
│   ├── test_modules.py            # Module unit tests
│   ├── test_engine.py             # Engine tests
│   ├── test_reporting.py          # Report generation tests
│   ├── test_config.py             # Configuration tests
│   └── fixtures/                  # Test data fixtures
├── data/payloads/                 # SSRF payloads
├── config.yaml                    # Default configuration
├── Dockerfile                     # Container deployment
├── docker-compose.yml             # Multi-service orchestration
├── requirements.txt               # Python dependencies
├── pyproject.toml                 # Project metadata
└── Makefile                       # Build automation
```

## Features

### Module 1 — SSRF Exposure Discovery
- Enumerates URL-accepting parameters (GET, POST, JSON, XML, GraphQL, WebSocket)
- Detects 30+ SSRF-susceptible parameter names
- Identifies URL path patterns for proxy/redirect/fetch endpoints
- Confidence-scored findings without payload execution

### Module 2 — Cloud Metadata Exposure Checks
- AWS (169.254.169.254, 169.254.170.2)
- Azure (169.254.169.254/metadata)
- GCP (metadata.google.internal)
- OCI (169.254.169.254/opc), Alibaba Cloud, OpenStack
- Documentation leaks, source code references, error messages

### Module 3 — Infrastructure Disclosure Detection
- Private IP ranges (RFC 1918, loopback, link-local)
- Internal hostnames (internal, local, corp, lan)
- Kubernetes, Docker, service mesh references
- Internal DNS names, URLs, proxy headers
- Backend technology fingerprints
- CI/CD pipeline references

### Module 4 — Sensitive File Discovery
- Configuration files, backups, logs, environment files
- Manifest files (package.json, requirements.txt, Dockerfile)
- Debug/info endpoints and secret/credential patterns

### Module 5 — JavaScript Analysis
- Extracts endpoints, API references, internal URLs
- Cloud storage references, environment variable indicators
- Hardcoded secret detection (AWS keys, tokens, etc.)

### Module 6 — Cloud Asset Enumeration
- S3 buckets, Azure storage accounts, GCS buckets
- CDN endpoints (CloudFront, CloudFlare, Fastly, Akamai)
- Public cloud services (Lambda, Firebase, Netlify, Vercel)

### Module 7 — Security Header Analysis
- CSP weakness detection (unsafe-inline, unsafe-eval, wildcards)
- CORS misconfiguration (wildcard origins, null origin)
- HSTS, Referrer-Policy, Permissions-Policy evaluation
- SSRF-specific misconfiguration highlighting

### Module 8 — API Surface Mapping
- REST endpoints, GraphQL endpoints
- OpenAPI/Swagger documentation references
- WebSocket endpoints
- Common path probing

### Module 9 — Risk Engine
- CVSS-based classification
- Contextual scoring (SSRF, disclosure multipliers)
- Severity: Informational, Low, Medium, High, Critical
- Weighted risk score aggregation

### Module 10 — Reporting
- HTML report with risk visualization
- JSON export for programmatic consumption
- CSV for spreadsheet analysis
- Executive summary and technical detail

### Exploitation Engine (Optional)
- **SSRF Exploitation:** Probes metadata services, internal services, callback verification
- **Authentication Bypass:** JWT none-algorithm, session hijacking, OAuth testing
- **Privilege Escalation:** IDOR, vertical/horizontal escalation
- **Data Extraction:** Metadata exfiltration, env/config extraction
- **RCE:** Command injection, deserialization, template injection assessment
- **Destructive Actions:** Data destruction, DoS, persistence vectors

All exploitation is **dry-run by default**. Live mode requires explicit `--no-dry-run` flag.

## Installation

### Local Installation

```bash
# Clone the repository
git clone https://github.com/your-org/ssrf-auditor.git
cd ssrf-auditor

# Install dependencies
pip install -r requirements.txt

# Optional: Install in development mode
pip install -e .
```

### Kali Linux Installation

```bash
sudo apt-get update
sudo apt-get install -y python3-pip python3-venv git

git clone https://github.com/your-org/ssrf-auditor.git
cd ssrf-auditor

python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

### Docker Deployment

```bash
# Build the image
docker build -t ssrf-auditor:latest .

# Run single target scan
docker run --rm \
  -v $(pwd)/results:/app/results \
  ssrf-auditor:latest \
  -u https://target.com --all-modules

# Run with docker-compose
docker-compose up ssrf-auditor-single

# Run exploitation (dry-run mode)
docker-compose --profile exploit up ssrf-auditor-exploit
```

## Usage

### Basic Scanning

```bash
# Scan single URL
python -m src.main -u https://target.com

# Scan multiple URLs from file
python -m src.main -l urls.txt

# Scan with all modules enabled
python -m src.main -u https://target.com --all-modules

# Specify report formats
python -m src.main -u https://target.com --report html json csv
```

### Module Selection

```bash
# JavaScript analysis only
python -m src.main -u https://target.com --js-analysis

# Infrastructure leaks detection
python -m src.main -u https://target.com --infra-leaks

# Cloud asset enumeration
python -m src.main -u https://target.com --cloud-assets

# API surface mapping
python -m src.main -u https://target.com --api-surface

# Enable multiple specific modules
python -m src.main -u https://target.com --js-analysis --infra-leaks --cloud-assets
```

### Exploitation (Authorized Testing Only)

```bash
# Dry-run mode (default) - shows what would be done
python -m src.main -u https://target.com --exploit --ssrf-exploit

# Full exploitation - SSRF + auth bypass + privilege esc
python -m src.main -u https://target.com --exploit --ssrf-exploit --auth-bypass --privilege-esc

# ALL exploitation modules in dry-run
python -m src.main -u https://target.com --all-modules --exploit

# LIVE MODE - actual exploitation (requires acknowledgment)
python -m src.main -u https://target.com --all-modules --exploit --no-dry-run
```

### Advanced Options

```bash
# Increase crawling depth
python -m src.main -u https://target.com --depth 5

# Increase threads and rate limit
python -m src.main -u https://target.com --threads 50 --rate-limit 100

# Use proxy (e.g., Burp Suite)
python -m src.main -u https://target.com --proxy http://127.0.0.1:8080

# Custom output directory
python -m src.main -u https://target.com --output /path/to/results

# Debug mode
python -m src.main -u https://target.com --debug
```

## Configuration

Edit `config.yaml` to customize behavior:

```yaml
general:
  max_threads: 20
  request_timeout: 30
  
rate_limiting:
  requests_per_second: 50
  
crawler:
  max_depth: 3
  max_pages: 500
  
modules:
  ssrf_discovery:
    enabled: true
  cloud_metadata:
    enabled: true
    
exploit:
  enabled: false
  dry_run: true
```

## Output

Reports are generated in the specified output directory (default: `results/`):

- `ssrf-audit-report-YYYYMMDD_HHMMSS.html` - Interactive HTML report
- `ssrf-audit-report-YYYYMMDD_HHMMSS.json` - Full JSON data
- `ssrf-audit-report-YYYYMMDD_HHMMSS.csv` - CSV findings export

### HTML Report Features
- Color-coded risk levels (Critical=Red, High=Orange, Medium=Yellow, Low=Green)
- Executive summary with risk score
- Finding details with evidence and remediation
- Tag-based classification
- Module execution tracking

## Testing

```bash
# Run all tests
make test
# or
pytest tests/ -v --cov=src

# Run with coverage report
pytest tests/ -v --cov=src --cov-report=term-missing --cov-report=html

# Run specific test file
pytest tests/test_modules.py -v

# Run online tests (requires network)
pytest tests/ -m "online"
```

## Security Safeguards

1. **Configuration-Based:** All scanning behavior is controlled via YAML configuration
2. **Dry-Run Default:** Exploitation engine operates in dry-run mode by default
3. **Explicit Consent:** Live exploitation requires `--no-dry-run` flag and user acknowledgment
4. **Rate Limiting:** Configurable rate limiting prevents denial of service
5. **No Storage of Secrets:** Forced anonymity option in reporting
6. **Authorization Notice:** Prominent warnings about authorized use only
7. **Respect robots.txt:** Optional respect for crawling restrictions
8. **Input Validation:** All inputs validated and sanitized

## Module Development

Create custom modules by extending `BaseModule`:

```python
from src.modules.base import BaseModule
from src.models import Finding, RiskLevel

class CustomModule(BaseModule):
    module_name = "custom"
    module_description = "Custom analysis module"

    async def run(self, urls: list[str]) -> list[Finding]:
        # Your analysis logic here
        pass
```

## License

MIT License - See LICENSE file for details.

## Disclaimer

This tool is for **authorized security testing and educational purposes only**. Users are responsible for complying with all applicable laws. The authors assume no liability and are not responsible for any misuse or damage caused by this program.
