# SSRF Payloads

This directory contains payload files for SSRF exploitation testing.

**WARNING:** These payloads are for authorized security testing only.
Unauthorized use is illegal and unethical.

## Contents

- `ssrf_payloads.txt` - Comprehensive list of SSRF payloads for:
  - Cloud metadata endpoints (AWS, GCP, Azure, OCI, Alibaba, OpenStack)
  - Internal service probes (databases, web servers, admin panels)
  - Private network ranges
  - File protocol payloads
  - Dict/Gopher protocol payloads
  - DNS rebinding bypasses

## Usage

These payloads are used by the SSRF exploitation module when
`--ssrf-exploit` is enabled with the exploitation engine.
