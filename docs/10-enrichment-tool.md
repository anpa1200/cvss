---
title: "CVSS v4.0 Enrichment Tool"
sidebar_position: 10
---

![](/img/cvss/1_CkcYfsDiA-sSCgAXK0SMZg.png)


## CVSS v4.0 Enrichment Tool

The pipeline described throughout this section is available as a standalone command-line tool: **[cvss_enrichment_tool](https://github.com/anpa1200/cvss_4.0)** (GitHub).

### Installation

**Requirements:** Python 3.8+, `requests` library, internet access to NVD / CISA / FIRST.org APIs. No database, no additional dependencies.

```bash
# 1. Clone the repository
git clone https://github.com/anpa1200/cvss_4.0.git
cd cvss_4.0

# 2. Install the only dependency
pip3 install requests

# 3. Run a quick test (no API key needed)
python3 cvss_enrichment_tool.py --cves CVE-2021-44228 --profile internal_vlan
```

**Optional — NVD API key.** Without a key, NVD rate-limits requests to 5 per 30 seconds — sufficient for ad-hoc lookups. For batches larger than ~20 CVEs, register a free key at `https://nvd.nist.gov/developers/request-an-api-key` and pass it with `--apikey`:

```bash
python3 cvss_enrichment_tool.py \
  --file cves.txt \
  --profile internet_facing \
  --output report.csv \
  --apikey YOUR_KEY_HERE
```

### How It Works

The tool implements the three-stage enrichment pipeline in a single automated run:

```
CVE IDs → NVD API (Base vector) → CISA KEV (E:A?) → EPSS API (E:P/E:U?)
        → Apply asset profile (MAV/MAC/CR/IR/AR/MSC...)
        → Output CVSS-BTE vector + severity band + SLA recommendation
```

**Stage 1 — Base vector (NVD API 2.0).** For each CVE ID the tool queries `services.nvd.nist.gov` and retrieves the CVSS vector string. It prefers a v4.0 vector; if only a v3.1 vector exists (common for CVEs predating November 2023), it applies threat-only enrichment and flags the result for manual re-scoring at the FIRST.org calculator.

**Stage 2 — Threat enrichment (KEV + EPSS).** The tool downloads the full CISA KEV catalog in a single request and checks each CVE against it. If listed → `E:A`. Otherwise it queries the FIRST.org EPSS API: EPSS ≥ 0.5 or ≥ 0.1 → `E:P`; below 0.1 → `E:U`.

**Stage 3 — Environmental enrichment (asset profile).** Modified Base metrics and Security Requirements from the selected profile are appended to the vector. The tool ships with six built-in profiles — `internet_facing`, `internal_vlan`, `isolated_ot`, `dev_test`, `healthcare_ehr`, `pci_payment` — covering the most common deployment contexts described in this article.

### Output

The tool prints a severity-ranked table and optionally writes CSV (`--output`) or JSON (`--json`) for import into ticket systems or dashboards:

```
CVE                   CVSS   KEV     EPSS  E      Severity    SLA
──────────────────────────────────────────────────────────────────
CVE-2021-44228         3.1   YES   0.9446  E:A    Critical    24–72 hours
CVE-2023-4966          3.1   YES   0.9435  E:A    Critical    24–72 hours
CVE-2023-34362         3.1   YES   0.9437  E:A    Critical    24–72 hours
CVE-2024-21762         3.1   YES   0.9308  E:A    Critical    24–72 hours
CVE-2025-32433         3.1   YES   0.5031  E:A    Critical    24–72 hours
```

Full documentation, profile definitions, and NVD API key instructions are in the repository README: **https://github.com/anpa1200/cvss_4.0**

---

## Common Usage Patterns

**Single CVE — quick check before a meeting:**

```bash
python3 cvss_enrichment_tool.py \
  --cves CVE-2025-32433 \
  --profile internal_vlan

# Output:
# CVE-2025-32433  CVSS: 4.0  KEV: YES  EPSS: 0.5031  E: E:A  Severity: Critical  SLA: 24–72 hours
# BTE vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A/MAV:A/MAC:H
# BTE Score: ~6.5 Medium  [internal_vlan profile applied]
```

**Batch from scanner — CSV input, JSON output for ticketing system:**

```bash
# Export CVE list from Tenable / Qualys / Rapid7 → cves.txt (one per line)
python3 cvss_enrichment_tool.py \
  --file cves.txt \
  --profile internet_facing \
  --output enriched_report.csv \
  --json enriched_report.json \
  --apikey YOUR_NVD_KEY

# enriched_report.json is suitable for import into Jira, ServiceNow, or SIEM
```

**Healthcare deployment — EHR system audit:**

```bash
python3 cvss_enrichment_tool.py \
  --file ehr_cves.txt \
  --profile healthcare_ehr \
  --output ehr_report.csv

# healthcare_ehr profile sets CR:H / IR:H / AR:H by default
# Any CVE scoring ≥ 4.0 after enrichment gets flagged for HIPAA risk analysis
```

**Comparing profiles for the same CVE list (what-if analysis):**

```bash
for profile in internet_facing internal_vlan dev_test isolated_ot; do
  echo "=== Profile: $profile ==="
  python3 cvss_enrichment_tool.py \
    --file cves.txt \
    --profile $profile \
    --quiet  # summary only
done

# Shows how the same vulnerability list scores differently across your segments
# Critical finding: a 9.8 Critical in internet_facing may be 4.5 Medium in dev_test
```

**Automation — daily cron enrichment:**

```bash
#!/bin/bash
# /etc/cron.d/cvss-enrich — runs at 06:00 daily
DATE=$(date +%Y-%m-%d)
python3 /opt/cvss_4.0/cvss_enrichment_tool.py \
  --file /var/scanner/today_cves.txt \
  --profile internet_facing \
  --output /var/reports/enriched_${DATE}.csv \
  --json /var/reports/enriched_${DATE}.json \
  --apikey $NVD_API_KEY

# Post-process: alert on any new Critical findings
python3 /opt/cvss_4.0/alert_new_criticals.py /var/reports/enriched_${DATE}.json
```

---

## Related Chapters

| Chapter | What you'll find |
|---------|-----------------|
| [Practical VM Workflow](/docs/vm-workflow) | The manual version of this pipeline + ticket template |
| [Threat & Environmental Metrics](/docs/threat-metrics) | How KEV, EPSS, and environmental profiles are determined |
| [Scoring Lifecycle](/docs/lifecycle) | The B→BT→BTE theory the tool implements |
