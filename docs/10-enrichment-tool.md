---
title: "CVSS v4.0 Enrichment Tool"
sidebar_position: 10
---

![](/img/cvss/1_CkcYfsDiA-sSCgAXK0SMZg.png)


## CVSS v4.0 Enrichment and Prioritization Tool

:::warning Heuristic scoring — not a CVSS v4.0 calculator
The enrichment tool uses **empirical point-delta heuristics** to approximate CVSS-BTE scores, not the official CVSS v4.0 scoring algorithm (which uses lookup tables, not formulas). Outputs should be treated as **prioritization guidance**, not authoritative CVSS-BTE scores. For authoritative scoring, use the [FIRST.org CVSS v4.0 calculator](https://www.first.org/cvss/calculator/4-0) with the vector strings the tool produces.
:::

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

**Stage 2 — Threat enrichment (KEV + EPSS).** The tool downloads the full CISA KEV catalog in a single request and checks each CVE against it. If listed → `E:A` (confirmed exploitation). For non-KEV CVEs, EPSS is used as a **triage signal** to flag CVEs for manual verification — it does not directly set `E:P`. See the output "Verify" column for CVEs that need exploit evidence review before assigning `E:P`.

**Stage 3 — Environmental enrichment (asset profile).** Modified Base metrics and Security Requirements from the selected profile are appended to the vector. The tool ships with six built-in profiles — `internet_facing`, `internal_vlan`, `isolated_ot`, `dev_test`, `healthcare_ehr`, `pci_payment` — covering the most common deployment contexts described in this article.

### Output

The tool prints a severity-ranked table and optionally writes CSV (`--output`) or JSON (`--json`) for import into ticket systems or dashboards.

The table shows four distinct concepts — keep them separate:
- **CVSS version**: the version NVD provides (often still 3.1 for older CVEs)
- **KEV / EPSS**: threat intelligence inputs
- **E:** value: analyst-assigned exploit maturity
- **Priority score / Severity / SLA**: the heuristic-adjusted output for triage

**Example — `internet_facing` profile (no environmental reduction applies):**

```
CVE                   CVSS   KEV     EPSS  E      Priority    Severity    SLA
────────────────────────────────────────────────────────────────────────────────
CVE-2021-44228         3.1   YES   0.9446  E:A    ~10.0       Critical    24–72 hours
CVE-2023-4966          3.1   YES   0.9435  E:A    ~9.4        Critical    24–72 hours
CVE-2023-34362         3.1   YES   0.9437  E:A    ~9.8        Critical    24–72 hours
CVE-2024-21762         3.1   YES   0.9308  E:A    ~9.6        Critical    24–72 hours
CVE-2025-32433         3.1   YES   0.5031  E:A    ~9.6        Critical    24–72 hours
```

**Example — same CVEs with `internal_vlan` profile (MAV:A + MAC:H applied):**

```
CVE                   CVSS   KEV     EPSS  E      Priority    Severity    SLA
────────────────────────────────────────────────────────────────────────────────
CVE-2021-44228         3.1   YES   0.9446  E:A    ~7.4        High        30 days
CVE-2023-4966          3.1   YES   0.9435  E:A    ~7.0        High        30 days
CVE-2023-34362         3.1   YES   0.9437  E:A    ~7.2        High        30 days
CVE-2024-21762         3.1   YES   0.9308  E:A    ~7.3        High        30 days
CVE-2025-32433         3.1   YES   0.5031  E:A    ~6.5        Medium      90 days
```

The same CVE list — dramatically different priorities depending on your actual network zone. The internet_facing profile produces Criticals requiring immediate action; internal_vlan produces Highs and Mediums for your next maintenance window. Both sets of numbers are **heuristic approximations** — verify important findings against the FIRST.org calculator using the vector strings in the output.

Full documentation, profile definitions, and NVD API key instructions are in the repository README: **https://github.com/anpa1200/cvss_4.0**

---

## Common Usage Patterns

**Single CVE — quick check before a meeting:**

```bash
python3 cvss_enrichment_tool.py \
  --cves CVE-2025-32433 \
  --profile internal_vlan

# Output (two columns — original severity vs profile-adjusted priority):
# CVE-2025-32433
#   NVD source vector:       CVSS v3.1 (v4.0 not yet available from NVD)
#   KEV:                     YES (added April 2025) → E:A
#   EPSS:                    0.5031
#   Vendor severity (Base):  Critical [10.0 — worst-case, internet-facing assumed]
#   Profile applied:         internal_vlan (MAV:A + MAC:H)
#   Adjusted priority:       ~6.5 Medium [heuristic — verify at FIRST.org calculator]
#   SLA recommendation:      90 days (patch at next maintenance window)
#   Enriched vector:         CVSS:4.0/AV:N/.../E:A/MAV:A/MAC:H
#
# NOTE: E:A (CISA KEV) is confirmed. Priority reduction is from environmental
# profile only (system is not internet-accessible). Do NOT defer indefinitely —
# if network posture changes, this becomes Critical again.
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
