---
title: "The CVSS Scoring Lifecycle"
sidebar_position: 4
---

![](/img/cvss/1_jyrczXiPUvm7eSD8eIaqbA.png)


## 5. The CVSS Lifecycle: CVSS-B → CVSS-BT → CVSS-BTE

FIRST.org describes CVSS v4.0 as a **living score** that matures as information becomes available. This lifecycle maps to organizational maturity and regulatory requirements.

```
┌──────────────────────────────────────────────────────────────────┐
│                    CVSS SCORING LIFECYCLE                         │
│                                                                   │
│  VENDOR PUBLISHES                                                 │
│  ┌─────────────┐                                                  │
│  │  CVSS-B     │  Base metrics only                               │
│  │  (Worst     │  → Published in NVD, CVE records                 │
│  │   Case)     │  → Generic, deployment-independent               │
│  │  e.g. 9.8   │  → Produced by vendor/researcher                 │
│  └──────┬──────┘                                                  │
│         │  Add Threat Intelligence (CISA KEV, EPSS, ExploitDB)   │
│         ▼                                                         │
│  ┌─────────────┐                                                  │
│  │  CVSS-BT    │  Base + Exploit Maturity                         │
│  │  (Current   │  → "Is this being exploited right now?"          │
│  │   Reality)  │  → Uses CISA KEV, EPSS, Metasploit, ExploitDB   │
│  │  e.g. 7.4   │  → Produced by consumer with threat intel        │
│  └──────┬──────┘                                                  │
│         │  Add Environmental Context (your network/data/controls) │
│         ▼                                                         │
│  ┌─────────────┐                                                  │
│  │  CVSS-BTE   │  Base + Threat + Environment                     │
│  │  (Your      │  → "How bad is this here, for us, today?"        │
│  │   Reality)  │  → Uses asset inventory, network topology,       │
│  │  e.g. 4.2   │     compensating controls, CIA requirements      │
│  └─────────────┘  → Produced by consumer security team           │
│                                                                   │
│  DECISION: Patch/Mitigate timeline based on CVSS-BTE severity     │
└──────────────────────────────────────────────────────────────────┘
```

**Practical implementation path:** You do not need to achieve CVSS-BTE overnight. Start with CVSS-B (vendor score from NVD). Add Threat metrics when you have a threat intel program (CVSS-BT). Add Environmental metrics as you build asset inventory and network documentation (CVSS-BTE). Each layer improves decision quality.

---

## Walking a CVE Through the Full Lifecycle

**CVE-2024-21762 (FortiOS SSL VPN heap overflow)** — a real example from Fortinet's perimeter device.

**Day 0 — Vendor publishes (February 8, 2024):**

```
NVD CVSS-B:
  CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
  Score: 10.0 Critical

At this point: scanner shows 10.0 for every FortiOS-based system you have.
No exploit confirmed. Default E:X = treated as E:A.
Action: Triage starts. Which of your FortiOS systems are internet-facing?
```

**Day 1 — CISA adds to KEV (February 9, 2024, confirmed exploitation):**

```
Threat update:
  E:A  (CISA KEV confirmed)

CVSS-BT:  10.0 Critical (E:A maintains maximum)
EPSS:     0.93+ (extremely high exploitation probability)

Action: Confirmed active exploitation. Internet-facing FortiOS = emergency patch NOW.
Internal / VPN-gated FortiOS = begin emergency change management.
```

**Day 3 — Your team applies environmental context:**

```
System A — Internet-facing SSL VPN concentrator:
  No environmental reduction possible. E:A + AV:N = genuine Critical.
  CVSS-BTE: 10.0  →  Patch within 24 hours (or take offline)

System B — FortiOS in DMZ, only reachable from corporate VPN:
  MAV:A  (not directly internet-facing — VPN required to reach it)
  MAC:H  (accessing the management plane requires jump host + MFA)
  MSC:L  (segment has limited blast radius — no domain controllers)
  CVSS:4.0/.../E:A/MAV:A/MAC:H/MSC:L
  CVSS-BTE: ~7.6 High  →  Emergency patch window within 48 hours

System C — FortiOS on isolated OT segment, no web-facing interfaces:
  MAV:L  (local access to OT zone required — air-gapped from corp)
  MAC:H  (physical OT network access, no remote management)
  MSC:N/MSI:N/MSA:N  (OT segment is isolated from corporate)
  CVSS:4.0/.../E:A/MAV:L/MAC:H/MSC:N/MSI:N/MSA:N
  CVSS-BTE: ~5.9 Medium  →  Patch at next OT maintenance window

Result:
  Without lifecycle: 3 systems × 10.0 Critical = emergency response on all 3
  With lifecycle:    1 genuine Critical, 1 High, 1 Medium
  Effort saved: ~60% — and the documented evidence is audit-ready
```

---

## 6. Threat Metrics in Practice: KEV, EPSS, and Exploit Feeds

### CISA Known Exploited Vulnerabilities (KEV) Catalog

The KEV catalog is the gold standard for `E:A` determination. CISA adds a CVE only when it has confirmed, real-world exploitation evidence. As of March 2026, the catalog contains approximately 1,550+ CVEs — out of over 240,000 published CVEs in NVD. That is well under 1%.

```bash
# Check KEV via API — works immediately, no registration needed
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json" \
  | python3 -c "
import json, sys
data = json.load(sys.stdin)
cve_id = 'CVE-2021-44228'
match = [v for v in data['vulnerabilities'] if v['cveID'] == cve_id]
if match:
    v = match[0]
    print(f'IN KEV: {v[\"vulnerabilityName\"]}')
    print(f'Due Date: {v[\"dueDate\"]}')
    print(f'Required Action: {v[\"requiredAction\"]}')
else:
    print('Not in KEV')
"
# Output for Log4Shell:
# IN KEV: Apache Log4j2 Remote Code Execution Vulnerability
# Due Date: 2021-12-24
# Required Action: Apply updates per vendor instructions.
```

**Batch KEV check — Python with CSV output:**

```python
import json, requests, csv, sys
from datetime import datetime

def load_kev() -> set:
    """Download and return the set of CVE IDs in CISA KEV."""
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    response = requests.get(url, timeout=30)
    response.raise_for_status()
    return {v["cveID"]: v for v in response.json()["vulnerabilities"]}

def load_epss(cve_ids: list) -> dict:
    """Fetch EPSS scores for a list of CVE IDs from FIRST.org API."""
    base_url = "https://api.first.org/data/v1/epss"
    scores = {}
    # API accepts comma-separated CVE IDs, max ~30 per request
    for i in range(0, len(cve_ids), 30):
        batch = ",".join(cve_ids[i:i+30])
        resp = requests.get(f"{base_url}?cve={batch}", timeout=30)
        if resp.ok:
            for item in resp.json().get("data", []):
                scores[item["cve"]] = float(item["epss"])
    return scores

def determine_exploit_maturity(cve_id: str, kev_data: dict, epss_scores: dict) -> str:
    """
    Determine Exploit Maturity based on KEV and EPSS.
    Returns the CVSS v4.0 E: value.
    """
    if cve_id in kev_data:
        return "E:A"  # Confirmed active exploitation

    epss = epss_scores.get(cve_id, 0.0)
    if epss >= 0.5:
        # EPSS ≥ 50% = high exploitation likelihood → strong POC signal
        return "E:P"
    elif epss >= 0.1:
        # Moderate signal — verify against ExploitDB/Metasploit/GitHub
        return "E:P"
    else:
        # Low EPSS, not in KEV — no exploitation evidence
        return "E:U"

# Example: Enrich a list of CVEs from your scanner
cves_from_scanner = [
    "CVE-2021-44228",  # Log4Shell
    "CVE-2023-4966",   # CitrixBleed
    "CVE-2023-34362",  # MOVEit SQLi
    "CVE-2024-21762",  # FortiOS SSL VPN
    "CVE-2025-32433",  # Erlang/OTP SSH
]

kev = load_kev()
epss = load_epss(cves_from_scanner)

print(f"{'CVE':<20} {'KEV':>5} {'EPSS':>8} {'E Value':<10}")
print("-" * 50)
for cve in cves_from_scanner:
    in_kev = "YES" if cve in kev else "NO"
    epss_score = epss.get(cve, 0.0)
    e_value = determine_exploit_maturity(cve, kev, epss)
    print(f"{cve:<20} {in_kev:>5} {epss_score:>8.4f} {e_value:<10}")
```

### EPSS — The Probabilistic Complement to CVSS

The **Exploit Prediction Scoring System (EPSS)** is a machine learning model maintained by FIRST.org that predicts the probability of a CVE being exploited in the wild within 30 days. It complements CVSS by answering a different question: not "how severe is the vulnerability?" but "how likely is it to be exploited soon?"

**EPSS characteristics:**
- Score range: 0.0 to 1.0 (probability)
- Updated daily
- Uses ML trained on NVD data, Metasploit module availability, ExploitDB entries, active threat feeds
- Free API: `https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX`

**How to combine CVSS + EPSS for prioritization:**

```
Priority Matrix:
                    EPSS Low (<0.1)    EPSS Medium (0.1-0.5)    EPSS High (>0.5)
CVSS High/Critical   → Schedule          → Priority                → Immediate
CVSS Medium          → Backlog           → Schedule                → Priority
CVSS Low             → Accept/Ignore     → Backlog                 → Schedule

Real examples (approximate, as of early 2024):
  CVE-2021-44228 (Log4Shell):   CVSS 10.0, EPSS ~0.97 → Immediate
  CVE-2023-4966  (CitrixBleed): CVSS 9.4,  EPSS ~0.97 → Immediate
  CVE-2021-34527 (PrintNightm): CVSS 8.8,  EPSS ~0.96 → Immediate
  CVE-2023-34362 (MOVEit):      CVSS 9.8,  EPSS ~0.96 → Immediate
  Typical new CVE (no exploit): CVSS 7.5,  EPSS ~0.002 → Schedule/Backlog
```

```bash
# Quick EPSS check for a CVE
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2021-44228" \
  | python3 -c "import json,sys; d=json.load(sys.stdin); print(d['data'][0])"
# {'cve': 'CVE-2021-44228', 'epss': '0.97530', 'percentile': '1.00000', 'date': '<today>'}
# EPSS scores are updated daily — check the date field to confirm freshness
```

### The Step-by-Step Threat Metric Determination Workflow

```
For each CVE in your scanner output:

Step 1: Check CISA KEV (30 seconds, fully automated)
  → IN KEV?  → Set E:A, mark as highest priority
  → NOT IN KEV? → Continue to Step 2

Step 2: Check EPSS score
  → EPSS ≥ 0.5?  → Strong exploitation likelihood → E:P at minimum
  → EPSS 0.1–0.5? → Moderate likelihood → E:P (verify against ExploitDB)
  → EPSS < 0.1?  → Low likelihood → Continue to Step 3

Step 3: Check ExploitDB / Metasploit / GitHub
  searchsploit CVE-XXXX-XXXXX
  msfconsole -q -x "search cve:XXXX-XXXXX type:exploit; exit"
  → Module/exploit found? → E:P
  → Nothing found? → Continue to Step 4

Step 4: Default assignment
  → No KEV, no EPSS signal, no public exploit → E:U
```

---

## Related Chapters

| Chapter | What you'll find |
|---------|-----------------|
| [Vector String Anatomy](/docs/vector-string) | How to read and write the vectors used in each lifecycle stage |
| [Threat & Environmental Metrics](/docs/threat-metrics) | Deep dive on E: determination and environmental adjustments |
| [Worked Examples](/docs/worked-examples) | Log4Shell and Erlang/OTP traced through the full lifecycle |
| [Practical VM Workflow](/docs/vm-workflow) | The 6-step operational process for your entire scanner output |
| [Enrichment Tool](/docs/enrichment-tool) | Automate the B→BT→BTE pipeline for any list of CVEs |
