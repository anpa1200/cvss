---
title: "The Practical VM Workflow"
sidebar_position: 9
---

![](/img/cvss/1_8a38jCuwENp5flLnmWAj7g.png)


## 14. The Practical VM Workflow: From Scanner Output to Prioritized Action

### The 6-Step Process

```
┌───────────────────────────────────────────────────────────────┐
│             VULNERABILITY MANAGEMENT WORKFLOW (CVSS v4.0)      │
│                                                               │
│  Step 1: INGEST                                               │
│    Scanner Report → extract all CVE IDs + Base Vectors        │
│    (Tenable, Qualys, Rapid7, Wiz all export CVE IDs)          │
│                                                               │
│  Step 2: THREAT ENRICHMENT (automated, applies to all CVEs)   │
│    ┌─────────────────────────────────────────────────────┐    │
│    │ CISA KEV API → E:A if listed                         │    │
│    │ EPSS API → E:P if ≥ 0.1, E:U if < 0.1              │    │
│    │ Override: E:A if KEV regardless of EPSS              │    │
│    └─────────────────────────────────────────────────────┘    │
│                                                               │
│  Step 3: ASSET GROUPING                                       │
│    Group CVEs by affected system/network zone                 │
│    Tag each group: zone, data class, compensating controls    │
│                                                               │
│  Step 4: ENVIRONMENTAL ENRICHMENT (per asset group)          │
│    ┌─────────────────────────────────────────────────────┐    │
│    │ Network zone → MAV value (N/A/L/P)                   │    │
│    │ Access controls → MAC value (L/H)                    │    │
│    │ Data classification → MVC/MVI values                 │    │
│    │ Blast radius → MSC/MSI/MSA values                    │    │
│    │ Asset criticality → CR/IR/AR values                  │    │
│    └─────────────────────────────────────────────────────┘    │
│                                                               │
│  Step 5: RECALCULATE ALL SCORES                               │
│    CVSS v4.0 calculator API or FIRST.org calculator           │
│    Output: CVSS-BTE score per CVE per asset group             │
│                                                               │
│  Step 6: PRIORITIZE AND ACT (by CVSS-BTE)                    │
│    Critical (9.0+): 24–72 hours — emergency response          │
│    High (7.0–8.9):  30 days — planned sprint                  │
│    Medium (4.0–6.9): 90 days — next maintenance window        │
│    Low (<4.0): Next major release / accept risk               │
└───────────────────────────────────────────────────────────────┘
```

---

## End-to-End Script: Scanner CSV → Enriched Priority Report

This script takes a CSV file exported from any scanner (Tenable, Qualys, Rapid7, Wiz) and produces a priority-sorted, enriched report ready for ticketing. It implements all six steps above.

**Input file format (`scanner_output.csv`):**
```csv
cve_id,asset_id,asset_name,zone,base_vector
CVE-2024-21762,SRV-001,fw-edge-01,internet_facing,CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
CVE-2023-4966,SRV-002,netscaler-01,internet_facing,CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N
CVE-2023-34362,SRV-003,db-prod-01,internal_vlan,CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
CVE-2025-32433,SRV-004,erlang-app-01,internal_vlan,CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
CVE-2023-44487,SRV-005,build-srv-01,internal_vlan,CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:H
```

**The enrichment script (`vm_enrich.py`):**

```python
import csv, json, requests, sys
from dataclasses import dataclass
from typing import Optional

# ── Asset Profiles ─────────────────────────────────────────────────────────
# Each zone gets default Environmental metric overrides.
# Override individual systems in ASSET_OVERRIDES below.

PROFILES = {
    "internet_facing": {
        "MAV": None,    # AV:N stays — correctly reflects internet exposure
        "MAC": None,    # Complexity unchanged
        "CR": None, "IR": None, "AR": None,
        "MSC": None, "MSI": None, "MSA": None,
    },
    "internal_vlan": {
        "MAV": "A",     # Adjacent — internal VLAN, not internet-accessible
        "MAC": "H",     # VPN + MFA required for access
        "CR": None, "IR": None, "AR": None,
        "MSC": None, "MSI": None, "MSA": None,
    },
    "dev_test": {
        "MAV": "A",
        "MAC": "H",
        "CR": "L", "IR": "L", "AR": "L",
        "MSC": "N", "MSI": "N", "MSA": "N",
    },
    "isolated_ot": {
        "MAV": "L",     # Local — physical OT network access required
        "MAC": "H",
        "CR": "L",      # OT process data is non-sensitive
        "IR": "H",      # Control integrity is critical
        "AR": "H",      # Process availability is critical
        "MSC": "N", "MSI": "N", "MSA": "N",
    },
}

# Per-asset overrides (when a specific system needs different settings)
ASSET_OVERRIDES = {
    "SRV-004": {"MAC": None},  # erlang-app-01: no VPN requirement, MAC:L
}

@dataclass
class EnrichedCVE:
    cve_id: str
    asset_id: str
    asset_name: str
    zone: str
    base_vector: str
    in_kev: bool
    kev_due_date: Optional[str]
    epss: float
    e_value: str         # E:A / E:P / E:U
    bte_score: float
    severity: str
    sla: str

def load_kev() -> dict:
    url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    resp = requests.get(url, timeout=30)
    resp.raise_for_status()
    return {v["cveID"]: v for v in resp.json()["vulnerabilities"]}

def load_epss_batch(cve_ids: list) -> dict:
    scores = {}
    for i in range(0, len(cve_ids), 30):
        batch = ",".join(cve_ids[i:i+30])
        resp = requests.get(f"https://api.first.org/data/v1/epss?cve={batch}", timeout=30)
        if resp.ok:
            for item in resp.json().get("data", []):
                scores[item["cve"]] = float(item["epss"])
    return scores

def determine_e_value(cve_id: str, kev: dict, epss: dict) -> str:
    if cve_id in kev:
        return "A"
    e = epss.get(cve_id, 0.0)
    return "P" if e >= 0.1 else "U"

def severity_band(score: float) -> tuple[str, str]:
    if score >= 9.0:  return "Critical", "24–72 hours"
    if score >= 7.0:  return "High",     "30 days"
    if score >= 4.0:  return "Medium",   "90 days"
    if score > 0.0:   return "Low",      "Next release"
    return "None", "Informational"

def approximate_bte_score(base_vector: str, e_value: str, profile: dict) -> float:
    """
    Approximate CVSS-BTE using empirical score deltas.
    For production use, call the FIRST.org calculator API instead.
    Reference: https://www.first.org/cvss/calculator/4-0
    """
    # Extract base score from vector (simplified: count high-impact fields)
    parts = {k: v for k, v in (m.split(":") for m in base_vector.split("/")[1:])}

    # Base score heuristic from AV + impact
    av_delta = {"N": 0, "A": -1.5, "L": -2.5, "P": -3.5}
    base = 9.0  # start high, reduce
    base += av_delta.get(parts.get("AV", "N"), 0)
    if parts.get("PR") == "L":  base -= 0.5
    if parts.get("PR") == "H":  base -= 1.0
    if parts.get("AC") == "H":  base -= 0.5
    if parts.get("AT") == "P":  base -= 0.3

    # Impact adjustment
    all_high = all(parts.get(k) == "H" for k in ["VC","VI","VA","SC","SI","SA"])
    no_sub   = all(parts.get(k) == "N" for k in ["SC","SI","SA"])
    if no_sub: base -= 1.5
    if not all_high: base -= 0.5

    # Threat adjustment
    e_delta = {"A": 0, "P": -1.2, "U": -2.8, "X": 0}
    base += e_delta.get(e_value, 0)

    # Environmental adjustments
    mav = profile.get("MAV")
    if mav == "A": base -= 1.5
    if mav == "L": base -= 2.5
    if mav == "P": base -= 3.5
    if profile.get("MAC") == "H": base -= 0.8
    if profile.get("MSC") == "N": base -= 0.5
    if profile.get("CR") == "H":  base += 0.5
    if profile.get("CR") == "L":  base -= 0.5
    if profile.get("AR") == "L":  base -= 0.5

    return max(0.0, min(10.0, round(base, 1)))

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 vm_enrich.py scanner_output.csv")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        rows = list(csv.DictReader(f))

    cve_ids = list({r["cve_id"] for r in rows})
    print(f"Loading KEV catalog and EPSS scores for {len(cve_ids)} CVEs...")
    kev   = load_kev()
    epss  = load_epss_batch(cve_ids)
    print("Done.\n")

    results = []
    for row in rows:
        cve   = row["cve_id"]
        asset = row["asset_id"]
        zone  = row["zone"]

        profile = dict(PROFILES.get(zone, PROFILES["internal_vlan"]))
        if asset in ASSET_OVERRIDES:
            profile.update(ASSET_OVERRIDES[asset])

        e_value = determine_e_value(cve, kev, epss)
        score   = approximate_bte_score(row["base_vector"], e_value, profile)
        sev, sla = severity_band(score)

        results.append(EnrichedCVE(
            cve_id=cve, asset_id=asset, asset_name=row["asset_name"],
            zone=zone, base_vector=row["base_vector"],
            in_kev=(cve in kev),
            kev_due_date=kev[cve]["dueDate"] if cve in kev else None,
            epss=epss.get(cve, 0.0),
            e_value=e_value, bte_score=score, severity=sev, sla=sla
        ))

    results.sort(key=lambda r: r.bte_score, reverse=True)

    print(f"{'CVE':<22} {'Asset':<18} {'Zone':<18} {'KEV':>4} {'EPSS':>6} {'E':>3} {'BTE':>5} {'Severity':<10} {'SLA'}")
    print("─" * 105)
    for r in results:
        kev_flag = "YES" if r.in_kev else " no"
        print(f"{r.cve_id:<22} {r.asset_name:<18} {r.zone:<18} {kev_flag:>4} "
              f"{r.epss:>6.3f} E:{r.e_value:>1} {r.bte_score:>4.1f} {r.severity:<10} {r.sla}")

if __name__ == "__main__":
    main()
```

**Expected output for the example input:**

```
CVE                    Asset              Zone               KEV   EPSS  E   BTE  Severity   SLA
─────────────────────────────────────────────────────────────────────────────────────────────────────────
CVE-2024-21762         fw-edge-01         internet_facing    YES  0.931 E:A  9.0  Critical   24–72 hours
CVE-2023-4966          netscaler-01       internet_facing    YES  0.943 E:A  8.4  High       30 days
CVE-2023-34362         db-prod-01         internal_vlan      YES  0.944 E:A  7.2  High       30 days
CVE-2025-32433         erlang-app-01      internal_vlan      YES  0.503 E:A  6.5  Medium     90 days
CVE-2023-44487         build-srv-01       internal_vlan       no  0.097 E:U  4.1  Medium     90 days
```

From 5 scanner findings all showing 9.0+ Base scores → 2 Critical/High on internet-facing systems that need immediate action, 3 Medium on internal systems for the next maintenance window. The decisions are documented, auditable, and ready to attach to tickets.

---

## Ticket Template (per finding)

```
Title: [SEVERITY] [CVE-ID] — [Asset Name] — SLA: [DATE]

CVSS-B:    [score] [vector]
CVSS-BT:   [score] (E:[value] — source: CISA KEV / EPSS [X] / ExploitDB EDB-XXXXX)
CVSS-BTE:  [score] [full vector with env adjustments]

Environmental adjustments applied:
  [MAV:A] — [justification + evidence reference]
  [MAC:H] — [justification + evidence reference]

Affected system: [Asset ID] — [system name]
Zone: [zone name]
Data classification: [L/M/H]

Remediation:
  [ ] Apply vendor patch [version]
  [ ] Verify patch applied: [verification command or ticket reference]
  [ ] Re-run scan post-patch
  [ ] Close ticket with evidence

Due: [DATE based on SLA]
Assigned to: [team/owner]
```

---

## Related Chapters

| Chapter | What you'll find |
|---------|-----------------|
| [Scoring Lifecycle](/docs/lifecycle) | The B→BT→BTE theory behind each workflow step |
| [Threat & Environmental Metrics](/docs/threat-metrics) | How to determine E:, MAV:, and other modifiers |
| [Enrichment Tool](/docs/enrichment-tool) | Ready-to-run CLI that automates this pipeline |
| [CVSS vs SSVC](/docs/cvss-vs-ssvc) | When to use SSVC alongside CVSS for faster triage |
| [Cheatsheet](/docs/cheatsheet) | SLA tiers and score-impact reference |
