---
title: "Quick Reference Cheatsheet"
sidebar_position: 13
---

![](/img/cvss/1_kxsiKTOJOevS1TrQ_rs1gg.png)
![](/img/cvss/1_lh8yzf7Ov-0DYt0INQnnxA.png)
![](/img/cvss/1_GHhF19IjqW-koABjMuvNRA.png)
![](/img/cvss/1_r9N4JxU0lxHj7dUqbw9Bog.png)


## 19. Quick Reference Cheatsheet

### CVSS v4.0 Base Metrics — Complete Reference

```
ATTACK VECTOR (AV):
  N = Network     — Remotely exploitable from internet
  A = Adjacent    — Same network segment / LAN required
  L = Local       — Local interactive shell access required
  P = Physical    — Physical device access required

ATTACK COMPLEXITY (AC):
  L = Low   — Repeatable without special conditions; script it
  H = High  — Requires active bypass of security mechanisms (ASLR, race condition)

ATTACK REQUIREMENTS (AT):  [NEW in v4.0 — replaces part of old AC]
  N = None    — No special deployment configuration needed
  P = Present — Non-default config must be present in deployment

PRIVILEGES REQUIRED (PR):
  N = None  — Unauthenticated / pre-auth
  L = Low   — Regular user account
  H = High  — Administrator / root / privileged service account

USER INTERACTION (UI):
  N = None    — Attacker acts alone, no victim participation
  P = Passive — Victim views/receives something (opens page, email preview)
  A = Active  — Victim explicitly performs an action (clicks link, runs file)

VULNERABLE SYSTEM (VC/VI/VA):  [Replaces C/I/A in v3.x]
  N = None    H = High    L = Low

SUBSEQUENT SYSTEM (SC/SI/SA):  [Replaces Scope Changed in v3.x]
  N = None    H = High    L = Low
```

### Exploit Maturity (E) — Decision Flowchart

```
Is CVE in CISA KEV?
  → YES: E:A (Attacked) ─────────────────────────────────────────┐
  → NO: ↓                                                        │
                                                                  │
Is EPSS ≥ 0.10?                                                   │
  → YES (0.1–0.5): Verify ExploitDB/Metasploit/GitHub → E:P     │
  → YES (≥ 0.5):  High exploitation probability → E:P minimum   │
  → NO:  ↓                                                       │
                                                                  │
Is there a public exploit? (ExploitDB, Metasploit, GitHub)        │
  → YES: E:P (Proof of Concept)                                  │
  → NO:  E:U (Unreported)                                        │
                                                                  └→ Maximum priority, patch immediately
```

### Environmental Metric Quick Decisions

```
"Is this system reachable from the internet?"
  YES → No AV change needed       NO → MAV:A (or L/P for more isolated)

"Does reaching this system require bypassing MFA/VPN/jump host?"
  YES → MAC:H                     NO → No AC change needed

"Does this system handle your most sensitive data?"
  NO → MVC:L (or N)              YES → No VC change, or set CR:H

"Can this system affect other systems if compromised?"
  NO → MSC:N/MSI:N/MSA:N        YES → No change, blast radius is real

"Is this a test/dev environment?"
  YES → CR:L/IR:L/AR:L           NO → Keep vendor defaults or raise CR/IR/AR
```

### Score Impact Reference (Approximate)

| Adjustment | Typical Score Impact |
|-----------|---------------------|
| `E:U` (vs default E:X) | −2.5 to −3.5 points |
| `E:P` (vs default E:X) | −1.0 to −1.5 points |
| `MAV:A` (vs AV:N) | −1.5 to −2.5 points |
| `MAC:H` (vs AC:L) | −0.5 to −1.5 points |
| `MSC:N/MSI:N/MSA:N` (vs SC:H/SI:H/SA:H) | −1.0 to −2.0 points |
| `CR:H/IR:H/AR:H` | +0.5 to +1.5 points |
| `CR:L/IR:L/AR:L` | −0.5 to −1.0 points |

*Note: CVSS v4.0 uses lookup tables, not formulas — these are empirical approximations.*

### Common Vector String Examples

```
# Worst case — all vendor defaults, no enrichment:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
→ 10.0 Critical

# Internet-facing, actively exploited (CISA KEV):
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:A
→ 10.0 Critical (E:A maintains maximum — patch immediately)

# Internet-facing, POC exists, not yet actively exploited:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P
→ ~8.4 High (7-day SLA)

# Internal (adjacent network), POC exists, MFA VPN required:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/MAV:A/MAC:H
→ ~7.4 High (30-day SLA)

# Internal, isolated (no subsequent system paths), no exploit evidence:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/MAV:A/MAC:H/MSC:N/MSI:N/MSA:N
→ ~4.5 Medium (90-day SLA)

# OT sensor, adjacent network, non-sensitive data, no subsequent paths:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:U/MAV:A/MAC:H/CR:L/MSC:N/MSI:N/MSA:N
→ ~3.9 Low (next maintenance window)
```

### SLA Tiers by CVSS-BTE Score

| CVSS-BTE | Severity | Recommended SLA | Example Trigger |
|----------|----------|----------------|----------------|
| 9.0–10.0 | Critical | 24–72 hours | KEV entry, internet-facing, unauthenticated RCE |
| 7.0–8.9 | High | 30 days | POC + internet-facing, or KEV + internal |
| 4.0–6.9 | Medium | 90 days | Internal, compensating controls, limited exploit |
| 0.1–3.9 | Low | Next release | Air-gapped, CR/IR/AR:L, no exploit evidence |
| 0.0 | None | Informational | Patch when convenient |

### Tools and Resources

```
SCORING & CALCULATION:
  FIRST.org v4.0 Calculator:   https://www.first.org/cvss/calculator/4-0
  NVD Calculator:              https://nvd.nist.gov/vuln-metrics/cvss/v4-calculator
  NVD API (vector retrieval):  https://services.nvd.nist.gov/rest/json/cves/2.0

SPECIFICATION & GUIDES:
  CVSS v4.0 Spec:              https://www.first.org/cvss/v4-0/
  Consumer Implementation Guide: https://www.first.org/cvss/v4.0/implementation-guide
  CVSS v4.0 User Guide:        https://www.first.org/cvss/user-guide

THREAT INTELLIGENCE:
  CISA KEV Catalog:            https://www.cisa.gov/known-exploited-vulnerabilities-catalog
  CISA KEV API (JSON):         https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
  EPSS API:                    https://api.first.org/data/v1/epss?cve=CVE-XXXX-XXXXX
  ExploitDB:                   https://www.exploit-db.com
  Metasploit:                  msfconsole -q -x "search cve:XXXX-XXXXX"

COMPLEMENTARY FRAMEWORKS:
  SSVC (CISA):                 https://www.cisa.gov/sites/default/files/publications/cisa-ssvc-guide.pdf
  CVSS vs SSVC Decision Guide: https://www.first.org/cvss/v4.0/implementation-guide (Section 4)
```

---

---

## Full Guide Navigation

| # | Chapter | Key Takeaway |
|---|---------|-------------|
| 1 | [Introduction](/docs/introduction) | Base scores are worst-case estimates — not your answer |
| 2 | [v3.1 vs v4.0](/docs/v3-vs-v4) | Scope:Changed → SC/SI/SA; new AT metric; cleaner temporal |
| 3 | [Vector String Anatomy](/docs/vector-string) | Every metric has a practical question — answer it honestly |
| 4 | [Scoring Lifecycle](/docs/lifecycle) | CVSS-B → CVSS-BT → CVSS-BTE — each layer adds precision |
| 5 | [Threat & Environmental Metrics](/docs/threat-metrics) | KEV + EPSS + environmental profile = actionable score |
| 6 | [Worked Examples](/docs/worked-examples) | Log4Shell, Erlang/OTP, CitrixBleed, MOVEit — real CVE traces |
| 7 | [Industry-Specific Scoring](/docs/industry-specific) | Healthcare, Finance, OT — different CIA priorities |
| 8 | [CVSS vs SSVC](/docs/cvss-vs-ssvc) | SSVC for triage, CVSS for documentation and compliance |
| 9 | [Practical VM Workflow](/docs/vm-workflow) | Scanner CSV → enriched ticket in 6 steps + Python script |
| 10 | [Enrichment Tool](/docs/enrichment-tool) | CLI that automates the full pipeline for any CVE list |
| 11 | [Regulatory Framework](/docs/regulatory) | 5-phase maturity model + audit evidence checklist |
| 12 | [Mistakes & Interview Q&A](/docs/mistakes) | 8 errors to avoid + 6 interview questions |
| 13 | [Cheatsheet](/docs/cheatsheet) | This page |

---

## Conclusion

CVSS v4.0 answers the question that vulnerability managers have been asking for years: *"Why is my scanner showing 500 Critical vulnerabilities when I clearly cannot patch all of them this week?"*

The answer is not that CVSS is broken. The answer is that CVSS Base scores were never intended to be your final answer. They are the starting point — a common language between a vendor who does not know your environment and a security team that does.

The three-layer model (CVSS-B → CVSS-BT → CVSS-BTE) gives your team the tools to translate a generic score into a deployment-specific one. Threat metrics (E + EPSS) eliminate the false urgency from the 95% of CVEs with no known exploit. Environmental metrics eliminate the false priority from scoring isolated systems as if they were internet-facing.

The real-world examples in this guide — Log4Shell, CitrixBleed, MOVEit, Erlang/OTP, firmware reports — illustrate both directions of this system. Sometimes (Log4Shell, CitrixBleed) the 10.0 score is correct, and environmental arguments are irrelevant: you patch immediately because active exploitation is confirmed and your exposure is real. Sometimes (internal OT sensor, air-gapped development system) a 9.8 Base score correctly becomes a 3.9 Low, not because the vulnerability is less dangerous, but because your deployment makes exploitation genuinely difficult and downstream impact genuinely limited.

**That is not gaming the system. That is using the system correctly.**

---

## Known Limitations of This Guide

| Area | Limitation |
|------|-----------|
| **CVSS v4.0 vectors** | Most worked-example vectors are analyst-computed using the FIRST.org calculator. NVD's CVSS v4.0 coverage is incomplete as of publication — many CVEs have only v3.1 NVD scores. Always verify vectors at [FIRST.org calculator](https://www.first.org/cvss/calculator/4-0). |
| **Enrichment tool scoring** | The tool uses heuristic point-delta approximations, not the official CVSS v4.0 lookup tables. Results are prioritization guidance, not authoritative CVSS-BTE scores. |
| **EPSS thresholds** | EPSS values used for triage filtering are illustrative. EPSS is a triage signal; only actual exploit evidence (KEV, ExploitDB, Metasploit) should set `E:P` or `E:A`. |
| **Score examples** | Score approximations (e.g., "~7.4 High") are heuristic estimates. Exact scores depend on the full CVSS v4.0 calculation — verify with the official calculator. |
| **KEV / EPSS data** | KEV and EPSS data changes daily. All references to KEV status, EPSS scores, and attribution are accurate as of March 2026 and will drift over time. |
| **Regulatory mapping** | CVSS is a severity scoring tool, not a regulatory framework. Regulatory requirements (PCI DSS, HIPAA, NIS2, etc.) must be evaluated against the actual regulatory text, not this guide. |
| **Not official FIRST.org documentation** | This guide is an independent practitioner resource. Official CVSS v4.0 documentation: [first.org/cvss/v4-0](https://www.first.org/cvss/v4-0/), [User Guide](https://www.first.org/cvss/user-guide), [Implementation Guide](https://www.first.org/cvss/v4.0/implementation-guide). |

---

*Author: Andrey Pautov*
*Published: March 2026*
*Tags: CVSS, Vulnerability Management, CVSSv4, Security, CTI, Risk Management, EPSS, Log4Shell, CitrixBleed*

---

### References

1. **CVSS v4.0 Specification** — FIRST.org: https://www.first.org/cvss/v4-0/
2. **CVSS v4.0 Consumer Implementation Guide** — FIRST.org: https://www.first.org/cvss/v4.0/implementation-guide
3. **CVSS v4.0 User Guide** — FIRST.org: https://www.first.org/cvss/user-guide
4. **EPSS (Exploit Prediction Scoring System)** — FIRST.org: https://www.first.org/epss/
5. **CISA Known Exploited Vulnerabilities Catalog** — CISA: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
6. **SSVC (Stakeholder-Specific Vulnerability Categorization)** — CISA: https://www.cisa.gov/ssvc
7. **NVD (National Vulnerability Database)** — NIST: https://nvd.nist.gov
8. **NVD API 2.0 Documentation**: https://nvd.nist.gov/developers/vulnerabilities
9. **CVE-2021-44228 (Log4Shell)** — Apache: https://logging.apache.org/log4j/2.x/security.html
10. **CVE-2023-4966 (CitrixBleed)** — Citrix: https://support.citrix.com/article/CTX579459
11. **CVE-2023-34362 (MOVEit SQLi)** — Progress: https://www.progress.com/security
12. **CVE-2024-21762 (FortiOS)** — Fortinet: https://www.fortiguard.com/psirt/FG-IR-24-015
13. **CVE-2025-32433 (Erlang/OTP SSH)** — Erlang security advisories: https://www.erlang.org/security
14. **"CVSS: A Scoring System or a Tool?"** — Oren Yulevitch, CVSS SIG presentation
15. **"Enhancing National Cyber Resilience: CVSS v4.0 as a Regulatory Framework"** — Rob Arnold, Acorn Pass / CVSS Associates (2025)
16. **Joint Advisory: Apache Log4j Vulnerability** — CISA, FBI, NSA (December 2021): https://www.cisa.gov/news-events/cybersecurity-advisories/aa21-356a
17. **CISA Advisory: Volt Typhoon** (CVE-2024-21762 context): https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-038a
