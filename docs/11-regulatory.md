---
title: "CVSS as Regulatory Framework"
sidebar_position: 11
---

![](/img/cvss/1_Phjw6InMQW2DgUEy8TSPrg.png)
![](/img/cvss/1_VS6SyXxBQgVBvVK7Tgdqzw.png)


## 15. CVSS as Regulatory Framework: The 5-Phase Maturity Model

The CVSS v4.0 lifecycle (CVSS-B → CVSS-BT → CVSS-BTE) maps directly to a regulatory maturity roadmap. This framework was formalized by Rob Arnold (Acorn Pass / CVSS Associates) in the whitepaper "Enhancing National Cyber Resilience: CVSS v4.0 as a Regulatory Framework" (2025).

### The 5 Phases + SCRM Track

| Phase | Name | CVSS Level | Timeframe | Objective |
|-------|------|-----------|-----------|-----------|
| **1** | Socialization | — | Pre-program | Organization is aware of CVSS; training in place |
| **2** | Self-Evaluation | CVSS-B | Months 1–12 | Remediate all Critical (Base ≥ 9.0) |
| **3** | External Validation | CVSS-B | Months 12–24 | Remediate all High (Base ≥ 7.0); audit verifies |
| **4** | Threat Awareness | CVSS-BT | Months 24–36 | Integrate threat intel; remediate by CVSS-BT priority |
| **5** | Environmental Context | CVSS-BTE | Months 36+ | Full BTE scoring with auditable documentation |
| **SCRM** | Supply Chain | CVSS-BTE | Concurrent from Phase 2 | Embed CVSS requirements in supplier contracts |

### The Gaming Prevention Problem

At Phase 5, CVSS-BTE scores can be lower than CVSS-B. This creates an incentive: organizations might manipulate Environmental metrics to claim compliance while leaving real vulnerabilities unaddressed.

The regulatory countermeasure:

**Auditors verify environmental claims against evidence:**
- `MAV:A` claimed → auditor validates against firewall rules, network diagrams, penetration test results
- `MAC:H` claimed → auditor validates against policy documents, VPN logs, MFA enrollment records
- `MSC:N` claimed → auditor validates against network topology and egress controls

**Auditors verify response to changing E metrics:**
- If `E:U` was set last quarter and the CVE just entered CISA KEV, did the organization detect this change?
- Did they update the E metric from U to A?
- Did they escalate the remediation priority accordingly?

The principle from the FIRST.org guide: **CVSS-BTE scores are defensible precisely because they are documented and auditable. An organization cannot reduce a score without leaving an evidence trail that auditors can verify.**

### Regulatory Applications by Framework

| Regulatory Framework | CVSS Requirement | How CVSS v4.0 Helps |
|---------------------|------------------|---------------------|
| **PCI DSS v4.0** | Risk-based patching; scan + remediate findings | CVSS-BTE for cardholder data environment scope |
| **NIST RMF (SP 800-53)** | Vulnerability scanning + prioritized remediation | CVSS-B as baseline; BTE for System Security Plan |
| **NIS2 (EU)** | Incident reporting + vulnerability management | CVSS-BTE documents risk decisions for supervisory authority |
| **HIPAA** | Risk analysis + risk management | CVSS-BTE with CR:H for PHI-handling systems |
| **NERC CIP (OT/ICS)** | Vulnerability management for bulk electric systems | CVSS-BTE with S:P supplemental for safety systems |

### Supply Chain CVSS (SCRM Track)

Organizations at Phase 5 embed CVSS requirements in supplier contracts:

```
Example supplier contract language:

1. The Supplier shall disclose CVSS v4.0 Base vectors for all
   vulnerabilities in delivered software within 5 business days
   of CVE publication.

2. The Supplier shall provide software updates or documented
   mitigations sufficient to enable the Buyer to achieve a
   CVSS-BTE score of ≤ Medium (6.9) for all High or Critical
   Base vulnerabilities.

3. The Supplier shall include CVSS v4.0 vectors for all known
   vulnerabilities in all Software Bills of Materials (SBOMs).

4. The Supplier shall notify the Buyer within 24 hours if any
   vulnerability in delivered software enters the CISA KEV catalog.
```

---

## 16. Supplemental Metrics: The Overlooked Context Layer

Supplemental metrics do not change the CVSS score. They add human-readable operational context that the numeric score cannot capture. Think of them as structured analyst notes attached to the vulnerability record.

| Metric | Symbol | Values | What It Communicates |
|--------|--------|--------|---------------------|
| **Safety** | S | N/P | Physical safety impact possible? Relevant for OT, medical devices, vehicles |
| **Automatable** | AU | N/Y | Can exploitation be fully automated (worm-like mass exploitation)? |
| **Recovery** | R | A/U/I | Automatic / User-assisted / Irrecoverable |
| **Value Density** | V | D/C | Diffuse (one system affected) / Concentrated (many systems/users affected) |
| **Vuln Response Effort** | RE | L/M/H | Effort required to patch/mitigate: Low (auto-update), Medium (manual), High (complex) |
| **Provider Urgency** | U | Clear/Green/Amber/Red | Vendor's urgency assessment |

### AU:Y — Automatable Exploitation

`AU:Y` means an attacker can script the exploit to run against thousands of targets without human intervention. This is the worm-capability indicator.

**Why it matters beyond the CVSS score:**

Log4Shell (`AU:Y`) was being exploited by automated scanners within 24 hours of POC release. A CVSS-BTE score of 7.4 High with `AU:Y` requires faster response than an 8.0 High with `AU:N` that requires a custom, targeted attack chain.

Real examples with `AU:Y`:
- Log4Shell (CVE-2021-44228) — `AU:Y`: log any HTTP request, mass exploitation immediate
- MOVEit Transfer (CVE-2023-34362) — `AU:Y`: Cl0p ran fully automated campaign
- HTTP/2 Rapid Reset (CVE-2023-44487) — `AU:Y`: DDoS amplification automated
- Heartbleed (CVE-2014-0160) — `AU:Y`: automated scanners ran within hours

### S:P — Safety Impact in OT/Medical

`S:P (Safety: Present)` flags that exploitation could result in physical harm to people or property. This metric is essential for:
- Industrial control systems (chemical plants, power grids, water treatment)
- Medical devices (infusion pumps, ventilators, pacemakers)
- Automotive systems (ECU vulnerabilities)

```
Example: Vulnerability in a pharmaceutical manufacturing control system
CVSS-BTE score: 5.9 Medium (due to MAV:A environmental adjustment)
Supplemental: /S:P (Safety: Present)

Without S:P context, this looks like a 90-day scheduled patch.
With S:P context, the medical device safety team must evaluate whether
the vulnerability could cause incorrect dosing, batch contamination,
or equipment failure — potentially regardless of the numeric CVSS score.
```

### R:I — Irrecoverable Systems

`R:I (Recovery: Irrecoverable)` means successful exploitation causes permanent damage that cannot be remediated without hardware replacement, data restoration from backup, or destructive re-imaging.

**Relevant scenarios:**
- Ransomware affecting backup systems (R:I — cannot restore without the backups)
- Firmware corruption on embedded devices (R:I — requires physical device replacement)
- Cryptographic key material theft (R:I — compromised keys cannot be "un-stolen")
- Industrial control setpoint modification causing equipment damage (R:I — physical damage)

---

## Mapping Your Program to the 5-Phase Model

Use this self-assessment to determine your current phase and the next milestone:

```
Phase 1 — Socialization:
  □ Security team has received CVSS v4.0 training
  □ Leadership is aware that Base scores ≠ risk
  □ A vulnerability management policy exists (even if informal)

Phase 2 — Self-Evaluation:
  □ Vulnerability scanner deployed, producing CVE lists with Base scores
  □ All Critical (CVSS-B ≥ 9.0) tracked and remediated within SLA
  □ CVE inventory maintained (even in a spreadsheet)
  Milestone: Zero unaddressed Criticals older than 90 days

Phase 3 — External Validation:
  □ All High (CVSS-B ≥ 7.0) tracked with SLA
  □ Process verified by external auditor or internal audit team
  □ Documented exception process for vulnerabilities that cannot be patched
  Milestone: Third-party confirmation that Critical and High backlogs are managed

Phase 4 — Threat Awareness:
  □ CISA KEV API checked for all new CVEs (automated)
  □ EPSS scores pulled and used to set E: metric
  □ CVSS-BT scores used for prioritization (not just CVSS-B)
  □ Threat intel source documented (KEV, EPSS, ExploitDB, commercial TI)
  Milestone: Remediation prioritization is driven by CVSS-BT, not CVSS-B alone

Phase 5 — Environmental Context:
  □ Asset inventory with network zone classification exists
  □ Environmental metrics (MAV/MAC/CR/IR/AR) applied per asset group
  □ Each adjustment backed by documented evidence (firewall rules, policy IDs)
  □ Environmental reviews tied to change management process
  □ CVSS-BTE scores used for SLA assignment and audit reporting
  Milestone: Full audit trail from CVE publication to documented remediation decision

SCRM Track (parallel):
  □ Supplier contracts require CVSS v4.0 vectors in vulnerability disclosures
  □ SBOM requirements reference CVSS scoring
  □ Supplier notification required within 24h of KEV entry
```

---

## Audit Evidence Checklist (Phase 5)

When a regulatory auditor asks to verify your CVSS-BTE scores, they will want:

| Claim | Evidence Required |
|-------|-----------------|
| `MAV:A` — system is not internet-facing | Firewall rule ID + last verified date + network diagram reference |
| `MAC:H` — compensating access controls | VPN policy document + MFA enrollment logs + change ticket ID |
| `MSC:N` — no subsequent system paths | Network egress rules + architecture diagram showing no lateral paths |
| `CR:L` — low confidentiality requirement | Asset classification document + data inventory showing no PII/PHI |
| `E:U` — no exploit evidence | KEV check timestamp + EPSS score + ExploitDB search result (negative) |
| `E:A` → score escalation | KEV entry date + updated CVSS-BT score + new SLA assignment date |

---

## Related Chapters

| Chapter | What you'll find |
|---------|-----------------|
| [Industry-Specific Scoring](/docs/industry-specific) | Profiles for healthcare, finance, OT/ICS |
| [Threat & Environmental Metrics](/docs/threat-metrics) | How each environmental adjustment is made and documented |
| [Practical VM Workflow](/docs/vm-workflow) | The operational process that generates regulatory evidence |
| [Common Mistakes](/docs/mistakes) | What breaks compliance — especially Mistake 4 (undocumented adjustments) |
