---
title: "Industry-Specific Scoring"
sidebar_position: 7
---

![](/img/cvss/1_tm9OPB1s40rEvjNIP2ARiQ.png)


## 12. Industry-Specific Scoring: Healthcare, Finance, OT/ICS

Different industries have fundamentally different CIA priority models. This affects how Security Requirements (CR/IR/AR) should be set.

### Healthcare (HIPAA Environment)

In healthcare, **Confidentiality** is paramount — HIPAA civil penalties range from ~$137 to ~$68,928 per violation (inflation-adjusted tiers as of 2023), with annual caps per violation category up to $2M+. Patient data exposure is the primary risk.

```
Healthcare Security Requirements Profile:
  CR:H — Patient data confidentiality: extremely high (HIPAA, HITECH)
  IR:H — Clinical data integrity: critical (wrong data → clinical decisions)
  AR:H — System availability: high (clinical workflows depend on uptime)

Example: CVE on a hospital's Electronic Health Record (EHR) system:

Base: CVSS:4.0/AV:N/AC:H/AT:N/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N
Base Score: 5.3 Medium

With healthcare profile:
  /CR:H/IR:H/AR:H
BTE Score: ~7.1 High — urgent patching required

Same vulnerability on internal developer workstation:
  /CR:L/IR:L/AR:L/MAV:L
BTE Score: ~2.8 Low — next maintenance window
```

**Healthcare-specific supplemental metrics:**
- `S:P` (Safety: Present) — for vulnerabilities in infusion pumps, ventilators, monitoring systems
- `R:I` (Recovery: Irrecoverable) — for ransomware affecting PACS/clinical imaging

### Financial Services (PCI-DSS / SOX Environment)

In finance, **Integrity** is often more critical than Confidentiality — financial data manipulation can cause immediate monetary loss, while data disclosure may take weeks to monetize.

```
Financial Services Security Requirements Profile:
  CR:H — Customer financial data: high (regulatory, reputational)
  IR:H — Transaction integrity: CRITICAL (fraud, unauthorized transfers)
  AR:H — Trading/payment systems: critical (SLAs, regulatory requirements)

Key distinction from healthcare: IR:H often matters MORE than CR:H here.

Example: SQL injection in a payment processing portal:
Base: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:L/SC:N/SI:N/SA:N
Base Score: 8.9 High

With PCI environment profile for payment card data scope:
  /CR:H/IR:H/AR:H
BTE Score: ~9.4 Critical — treat as emergency

Same vulnerability on a market-data read-only display terminal:
  /CR:L/IR:L/AR:L/MAV:A
BTE Score: ~4.1 Medium
```

### OT/ICS (Industrial Control Systems)

In OT environments, **Availability and Safety** often supersede Confidentiality. Data breaches are bad; plant shutdowns and physical harm are catastrophic.

```
OT/ICS Security Requirements Profile:
  CR:L  — Process data is often not sensitive (flow rates, temperatures)
  IR:H  — Control data integrity is critical (wrong setpoint = equipment damage)
  AR:H  — Process availability is critical (plant shutdown = immediate loss)
  S:P   — Many OT vulnerabilities have physical safety implications

Critical distinction: In OT, patching is NOT always possible on short timelines.
A patch that requires a production system restart may be more disruptive than
the vulnerability itself.

CVSS-BTE for OT must account for:
  1. The actual network exposure (almost always MAV:A or MAV:L for OT)
  2. The patching cost (use Vulnerability Response Effort: RE:H for OT)
  3. The safety impact (Safety: S:P when applicable)

Example: CVE on a Siemens S7 PLC (SCADA context):
Base: CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:H/VA:H/SC:H/SI:H/SA:H
Base Score: 9.3 Critical

OT environmental adjustment:
  MAV:A  — PLC on isolated OT VLAN, air-gapped from corporate
  MAC:H  — Access requires physical OT network entry (secured facility)
  CR:L   — Process data is non-sensitive
  IR:H   — Control integrity critical
  AR:H   — Process availability critical
  /S:P   — Physical safety implications (supplemental, not scored)
  /RE:H  — Patching requires production window, vendor support (supplemental)

BTE Score: ~7.8 High
Action: Schedule for next maintenance window (may be months away)
Interim mitigation: Network segmentation controls (document in CVSS-BTE)
```

### Industry Scoring Profile Quick Reference

| Industry | CR | IR | AR | Primary Risk | Key Supplemental |
|----------|----|----|-----|-------------|-----------------|
| Healthcare | H | H | H | Patient data, HIPAA | S:P (medical devices) |
| Finance (PCI) | H | H | H | Transaction fraud | AU:Y (automatable attacks) |
| Finance (trading) | M | H | H | Market manipulation | AR:H for trading systems |
| OT/ICS | L | H | H | Physical safety, uptime | S:P, RE:H, R:I |
| Education | M | M | L | Student PII | — |
| E-commerce | H | H | H | Customer data, availability | AU:Y, V:C |
| Government (classified) | H | H | M | Data sovereignty | — |

---

## Building an Asset Profile for Your Environment

An industry profile is a named set of default metric overrides you apply to all systems in a given segment. Here is how to build one:

```python
# Asset profile definition — Financial Services (PCI cardholder data environment)
PROFILE_PCI_CDE = {
    "name": "pci_payment",
    "description": "PCI cardholder data environment — payment processing scope",
    "security_requirements": {
        "CR": "H",  # Customer financial data — high confidentiality requirement
        "IR": "H",  # Transaction integrity — critical (fraud if modified)
        "AR": "H",  # Payment system availability — contractual SLA obligations
    },
    "default_modifiers": {
        # If system is in CDE but behind WAF + MFA:
        "MAC": "H",
        # Subsequent system impact reduced if CDE is properly segmented:
        "MSC": "L",
        "MSI": "L",
    },
    "notes": "PCI DSS v4.0 Requirement 6.3 — all vulnerabilities affecting CDE must be tracked with risk ratings"
}

# Asset profile — OT/ICS production control systems
PROFILE_OT_PRODUCTION = {
    "name": "isolated_ot",
    "description": "Production OT/ICS — air-gapped from corporate",
    "security_requirements": {
        "CR": "L",  # Process data (flow rates, temperatures) is non-sensitive
        "IR": "H",  # Control integrity — wrong setpoint = equipment damage
        "AR": "H",  # Process availability — plant shutdown = immediate financial/safety impact
    },
    "default_modifiers": {
        "MAV": "A",  # OT VLAN, not internet-accessible
        "MAC": "H",  # Physical OT network required (secured facility)
        "MSC": "N",  # OT is segmented from corporate
        "MSI": "N",
        "MSA": "N",
    },
    "supplemental": {
        "S": "P",   # Safety: Present — control systems have physical impact potential
        "RE": "H",  # Patching requires production window + vendor support
    }
}
```

Use these profiles consistently across all CVEs affecting systems in each segment. When a system changes segment (e.g., an OT system gets a cloud management connector), update its profile assignment and re-evaluate all open CVEs.

See [Chapter 5 — Threat & Environmental Metrics](/docs/threat-metrics) for the full environmental adjustment decision process, and [Chapter 9 — VM Workflow](/docs/vm-workflow) for how profiles fit into the end-to-end pipeline.

---

## Related Chapters

| Chapter | What you'll find |
|---------|-----------------|
| [Threat & Environmental Metrics](/docs/threat-metrics) | How to set CR/IR/AR and Modified Base metrics with evidence |
| [Worked Examples](/docs/worked-examples) | Real CVEs scored in different deployment contexts |
| [Regulatory Evidence](/docs/regulatory) | How industry profiles map to HIPAA, PCI DSS, NERC CIP |
| [Practical VM Workflow](/docs/vm-workflow) | Using profiles in your end-to-end VM process |
