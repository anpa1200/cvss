---
title: "CVSS vs SSVC: When to Use Which"
sidebar_position: 8
---

![](/img/cvss/1_k_QWh3vzpMP0Ezy-dXLQXg.png)


## 13. CVSS vs SSVC: When to Use Which

**SSVC (Stakeholder-Specific Vulnerability Categorization)** is CISA's decision-tree framework for vulnerability prioritization. It is an alternative (not replacement) to CVSS that uses a different model.

### How SSVC Works

SSVC asks four questions in sequence, each with structured answers:

```
1. Exploitation Status
   → None / POC / Active
   (same concept as CVSS E metric, but drives the whole tree)

2. Automatable
   → Yes / No
   (Can the vulnerability be exploited at scale without human interaction?)

3. Technical Impact
   → Partial / Total
   (Does exploitation give total system control or partial?)

4. Mission and Well-being Impact
   → Minimal / Material / Irreversible
   (What is the downstream organizational and human impact?)

Outputs (instead of a number): Track / Attend / Act / Immediate
```

### CVSS vs SSVC Comparison

| Dimension | CVSS v4.0 | SSVC |
|-----------|-----------|------|
| **Output** | Numeric score (0–10) + severity band | Decision recommendation (Act/Attend/Track) |
| **Adjustability** | Highly granular — 20+ metrics | Structured decision tree — 4 questions |
| **Threat intel integration** | E metric (A/P/U) | Exploitation status (None/POC/Active) |
| **Environment modeling** | Modified Base + Security Requirements | Mission & Well-being Impact |
| **Regulatory acceptance** | NIST SP 800-51, PCI DSS, HIPAA | CISA-endorsed, US government frameworks |
| **Automation potential** | High (vector strings, APIs) | Moderate (decision tree is less numeric) |
| **Learning curve** | High (many metrics) | Lower (structured questions) |

### When to Use Each

**Use CVSS when:**
- Regulatory compliance requires it (PCI DSS, HIPAA, NIS2, NIST RMF)
- You need a numeric score for SLA tracking and audit trails
- You are integrating with SIEM, ticketing systems, or scanners that consume CVSS vectors
- You need fine-grained documentation of WHY a vulnerability is de-prioritized
- Supply chain transparency (SBOM, vendor contracts)

**Use SSVC when:**
- You need rapid triage without deep metric analysis
- Your team is small and lacks time for full CVSS-BTE enrichment
- You are in a government/defense context where CISA guidance is authoritative
- You want a clear output for non-technical stakeholders ("Act on this now" vs "Track it")

**Use both when:**
- CVSS-BTE for documentation, compliance, and audit
- SSVC for team-level triage and prioritization decisions
- Both frameworks reaching the same conclusion = high confidence

**Example comparison — CVE-2023-4966 (CitrixBleed):**

```
CVSS-BTE (internet-facing NetScaler, E:A):
  Score: 9.4 Critical
  SLA: Patch within 24 hours
  Documentation: vector string with E:A, justification for each metric

SSVC:
  Exploitation: Active
  Automatable: Yes (scanning was automated, documented)
  Technical Impact: Total (full session token theft)
  Mission/Well-being: Irreversible (customer data exposure, regulatory)
  → Decision: Immediate

Both outputs agree: drop everything, patch now.
```

---

## Practical Decision: Which Should I Use Today?

```
If your team:
  ✓ Has a compliance requirement (PCI, HIPAA, NIS2, NIST RMF)     → CVSS (mandatory)
  ✓ Needs numeric SLAs for ticketing/reporting                     → CVSS
  ✓ Has scanner + SIEM integration consuming CVSS vectors          → CVSS
  ✓ Is small (1–3 people) and needs fast daily triage              → SSVC (quicker)
  ✓ Reports to non-technical leadership ("act / attend / track")   → SSVC

If you use SSVC for daily triage and CVSS-BTE for documentation:
  Morning standup: SSVC decision tree → "Act on these 3, attend to these 7"
  Ticket creation: CVSS-BTE vector + score → audit-ready record of the decision
  Compliance audit: CVSS-BTE documentation satisfies regulatory reviewers
```

**Running SSVC in parallel with CVSS — a quick Python implementation:**

```python
def ssvc_decision(exploitation: str, automatable: bool,
                  technical_impact: str, mission_impact: str) -> str:
    """
    Simplified SSVC decision tree.
    Returns: 'Immediate' | 'Act' | 'Attend' | 'Track'
    """
    if exploitation == "active":
        if automatable and technical_impact == "total":
            return "Immediate"
        elif mission_impact == "irreversible":
            return "Immediate"
        else:
            return "Act"

    if exploitation == "poc":
        if automatable and technical_impact == "total":
            return "Act"
        elif mission_impact in ("irreversible", "material"):
            return "Act"
        else:
            return "Attend"

    # exploitation == "none"
    if technical_impact == "total" and mission_impact == "irreversible":
        return "Attend"
    return "Track"

# Example usage alongside CVSS-BTE:
result = ssvc_decision(
    exploitation="active",   # E:A in CVSS
    automatable=True,        # AU:Y in CVSS supplemental
    technical_impact="total",
    mission_impact="irreversible"
)
print(f"SSVC: {result}")   # → Immediate
# CVSS-BTE: 10.0 Critical  → Both agree: patch now
```

---

## Related Chapters

| Chapter | What you'll find |
|---------|-----------------|
| [Introduction](/docs/introduction) | Why CVSS Base score alone fails and what the alternatives are |
| [Threat & Environmental Metrics](/docs/threat-metrics) | The E: metric that drives both CVSS and SSVC exploitation status |
| [Practical VM Workflow](/docs/vm-workflow) | Where to slot SSVC vs CVSS in your daily process |
| [Regulatory Framework](/docs/regulatory) | When CVSS is legally required vs where SSVC is government-endorsed |
