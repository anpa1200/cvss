---
title: "The 8 Most Common CVSS Mistakes"
sidebar_position: 12
---

![](/img/cvss/1_MkFQre3jSuIhOxGQVBdsEQ.png)


## 17. The 8 Most Common CVSS Mistakes

### Mistake 1: Treating the Base Score as the Final Answer

The Base score is produced by a vendor who has never seen your environment. It reflects the worst-case scenario for their entire customer base. For any specific deployment, it is almost always an overestimate. Always enrich with Threat and Environmental metrics before prioritizing remediation.

**What it looks like:** Team sorts scanner output by Base score, assigns SLAs based on Critical/High/Medium bands from raw scanner, spends 90% of effort on low-risk vulnerabilities because their Base scores are high.

### Mistake 2: Never Setting E:U for CVEs Without Exploit Evidence

Leaving `E:X` (Not Defined) means CVSS assumes every CVE is actively exploited. Given that ~95% of CVEs have no known working exploit, this guarantees your prioritization is inverted. Setting `E:U` for no-exploit CVEs is not optimism — it is accuracy and it is required for CVSS to function as a tool rather than a scare generator.

**The fix:** Automate KEV + EPSS checks for all new CVEs. Default new CVEs without KEV or EPSS signal to `E:U`.

### Mistake 3: Applying the Same Environmental Profile to All Systems

An internet-facing web application and an air-gapped industrial controller have entirely different attack vectors, compensating controls, and data sensitivity. Applying identical Environmental metrics to both produces inaccurate scores for both systems. Define asset groups and apply distinct profiles per group.

### Mistake 4: Not Documenting Environmental Adjustments

If you lower a CVE from 9.8 to 4.2 using `MAV:A/MAC:H/MSC:N` but cannot produce evidence for each adjustment when an auditor asks, those adjustments provide no compliance value. Every Modified metric must cite a specific control, policy, network diagram, or asset classification document.

### Mistake 5: Confusing CVSS-BTE with Risk Score

CVSS-BTE measures severity adjusted for your environment. It is not a risk score. A CVSS-BTE 5.0 Medium vulnerability on a system controlling a nuclear cooling pump may represent existential organizational risk. CVSS informs prioritization within a risk framework — it is not the risk framework itself. Overlay CVSS-BTE with asset criticality, business impact, and regulatory consequence to produce risk decisions.

### Mistake 6: Static Environmental Metrics

Environmental metrics become stale the moment your environment changes. A system that was air-gapped (MAV:A justified) may have had a cloud management connector added three months later. The `MAV:A` you documented is now wrong, and your 4.5 Medium is actually an 8.9 High.

**The fix:** Tie Environmental metric review to change management. Any change to a system's network connections, access controls, or data classification should trigger a CVSS-BTE re-evaluation.

### Mistake 7: Using v3.x Vectors with v4.0 Tools (and Vice Versa)

CVSS v4.0 vectors are incompatible with v3.x parsers. The `S` (Scope) metric from v3.x does not exist in v4.0; the dual-system impact model (VC/VI/VA + SC/SI/SA) does not exist in v3.x. Tools that parse v3.1 vectors will misinterpret v4.0 vectors and produce incorrect scores. Verify scanner, SIEM, and ticketing system compatibility with CVSS v4.0.

**Check your tools:** As of early 2025, Tenable Nessus, Qualys VMDR, and Rapid7 InsightVM all publish CVSS v4.0 scores for new CVEs, but legacy integrations may still expose v3.1 scores by default. Check API output, not just UI display.

### Mistake 8: Treating CISA KEV as the Only Source of E:A

CISA KEV is the best publicly available source for `E:A` determination, but it has coverage gaps. CISA focuses on US federal agency exposure; some CVEs exploited extensively in other regions or sectors may not appear in KEV. Supplement with:
- Vendor advisories that explicitly state "under active exploitation"
- Commercial threat intelligence feeds (Mandiant, Recorded Future, Greynoise)
- CERT/CC, national CERT advisories (CERT-EU, BSI, ANSSI)
- Industry-specific ISACs (FS-ISAC for finance, H-ISAC for healthcare)

---

## 18. Interview Questions and Answers

For threat intelligence researcher and vulnerability management roles, these questions test practical CVSS competency beyond theoretical knowledge.

---

**Q1: "A CVE is published with CVSS Base score 9.8. Your scanner flags 400 systems as affected. What is your first step?"**

**A:** My first step is not to start patching. It is to enrich the score with Threat Metrics. I check the CISA KEV catalog (automated, takes seconds) and pull the EPSS score from FIRST.org. If the CVE is not in KEV and has EPSS below 0.1, the default assumption of active exploitation is almost certainly wrong. Setting `E:U` for this CVE can drop 9.8 to approximately 6.5 Medium. Then I check my asset inventory to identify which of the 400 systems are internet-facing versus internal. Internet-facing systems with any exploit evidence get immediate priority; internal systems behind compensating controls get scheduled into the next maintenance window. The goal is to go from "400 Critical" to "12 systems requiring emergency action, 388 requiring scheduled patching" — and to document every decision in the CVSS vector.

---

**Q2: "Explain the difference between E:A and E:P in terms of operational response."**

**A:** Both indicate exploitation capability exists, but they represent different operational realities.

`E:P (Proof of Concept)` means working exploit code is publicly available — on GitHub, ExploitDB, or in a framework like Metasploit — but it has not yet been confirmed as used by threat actors against real targets. This typically means: (1) automated mass exploitation has not started, (2) you likely have days to weeks before widespread opportunistic exploitation begins, (3) targeted exploitation by sophisticated actors is possible.

`E:A (Attacked)` means confirmed real-world exploitation, typically documented through CISA KEV, vendor advisories, or verified incident response reports. This means: (1) the attack is happening now, (2) any exposed system is a target, (3) response window is measured in hours, not days.

In score terms, `E:A` maintains the full Base score; `E:P` reduces it moderately. But operationally, `E:P` on an internet-facing system should be treated almost as urgently as `E:A` because the `E:A` determination may be only days away.

---

**Q3: "How does CVSS v4.0 handle a vulnerability in an Erlang/OTP SSH server that is only accessible from the corporate network?"**

**A:** The Base score (10.0 for CVE-2025-32433) assumes the worst-case deployment — internet-accessible. Since the system is behind corporate network controls, I apply `MAV:A` (Modified Attack Vector: Adjacent). This reflects that an attacker must be on the corporate network first. If access also requires VPN with MFA, I add `MAC:H`. If no working exploit exists and it is not in CISA KEV, I set `E:U`. With `E:U/MAV:A/MAC:H`, the score drops from 10.0 to approximately 5.9 Medium. This is the correct operational assessment: a dangerous vulnerability that is not an emergency for this specific deployment because the attacker's prerequisites are substantial.

---

**Q4: "What is EPSS and how does it complement CVSS?"**

**A:** EPSS (Exploit Prediction Scoring System) is a machine learning model maintained by FIRST.org that predicts the probability of a CVE being exploited in the wild within the next 30 days. Where CVSS measures severity (how bad if exploited), EPSS measures likelihood (how probable exploitation is). EPSS ranges from 0 to 1 (probability).

They are complementary because a vulnerability can be: (1) high severity + high EPSS = clear immediate priority; (2) high severity + low EPSS = schedule carefully; (3) low severity + high EPSS = watch carefully for campaigns targeting it; (4) low severity + low EPSS = lowest priority.

For Exploit Maturity determination, EPSS ≥ 0.1 suggests a POC or exploitation attempt likely exists — I use this as a trigger to verify against ExploitDB and Metasploit.

---

**Q5: "A vendor publishes CVSS v4.0 score 6.5 for a vulnerability in a medical device. Your hospital's security team wants to defer patching. Is the 6.5 score sufficient justification?"**

**A:** No. CVSS-B 6.5 is the vendor's generic assessment. For a medical device in a hospital, I need CVSS-BTE with healthcare-appropriate Security Requirements. I would set `CR:H/IR:H/AR:H` because patient data, clinical data integrity, and device availability are all critical in healthcare. Additionally, the Supplemental Safety metric `S:P` (Safety: Present) is relevant if the device is involved in patient treatment — a ventilator or infusion pump vulnerability can have physical safety implications regardless of the numeric CVSS score.

After applying the healthcare profile, the effective BTE score will likely be higher than 6.5, and `S:P` requires a safety impact assessment regardless of score. A hospital cannot defer patching a medical device solely because the Base score is Medium.

---

**Q6: "What changed from CVSS v3.1 to v4.0 that matters most operationally?"**

**A:** Three changes matter most operationally.

First, the dual-system impact model. v4.0 separates Vulnerable System (VC/VI/VA) from Subsequent System (SC/SI/SA) impact, replacing the vague Scope:Changed/Unchanged with explicit scores for both the immediate victim and downstream systems. This enables much more accurate scoring of vulnerabilities with lateral movement potential.

Second, the Attack Requirements (AT) metric separates attacker effort (AC) from deployment preconditions (AT). A race condition requires attacker effort regardless of deployment. A vulnerability requiring non-default configuration has a deployment precondition. These are different and should score differently.

Third, simplified Threat metrics. The v3.x Temporal group had three metrics (E, RL, RC) — Remediation Level and Report Confidence were typically left at defaults, making them meaningless. v4.0 has one Threat metric (Exploit Maturity) that actually gets used.

---

## Mistake Diagnosis Checklist

If your vulnerability management program shows any of these symptoms, look up the corresponding mistake:

| Symptom | Likely Mistake |
|---------|----------------|
| Team is always in emergency mode despite no recent incidents | Mistake 1 (Base score treated as final) |
| 400+ Criticals in backlog, all untouched for months | Mistake 2 (E:U never set) + Mistake 1 |
| "We applied the same risk reduction to all 800 systems" | Mistake 3 (same profile for all) |
| Auditor rejects your CVSS-BTE scores | Mistake 4 (no documentation) |
| "Our CVSS-BTE is 3.9 — we're fine" on a nuclear plant system | Mistake 5 (BTE ≠ risk score) |
| A system that was "Medium" last year is now breached | Mistake 6 (stale environmental metrics) |
| Scanner imports v4.0 vectors but shows wrong scores | Mistake 7 (v3 parser reading v4 vectors) |
| Missed an actively exploited CVE not listed in KEV | Mistake 8 (KEV as only source) |

---

## Related Chapters

| Chapter | What you'll find |
|---------|-----------------|
| [Introduction](/docs/introduction) | Why the Base score problem exists |
| [Scoring Lifecycle](/docs/lifecycle) | The correct B→BT→BTE workflow that prevents Mistakes 1–3 |
| [Threat & Environmental Metrics](/docs/threat-metrics) | How to correctly apply E:, MAV:, and documentation (Mistakes 2, 4, 6) |
| [Practical VM Workflow](/docs/vm-workflow) | The process that prevents Mistakes 1, 3, 6 |
| [Cheatsheet](/docs/cheatsheet) | Quick reference when you need to decide fast without making mistakes |
