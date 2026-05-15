---
title: "Threat & Environmental Metrics"
sidebar_position: 5
---

![](/img/cvss/1_ojvuO08eeq7sHLCxfQT4DA.png)


## 7. Environmental Metrics: Scoring for Your Environment

### The Core Principle

A vulnerability vendor scores a system as if it is:
- Directly accessible from the internet (AV:N)
- Running with no compensating controls
- Processing your most sensitive data
- Able to reach any system in your network

Your security team knows this is almost never true for any given system. Environmental metrics encode that knowledge as documented, auditable adjustments.

### Practical Environmental Metric Decisions

**Decision 1: Network Exposure**

```
Vendor scored: AV:N (reachable from anywhere on the internet)

Scenario A — Internet-facing server:
  No change needed. AV:N reflects reality.

Scenario B — Internal VLAN, firewall-controlled:
  MAV:A (Modified Attack Vector: Adjacent)
  Documentation: "System resides on VLAN 10, firewall rule FW-2041 blocks
  all inbound access from WAN. Last verified: [date], Change ticket: [ID]"
  Score effect: -1.5 to -2.5 points typically

Scenario C — Jump host required, no direct network path:
  MAV:L (Modified Attack Vector: Local)
  Documentation: "SSH access only via jump-host JUMP-01, no direct routing
  from any external zone. Network diagram: NDG-004"
  Score effect: more significant reduction
```

**Decision 2: Compensating Security Controls**

```
Vendor scored: AC:L (low complexity — straightforward exploitation)

Your reality: system access requires:
  (1) VPN authentication with hardware MFA token
  (2) Jump host with session recording
  (3) IP allowlisting to specific bastion hosts

→ MAC:H (Modified Attack Complexity: High)
  "Exploiting this in our environment requires bypassing enterprise VPN
  (MFA-protected), jump host IP filtering, and session monitoring.
  Policy reference: NET-POLICY-022"
```

**Decision 3: Data Sensitivity**

```
Vendor scored: VC:H (high confidentiality impact — assumes worst-case data)

Scenario A — System processes PII, financial, or health data:
  No change. VC:H is appropriate.
  Consider setting CR:H to amplify the score.

Scenario B — System is a build server, processes only source code and
artifact hashes, no customer data:
  MVC:L (Modified Vulnerable System Confidentiality: Low)
  Documentation: "System data classification: Internal/Technical per
  DLP-2023. No PII, financial, or regulated data categories."
```

**Decision 4: Blast Radius (Subsequent System Impact)**

```
Vendor scored: SC:H/SI:H/SA:H (can affect downstream systems)

Your reality: this system has no outbound connections except to its
own read-only database. No service accounts with lateral movement
potential. Network segmentation enforced by firewall.

MSC:N / MSI:N / MSA:N
Documentation: "System [ID] network connections: inbound from [A,B],
outbound to [DB-READONLY] only. Firewall egress rules [FW-2201 through
FW-2203] block all other outbound. Network architecture diagram NDG-007."
```

**Decision 5: Security Requirements — Adjusting for Asset Criticality**

Security Requirements (CR/IR/AR) work differently from Modified Base metrics. Instead of overriding vendor assumptions, they adjust the score up or down based on how important CIA is for this asset in your organization:

```
High-criticality asset (production customer database):
  CR:H / IR:H / AR:H
  → Score increases above the environmental-adjusted Base
  → The same vulnerability is MORE severe here than the vendor assumed

Low-criticality asset (developer test environment):
  CR:L / IR:L / AR:L
  → Score decreases below the environmental-adjusted Base
  → The same vulnerability is LESS severe here

Same vulnerability, CVE-2023-44487 (HTTP/2 Rapid Reset):
  On production CDN edge:  BTE = 8.9 High (AR:H — availability critical)
  On dev test instance:    BTE = 3.2 Low  (AR:L — availability optional)
```

### Environmental Adjustment Documentation Template

```
CVE: [CVE-XXXX-XXXXX]
Asset: [system name / ID]
Asset Classification: [Confidentiality: L/M/H] [Integrity: L/M/H] [Availability: L/M/H]

Base Vector (from NVD):
  [CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H]
  Base Score: [10.0 Critical]

Threat Enrichment:
  E: [A/P/U] — Source: [CISA KEV / ExploitDB EDB-XXXXX / No evidence]
  EPSS: [score] — Percentile: [XX]th

Environmental Adjustments:
  [MAV:A] — [System on internal VLAN, not internet-accessible. Evidence: FW-RULE-XXXX]
  [MAC:H] — [Access requires MFA VPN. Evidence: POLICY-NET-022]
  [MSC:N/MSI:N/MSA:N] — [Isolated system, no lateral movement paths. Evidence: NDG-007]

BTE Vector:
  [CVSS:4.0/.../E:P/MAV:A/MAC:H/MSC:N/MSI:N/MSA:N]
  BTE Score: [5.9 Medium]

Approved by: [Name, Title]
Date: [YYYY-MM-DD]
Next Review: [YYYY-MM-DD or "on next change event"]
Change Ticket: [TICKET-ID]
```

---

## 8. Environmental Metrics in Practice: Additional Context

The environmental documentation template above captures the full audit trail required for regulatory compliance. Each Modified metric entry requires:

1. **The metric value** (e.g., `MAV:A`)
2. **A specific, verifiable justification** (e.g., "System resides on VLAN 10")
3. **Evidence reference** (firewall rule ID, policy document, network diagram)
4. **A dated review** tied to change management

**Tying Environmental reviews to change management** is the operational key. Any of the following events should trigger a CVSS-BTE re-evaluation for all CVEs currently scored against the affected asset:

- Network topology change (new firewall rule, VLAN reassignment)
- New service account or API credential added
- Data classification change (system begins processing PII)
- Access control change (MFA removed, VPN requirement lifted)
- New network path created (cloud connector, new VPN tunnel)

Without this tie-in, Environmental metrics silently become stale — and a previously documented `MAV:A` may no longer reflect reality.
