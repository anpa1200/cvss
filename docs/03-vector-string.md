---
title: "Anatomy of a CVSS v4.0 Vector String"
sidebar_position: 3
---

![](/img/cvss/1_90fOtR4kz1tjbBgJ5z-2rw.png)


## 3. Anatomy of a CVSS v4.0 Vector String

The vector string is the machine-readable representation of all CVSS metric choices. It is the authoritative record of a vulnerability's scoring.

### Full v4.0 Vector String Format

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H
```

Breaking it down:

```
CVSS:4.0          — version identifier (required prefix)

BASE METRICS (all 11 required — no omissions allowed):
  AV:N            — Attack Vector: Network (remotely exploitable)
  AC:L            — Attack Complexity: Low (straightforward)
  AT:N            — Attack Requirements: None (no preconditions)
  PR:N            — Privileges Required: None (unauthenticated)
  UI:N            — User Interaction: None (attacker acts alone)
  VC:H            — Vulnerable System Confidentiality: High (full disclosure)
  VI:H            — Vulnerable System Integrity: High (full modification)
  VA:H            — Vulnerable System Availability: High (full disruption)
  SC:H            — Subsequent System Confidentiality: High
  SI:H            — Subsequent System Integrity: High
  SA:H            — Subsequent System Availability: High

THREAT METRICS (optional — defaults to X which assumes A):
  E:A             — Exploit Maturity: Attacked (actively exploited)

ENVIRONMENTAL METRICS (optional — all default to X):
  CR:X / IR:X / AR:X  — Security Requirements (not defined = use vendor defaults)
  MAV:A           — Modified Attack Vector: Adjacent (overrides AV:N)
  MAC:H           — Modified Attack Complexity: High (compensating controls)
  MAT:X           — Modified Attack Requirements: Not Defined
  MPR:X           — Modified Privileges Required: Not Defined
  MUI:X           — Modified User Interaction: Not Defined
  MVC:X / MVI:X / MVA:X   — Modified Vulnerable System impact
  MSC:X / MSI:X / MSA:X   — Modified Subsequent System impact

SUPPLEMENTAL METRICS (optional — informational, no score effect):
  S:X             — Safety
  AU:Y            — Automatable: Yes
  R:X             — Recovery
  V:X             — Value Density
  RE:X            — Vulnerability Response Effort
  U:X             — Provider Urgency
```

### Compact Form — Only Non-Default Values

In practice, only include metrics that differ from "Not Defined" (X). A fully enriched vector for an isolated internal system with POC exploit:

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/MAV:A/MAC:H
```

The base metrics (all 11) are always required. Everything after that is optional and only included when set.

### Parsing the Vector Programmatically

```python
def parse_cvss_v4_vector(vector: str) -> dict:
    """Parse a CVSS v4.0 vector string into a dictionary."""
    if not vector.startswith("CVSS:4.0/"):
        raise ValueError("Not a CVSS v4.0 vector")

    parts = vector[9:].split("/")
    metrics = {}
    for part in parts:
        if ":" in part:
            key, value = part.split(":", 1)
            metrics[key] = value
    return metrics

# Example usage:
vector = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H/E:P/MAV:A"
parsed = parse_cvss_v4_vector(vector)
# {'AV': 'N', 'AC': 'L', 'AT': 'N', 'PR': 'N', 'UI': 'N',
#  'VC': 'H', 'VI': 'H', 'VA': 'H', 'SC': 'H', 'SI': 'H', 'SA': 'H',
#  'E': 'P', 'MAV': 'A'}

exploit_maturity = parsed.get("E", "X")  # X = Not Defined (defaults to A)
attack_vector = parsed.get("MAV", parsed.get("AV"))  # Modified overrides Base
```

### The Calculator

The FIRST.org calculator at `https://www.first.org/cvss/calculator/4-0` provides a visual interface. As you make selections, the vector string updates in real-time. Use the vector string as the authoritative record; use the calculator as the working interface.

---

## 4. The Three Metric Groups Explained

![](/img/cvss/1_DpPm8CoS6x5CsUHC_ADcdQ.png)
![](/img/cvss/1_ysB7U2l00IjRQCn4bobLrg.png)
![](/img/cvss/1_9qLA02caf-NTGxC19_5VrA.png)
![](/img/cvss/1_vw79R12dK72SrGCLz3mZtg.png)


### Group 1: Base Metrics (Set by Vendor)

Base metrics describe the intrinsic properties of the vulnerability itself, independent of time and environment.

**Exploitability Metrics — describe the attack path:**

| Metric | Values | Practical Question |
|--------|--------|-------------------|
| **Attack Vector (AV)** | N/A/L/P | Where does the attacker need to be? Network = internet; Adjacent = same subnet; Local = shell access; Physical = hands on device |
| **Attack Complexity (AC)** | L/H | Does the attacker need to actively circumvent security controls, win a race condition, or perform non-repeatable actions? |
| **Attack Requirements (AT)** | N/P | Does exploitability depend on non-standard configuration being present in the deployment? |
| **Privileges Required (PR)** | N/L/H | What level of access does the attacker need before attacking? None = pre-auth; Low = regular user; High = admin |
| **User Interaction (UI)** | N/P/A | None = attacker acts alone; Passive = user views something (opens a page, receives email); Active = user explicitly performs an action (clicks, approves, executes) |

**Impact Metrics — what happens after a successful exploit:**

| Metric | Values | What It Measures |
|--------|--------|-----------------|
| **VC / VI / VA** | N/L/H | CIA impact on the system directly exploited (the one with the vulnerable software) |
| **SC / SI / SA** | N/L/H | CIA impact on *other systems* that can be affected as a consequence — adjacent servers, downstream APIs, the whole network |

**Score Ranges (v4.0):**

| Score | Severity | General Response |
|-------|----------|-----------------|
| 0.0 | None | No action needed |
| 0.1–3.9 | Low | Next release cycle |
| 4.0–6.9 | Medium | 90-day SLA |
| 7.0–8.9 | High | 30-day SLA |
| 9.0–10.0 | Critical | 24–72 hours |

### Group 2: Threat Metrics (Consumer + Threat Intel)

Contains one metric: **Exploit Maturity (E)**.

**The most impactful single adjustment available.** Setting E:U for a CVE with no public exploit can drop a 10.0 Critical to a 6–7 Medium/High — moving it from a 3am emergency to a scheduled maintenance window.

**Primary sources for Exploit Maturity determination:**

| Source | Access | What It Tells You |
|--------|--------|------------------|
| **CISA KEV Catalog** | Free API | If listed: `E:A`. CISA only adds CVEs confirmed exploited in the wild. |
| **EPSS Score** | Free API (FIRST.org) | Probability (0–1) of exploitation within 30 days. EPSS ≥ 0.1 → verify for `E:P`; EPSS ≥ 0.5 → strong `E:P` signal |
| **Metasploit Framework** | Free | Module present = functional exploit exists → `E:P`; if exploit is marked "excellent" → `E:P` at minimum |
| **ExploitDB / searchsploit** | Free | Exploit code published → `E:P` |
| **GitHub public repos** | Free | CVE-XXXX-XXXXX repos with working code → `E:P` |
| **Vendor advisories** | Free | Often state "under active exploitation" → `E:A` |
| **Commercial TI** | Paid | Recorded Future, Mandiant, Greynoise — earliest warning of `E:A` |

### Group 3: Environmental Metrics (Consumer + Local Knowledge)

Two sub-groups that let you encode what your security team knows about the actual deployment.

**Security Requirements (CR/IR/AR)** — how important is CIA for this specific asset:

```
High-criticality production payment API:
  CR:H / IR:H / AR:H  →  scores INCREASE relative to Base
  (This system is more important to protect than the vendor assumed)

Development test server (no real data, not customer-facing):
  CR:L / IR:L / AR:L  →  scores DECREASE relative to Base
  (This system is less important than the vendor assumed)
```

**Modified Base Metrics (MAV, MAC, MAT, MPR, MUI, MVC, MVI, MVA, MSC, MSI, MSA)** — override specific Base values to reflect actual deployment conditions. When a Modified metric is set, it replaces the corresponding Base metric in the score calculation:

```
Vendor assumed: AV:N (any internet attacker)
Your reality:   MAV:A (system is behind a firewall, adjacent network only)
→ Score drops by ~1.5–2.5 points

Vendor assumed: AC:L (straightforward exploitation)
Your reality:   MAC:H (attacker must first bypass your MFA + VPN)
→ Score drops further
```

---

## Reading a Real CVE Vector at a Glance

Practice reading these three vectors — no calculator needed, just the metric tables above:

**CVE-2023-4966 (CitrixBleed) — NVD published vector:**

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N

Reading it:
  AV:N  — Remote, internet-accessible (NetScaler is a perimeter device)
  AC:L  — Trivial exploitation (send oversized HTTP GET, read buffer)
  AT:N  — Default Citrix install, no special config needed
  PR:N  — Unauthenticated (the whole point — session token theft pre-auth)
  UI:N  — Attacker acts alone
  VC:H  — Session tokens (in Vulnerable System memory) are fully read
  VI:N  — No write capability (read-only memory leak)
  VA:N  — Service remains running
  SC:H  — Session tokens → authenticated access to backend systems (subsequent systems)
  SI:N  — Attacker uses sessions but doesn't modify downstream data
  SA:N  — Downstream availability unaffected

Score: 9.4 Critical
The high score is driven by AV:N + PR:N + SC:H — internet access, no auth, lateral movement via stolen sessions.
```

**CVE-2025-32433 (Erlang/OTP SSH) — as published:**

```
CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H

All H's across both systems. This is the worst-case base vector (10.0).
Exploit is unauthenticated pre-auth RCE in the SSH daemon itself.
Any subsequent system accessible from the SSH server is at risk.

With environment:  E:U/MAV:A/MAC:H  →  ~5.9 Medium
(Corporate-only access, VPN required, no active exploit)
```

**A typical scanner finding — medium-severity web app vulnerability:**

```
CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N

Reading it:
  AT:P  — Requires a non-default application configuration (deployment precondition)
  PR:L  — Attacker needs a low-privilege account (authenticated)
  VC:L  — Partial data read (not full compromise)
  VI:L  — Limited write (not arbitrary code execution)
  SC:N/SI:N/SA:N — No lateral movement path

Score: ~5.3 Medium — accurate for a limited post-auth partial-access vuln.
With E:U (no exploit) this becomes ~3.1 Low — properly scheduled.
```

---

## Related Chapters

| Chapter | What you'll find |
|---------|-----------------|
| [v3.1 vs v4.0 Comparison](/docs/v3-vs-v4) | How to translate your existing v3.1 vectors |
| [Scoring Lifecycle](/docs/lifecycle) | Adding Threat and Environmental metrics to your vector |
| [Threat & Environmental Metrics](/docs/threat-metrics) | How to determine E:, MAV:, MAC: values |
| [Worked Examples](/docs/worked-examples) | Full annotated vectors for real CVEs |
| [Cheatsheet](/docs/cheatsheet) | All metric values on one page |
