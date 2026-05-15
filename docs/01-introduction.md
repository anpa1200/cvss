---
title: "Introduction: CVSS Is a Tool, Not a Score"
sidebar_position: 1
---

![](/img/cvss/1_B9qDekxyxZ4e_C-SbSYhgw.png)


# CVSS v4.0: The Practical Field Guide for Vulnerability Management

*From a number that nobody trusts to a tool that changes how you work*

---

## Table of Contents

0. [Introduction: CVSS Is a Tool, Not a Score](#introduction)
1. [What Changed in v4.0 — and Why It Matters](#what-changed)
2. [v3.1 vs v4.0: Side-by-Side with Real CVEs](#v3-vs-v4)
3. [Anatomy of a CVSS v4.0 Vector String](#vector-string)
4. [The Three Metric Groups Explained](#metric-groups)
5. [The CVSS Lifecycle: CVSS-B → CVSS-BT → CVSS-BTE](#lifecycle)
6. [Threat Metrics in Practice: KEV, EPSS, and Exploit Feeds](#threat-metrics)
7. [Environmental Metrics: Scoring for Your Environment](#environmental-metrics)
8. [Worked Example 1: CVE-2021-44228 Log4Shell — Score Evolution Over 72 Hours](#log4shell)
9. [Worked Example 2: CVE-2025-32433 Erlang/OTP — From 10.0 to 5.9](#worked-example-cve)
10. [Worked Example 3: Firmware Report — 18 Criticals Become Medium](#worked-example-firmware)
11. [Worked Example 4: CitrixBleed, MOVEit, FortiOS — Three Real-World Cases](#real-world-cases)
12. [Industry-Specific Scoring: Healthcare, Finance, OT/ICS](#industry-specific)
13. [CVSS vs SSVC: When to Use Which](#ssvc)
14. [The Practical VM Workflow: From Scanner Output to Prioritized Action](#vm-workflow)
15. [CVSS as Regulatory Framework: The 5-Phase Maturity Model](#regulatory)
16. [Supplemental Metrics: The Overlooked Context Layer](#supplemental)
17. [The 8 Most Common CVSS Mistakes](#mistakes)
18. [Interview Questions and Answers](#interview-qa)
19. [Quick Reference Cheatsheet](#cheatsheet)

---

## Introduction: CVSS Is a Tool, Not a Score

Every security team has a vulnerability scanner. Every scanner produces a list with numbers. And almost every team treats those numbers as the truth — sorting by score descending, starting at 9.8, working down.

This is wrong. And CVSS v4.0 was designed to fix it.

The CVSS SIG (Special Interest Group), which maintains the standard at FIRST.org, makes this point explicitly in the Consumer Implementation Guide: **the Base score is a worst-case estimate for an unmitigated system in a generic environment, produced by a vendor who has never seen your network**. It is a starting point, not an answer.

### The 3–5% Problem

According to CISA and multiple published threat intelligence studies, only **3–5% of published CVEs have a known, functional exploit at any given time**. The Exploit Prediction Scoring System (EPSS), maintained by FIRST.org, corroborates this: the median EPSS score across all published CVEs hovers below 0.05 (5% probability of exploitation within 30 days).

Yet the default CVSS calculation assumes a mature, weaponized exploit exists for every vulnerability. This means every score you see in your scanner — before you apply Threat and Environmental metrics — is calculated under an assumption that is false for 95–97% of CVEs.

### The Operational Consequence

Consider a mid-size organization's typical scanner output:

```
Scanner report — typical enterprise environment:
  Total CVEs:        847
  Critical (9.0+):    94
  High (7.0–8.9):    203

With Base scores only, approximate remediation timeline:
  94 Critical × ~8 hours each = 752 analyst-hours
  203 High × ~4 hours each   = 812 analyst-hours

With Threat + Environmental enrichment (conservative estimate):
  ~5 true Critical (KEV or active exploit, exposed system): 40 hours
  ~22 true High (POC exists OR exposure without controls): 88 hours

Reduction: from ~1,564 analyst-hours to ~128 analyst-hours
— a 92% reduction in wasted effort
```

CVSS v4.0 provides the mechanism to achieve this reduction. This guide shows you exactly how.

---

## 1. What Changed in v4.0 — and Why It Matters

![](/img/cvss/1_-B_wNZ8-J12IGCQN695TVw.png)
![](/img/cvss/1_9K7ZVsd6Yk6Y8t_cD1XOQQ.png)
![](/img/cvss/1_Ztb_ZKPbhCx0XKTKyoRmvQ.png)
![](/img/cvss/1__T8ZhwZzVovfebnNGz6buw.png)
![](/img/cvss/1_87hv3fMjAi_z6OEP3aJvMA.png)


CVSS v4.0 was released on November 1, 2023. The changes are more significant than any previous version update — v4.0 is effectively a redesign of the impact and temporal models.

### New Impact Model: Two Systems Instead of One

The biggest structural change: CVSS v4.0 separates impact into two systems:

**Vulnerable System** — the component directly compromised by the vulnerability (what the attacker hits first).
**Subsequent System** — any system affected as a downstream consequence of exploiting the vulnerable system.

In v3.x, this distinction was handled through the vague "Scope" metric (Unchanged/Changed). In v4.0, it is explicit and granular:

```
v3.1 impact metrics:
  C (Confidentiality): None / Low / High
  I (Integrity):       None / Low / High
  A (Availability):    None / Low / High
  S (Scope):           Unchanged / Changed

v4.0 impact metrics:
  VC (Vulnerable System Confidentiality): None / Low / High
  VI (Vulnerable System Integrity):       None / Low / High
  VA (Vulnerable System Availability):    None / Low / High
  SC (Subsequent System Confidentiality): None / Low / High
  SI (Subsequent System Integrity):       None / Low / High
  SA (Subsequent System Availability):    None / Low / High
```

**Why this matters operationally:** In v3.x, if an SSH daemon vulnerability only affects the single server it runs on, you score it Scope:Unchanged. If it can propagate to a database behind it, Scope:Changed. These two scenarios produced different base scores, but there was no way to capture *how much* the subsequent system was affected. In v4.0, you can score a vulnerability that fully compromises the immediate system (`VC:H/VI:H/VA:H`) but has only partial downstream confidentiality impact (`SC:L/SI:N/SA:N`) — a much more precise description of real-world attack chains.

### New Metric: Attack Requirements (AT)

v4.0 adds **Attack Requirements (AT)** alongside Attack Complexity (AC). These two metrics were previously collapsed into one:

| Metric | What It Measures | Values |
|--------|-----------------|--------|
| **Attack Complexity (AC)** | Does the attacker need to bypass security mechanisms? (attacker's effort) | Low / High |
| **Attack Requirements (AT)** | Are there specific preconditions in the *target's deployment* for exploitability? | None / Present |

**Real-world example:** CVE-2022-26134 (Confluence OGNL injection):
- `AC:L` — exploitation is straightforward, no bypass required
- `AT:N` — no special deployment preconditions; works against default installations

Contrast with a race condition vulnerability:
- `AC:H` — attacker must win a timing race (active effort)
- `AT:N` — no special deployment needed; the race condition is intrinsic

Or a vulnerability that only triggers when a non-default configuration is enabled:
- `AC:L` — once the config is present, exploitation is simple
- `AT:P` — the non-default configuration must be present (deployment precondition)

### New Threat Metric: Exploit Maturity (E)

The old v3.x Temporal metric group is now the **Threat** metric group, containing a single metric: **Exploit Maturity (E)**. The old Remediation Level and Report Confidence metrics were removed.

| Value | Symbol | Meaning | Score Effect |
|-------|--------|---------|-------------|
| **Not Defined** | X | No information — CVSS defaults to Attacked | None (worst case applied) |
| **Attacked** | A | Actively exploited in the wild (confirmed) | Maximum score maintained |
| **POC** | P | Proof of Concept exists publicly | Moderate score reduction |
| **Unreported** | U | No public exploit evidence | Significant score reduction |

**The E:X trap:** When a CVE is published with no Exploit Maturity specified — which is the default from NVD and most scanners — CVSS v4.0 calculates as if `E:A`. If you have 500 CVEs and never set Exploit Maturity, you are treating all 500 as actively exploited. Setting `E:U` for CVEs with no exploit evidence is not optimism — it is accuracy.

### Cleaner Naming: CVSS-B, CVSS-BT, CVSS-BTE

v4.0 introduces formal nomenclature for the scoring lifecycle. This naming is important for compliance documentation and vendor communication:

| Name | Metrics Used | Who Produces It | Meaning |
|------|-------------|----------------|---------|
| **CVSS-B** | Base only | Vendor / NVD | Worst-case, generic severity |
| **CVSS-BT** | Base + Threat | Consumer + threat intel | Severity given current exploit activity |
| **CVSS-BTE** | Base + Threat + Environmental | Consumer + all context | Severity in your specific deployment |

### Supplemental Metric Group (New)

A new optional group of metrics that provide **context without affecting the score**: Safety (S), Automatable (AU), Recovery (R), Value Density (V), Vulnerability Response Effort (RE), Provider Urgency (U). These allow vendors to communicate operational context that the numeric score cannot capture.
