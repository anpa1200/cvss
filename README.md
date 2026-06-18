# CVSS v4.0 Field Guide

[![CI](https://github.com/anpa1200/cvss/actions/workflows/ci.yml/badge.svg)](https://github.com/anpa1200/cvss/actions/workflows/ci.yml)
[![Deploy](https://github.com/anpa1200/cvss/actions/workflows/deploy.yml/badge.svg)](https://github.com/anpa1200/cvss/actions/workflows/deploy.yml)
[![Release](https://img.shields.io/github/v/release/anpa1200/cvss)](https://github.com/anpa1200/cvss/releases)

**[Live site →](https://1200km.com/cvss/)**

A practitioner guide to applying CVSS v4.0 concepts — Base, Threat, and Environmental metrics — to real vulnerability management decisions. Thirteen chapters covering the full lifecycle from raw scanner output to prioritized, auditable remediation actions.

---

## What this guide covers

| Chapter | Topic |
|---------|-------|
| 1 | Introduction — why Base scores alone are not enough |
| 2 | CVSS v3.1 vs v4.0 — what changed and why it matters |
| 3 | Vector string anatomy — reading every metric |
| 4 | Scoring lifecycle — CVSS-B → CVSS-BT → CVSS-BTE |
| 5 | Threat & Environmental metrics — scoring for your deployment |
| 6 | Worked examples — Log4Shell, Erlang/OTP SSH, CitrixBleed, MOVEit, FortiOS |
| 7 | Industry-specific scoring — healthcare, finance, OT/ICS |
| 8 | CVSS vs SSVC — when to use which |
| 9 | Practical VM workflow — scanner CSV → prioritized ticket |
| 10 | Enrichment tool — CLI that automates the pipeline |
| 11 | Regulatory evidence — using CVSS-BTE for compliance documentation |
| 12 | Common mistakes & interview Q&A |
| 13 | Quick reference cheatsheet |

---

## Scope

This is a **practitioner guide**, not official FIRST.org documentation. The CVSS v4.0 vectors used in worked examples are analyst-computed using the [FIRST.org CVSS v4.0 calculator](https://www.first.org/cvss/calculator/4-0), as NVD's v4.0 coverage remains incomplete for many CVEs. Official documentation: [first.org/cvss/v4-0](https://www.first.org/cvss/v4-0/).

Score examples are approximate. Environmental adjustments are illustrative — verify against your own firewall rules, network diagrams, and asset classification before using for compliance or audit purposes.

---

## Related tool

**[cvss_enrichment_tool](https://github.com/anpa1200/cvss_4.0)** — CLI that automates the Base → Threat → Environmental enrichment pipeline described in Chapter 10. Fetches live data from NVD, CISA KEV, and EPSS. Outputs heuristic priority estimates (not authoritative CVSS-BTE scores).

---

## Built with

[Docusaurus v3](https://docusaurus.io/) — deployed to GitHub Pages via GitHub Actions on every push to `main`.

To run locally:

```bash
npm install
npm run start        # dev server at localhost:3000
npm run build        # production build (fails on broken links)
npm run serve        # serve the production build locally
```

---

## Author

**Andrey Pautov** — CTI analyst, Medium [@1200km](https://medium.com/@1200km)

---

## References

- CVSS v4.0 Specification: https://www.first.org/cvss/v4-0/
- CVSS v4.0 Consumer Implementation Guide: https://www.first.org/cvss/v4.0/implementation-guide
- CVSS v4.0 User Guide: https://www.first.org/cvss/user-guide
- EPSS: https://www.first.org/epss/
- CISA KEV: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- NVD: https://nvd.nist.gov

## 1200km Ecosystem

This project is part of the 1200km security research ecosystem. Use [AdversaryGraph](https://1200km.com/adversarygraph/) for CTI-to-detection workflows, ATT&CK/ATLAS mapping, actor relevance, IOC enrichment, and analyst-ready reporting.

- [AdversaryGraph project hub](https://1200km.com/adversarygraph/)
- [AdversaryGraph documentation](https://1200km.com/adversarygraph-docs/)
- [Live ATT&CK/ATLAS workspace](https://1200km.com/threat-matrix/)
- [1200km security research ecosystem](https://1200km.com/)

