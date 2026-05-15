---
title: "The Practical VM Workflow"
sidebar_position: 9
---

![](/img/cvss/1_8a38jCuwENp5flLnmWAj7g.png)


## 14. The Practical VM Workflow: From Scanner Output to Prioritized Action

### The 6-Step Process

```
┌───────────────────────────────────────────────────────────────┐
│             VULNERABILITY MANAGEMENT WORKFLOW (CVSS v4.0)      │
│                                                               │
│  Step 1: INGEST                                               │
│    Scanner Report → extract all CVE IDs + Base Vectors        │
│    (Tenable, Qualys, Rapid7, Wiz all export CVE IDs)          │
│                                                               │
│  Step 2: THREAT ENRICHMENT (automated, applies to all CVEs)   │
│    ┌─────────────────────────────────────────────────────┐    │
│    │ CISA KEV API → E:A if listed                         │    │
│    │ EPSS API → E:P if ≥ 0.1, E:U if < 0.1              │    │
│    │ Override: E:A if KEV regardless of EPSS              │    │
│    └─────────────────────────────────────────────────────┘    │
│                                                               │
│  Step 3: ASSET GROUPING                                       │
│    Group CVEs by affected system/network zone                 │
│    Tag each group: zone, data class, compensating controls    │
│                                                               │
│  Step 4: ENVIRONMENTAL ENRICHMENT (per asset group)          │
│    ┌─────────────────────────────────────────────────────┐    │
│    │ Network zone → MAV value (N/A/L/P)                   │    │
│    │ Access controls → MAC value (L/H)                    │    │
│    │ Data classification → MVC/MVI values                 │    │
│    │ Blast radius → MSC/MSI/MSA values                    │    │
│    │ Asset criticality → CR/IR/AR values                  │    │
│    └─────────────────────────────────────────────────────┘    │
│                                                               │
│  Step 5: RECALCULATE ALL SCORES                               │
│    CVSS v4.0 calculator API or FIRST.org calculator           │
│    Output: CVSS-BTE score per CVE per asset group             │
│                                                               │
│  Step 6: PRIORITIZE AND ACT (by CVSS-BTE)                    │
│    Critical (9.0+): 24–72 hours — emergency response          │
│    High (7.0–8.9):  30 days — planned sprint                  │
│    Medium (4.0–6.9): 90 days — next maintenance window        │
│    Low (<4.0): Next major release / accept risk               │
└───────────────────────────────────────────────────────────────┘
```
