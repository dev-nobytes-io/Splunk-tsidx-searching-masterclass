# Splunk TSIDX Searching Masterclass
## Enterprise SIEM at Scale — Detection Engineering Under Extreme Conditions

> **Scenario**: Trillions of events per hour. Degraded infrastructure. Poor data quality.
> Active Directory, SMB, LDAP, Corelight, WinEventLog, Sysmon. This is the real world.

---

## Environment Assumptions

| Component | Detail |
|---|---|
| **Indexes** | `corelight` (all machines), `wineventlog` (servers), `sysmon` (all machines) |
| **Scale** | Trillions of events/hour; multi-site enterprise |
| **Infrastructure** | Domain Controllers, jumphosts, identity systems, file servers, workstations |
| **Constraints** | RAM limits, compute limits, network saturation, data quality issues |
| **Protocols** | AD/Kerberos, LDAP/LDAPS, SMB/CIFS, RPC, WMI, DNS, HTTP |

---

## Modules

| # | Module | Focus |
|---|---|---|
| [01](./01-infrastructure-overview.md) | **Infrastructure Overview** | Architecture, data flows, index topology, TSIDX internals |
| [02](./02-search-optimization-fundamentals.md) | **Search Optimization Fundamentals** | Bloom filters, TSIDX, search order, eval vs field extraction |
| [03](./03-cross-index-correlation.md) | **Cross-Index Correlation** | Joining corelight + wineventlog + sysmon efficiently |
| [04](./04-active-directory-detections.md) | **Active Directory Detections** | Kerberos, LDAP enumeration, DCSync, GPO abuse |
| [05](./05-lateral-movement-and-smb.md) | **Lateral Movement & SMB** | Pass-the-hash, PsExec, SMB enumeration, admin shares |
| [06](./06-resource-constrained-searching.md) | **Resource-Constrained Searching** | RAM pressure, CPU throttling, network-limited searches |
| [07](./07-data-quality-and-normalization.md) | **Data Quality & Normalization** | Null fields, format drift, multiline events, deduplication |
| [08](./08-advanced-detection-engineering.md) | **Advanced Detection Engineering** | Baselining, ML primitives, rare(), streamstats, event sequencing |
| [09](./09-performance-reference-card.md) | **Performance Reference Card** | Quick-reference: command costs, anti-patterns, cheat sheet |
| [10](./10-streaming-and-distributable-commands.md) | **Streaming & Distributable Commands** | Push work to indexers, split-point architecture, per-attack-stage patterns |

---

## Core Principles at Scale

```
EFFICIENCY HIERARCHY (fastest → slowest)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. Index-time filtering      (index=, sourcetype=, host=, _time)
2. Bloom filter hits         (raw keyword search before pipe)
3. TSIDX lookup              (indexed fields via tstats / prestats)
4. Distributable streaming   (eval, where, fields, CSV lookup — on indexers)
5. Bucket scanning           (rawdata, field extractions)
6. Centralized streaming     (streamstats, eventstats — search head only)
7. Aggregation               (stats, chart, timechart — search head only)
8. Sub-searches              ([ search ... ])
9. Joins                     (join, append, appendcols)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

---

## The Golden Rules

1. **Filter early, filter hard** — Every clause before the first `|` reduces raw data scanned
2. **`tstats` before `stats`** — When fields are indexed, `tstats` skips rawdata entirely
3. **Time is your cheapest filter** — Always bound your searches; `earliest=-15m` costs almost nothing
4. **Subsearches kill performance** — Replace with `lookup`, `inputlookup`, or `join` with care
5. **`index=` first, always** — Splunk scans bloom filters per-index; mixing indexes without explicit declaration wastes bloom filter checks
6. **`NOT` is expensive, `!=` is worse** — Use exclusion lookups or `where` with `match()` instead
7. **Know your data distribution** — A search for EventCode=4624 on wineventlog may return billions; pre-filter with `LogonType=3` or `ComputerName="DC*"` first

---

## Quick Navigation by Attack Technique

| MITRE Technique | Module |
|---|---|
| T1078 — Valid Accounts | [04](./04-active-directory-detections.md), [08](./08-advanced-detection-engineering.md) |
| T1110 — Brute Force | [04](./04-active-directory-detections.md) |
| T1003.006 — DCSync | [04](./04-active-directory-detections.md) |
| T1021.002 — SMB/Windows Admin Shares | [05](./05-lateral-movement-and-smb.md) |
| T1550.002 — Pass the Hash | [05](./05-lateral-movement-and-smb.md) |
| T1018 — Remote System Discovery | [05](./05-lateral-movement-and-smb.md) |
| T1087 — Account Discovery (LDAP) | [04](./04-active-directory-detections.md) |
| T1484 — Group Policy Abuse | [04](./04-active-directory-detections.md) |
| T1595 — Active Scanning | [03](./03-cross-index-correlation.md) |
