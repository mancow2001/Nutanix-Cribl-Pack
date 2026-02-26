# Nutanix ASIM Normalizer Pack

A Cribl Pack that normalizes Nutanix AHV, CVM API, and Prism Central audit events to Microsoft Sentinel ASIM (Advanced Security Information Model) AuditEvent schema with MITRE ATT&CK enrichment, configurable output modes, and data reduction.

## Overview

This pack processes three distinct Nutanix event source types and:
- Normalizes events to a 27-field ASIM AuditEvent schema v0.1.2
- Routes events by source type via chain pipelines
- Enriches with MITRE ATT&CK tactic/technique mappings via lookup tables
- Filters low-value AHV events for data reduction (~45% volume reduction)
- Supports configurable output modes (ASIM-only vs enriched)

## Supported Source Types

| Source Type | Appname | Description | Pipeline |
|-------------|---------|-------------|----------|
| AHV Audit | (none) | Linux auditd events from AHV hypervisor nodes | `nutanix_ahv_audit` |
| API Audit | `api_audit`, `api_audit_v3` | CVM REST API audit logs | `nutanix_api_audit` |
| Consolidated Audit | `consolidated_audit` | Prism Central IAM/admin JSON audit events | `nutanix_consolidated_audit` |

## AHV Audit Event Types

| Event Type | Action | Security Value | MITRE Mapping |
|------------|--------|----------------|---------------|
| CONFIG_CHANGE | Keep | High - Configuration modifications | Persistence / T1098 |
| CREATE | Keep | High - Resource creation | Persistence / T1136 |
| DELETE | Keep | High - Resource deletion | Impact / T1485 |
| SERVICE_START | Keep | High - Service lifecycle | Execution / T1569 |
| SERVICE_STOP | Keep | High - Service lifecycle | Impact / T1489 |
| ANOM_PROMISCUOUS | Keep | Critical - Security anomaly | Discovery / T1040 |
| SYSCALL | Keep | Medium - System activity | Execution / T1059 |
| PATH | Keep | Medium - File access | Discovery / T1083 |
| VIRT_MACHINE_ID | Keep | Low - VM context | - |
| NORMAL | Keep | Low - Normal audit | - |
| PROCTITLE | Drop | Low - Redundant | - |
| SOCKADDR | Drop | Low - Redundant | - |
| PARENT | Drop | Low - Redundant | - |

## ASIM Field Schema (27 Fields)

| ASIM Field | Source | Description |
|------------|--------|-------------|
| TimeGenerated | _time | Event timestamp in ISO 8601 |
| EventVendor | Static | "Nutanix" |
| EventProduct | Static | "AHV", "Prism", or "Prism Central" |
| EventSchema | Static | "AuditEvent" |
| EventSchemaVersion | Static | "0.1.2" |
| EventCount | Static | 1 |
| EventType | Lookup/mapping | Set, Create, Delete, Enable, Disable, Execute, Read, Other |
| EventResult | res/success field | Success, Failure, or NA |
| EventSeverity | Lookup risk_level | High, Medium, Low, Informational |
| EventOriginalType | audit_type/appname | Original event type |
| EventCategory | Lookup | Configuration, Service Lifecycle, etc. |
| Dvc | host | Reporting device |
| DvcHostname | host | Device hostname |
| ActorUsername | AUID/userName | User performing action |
| SrcIpAddr | params.ip_address | Source IP (consolidated audit) |
| ActorSessionId | ses/uuid | Session identifier |
| AccessMethod | Source-dependent | auditd, API, browser info |
| Operation | op/httpMethod | Action performed |
| Object | unit/exe/endpoint | Target of operation |
| ObjectType | Lookup | Configuration Atom, Service, Cloud Resource, etc. |
| OldValue | - | Previous value (when available) |
| NewValue | defaultMsg | New value or description |
| SecurityAlert | Lookup/logic | Boolean security relevance flag |
| RiskLevel | Lookup | critical, high, medium, low, info |
| MitreTactic | Lookup | MITRE ATT&CK tactic name |
| MitreTechniqueId | Lookup | MITRE technique ID (e.g., T1098) |
| MitreTechniqueName | Lookup | MITRE technique name |

## Pack Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| output_mode | string | asim_only | `asim_only` keeps only 27 ASIM fields. `enriched` keeps ASIM + vendor fields. |
| raw_handling | string | remove | `keep` preserves _raw, `truncate` keeps first 256 chars, `remove` drops _raw. |
| enable_mitre_enrichment | string | security_only | `all` enriches every event, `security_only` only security events, `off` disables. |
| event_filter | string | all | `all` emits everything, `security` keeps security events, `operational` keeps non-security. |

## Pipeline Architecture

```
Syslog Source
    │
    ▼
route.yml ─────► nutanix_source_detect
                    │
                    ├── AHV auditd ──────► nutanix_ahv_audit
                    │                        ├─ Parse audit_type, AUID, op, res
                    │                        ├─ Lookup nutanix_audit_type_map.csv
                    │                        ├─ Drop PROCTITLE/SOCKADDR/PARENT
                    │                        ├─ Map 27 ASIM fields
                    │                        └─ Output mode control
                    │
                    ├── api_audit ───────► nutanix_api_audit
                    │                        ├─ Parse pipe-delimited fields
                    │                        ├─ Lookup nutanix_api_security.csv
                    │                        ├─ Map 27 ASIM fields
                    │                        └─ Output mode control
                    │
                    ├── consolidated ────► nutanix_consolidated_audit
                    │                        ├─ Parse JSON message body
                    │                        ├─ Extract IAM/admin fields
                    │                        ├─ Map 27 ASIM fields
                    │                        └─ Output mode control
                    │
                    └── unknown ─────────► Basic ASIM fields (passthrough)
```

## Installation

1. Import the pack into your Cribl Stream instance
2. Configure pack parameters (output_mode, raw_handling, etc.)
3. Attach the pack route to your Nutanix syslog source
4. Deploy the Sentinel ARM template from `sentinel/NutanixAuditEvent_CL.json`
5. Configure your destination for Microsoft Sentinel

## Lookup Tables

### `nutanix_audit_type_map.csv`
Maps AHV audit_type to ASIM fields, severity, MITRE ATT&CK mappings, and drop flags. Edit to customize event handling.

### `nutanix_api_security.csv`
Maps API httpMethod to event type, risk level, and MITRE ATT&CK mappings. Edit to customize API event classification.

## Requirements

- Cribl Stream 4.0.0 or later
- Nutanix syslog forwarding configured (AHV, CVM, and/or Prism Central)
- Microsoft Sentinel workspace for ingestion

## License

MIT License
