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

## ASIM AuditEvent Field Schema

Fields are classified per the [Microsoft ASIM AuditEvent schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-audit). Use the `include_recommended_fields` parameter to strip recommended fields for maximum data reduction.

### Mandatory Fields (always emitted in `asim_only` mode)

| ASIM Field | Source | Description |
|------------|--------|-------------|
| EventVendor | Static | "Nutanix" |
| EventProduct | Static | "Prism" or "Prism Central" |
| EventSchema | Static | "AuditEvent" |
| EventSchemaVersion | Static | "0.1.2" |
| EventCount | Static | 1 |
| EventStartTime | _time | Event start timestamp in ISO 8601 |
| EventEndTime | _time | Event end timestamp in ISO 8601 |
| TimeGenerated | _time | Sentinel ingestion timestamp (alias for EventStartTime) |
| EventType | Lookup/mapping | Set, Create, Delete, Enable, Execute, Read, Other |
| EventResult | res/success field | Success, Failure, or NA |
| Dvc | host | Reporting device |
| Operation | op/httpMethod | Action performed |
| Object | unit/exe/endpoint | Target of operation |

### Recommended Fields (removable via `include_recommended_fields = false`)

| ASIM Field | Source | Description |
|------------|--------|-------------|
| EventSeverity | Lookup risk_level | High, Medium, Informational |
| EventOriginalType | audit_type/appname | Original event type |
| DvcHostname | host | Device hostname |
| ActorUsername | AUID/userName | User performing action |
| ActorUsernameType | Conditional | Username format type (Simple) |
| SrcIpAddr | params.ip_address | Source IP address |
| ActorSessionId | ses/uuid | Session identifier |
| ObjectType | Lookup | Configuration Atom, Service, Cloud Resource, Policy Rule, Other |
| OldValue | config_before/params | Previous value (when available) |
| NewValue | defaultMsg/payload | New value or description |

### MITRE Enrichment Fields (controlled by `enable_mitre_enrichment`)

| Field | Source | Description |
|-------|--------|-------------|
| MitreTactic | Lookup | MITRE ATT&CK tactic name |
| MitreTechniqueId | Lookup | MITRE technique ID (e.g., T1098) |
| MitreTechniqueName | Lookup | MITRE technique name |

## Pack Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| output_mode | string | asim_only | `asim_only` keeps only ASIM fields + MITRE enrichment. `enriched` keeps ASIM + vendor fields. |
| include_recommended_fields | boolean | true | Include recommended ASIM fields in `asim_only` output. When false, only mandatory ASIM fields and MITRE enrichment are emitted. |
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

1. Download the latest `.crbl` file from the [Releases](../../releases) page
2. In Cribl Stream, go to **Packs** → **Add Pack** → **Import from File** and upload the `.crbl` file
3. Configure pack parameters (output_mode, raw_handling, etc.)
4. Attach the pack route to your Nutanix syslog source
5. Deploy the Sentinel ARM template from `sentinel/NutanixAuditEvent_CL.json`
6. Configure your destination for Microsoft Sentinel

## Releases

Tagged releases automatically build an importable `.crbl` pack file via GitHub Actions. To create a release:

```bash
git tag v2.1.0
git push origin v2.1.0
```

The workflow packages `package.json`, `README.md`, `default/`, and `data/` into a `.crbl` tarball and attaches it to a GitHub Release with auto-generated release notes.

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
