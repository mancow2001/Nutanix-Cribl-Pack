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

- **AHV Audit** — Linux auditd events from AHV hypervisor nodes. Appname: (none). Pipeline: `nutanix_ahv_audit`
- **API Audit** — CVM REST API audit logs. Appname: `api_audit`, `api_audit_v3`. Pipeline: `nutanix_api_audit`
- **Consolidated Audit** — Prism Central IAM/admin JSON audit events. Appname: `consolidated_audit`. Pipeline: `nutanix_consolidated_audit`

## AHV Audit Event Types

**Kept Events (High/Critical):**
- `CONFIG_CHANGE` — High: Configuration modifications. MITRE: Persistence / T1098
- `CREATE` — High: Resource creation. MITRE: Persistence / T1136
- `DELETE` — High: Resource deletion. MITRE: Impact / T1485
- `SERVICE_START` — High: Service lifecycle. MITRE: Execution / T1569
- `SERVICE_STOP` — High: Service lifecycle. MITRE: Impact / T1489
- `ANOM_PROMISCUOUS` — Critical: Security anomaly. MITRE: Discovery / T1040

**Kept Events (Medium/Low):**
- `SYSCALL` — Medium: System activity. MITRE: Execution / T1059
- `PATH` — Medium: File access. MITRE: Discovery / T1083
- `VIRT_MACHINE_ID` — Low: VM context
- `NORMAL` — Low: Normal audit

**Dropped Events:**
- `PROCTITLE` — Low: Redundant
- `SOCKADDR` — Low: Redundant
- `PARENT` — Low: Redundant

## ASIM AuditEvent Field Schema

Fields are classified per the [Microsoft ASIM AuditEvent schema](https://learn.microsoft.com/en-us/azure/sentinel/normalization-schema-audit). Use the `include_recommended_fields` parameter to strip recommended fields for maximum data reduction.

### Mandatory Fields (always emitted in `asim_only` mode)

- `EventVendor` — (Static) "Nutanix"
- `EventProduct` — (Static) "Prism" or "Prism Central"
- `EventSchema` — (Static) "AuditEvent"
- `EventSchemaVersion` — (Static) "0.1.2"
- `EventCount` — (Static) 1
- `EventStartTime` — (_time) Event start timestamp in ISO 8601
- `EventEndTime` — (_time) Event end timestamp in ISO 8601
- `TimeGenerated` — (_time) Sentinel ingestion timestamp (alias for EventStartTime)
- `EventType` — (Lookup/mapping) Set, Create, Delete, Enable, Execute, Read, Other
- `EventResult` — (res/success field) Success, Failure, or NA
- `Dvc` — (host) Reporting device
- `Operation` — (op/httpMethod) Action performed
- `Object` — (unit/exe/endpoint) Target of operation

### Recommended Fields (removable via `include_recommended_fields = false`)

- `EventSeverity` — (Lookup risk_level) High, Medium, Informational
- `EventOriginalType` — (audit_type/appname) Original event type
- `DvcHostname` — (host) Device hostname
- `ActorUsername` — (AUID/userName) User performing action
- `ActorUsernameType` — (Conditional) Username format type (Simple)
- `SrcIpAddr` — (params.ip_address) Source IP address
- `ActorSessionId` — (ses/uuid) Session identifier
- `ObjectType` — (Lookup) Configuration Atom, Service, Cloud Resource, Policy Rule, Other
- `OldValue` — (config_before/params) Previous value (when available)
- `NewValue` — (defaultMsg/payload) New value or description

### MITRE Enrichment Fields (controlled by `enable_mitre_enrichment`)

- `MitreTactic` — (Lookup) MITRE ATT&CK tactic name
- `MitreTechniqueId` — (Lookup) MITRE technique ID (e.g., T1098)
- `MitreTechniqueName` — (Lookup) MITRE technique name

## Pack Parameters

- **`output_mode`** (string, default: `asim_only`) — `asim_only` keeps only ASIM fields + MITRE enrichment. `enriched` keeps ASIM + vendor fields.
- **`include_recommended_fields`** (boolean, default: `true`) — Include recommended ASIM fields in `asim_only` output. When false, only mandatory ASIM fields and MITRE enrichment are emitted.
- **`raw_handling`** (string, default: `remove`) — `keep` preserves _raw, `truncate` keeps first 256 chars, `remove` drops _raw.
- **`enable_mitre_enrichment`** (string, default: `security_only`) — `all` enriches every event, `security_only` only security events, `off` disables.
- **`event_filter`** (string, default: `all`) — `all` emits everything, `security` keeps security events, `operational` keeps non-security.

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
