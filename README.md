# Nutanix ASIM Normalizer Pack

A Cribl Pack that normalizes Nutanix AHV syslog events to Microsoft Sentinel ASIM (Advanced Security Information Model) AuditEvent schema with built-in data reduction.

## Overview

This pack processes Linux auditd logs from Nutanix AHV hypervisor hosts and:
- Normalizes events to ASIM AuditEvent schema v0.1.2
- Filters low-value events for data reduction (~40-50% volume reduction)
- Extracts security-relevant fields for Sentinel analytics

## Supported Event Types

| Event Type | Action | Security Value |
|------------|--------|----------------|
| CONFIG_CHANGE | Keep | High - Configuration modifications |
| CREATE | Keep | High - Resource creation |
| DELETE | Keep | High - Resource deletion |
| SERVICE_START | Keep | High - Service lifecycle |
| SERVICE_STOP | Keep | High - Service lifecycle |
| ANOM_PROMISCUOUS | Keep | High - Security anomaly |
| SYSCALL | Keep | Medium - System activity |
| PATH | Keep | Medium - File access |
| VIRT_MACHINE_ID | Keep | Medium - VM context |
| PROCTITLE | Drop | Low - Redundant |
| SOCKADDR | Drop | Low - Redundant |
| PARENT | Drop | Low - Redundant |

## ASIM Field Mappings

| ASIM Field | Source | Description |
|------------|--------|-------------|
| EventVendor | Static | "Nutanix" |
| EventProduct | Static | "AHV" |
| EventSchema | Static | "AuditEvent" |
| EventSchemaVersion | Static | "0.1.2" |
| EventType | audit_type lookup | Set, Create, Delete, Enable, Disable, Execute, Read |
| EventResult | res field | Success or Failure |
| EventSeverity | severity lookup | High, Medium, Low, Informational |
| Dvc | host | Reporting device |
| ActorUsername | AUID field | User performing action |
| ActorUserId | auid field | Numeric user ID |
| Operation | op field | Original operation name |
| Object | unit/exe field | Target of operation |
| ObjectType | audit_type lookup | Configuration Atom, Cloud Resource, Service |

## Installation

1. Import the pack into your Cribl Stream instance
2. Attach the `nutanix-main` pipeline to your Nutanix syslog source
3. Configure your destination for Microsoft Sentinel

## Pipeline Flow

```
Syslog Source -> nutanix-main -> nutanix-asim-audit -> Sentinel Destination
```

## Requirements

- Cribl Stream 4.0.0 or later
- Nutanix AHV syslog forwarding configured
- Microsoft Sentinel workspace for ingestion

## Customization

### Adjust Data Reduction

Edit `lookups/nutanix_drop_types.csv` to modify which event types are filtered:

```csv
audit_type,drop_reason
PROCTITLE,Redundant - process title encoded
SOCKADDR,Redundant - low security value
```

### Modify Severity Mapping

Edit `lookups/nutanix_severity_map.csv` to adjust severity classifications.

### Modify Event Type Mapping

Edit `lookups/nutanix_eventtype_map.csv` to adjust ASIM EventType assignments.

## License

MIT License
