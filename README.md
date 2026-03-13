# azure-audit
Azure environment evidence collection tool for NIST 800-53 security assessments in DoD IL5 cloud environments.

## Script
`Invoke-AzureIL5EvidenceCollection.ps1`

This is a monolithic PowerShell script that runs in the current Azure CLI auth context and exports evidence only (no pass/fail adjudication).

## Quick Start
```powershell
az login
.\Invoke-AzureIL5EvidenceCollection.ps1 -OutputRoot .\out
```

## Common Options
```powershell
# Target specific subscriptions
.\Invoke-AzureIL5EvidenceCollection.ps1 -SubscriptionId "00000000-0000-0000-0000-000000000000"

# Increase activity log lookback (default 90 days)
.\Invoke-AzureIL5EvidenceCollection.ps1 -ActivityLogDays 180

# Timeout and heartbeat tuning (defaults: 300s timeout, 20s heartbeat)
.\Invoke-AzureIL5EvidenceCollection.ps1 -CommandTimeoutSeconds 600 -CommandHeartbeatSeconds 15

# Deep collection (slower): per-resource diagnostic settings and full resource config dumps
.\Invoke-AzureIL5EvidenceCollection.ps1 -IncludeResourceDiagnostics -IncludeResourceConfigDump

# Export dataset-to-control mapping catalog CSV (default path under run folder)
.\Invoke-AzureIL5EvidenceCollection.ps1 -ControlCatalogCsv
 
# Custom control catalog CSV path
.\Invoke-AzureIL5EvidenceCollection.ps1 -ControlCatalogCsv -ControlCatalogCsvPath .\out\control_catalog.csv

# Air-gapped profile: skips datasets that require missing Azure CLI extensions
.\Invoke-AzureIL5EvidenceCollection.ps1 -AirGappedProfile
```

## Output
Each run writes a timestamped directory:
- `summary.json`: run metadata and high-level counts
- `evidence_index.json`: dataset-to-file map with command provenance and NIST control-family tags
- `collection_errors.json`: non-fatal command failures (unsupported command/extension/permissions)
- `collection_skipped.json`: intentionally skipped datasets (for example in `-AirGappedProfile`)
- `subscription_*`: per-subscription evidence JSON files

Runtime behavior:
- While a command is still running, heartbeat status lines are printed every `-CommandHeartbeatSeconds`.
- If a command exceeds `-CommandTimeoutSeconds`, it is terminated, logged to `collection_errors.json`, and the script continues.
- In `-AirGappedProfile`, extension auto-install is disabled and extension-dependent datasets are skipped cleanly.

When `-ControlCatalogCsv` is enabled, a CSV is also written with:
- dataset scope + command provenance
- mapped NIST 800-53 Rev 5 control families
- mapped NIST 800-53 Rev 5 control IDs (for assessor evidence indexing)

## Offline Analysis Tools

### Browser Evidence Viewer (No Server)
- Open `tools/viewer/index.html` directly in a browser (`file://`).
- Load a run folder (for example `evidence/azure_audit_YYYYMMDD_HHMMSS`).
- View KPIs, dataset coverage, errors/skips, control-family/control-ID aggregation, and raw JSON.
- Use `Print Report (PDF)` to export a document-ready report.

Details: `tools/viewer/README.md`

### LLM Packet Exporter
Build LLM-friendly outputs from a run folder:

```powershell
# Use latest run under .\evidence
.\tools\build-llm-packet.ps1

# Specify a run folder
.\tools\build-llm-packet.ps1 -RunPath .\evidence\azure_audit_20260313_120000
```

Outputs under `<run>\llm_packet\`:
- `llm_packet.md`
- `llm_packet.jsonl`
