# Offline Evidence Viewer

This viewer runs directly from `file://` and does not require a web server or internet access.

## Open Viewer
Open this file in a browser:

`tools/viewer/index.html`

## Load Evidence
Use one of two methods:

1. `Select Evidence Folder` (preferred)
- Works in Chromium-based browsers supporting File System Access API.
- Pick the run directory (for example `evidence/azure_audit_YYYYMMDD_HHMMSS`).

2. Folder upload fallback
- Use the folder input control and select the same run directory.

## What It Shows
- Run KPIs from `summary.json`
- Dataset coverage from `evidence_index.json`
- Errors from `collection_errors.json`
- Skips from `collection_skipped.json`
- NIST family/control aggregations
- Raw JSON file viewer for any evidence file

## Print to PDF
Click `Print Report (PDF)` in the toolbar.

The print layout removes non-report controls and formats tables for document export.

## Air-Gapped Notes
- No external scripts, fonts, or CDNs are used.
- All rendering is local in the browser.
- Keep the evidence folder and viewer files on the same isolated media/system.

