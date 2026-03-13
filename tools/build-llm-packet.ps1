#!/usr/bin/env pwsh
<#
.SYNOPSIS
Builds LLM-friendly packet files from an Azure audit evidence run folder.

.DESCRIPTION
Generates:
 - llm_packet.md
 - llm_packet.jsonl

Works offline and does not require internet access.
#>

[CmdletBinding()]
param(
    [string]$EvidenceRoot = ".\evidence",
    [string]$RunPath,
    [string]$OutputDir,
    [int]$MaxCharsPerDataset = 20000,
    [int]$MaxDatasets = 500
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Resolve-RunPath {
    param([string]$EvidenceRootPath, [string]$RunPathParam)

    if ($RunPathParam) {
        $resolved = Resolve-Path -Path $RunPathParam -ErrorAction Stop
        return $resolved.Path
    }

    $resolvedEvidence = Resolve-Path -Path $EvidenceRootPath -ErrorAction Stop
    $candidates = Get-ChildItem -Path $resolvedEvidence.Path -Directory |
        Where-Object { $_.Name -like "azure_audit_*" } |
        Sort-Object LastWriteTime -Descending

    if (-not $candidates -or $candidates.Count -eq 0) {
        throw "No azure_audit_* run folder found under '$($resolvedEvidence.Path)'."
    }
    return $candidates[0].FullName
}

function Read-JsonFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return $null }
    try {
        return Get-Content -Path $Path -Raw | ConvertFrom-Json -Depth 100
    }
    catch {
        return $null
    }
}

function Get-FileTextCapped {
    param([string]$Path, [int]$MaxChars)
    $raw = Get-Content -Path $Path -Raw
    if ($raw.Length -le $MaxChars) { return $raw }
    return $raw.Substring(0, $MaxChars)
}

try {
    if ($MaxCharsPerDataset -lt 1000) {
        throw "MaxCharsPerDataset must be >= 1000."
    }
    if ($MaxDatasets -lt 1) {
        throw "MaxDatasets must be >= 1."
    }

    $runFolder = Resolve-RunPath -EvidenceRootPath $EvidenceRoot -RunPathParam $RunPath
    $summaryPath = Join-Path $runFolder "summary.json"
    $indexPath = Join-Path $runFolder "evidence_index.json"
    $errorsPath = Join-Path $runFolder "collection_errors.json"
    $skippedPath = Join-Path $runFolder "collection_skipped.json"

    $summary = Read-JsonFile -Path $summaryPath
    $index = @(Read-JsonFile -Path $indexPath)
    $errors = @(Read-JsonFile -Path $errorsPath)
    $skipped = @(Read-JsonFile -Path $skippedPath)

    if (-not $index -or $index.Count -eq 0) {
        throw "No evidence index entries found in '$runFolder'."
    }

    if (-not $OutputDir) {
        $OutputDir = Join-Path $runFolder "llm_packet"
    }
    if (-not [System.IO.Path]::IsPathRooted($OutputDir)) {
        $OutputDir = Join-Path $runFolder $OutputDir
    }
    $null = New-Item -Path $OutputDir -ItemType Directory -Force

    $mdPath = Join-Path $OutputDir "llm_packet.md"
    $jsonlPath = Join-Path $OutputDir "llm_packet.jsonl"

    $indexSorted = $index |
        Sort-Object @{ Expression = { [int]($_.records) }; Descending = $true }, dataset |
        Select-Object -First $MaxDatasets

    $families = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    $controls = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)

    foreach ($row in $indexSorted) {
        foreach ($f in @($row.nist_800_53_families)) { if ($f) { $null = $families.Add([string]$f) } }
        foreach ($c in @($row.nist_800_53_controls)) { if ($c) { $null = $controls.Add([string]$c) } }
    }

    $md = New-Object System.Text.StringBuilder
    $bt = [char]96
    $null = $md.AppendLine("# Azure Audit LLM Packet")
    $null = $md.AppendLine("")
    $null = $md.AppendLine("## Run Metadata")
    $null = $md.AppendLine("")
    $null = $md.AppendLine(("- Run folder: {0}{0}{1}{0}{0}" -f $bt, $runFolder))
    if ($summary) {
        $null = $md.AppendLine("- Started: $($summary.run_started)")
        $null = $md.AppendLine("- Finished: $($summary.run_finished)")
        $null = $md.AppendLine("- Datasets collected: $($summary.datasets_collected)")
        $null = $md.AppendLine("- Command failures: $($summary.command_failures)")
        $null = $md.AppendLine("- Datasets skipped: $($summary.datasets_skipped)")
    }
    $null = $md.AppendLine("- Index rows included in packet: $($indexSorted.Count)")
    $null = $md.AppendLine("- Error rows: $($errors.Count)")
    $null = $md.AppendLine("- Skipped rows: $($skipped.Count)")
    $null = $md.AppendLine("")
    $null = $md.AppendLine("## Coverage")
    $null = $md.AppendLine("")
    $null = $md.AppendLine("- Control families: $(($families | Sort-Object) -join ', ')")
    $null = $md.AppendLine("- Control IDs: $(($controls | Sort-Object) -join ', ')")
    $null = $md.AppendLine("")
    $null = $md.AppendLine("## Errors")
    $null = $md.AppendLine("")
    if ($errors.Count -eq 0) {
        $null = $md.AppendLine("_None_")
    }
    else {
        foreach ($e in $errors) {
            $null = $md.AppendLine("- [$($e.timestamp)] scope=$($e.scope) dataset=$($e.dataset)")
            $null = $md.AppendLine(("  - command: {0}{0}{1}{0}{0}" -f $bt, $e.command))
            $null = $md.AppendLine("  - error: $($e.error)")
        }
    }
    $null = $md.AppendLine("")
    $null = $md.AppendLine("## Skipped")
    $null = $md.AppendLine("")
    if ($skipped.Count -eq 0) {
        $null = $md.AppendLine("_None_")
    }
    else {
        foreach ($s in $skipped) {
            $null = $md.AppendLine("- [$($s.timestamp)] scope=$($s.scope) dataset=$($s.dataset)")
            $null = $md.AppendLine(("  - command: {0}{0}{1}{0}{0}" -f $bt, $s.command))
            $null = $md.AppendLine("  - reason: $($s.reason)")
        }
    }
    $null = $md.AppendLine("")
    $null = $md.AppendLine("## Dataset Extracts")
    $null = $md.AppendLine("")

    if (Test-Path $jsonlPath) { Remove-Item $jsonlPath -Force }

    $packetMeta = [pscustomobject]@{
        type = "packet_meta"
        run_folder = $runFolder
        created_at = (Get-Date).ToString("o")
        datasets_included = $indexSorted.Count
        max_chars_per_dataset = $MaxCharsPerDataset
        control_families = @($families | Sort-Object)
        control_ids = @($controls | Sort-Object)
    }
    ($packetMeta | ConvertTo-Json -Depth 10 -Compress) | Add-Content -Path $jsonlPath

    foreach ($row in $indexSorted) {
        $evidencePath = [string]$row.file
        if (-not [System.IO.Path]::IsPathRooted($evidencePath)) {
            $evidencePath = Join-Path $runFolder $evidencePath
        }
        if (-not (Test-Path $evidencePath)) { continue }

        $snippet = Get-FileTextCapped -Path $evidencePath -MaxChars $MaxCharsPerDataset
        $null = $md.AppendLine("### $($row.dataset)")
        $null = $md.AppendLine("")
        $null = $md.AppendLine(("- scope: {0}{0}{1}{0}{0}" -f $bt, $row.scope))
        $null = $md.AppendLine("- records: $($row.records)")
        $null = $md.AppendLine(("- file: {0}{0}{1}{0}{0}" -f $bt, $row.file))
        $null = $md.AppendLine(("- command: {0}{0}{1}{0}{0}" -f $bt, $row.command))
        $null = $md.AppendLine("- families: $(($row.nist_800_53_families -join ', '))")
        $null = $md.AppendLine("- controls: $(($row.nist_800_53_controls -join ', '))")
        $null = $md.AppendLine("")
        $null = $md.AppendLine(($bt * 3) + "json")
        $null = $md.AppendLine($snippet)
        $null = $md.AppendLine($bt * 3)
        $null = $md.AppendLine("")

        $entry = [pscustomobject]@{
            type = "dataset_extract"
            dataset = $row.dataset
            scope = $row.scope
            records = $row.records
            evidence_file = $row.file
            command = $row.command
            nist_800_53_families = $row.nist_800_53_families
            nist_800_53_controls = $row.nist_800_53_controls
            content = $snippet
        }
        ($entry | ConvertTo-Json -Depth 20 -Compress) | Add-Content -Path $jsonlPath
    }

    Set-Content -Path $mdPath -Value $md.ToString() -Encoding utf8

    Write-Host ("Created: {0}" -f $mdPath)
    Write-Host ("Created: {0}" -f $jsonlPath)
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
