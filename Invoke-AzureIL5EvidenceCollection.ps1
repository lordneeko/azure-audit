#!/usr/bin/env pwsh
<#
.SYNOPSIS
Collects Azure evidence for DoD IL5/NIST SP 800-53 assessments.

.DESCRIPTION
Runs under existing Azure CLI authentication context and exports broad evidence
across subscriptions without attempting pass/fail determinations.

Designed as a single-file script for restricted environments where copy/paste is required.
#>

[CmdletBinding()]
param(
    [string]$OutputRoot = ".\evidence",
    [string[]]$SubscriptionId,
    [int]$ActivityLogDays = 90,
    [switch]$IncludeResourceDiagnostics,
    [switch]$IncludeResourceConfigDump,
    [switch]$ControlCatalogCsv,
    [string]$ControlCatalogCsvPath,
    [switch]$AirGappedProfile
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$script:StartedAt = Get-Date
$script:EvidenceIndex = New-Object System.Collections.Generic.List[object]
$script:CollectionErrors = New-Object System.Collections.Generic.List[object]
$script:CollectionSkipped = New-Object System.Collections.Generic.List[object]
$script:InstalledAzExtensions = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
$script:FamilyToControls = @{
    AC = @("AC-2", "AC-3", "AC-4", "AC-5", "AC-6", "AC-17", "AC-18", "AC-19")
    AU = @("AU-2", "AU-3", "AU-6", "AU-8", "AU-9", "AU-12")
    CA = @("CA-2", "CA-7", "CA-8", "CA-9")
    CM = @("CM-2", "CM-3", "CM-4", "CM-6", "CM-7", "CM-8", "CM-10")
    CP = @("CP-2", "CP-4", "CP-9", "CP-10")
    IA = @("IA-2", "IA-4", "IA-5", "IA-8")
    IR = @("IR-4", "IR-5", "IR-6", "IR-8")
    MP = @("MP-4", "MP-5", "MP-6")
    PL = @("PL-2", "PL-4", "PL-8")
    PM = @("PM-5", "PM-9", "PM-10", "PM-11", "PM-12")
    PS = @("PS-2", "PS-3", "PS-6", "PS-7")
    RA = @("RA-3", "RA-5", "RA-7")
    SA = @("SA-3", "SA-4", "SA-8", "SA-10", "SA-11")
    SC = @("SC-2", "SC-3", "SC-4", "SC-7", "SC-8", "SC-12", "SC-13", "SC-28", "SC-39")
    SI = @("SI-2", "SI-3", "SI-4", "SI-5", "SI-7")
}

function Write-Info {
    param([string]$Message)
    Write-Host ("[{0}] [INFO] {1}" -f (Get-Date -Format s), $Message)
}

function Write-Warn {
    param([string]$Message)
    Write-Host ("[{0}] [WARN] {1}" -f (Get-Date -Format s), $Message) -ForegroundColor Yellow
}

function New-SafeName {
    param([string]$Name)
    return ($Name -replace "[^a-zA-Z0-9\-_\.]", "_")
}

function Ensure-Tooling {
    if (-not (Get-Command az -ErrorAction SilentlyContinue)) {
        throw "Azure CLI (az) was not found in PATH."
    }

    $null = & az account show --output none 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "Azure CLI is not authenticated. Run 'az login' and retry."
    }
}

function Initialize-ExtensionInventory {
    $raw = & az extension list --only-show-errors --output json 2>&1
    if ($LASTEXITCODE -ne 0) {
        return
    }

    try {
        $extensions = $raw | ConvertFrom-Json -Depth 50
        foreach ($ext in @($extensions)) {
            if ($ext.name) {
                $null = $script:InstalledAzExtensions.Add($ext.name.ToLowerInvariant())
            }
        }
    }
    catch {
        # Continue without extension inventory if parsing fails.
    }
}

function Get-ControlIdsForFamilies {
    param([string[]]$Families)
    $controls = New-Object System.Collections.Generic.HashSet[string]([System.StringComparer]::OrdinalIgnoreCase)
    foreach ($family in @($Families)) {
        if ($script:FamilyToControls.ContainsKey($family)) {
            foreach ($control in $script:FamilyToControls[$family]) {
                $null = $controls.Add($control)
            }
        }
    }
    return @($controls | Sort-Object)
}

function Add-SkippedDataset {
    param(
        [string]$Scope,
        [string]$Dataset,
        [string]$Command,
        [string]$Reason,
        [string[]]$NistFamilies,
        [string[]]$ControlIds
    )

    $script:CollectionSkipped.Add([pscustomobject]@{
        timestamp = (Get-Date).ToString("o")
        scope = $Scope
        dataset = $Dataset
        command = $Command
        reason = $Reason
        nist_800_53_families = $NistFamilies
        nist_800_53_controls = $ControlIds
    }) | Out-Null
}

function Invoke-AzJson {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][string[]]$Args,
        [Parameter(Mandatory = $true)][string]$OutputFile,
        [Parameter(Mandatory = $true)][string]$Scope,
        [Parameter(Mandatory = $true)][string]$Dataset,
        [Parameter(Mandatory = $true)][string[]]$NistFamilies,
        [string[]]$RequiredExtensions
    )

    $display = "az " + ($Args -join " ")
    $controlIds = Get-ControlIdsForFamilies -Families $NistFamilies

    if ($AirGappedProfile -and $RequiredExtensions -and $RequiredExtensions.Count -gt 0) {
        $missingExtensions = @($RequiredExtensions | Where-Object { -not $script:InstalledAzExtensions.Contains($_.ToLowerInvariant()) })
        if ($missingExtensions.Count -gt 0) {
            $reason = "Air-gapped mode skip; missing extension(s): {0}" -f ($missingExtensions -join ",")
            Write-Info ("Skipping {0}: {1}" -f $Dataset, $reason)
            Add-SkippedDataset -Scope $Scope -Dataset $Dataset -Command $display -Reason $reason -NistFamilies $NistFamilies -ControlIds $controlIds
            return
        }
    }

    Write-Info $display

    $fullArgs = @() + $Args + @("--only-show-errors", "--output", "json")
    $raw = & az @fullArgs 2>&1
    $exit = $LASTEXITCODE

    if ($exit -ne 0) {
        $msg = ($raw | Out-String).Trim()
        if (-not $msg) { $msg = "Unknown Azure CLI error." }
        Write-Warn ("Failed: {0}" -f $display)
        $script:CollectionErrors.Add([pscustomobject]@{
            timestamp = (Get-Date).ToString("o")
            scope = $Scope
            dataset = $Dataset
            command = $display
            error = $msg
        }) | Out-Null
        return
    }

    try {
        $parsed = $raw | ConvertFrom-Json -Depth 100
    }
    catch {
        $msg = "JSON parse failure for command: $display"
        Write-Warn $msg
        $script:CollectionErrors.Add([pscustomobject]@{
            timestamp = (Get-Date).ToString("o")
            scope = $Scope
            dataset = $Dataset
            command = $display
            error = $_.Exception.Message
        }) | Out-Null
        return
    }

    $dir = Split-Path -Path $OutputFile -Parent
    if (-not (Test-Path $dir)) {
        $null = New-Item -ItemType Directory -Path $dir -Force
    }

    $parsed | ConvertTo-Json -Depth 100 | Set-Content -Path $OutputFile -Encoding utf8

    $count = 1
    if ($parsed -is [System.Array]) {
        $count = $parsed.Count
    }
    elseif ($null -eq $parsed) {
        $count = 0
    }

    $script:EvidenceIndex.Add([pscustomobject]@{
        timestamp = (Get-Date).ToString("o")
        scope = $Scope
        dataset = $Dataset
        file = $OutputFile
        command = $display
        records = $count
        nist_800_53_families = $NistFamilies
        nist_800_53_controls = $controlIds
    }) | Out-Null
}

function Add-SubscriptionCollection {
    param(
        [Parameter(Mandatory = $true)][string]$SubId,
        [Parameter(Mandatory = $true)][string]$SubName,
        [Parameter(Mandatory = $true)][string]$SubFolder
    )

    $scope = "subscription/$SubId"

    $commands = @(
        @{ dataset = "resource_groups"; args = @("group", "list", "--subscription", $SubId); fam = @("CM", "CA", "PM") }
        @{ dataset = "resources"; args = @("resource", "list", "--subscription", $SubId); fam = @("CM", "PM", "RA") }
        @{ dataset = "tags"; args = @("tag", "list", "--subscription", $SubId); fam = @("CM", "PM") }
        @{ dataset = "resource_locks"; args = @("lock", "list", "--subscription", $SubId); fam = @("CM", "SC") }
        @{ dataset = "deployments"; args = @("deployment", "sub", "list", "--subscription", $SubId); fam = @("CM", "SA") }
        @{ dataset = "role_assignments"; args = @("role", "assignment", "list", "--all", "--subscription", $SubId); fam = @("AC", "IA", "PS") }
        @{ dataset = "role_definitions"; args = @("role", "definition", "list", "--subscription", $SubId); fam = @("AC", "IA", "PS") }
        @{ dataset = "policy_assignments"; args = @("policy", "assignment", "list", "--disable-scope-strict-match", "--subscription", $SubId); fam = @("CM", "CA", "PL") }
        @{ dataset = "policy_definitions"; args = @("policy", "definition", "list", "--subscription", $SubId); fam = @("CM", "CA", "PL") }
        @{ dataset = "policy_initiatives"; args = @("policy", "set-definition", "list", "--subscription", $SubId); fam = @("CM", "CA", "PL") }
        @{ dataset = "policy_exemptions"; args = @("policy", "exemption", "list", "--subscription", $SubId); fam = @("CA", "CM") }
        @{ dataset = "policy_states_latest"; args = @("policy", "state", "list", "--subscription", $SubId, "--top", "5000"); fam = @("CA", "CM", "RA") }
        @{ dataset = "security_pricing"; args = @("security", "pricing", "list", "--subscription", $SubId); fam = @("RA", "SI", "SC") }
        @{ dataset = "security_contacts"; args = @("security", "contact", "list", "--subscription", $SubId); fam = @("IR", "SI") }
        @{ dataset = "security_workspace_settings"; args = @("security", "workspace-setting", "list", "--subscription", $SubId); fam = @("AU", "SI", "SC") }
        @{ dataset = "security_settings"; args = @("security", "setting", "list", "--subscription", $SubId); fam = @("AU", "SI", "SC") }
        @{ dataset = "security_automations"; args = @("security", "automation", "list", "--subscription", $SubId); fam = @("IR", "SI", "AU") }
        @{ dataset = "security_alerts"; args = @("security", "alert", "list", "--subscription", $SubId); fam = @("IR", "SI", "AU") }
        @{ dataset = "security_assessments"; args = @("security", "assessment", "list", "--subscription", $SubId); fam = @("CA", "RA", "SI") }
        @{ dataset = "security_regulatory_standards"; args = @("security", "regulatory-compliance-standard", "list", "--subscription", $SubId); fam = @("CA", "PL", "PM") }
        @{ dataset = "security_regulatory_controls"; args = @("security", "regulatory-compliance-control", "list", "--subscription", $SubId); fam = @("CA", "PL", "PM") }
        @{ dataset = "security_regulatory_assessments"; args = @("security", "regulatory-compliance-assessment", "list", "--subscription", $SubId); fam = @("CA", "RA", "PM") }
        @{ dataset = "secure_scores"; args = @("security", "secure-score", "list", "--subscription", $SubId); fam = @("CA", "RA", "PM") }
        @{ dataset = "vnets"; args = @("network", "vnet", "list", "--subscription", $SubId); fam = @("SC", "AC", "CM") }
        @{ dataset = "subnets_via_graph"; args = @("graph", "query", "-q", "Resources | where type =~ 'microsoft.network/virtualnetworks/subnets' | where subscriptionId =~ '$SubId'"); fam = @("SC", "AC", "CM"); ext = @("resource-graph") }
        @{ dataset = "nsgs"; args = @("network", "nsg", "list", "--subscription", $SubId); fam = @("SC", "AC", "CM") }
        @{ dataset = "route_tables"; args = @("network", "route-table", "list", "--subscription", $SubId); fam = @("SC", "CM") }
        @{ dataset = "firewalls"; args = @("network", "firewall", "list", "--subscription", $SubId); fam = @("SC", "SI") }
        @{ dataset = "application_gateways"; args = @("network", "application-gateway", "list", "--subscription", $SubId); fam = @("SC", "SI") }
        @{ dataset = "load_balancers"; args = @("network", "lb", "list", "--subscription", $SubId); fam = @("SC", "CM") }
        @{ dataset = "public_ips"; args = @("network", "public-ip", "list", "--subscription", $SubId); fam = @("SC", "AC", "CM") }
        @{ dataset = "private_endpoints"; args = @("network", "private-endpoint", "list", "--subscription", $SubId); fam = @("SC", "AC", "CM") }
        @{ dataset = "private_link_services"; args = @("network", "private-link-service", "list", "--subscription", $SubId); fam = @("SC", "AC") }
        @{ dataset = "ddos_plans"; args = @("network", "ddos-protection", "list", "--subscription", $SubId); fam = @("SC", "SI") }
        @{ dataset = "network_watchers"; args = @("network", "watcher", "list", "--subscription", $SubId); fam = @("AU", "SI") }
        @{ dataset = "bastions"; args = @("network", "bastion", "list", "--subscription", $SubId); fam = @("AC", "SC", "IA") }
        @{ dataset = "virtual_machines"; args = @("vm", "list", "--show-details", "--subscription", $SubId); fam = @("CM", "SI", "SC", "AC") }
        @{ dataset = "vm_scale_sets"; args = @("vmss", "list", "--subscription", $SubId); fam = @("CM", "SI", "SC") }
        @{ dataset = "managed_disks"; args = @("disk", "list", "--subscription", $SubId); fam = @("SC", "MP", "CM") }
        @{ dataset = "snapshots"; args = @("snapshot", "list", "--subscription", $SubId); fam = @("SC", "MP", "CM") }
        @{ dataset = "compute_gallery"; args = @("sig", "list", "--subscription", $SubId); fam = @("CM", "SA") }
        @{ dataset = "aks_clusters"; args = @("aks", "list", "--subscription", $SubId); fam = @("CM", "SC", "SI", "AC") }
        @{ dataset = "container_registries"; args = @("acr", "list", "--subscription", $SubId); fam = @("SC", "CM", "SI") }
        @{ dataset = "container_instances"; args = @("container", "list", "--subscription", $SubId); fam = @("CM", "SC", "SI") }
        @{ dataset = "container_apps"; args = @("containerapp", "list", "--subscription", $SubId); fam = @("CM", "SC", "SI"); ext = @("containerapp") }
        @{ dataset = "key_vaults"; args = @("keyvault", "list", "--subscription", $SubId); fam = @("SC", "IA", "AC", "MP") }
        @{ dataset = "storage_accounts"; args = @("storage", "account", "list", "--subscription", $SubId); fam = @("SC", "MP", "AU", "CM") }
        @{ dataset = "sql_servers"; args = @("sql", "server", "list", "--subscription", $SubId); fam = @("SC", "AU", "CM", "IA") }
        @{ dataset = "cosmosdb_accounts"; args = @("cosmosdb", "list", "--subscription", $SubId); fam = @("SC", "AU", "CM", "IA") }
        @{ dataset = "postgres_flexible_servers"; args = @("postgres", "flexible-server", "list", "--subscription", $SubId); fam = @("SC", "AU", "CM", "IA") }
        @{ dataset = "mysql_flexible_servers"; args = @("mysql", "flexible-server", "list", "--subscription", $SubId); fam = @("SC", "AU", "CM", "IA") }
        @{ dataset = "redis_caches"; args = @("redis", "list", "--subscription", $SubId); fam = @("SC", "CM") }
        @{ dataset = "servicebus_namespaces"; args = @("servicebus", "namespace", "list", "--subscription", $SubId); fam = @("SC", "CM", "AU") }
        @{ dataset = "eventhub_namespaces"; args = @("eventhubs", "namespace", "list", "--subscription", $SubId); fam = @("SC", "CM", "AU") }
        @{ dataset = "webapps"; args = @("webapp", "list", "--subscription", $SubId); fam = @("CM", "SC", "SI") }
        @{ dataset = "functionapps"; args = @("functionapp", "list", "--subscription", $SubId); fam = @("CM", "SC", "SI") }
        @{ dataset = "logicapps"; args = @("logicapp", "list", "--subscription", $SubId); fam = @("CM", "SC", "AU"); ext = @("logic") }
        @{ dataset = "api_management"; args = @("apim", "list", "--subscription", $SubId); fam = @("SC", "CM", "SI"); ext = @("apim") }
        @{ dataset = "synapse_workspaces"; args = @("synapse", "workspace", "list", "--subscription", $SubId); fam = @("SC", "CM", "AU"); ext = @("synapse") }
        @{ dataset = "databricks_workspaces"; args = @("databricks", "workspace", "list", "--subscription", $SubId); fam = @("SC", "CM", "AU"); ext = @("databricks") }
        @{ dataset = "recovery_services_vaults"; args = @("backup", "vault", "list", "--subscription", $SubId); fam = @("CP", "SC", "CM") }
        @{ dataset = "log_analytics_workspaces"; args = @("monitor", "log-analytics", "workspace", "list", "--subscription", $SubId); fam = @("AU", "SI", "CA") }
        @{ dataset = "monitor_action_groups"; args = @("monitor", "action-group", "list", "--subscription", $SubId); fam = @("IR", "AU", "SI") }
        @{ dataset = "monitor_metric_alerts"; args = @("monitor", "metrics", "alert", "list", "--subscription", $SubId); fam = @("AU", "SI", "IR") }
        @{ dataset = "monitor_activity_log_alerts"; args = @("monitor", "activity-log", "alert", "list", "--subscription", $SubId); fam = @("AU", "SI", "IR") }
        @{ dataset = "monitor_scheduled_query_alerts"; args = @("monitor", "scheduled-query", "list", "--subscription", $SubId); fam = @("AU", "SI", "IR") }
        @{ dataset = "monitor_data_collection_rules"; args = @("monitor", "data-collection", "rule", "list", "--subscription", $SubId); fam = @("AU", "SI", "CM") }
        @{ dataset = "monitor_data_collection_endpoints"; args = @("monitor", "data-collection", "endpoint", "list", "--subscription", $SubId); fam = @("AU", "SI", "CM") }
        @{ dataset = "monitor_diagnostic_settings_subscription"; args = @("monitor", "diagnostic-settings", "subscription", "list", "--subscription", $SubId); fam = @("AU", "SI", "CA") }
        @{ dataset = "monitor_log_profiles"; args = @("monitor", "log-profiles", "list", "--subscription", $SubId); fam = @("AU", "SI", "CA") }
        @{ dataset = "activity_logs"; args = @("monitor", "activity-log", "list", "--offset", ("{0}d" -f $ActivityLogDays), "--max-events", "10000", "--subscription", $SubId); fam = @("AU", "IR", "SI") }
        @{ dataset = "advisor_recommendations"; args = @("advisor", "recommendation", "list", "--subscription", $SubId); fam = @("RA", "CA", "PM") }
    )

    foreach ($cmd in $commands) {
        $safeDataset = New-SafeName $cmd.dataset
        $file = Join-Path $SubFolder ("{0}.json" -f $safeDataset)
        $requiredExtensions = @()
        if ($cmd.ContainsKey("ext")) {
            $requiredExtensions = @($cmd.ext)
        }
        Invoke-AzJson -Args $cmd.args -OutputFile $file -Scope $scope -Dataset $cmd.dataset -NistFamilies $cmd.fam -RequiredExtensions $requiredExtensions
    }

    $vmListFile = Join-Path $SubFolder "virtual_machines.json"
    if (Test-Path $vmListFile) {
        try {
            $vms = Get-Content $vmListFile | ConvertFrom-Json -Depth 100
            foreach ($vm in @($vms)) {
                if (-not $vm.name -or -not $vm.resourceGroup) { continue }
                $vmSafe = New-SafeName $vm.name
                Invoke-AzJson -Args @("vm", "show", "-g", $vm.resourceGroup, "-n", $vm.name, "--subscription", $SubId) `
                    -OutputFile (Join-Path $SubFolder ("vm_{0}_detail.json" -f $vmSafe)) `
                    -Scope $scope -Dataset ("vm_detail_{0}" -f $vm.name) -NistFamilies @("CM", "SC", "SI", "AC")
                Invoke-AzJson -Args @("vm", "extension", "list", "-g", $vm.resourceGroup, "--vm-name", $vm.name, "--subscription", $SubId) `
                    -OutputFile (Join-Path $SubFolder ("vm_{0}_extensions.json" -f $vmSafe)) `
                    -Scope $scope -Dataset ("vm_extensions_{0}" -f $vm.name) -NistFamilies @("CM", "SI", "SC")
            }
        }
        catch {
            Write-Warn ("Unable to expand VM details for subscription {0}: {1}" -f $SubId, $_.Exception.Message)
        }
    }

    $aksFile = Join-Path $SubFolder "aks_clusters.json"
    if (Test-Path $aksFile) {
        try {
            $clusters = Get-Content $aksFile | ConvertFrom-Json -Depth 100
            foreach ($aks in @($clusters)) {
                if (-not $aks.name -or -not $aks.resourceGroup) { continue }
                $aksSafe = New-SafeName $aks.name
                Invoke-AzJson -Args @("aks", "show", "-g", $aks.resourceGroup, "-n", $aks.name, "--subscription", $SubId) `
                    -OutputFile (Join-Path $SubFolder ("aks_{0}_detail.json" -f $aksSafe)) `
                    -Scope $scope -Dataset ("aks_detail_{0}" -f $aks.name) -NistFamilies @("CM", "SC", "SI", "AC")
            }
        }
        catch {
            Write-Warn ("Unable to expand AKS details for subscription {0}: {1}" -f $SubId, $_.Exception.Message)
        }
    }

    if ($IncludeResourceDiagnostics -or $IncludeResourceConfigDump) {
        $resourcesFile = Join-Path $SubFolder "resources.json"
        if (Test-Path $resourcesFile) {
            try {
                $resources = Get-Content $resourcesFile | ConvertFrom-Json -Depth 100
                foreach ($res in @($resources)) {
                    if (-not $res.id) { continue }
                    $resToken = New-SafeName (($res.name + "_" + $res.type).ToLowerInvariant())
                    if ($IncludeResourceConfigDump) {
                        Invoke-AzJson -Args @("resource", "show", "--ids", $res.id, "--subscription", $SubId) `
                            -OutputFile (Join-Path $SubFolder ("resource_{0}_config.json" -f $resToken)) `
                            -Scope $scope -Dataset ("resource_config_{0}" -f $res.name) -NistFamilies @("CM", "SC", "RA")
                    }
                    if ($IncludeResourceDiagnostics) {
                        Invoke-AzJson -Args @("monitor", "diagnostic-settings", "list", "--resource", $res.id, "--subscription", $SubId) `
                            -OutputFile (Join-Path $SubFolder ("resource_{0}_diagnostics.json" -f $resToken)) `
                            -Scope $scope -Dataset ("resource_diagnostics_{0}" -f $res.name) -NistFamilies @("AU", "SI", "CA")
                    }
                }
            }
            catch {
                Write-Warn ("Unable to expand resource-level diagnostics/config for subscription {0}: {1}" -f $SubId, $_.Exception.Message)
            }
        }
    }
}

try {
    Ensure-Tooling
    Initialize-ExtensionInventory

    $runId = Get-Date -Format "yyyyMMdd_HHmmss"
    $root = Join-Path $OutputRoot ("azure_audit_{0}" -f $runId)
    $null = New-Item -Path $root -ItemType Directory -Force

    Write-Info ("Output root: {0}" -f $root)

    Invoke-AzJson -Args @("version") -OutputFile (Join-Path $root "az_version.json") `
        -Scope "session" -Dataset "az_version" -NistFamilies @("SA", "CM")
    Invoke-AzJson -Args @("extension", "list") -OutputFile (Join-Path $root "az_extensions.json") `
        -Scope "session" -Dataset "az_extensions" -NistFamilies @("SA", "CM")
    Invoke-AzJson -Args @("account", "show") -OutputFile (Join-Path $root "account_show.json") `
        -Scope "session" -Dataset "account_show" -NistFamilies @("AC", "IA", "PS")
    Invoke-AzJson -Args @("account", "list", "--all") -OutputFile (Join-Path $root "account_list.json") `
        -Scope "tenant" -Dataset "account_list" -NistFamilies @("AC", "CM", "PM")
    Invoke-AzJson -Args @("account", "management-group", "list") -OutputFile (Join-Path $root "management_groups.json") `
        -Scope "tenant" -Dataset "management_groups" -NistFamilies @("PM", "CA", "CM")
    Invoke-AzJson -Args @("resource", "list", "--tag", "DoDIL=5") -OutputFile (Join-Path $root "resources_tagged_dodil5.json") `
        -Scope "tenant" -Dataset "resources_tagged_dodil5" -NistFamilies @("PM", "CM")

    $subListPath = Join-Path $root "account_list.json"
    if (-not (Test-Path $subListPath)) {
        throw "Subscription listing not available. Cannot continue."
    }

    $allSubs = Get-Content $subListPath | ConvertFrom-Json -Depth 100
    $enabledSubs = @($allSubs | Where-Object { $_.state -eq "Enabled" })

    if ($SubscriptionId -and $SubscriptionId.Count -gt 0) {
        $targetSubs = @($enabledSubs | Where-Object { $SubscriptionId -contains $_.id })
    }
    else {
        $targetSubs = $enabledSubs
    }

    if (-not $targetSubs -or $targetSubs.Count -eq 0) {
        throw "No enabled subscriptions were selected for evidence collection."
    }

    Write-Info ("Target subscriptions: {0}" -f $targetSubs.Count)

    foreach ($sub in $targetSubs) {
        $subSafe = New-SafeName $sub.name
        $subFolder = Join-Path $root ("subscription_{0}_{1}" -f $subSafe, $sub.id)
        $null = New-Item -Path $subFolder -ItemType Directory -Force
        Write-Info ("Collecting subscription: {0} ({1})" -f $sub.name, $sub.id)
        Add-SubscriptionCollection -SubId $sub.id -SubName $sub.name -SubFolder $subFolder
    }

    $indexPath = Join-Path $root "evidence_index.json"
    $errorsPath = Join-Path $root "collection_errors.json"
    $skippedPath = Join-Path $root "collection_skipped.json"
    $summaryPath = Join-Path $root "summary.json"

    $script:EvidenceIndex | ConvertTo-Json -Depth 100 | Set-Content -Path $indexPath -Encoding utf8
    $script:CollectionErrors | ConvertTo-Json -Depth 100 | Set-Content -Path $errorsPath -Encoding utf8
    $script:CollectionSkipped | ConvertTo-Json -Depth 100 | Set-Content -Path $skippedPath -Encoding utf8

    $controlCatalogResolved = $null
    if ($ControlCatalogCsv) {
        if ($ControlCatalogCsvPath) {
            if ([System.IO.Path]::IsPathRooted($ControlCatalogCsvPath)) {
                $controlCatalogResolved = $ControlCatalogCsvPath
            }
            else {
                $controlCatalogResolved = Join-Path $root $ControlCatalogCsvPath
            }
        }
        else {
            $controlCatalogResolved = Join-Path $root "control_catalog.csv"
        }

        $catalogRows = New-Object System.Collections.Generic.List[object]
        foreach ($item in $script:EvidenceIndex) {
            $catalogRows.Add([pscustomobject]@{
                status = "collected"
                scope = $item.scope
                dataset = $item.dataset
                evidence_file = $item.file
                command = $item.command
                nist_800_53_families = (@($item.nist_800_53_families) -join ";")
                nist_800_53_controls = (@($item.nist_800_53_controls) -join ";")
            }) | Out-Null
        }
        foreach ($item in $script:CollectionSkipped) {
            $catalogRows.Add([pscustomobject]@{
                status = "skipped"
                scope = $item.scope
                dataset = $item.dataset
                evidence_file = ""
                command = $item.command
                nist_800_53_families = (@($item.nist_800_53_families) -join ";")
                nist_800_53_controls = (@($item.nist_800_53_controls) -join ";")
            }) | Out-Null
        }

        $catalogDir = Split-Path -Path $controlCatalogResolved -Parent
        if (-not (Test-Path $catalogDir)) {
            $null = New-Item -ItemType Directory -Path $catalogDir -Force
        }
        $catalogRows | Export-Csv -NoTypeInformation -Encoding utf8 -Path $controlCatalogResolved
    }

    $summary = [pscustomobject]@{
        run_started = $script:StartedAt.ToString("o")
        run_finished = (Get-Date).ToString("o")
        output_root = $root
        subscription_filter = $SubscriptionId
        activity_log_days = $ActivityLogDays
        include_resource_diagnostics = [bool]$IncludeResourceDiagnostics
        include_resource_config_dump = [bool]$IncludeResourceConfigDump
        air_gapped_profile = [bool]$AirGappedProfile
        control_catalog_csv_enabled = [bool]$ControlCatalogCsv
        control_catalog_csv_path = $controlCatalogResolved
        datasets_collected = $script:EvidenceIndex.Count
        datasets_skipped = $script:CollectionSkipped.Count
        command_failures = $script:CollectionErrors.Count
    }
    $summary | ConvertTo-Json -Depth 10 | Set-Content -Path $summaryPath -Encoding utf8

    Write-Info ("Completed. Datasets: {0}, Skipped: {1}, Failures: {2}" -f $script:EvidenceIndex.Count, $script:CollectionSkipped.Count, $script:CollectionErrors.Count)
    Write-Info ("Evidence index: {0}" -f $indexPath)
    Write-Info ("Run summary: {0}" -f $summaryPath)
    if ($ControlCatalogCsv -and $controlCatalogResolved) {
        Write-Info ("Control catalog CSV: {0}" -f $controlCatalogResolved)
    }
}
catch {
    Write-Error $_.Exception.Message
    exit 1
}
