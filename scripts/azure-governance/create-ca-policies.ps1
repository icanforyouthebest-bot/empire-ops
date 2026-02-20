# ===============================================================
# Create Empire Conditional Access Policies
# Empire-CA01: Block Legacy Auth
# Empire-CA02: Require MFA All Users
# Empire-CA03: Require MFA Admins (No Exception)
# ===============================================================
param(
    [string]$TenantId     = $env:TENANT_ID,
    [string]$ClientId     = $env:CLIENT_ID,
    [string]$ClientSecret = $env:CLIENT_SECRET,
    [string]$SupabaseUrl  = $env:SUPABASE_URL,
    [string]$SupabaseKey  = $env:SUPABASE_SERVICE_ROLE_KEY
)

function Write-Audit {
    param([string]$Check, [string]$Status, [string]$Detail, [string]$Severity = "info")
    Write-Host "  [$Status] $Check | $Detail"
    if ($SupabaseUrl -and $SupabaseKey) {
        $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
        $entry = @{ layer="CAPolicy"; check_name=$Check; status=$Status; action="CREATE"; detail=$Detail; severity=$Severity; source="create-ca-policies" }
        try { Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null } catch {}
    }
}

if (-not $TenantId -or -not $ClientId -or -not $ClientSecret) {
    Write-Host "  [SKIP] No Azure credentials"
    exit 0
}

# Get token
$tokenBody = @{ grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope="https://graph.microsoft.com/.default" }
try {
    $token = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
} catch {
    Write-Warning "  Token failed: $($_.Exception.Message)"; exit 1
}

$azH = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

Write-Host "============================================================"
Write-Host "  CREATE EMPIRE CONDITIONAL ACCESS POLICIES"
Write-Host "  Empire-CA01: Block Legacy Auth"
Write-Host "  Empire-CA02: MFA All Users"
Write-Host "  Empire-CA03: MFA Admins (no exception)"
Write-Host "============================================================"

# Check existing policies
$existing = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $azH
$empireCA01 = $existing.value | Where-Object { $_.displayName -eq "Empire-CA01-BlockLegacyAuth" }
$empireCA02 = $existing.value | Where-Object { $_.displayName -eq "Empire-CA02-MFAAllUsers" }
$empireCA03 = $existing.value | Where-Object { $_.displayName -eq "Empire-CA03-MFAAdmins" }

# ── CA01: Block Legacy Authentication ─────────────────────────
Write-Host ""
Write-Host "[1/3] Empire-CA01: Block Legacy Auth..."
if ($empireCA01) {
    Write-Audit -Check "Empire-CA01" -Status "OK" -Detail "Already exists: $($empireCA01.state)"
} else {
    $ca01 = @{
        displayName = "Empire-CA01-BlockLegacyAuth"
        state       = "enabled"
        conditions  = @{
            users          = @{ includeUsers = @("All") }
            applications   = @{ includeApplications = @("All") }
            clientAppTypes = @("exchangeActiveSync", "other")
        }
        grantControls = @{ operator = "OR"; builtInControls = @("block") }
    }
    try {
        $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Method POST -Headers $azH -Body ($ca01 | ConvertTo-Json -Depth 10)
        Write-Audit -Check "Empire-CA01" -Status "APPLIED" -Detail "Created: Block Legacy Auth policy ID=$($result.id)" -Severity "info"
    } catch {
        Write-Audit -Check "Empire-CA01" -Status "FAILED" -Detail "Create failed: $($_.Exception.Message)" -Severity "high"
    }
}

# ── CA02: MFA for All Users ────────────────────────────────────
Write-Host "[2/3] Empire-CA02: MFA All Users..."
if ($empireCA02) {
    Write-Audit -Check "Empire-CA02" -Status "OK" -Detail "Already exists: $($empireCA02.state)"
} else {
    $ca02 = @{
        displayName = "Empire-CA02-MFAAllUsers"
        state       = "enabledForReportingButNotEnforced"  # Report mode first — safe
        conditions  = @{
            users        = @{ includeUsers = @("All"); excludeUsers = @() }
            applications = @{ includeApplications = @("All") }
        }
        grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
    }
    try {
        $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Method POST -Headers $azH -Body ($ca02 | ConvertTo-Json -Depth 10)
        Write-Audit -Check "Empire-CA02" -Status "APPLIED" -Detail "Created: MFA All Users (report mode) ID=$($result.id)" -Severity "info"
    } catch {
        Write-Audit -Check "Empire-CA02" -Status "FAILED" -Detail "Create failed: $($_.Exception.Message)" -Severity "high"
    }
}

# ── CA03: MFA for Admins (no exception) ───────────────────────
Write-Host "[3/3] Empire-CA03: MFA Admins..."
if ($empireCA03) {
    Write-Audit -Check "Empire-CA03" -Status "OK" -Detail "Already exists: $($empireCA03.state)"
} else {
    $adminRoles = @(
        "62e90394-69f5-4237-9190-012177145e10"  # Global Administrator
        "194ae4cb-b126-40b2-bd5b-6091b380977d"  # Security Administrator
        "f28a1f50-f6e7-4571-818b-6a12f2af6b6c"  # SharePoint Administrator
        "29232cdf-9323-42fd-ade2-1d097af3e4de"  # Exchange Administrator
        "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"  # Conditional Access Administrator
    )
    $ca03 = @{
        displayName = "Empire-CA03-MFAAdmins"
        state       = "enabled"
        conditions  = @{
            users        = @{ includeRoles = $adminRoles }
            applications = @{ includeApplications = @("All") }
        }
        grantControls = @{ operator = "OR"; builtInControls = @("mfa") }
    }
    try {
        $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Method POST -Headers $azH -Body ($ca03 | ConvertTo-Json -Depth 10)
        Write-Audit -Check "Empire-CA03" -Status "APPLIED" -Detail "Created: MFA Admins (enabled) ID=$($result.id)" -Severity "info"
    } catch {
        Write-Audit -Check "Empire-CA03" -Status "FAILED" -Detail "Create failed: $($_.Exception.Message)" -Severity "high"
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  CA POLICIES COMPLETE"
Write-Host "  Empire-CA01: Block Legacy Auth — ACTIVE"
Write-Host "  Empire-CA02: MFA All Users — REPORT MODE (safe)"
Write-Host "  Empire-CA03: MFA Admins — ENABLED"
Write-Host "============================================================"
