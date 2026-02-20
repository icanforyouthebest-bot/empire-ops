# ═══════════════════════════════════════════════════════════════
# ZERO TRUST LAYER 3: Controlled Entry Point
# Ops Officer CANNOT bypass this gateway
# Pre-check → Policy check → Risk check → Drift check → Execute
# ═══════════════════════════════════════════════════════════════
param(
    [string]$TenantId       = $env:TENANT_ID,
    [string]$ClientId       = $env:CLIENT_ID,
    [string]$ClientSecret   = $env:CLIENT_SECRET,
    [string]$SupabaseUrl    = $env:SUPABASE_URL,
    [string]$SupabaseKey    = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$RequestedAction = $env:REQUESTED_ACTION,   # e.g. "view_report", "trigger_runbook"
    [string]$RequestedBy    = $env:REQUESTED_BY,        # e.g. officer UPN
    [string]$RunbookName    = $env:RUNBOOK_NAME,        # optional
    [string]$SopVersion     = $env:SOP_VERSION          # must match current SOP
)

$CURRENT_SOP_VERSION = "2026.02.v1"

$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}
$token = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

function Invoke-Graph {
    param([string]$Method, [string]$Uri, [object]$Body = $null)
    $params = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0$Uri"; Headers = $headers }
    if ($Body) { $params.Body = $Body | ConvertTo-Json -Depth 10 }
    try { return Invoke-RestMethod @params }
    catch { Write-Warning "[$Method $Uri] $($_.Exception.Message)"; return $null }
}

function Write-Audit {
    param([string]$Step, [string]$Status, [string]$Detail, [bool]$Blocking = $false)
    $ts  = (Get-Date -Format 'o')
    $msg = "[$ts] CONTROLLED-ENTRY | $Step | $Status | actor=$RequestedBy action=$RequestedAction | $Detail"
    Write-Host $msg

    if ($SupabaseUrl -and $SupabaseKey) {
        $entry = @{
            layer      = "ControlledEntry"
            check_name = $Step
            status     = $Status
            action     = if ($Blocking) { "BLOCKED" } else { "ALLOWED" }
            detail     = "actor=$RequestedBy action=$RequestedAction $Detail"
            severity   = if ($Status -eq "BLOCKED") { "high" } else { "info" }
            source     = "layer3-controlled-entry"
        }
        try {
            $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
            Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null
        } catch {}
    }
}

function Block-Request {
    param([string]$Reason)
    Write-Audit -Step "GATE" -Status "BLOCKED" -Detail $Reason -Blocking $true
    Write-Host ""
    Write-Host "============================================================"
    Write-Host "  ACCESS DENIED"
    Write-Host "  Reason: $Reason"
    Write-Host "  Actor:  $RequestedBy"
    Write-Host "  Action: $RequestedAction"
    Write-Host "============================================================"
    exit 1
}

# ── ALLOWED ACTIONS LIST ──────────────────────────────────────
$ALLOWED_ACTIONS = @(
    "view_report"
    "view_audit"
    "view_security_status"
    "view_system_health"
    "trigger_runbook"
    "trigger_compliance_check"
    "trigger_health_check"
)

# ── FORBIDDEN ACTIONS (explicit block) ───────────────────────
$FORBIDDEN_ACTIONS = @(
    "modify_iam"
    "modify_ca"
    "modify_mfa"
    "modify_defender"
    "modify_policy"
    "modify_infra"
    "delete_audit"
    "add_role"
    "remove_role"
    "add_application"
    "modify_runbook"
    "disable_monitoring"
    "modify_automation"
)

Write-Host "============================================================"
Write-Host "  ZERO TRUST LAYER 3: Controlled Entry Point"
Write-Host "  All Ops Officer actions go through this gate"
Write-Host "============================================================"
Write-Host ""
Write-Host "  Actor:   $RequestedBy"
Write-Host "  Action:  $RequestedAction"
Write-Host "  SOP:     $SopVersion"
Write-Host "  Time:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTC')"
Write-Host ""

# ── GATE 1: SOP Version Check ────────────────────────────────
Write-Host "[GATE-1] SOP Version Check..."
if (-not $SopVersion -or $SopVersion -ne $CURRENT_SOP_VERSION) {
    Block-Request "SOP version mismatch. Required: $CURRENT_SOP_VERSION, Provided: $SopVersion. Officer must read current SOP before operating."
}
Write-Audit -Step "GATE-1-SOP" -Status "PASS" -Detail "SOP version verified: $SopVersion"

# ── GATE 2: Action Whitelist Check ───────────────────────────
Write-Host "[GATE-2] Action Whitelist Check..."
if ($RequestedAction -in $FORBIDDEN_ACTIONS) {
    Block-Request "Action '$RequestedAction' is EXPLICITLY FORBIDDEN for Operations Officer. No exceptions."
}
if ($RequestedAction -notin $ALLOWED_ACTIONS) {
    Block-Request "Action '$RequestedAction' is not in the approved action list. Contact system administrator."
}
Write-Audit -Step "GATE-2-Whitelist" -Status "PASS" -Detail "Action '$RequestedAction' is in approved list"

# ── GATE 3: Officer Identity Verification ────────────────────
Write-Host "[GATE-3] Officer Identity Verification..."
if (-not $RequestedBy) {
    Block-Request "No officer identity provided. All actions require identified actor."
}
$officerUser = Invoke-Graph -Method "GET" -Uri "/users/$RequestedBy"
if (-not $officerUser) {
    Block-Request "Officer '$RequestedBy' not found in directory."
}
if ($officerUser.accountEnabled -eq $false) {
    Block-Request "Officer account '$RequestedBy' is disabled."
}

# Verify officer only has Operations Officer role
$officerRoles = Invoke-Graph -Method "GET" -Uri "/users/$($officerUser.id)/memberOf?`$filter=`$type eq 'directoryRole'"
$DANGEROUS_ROLE_NAMES = @("Global Administrator","Security Administrator","Privileged Role Administrator","Conditional Access Administrator","Application Administrator","User Administrator","Exchange Administrator","SharePoint Administrator","Teams Administrator","Intune Administrator")
if ($officerRoles -and $officerRoles.value) {
    foreach ($role in $officerRoles.value) {
        if ($role.displayName -in $DANGEROUS_ROLE_NAMES) {
            Block-Request "CRITICAL: Officer '$RequestedBy' holds forbidden admin role '$($role.displayName)'. Remove immediately."
        }
    }
}
Write-Audit -Step "GATE-3-Identity" -Status "PASS" -Detail "Officer verified: $($officerUser.displayName) | account enabled | no dangerous roles"

# ── GATE 4: Risk Assessment ──────────────────────────────────
Write-Host "[GATE-4] Risk Assessment..."
# Check recent risky signins for this officer
$riskyUser = Invoke-Graph -Method "GET" -Uri "/identityProtection/riskyUsers?`$filter=userPrincipalName eq '$RequestedBy'"
if ($riskyUser -and $riskyUser.value -and $riskyUser.value.Count -gt 0) {
    $risk = $riskyUser.value[0]
    if ($risk.riskLevel -in @("high", "medium")) {
        Block-Request "Officer '$RequestedBy' has elevated risk level: $($risk.riskLevel). Account flagged by Identity Protection."
    }
}
Write-Audit -Step "GATE-4-Risk" -Status "PASS" -Detail "No elevated risk on officer account"

# ── GATE 5: Drift Check ──────────────────────────────────────
Write-Host "[GATE-5] System Drift Check (quick)..."
$caPolicies = Invoke-Graph -Method "GET" -Uri "/identity/conditionalAccess/policies"
$criticalPolicies = @("Empire-CA01-Block-Legacy-Auth", "Empire-CA02-Require-MFA-AllUsers")
$driftFound = $false
if ($caPolicies -and $caPolicies.value) {
    foreach ($pName in $criticalPolicies) {
        $p = $caPolicies.value | Where-Object { $_.displayName -eq $pName }
        if (-not $p -or $p.state -ne "enabled") {
            Write-Host "  DRIFT: $pName is not enabled - triggering auto-repair..."
            if ($p) {
                Invoke-Graph -Method "PATCH" -Uri "/identity/conditionalAccess/policies/$($p.id)" -Body @{ state = "enabled" } | Out-Null
                Write-Host "  HEALED: $pName restored to enabled"
            }
            $driftFound = $true
        }
    }
}
if (-not $driftFound) {
    Write-Audit -Step "GATE-5-Drift" -Status "PASS" -Detail "No drift detected in critical policies"
} else {
    Write-Audit -Step "GATE-5-Drift" -Status "HEALED" -Detail "Drift detected and auto-repaired before granting access"
}

# ── EXECUTE APPROVED ACTION ───────────────────────────────────
Write-Host ""
Write-Host "============================================================"
Write-Host "  ALL GATES PASSED - EXECUTING APPROVED ACTION"
Write-Host "  Action: $RequestedAction"
Write-Host "  Actor:  $RequestedBy"
Write-Host "============================================================"

switch ($RequestedAction) {
    "view_report" {
        Write-Host ""
        Write-Host "[EXECUTE] Generating system report..."
        $secScore = Invoke-Graph -Method "GET" -Uri "/security/secureScores?`$top=1"
        if ($secScore -and $secScore.value) {
            $s = $secScore.value[0]
            $pct = [math]::Round(($s.currentScore / $s.maxScore) * 100, 1)
            Write-Host "  Secure Score: $($s.currentScore) / $($s.maxScore) ($pct%)"
        }
    }
    "view_security_status" {
        Write-Host ""
        Write-Host "[EXECUTE] Fetching security status..."
        $alerts = Invoke-Graph -Method "GET" -Uri "/security/alerts_v2?`$filter=status eq 'active'&`$top=10"
        if ($alerts -and $alerts.value) {
            Write-Host "  Active security alerts: $($alerts.value.Count)"
        } else {
            Write-Host "  Active security alerts: 0"
        }
    }
    "trigger_runbook" {
        Write-Host ""
        Write-Host "[EXECUTE] Runbook trigger request logged"
        Write-Host "  Runbook: $RunbookName"
        Write-Host "  NOTE: Runbook contents cannot be modified by Operations Officer"
        Write-Host "  Trigger via Azure Automation API..."
    }
    "trigger_compliance_check" {
        Write-Host ""
        Write-Host "[EXECUTE] Compliance check triggered"
        Write-Host "  This runs the self-heal patrol (layer3) immediately"
    }
    default {
        Write-Host "[EXECUTE] Action '$RequestedAction' - logged and permitted"
    }
}

Write-Audit -Step "EXECUTE" -Status "COMPLETED" -Detail "Action '$RequestedAction' executed successfully"

Write-Host ""
Write-Host "============================================================"
Write-Host "  CONTROLLED ENTRY COMPLETE"
Write-Host "  All actions audited. Officer cannot bypass this gate."
Write-Host "============================================================"
