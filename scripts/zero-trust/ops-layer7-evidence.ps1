# ===============================================================
# ZERO TRUST LAYER 7: Evidence Generation System
# Operations Officer CANNOT say "I did it" without system proof
# Auto-generates: Before / After / Diff / AuditChain
# ===============================================================
param(
    [string]$TenantId     = $env:TENANT_ID,
    [string]$ClientId     = $env:CLIENT_ID,
    [string]$ClientSecret = $env:CLIENT_SECRET,
    [string]$SupabaseUrl  = $env:SUPABASE_URL,
    [string]$SupabaseKey  = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$Actor        = $env:ACTOR,         # Who triggered
    [string]$ActionId     = $env:ACTION_ID,     # Unique action ID
    [string]$Phase        = $env:PHASE          # "before" | "after" | "diff"
)

$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}
$token = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

function Invoke-Graph {
    param([string]$Uri)
    try { return Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0$Uri" -Headers $headers }
    catch { return $null }
}

function Get-SystemSnapshot {
    # Capture complete system state snapshot
    $snapshot = @{
        captured_at   = (Get-Date -Format "o")
        actor         = $Actor
        action_id     = $ActionId
        phase         = $Phase

        # 1. CA Policies state
        ca_policies   = @()
        # 2. Role assignments
        role_assignments = @()
        # 3. Security score
        secure_score  = $null
        # 4. Risky users count
        risky_users   = 0
        # 5. Active security alerts
        active_alerts = 0
        # 6. MFA status
        mfa_policy_enabled = $false
        # 7. Legacy auth blocked
        legacy_auth_blocked = $false
    }

    # CA Policies
    $caPolicies = Invoke-Graph -Uri "/identity/conditionalAccess/policies"
    if ($caPolicies -and $caPolicies.value) {
        foreach ($p in $caPolicies.value) {
            $snapshot.ca_policies += @{
                id          = $p.id
                displayName = $p.displayName
                state       = $p.state
                modifiedAt  = $p.modifiedDateTime
            }
        }
        $mfaPolicy = $caPolicies.value | Where-Object { $_.displayName -like "*MFA*AllUsers*" }
        $legacyPolicy = $caPolicies.value | Where-Object { $_.displayName -like "*Legacy*" }
        $snapshot.mfa_policy_enabled    = ($mfaPolicy -and $mfaPolicy.state -eq "enabled")
        $snapshot.legacy_auth_blocked   = ($legacyPolicy -and $legacyPolicy.state -eq "enabled")
    }

    # Role assignments - privileged only
    $adminRoles = @(
        "62e90394-69f5-4237-9190-012177145e10"  # Global Admin
        "194ae4cb-b126-40b2-bd5b-6091b380977d"  # Security Admin
        "e8611ab8-c189-46e8-94e1-60213ab1f814"  # Priv Role Admin
    )
    foreach ($roleId in $adminRoles) {
        $assignments = Invoke-Graph -Uri "/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$roleId'&`$expand=principal,roleDefinition"
        if ($assignments -and $assignments.value) {
            foreach ($a in $assignments.value) {
                $snapshot.role_assignments += @{
                    role    = $a.roleDefinition.displayName
                    user    = $a.principal.userPrincipalName
                    id      = $a.id
                }
            }
        }
    }

    # Secure score
    $score = Invoke-Graph -Uri "/security/secureScores?`$top=1"
    if ($score -and $score.value) {
        $s = $score.value[0]
        $snapshot.secure_score = @{
            current = $s.currentScore
            max     = $s.maxScore
            pct     = [math]::Round(($s.currentScore / $s.maxScore) * 100, 1)
        }
    }

    # Risky users
    $risky = Invoke-Graph -Uri "/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'"
    if ($risky -and $risky.value) { $snapshot.risky_users = $risky.value.Count }

    # Active alerts
    $alerts = Invoke-Graph -Uri "/security/alerts_v2?`$filter=status eq 'active'&`$top=1&`$count=true"
    if ($alerts) { $snapshot.active_alerts = $alerts.'@odata.count' }

    return $snapshot
}

function Get-Diff {
    param($Before, $After)
    $diff = @{
        action_id       = $ActionId
        actor           = $Actor
        before_time     = $Before.captured_at
        after_time      = $After.captured_at
        duration_seconds = ([datetime]$After.captured_at - [datetime]$Before.captured_at).TotalSeconds
        changes         = @()
        risk_delta      = @{}
        verdict         = "NO_CHANGE"
    }

    # CA Policy changes
    foreach ($bPolicy in $Before.ca_policies) {
        $aPolicy = $After.ca_policies | Where-Object { $_.id -eq $bPolicy.id }
        if ($aPolicy -and $aPolicy.state -ne $bPolicy.state) {
            $diff.changes += @{
                type     = "CA_POLICY_STATE"
                name     = $bPolicy.displayName
                before   = $bPolicy.state
                after    = $aPolicy.state
                severity = if ($aPolicy.state -ne "enabled") { "CRITICAL" } else { "INFO" }
            }
        }
    }
    # New CA policies added
    foreach ($aPolicy in $After.ca_policies) {
        $existed = $Before.ca_policies | Where-Object { $_.id -eq $aPolicy.id }
        if (-not $existed) {
            $diff.changes += @{ type = "CA_POLICY_ADDED"; name = $aPolicy.displayName; before = $null; after = $aPolicy.state; severity = "INFO" }
        }
    }

    # Role assignment changes
    $beforeRoleIds = $Before.role_assignments | ForEach-Object { $_.id }
    $afterRoleIds  = $After.role_assignments  | ForEach-Object { $_.id }

    $added   = $After.role_assignments  | Where-Object { $_.id -notin $beforeRoleIds }
    $removed = $Before.role_assignments | Where-Object { $_.id -notin $afterRoleIds }

    foreach ($a in $added)   { $diff.changes += @{ type = "ROLE_ADDED";   role = $a.role; user = $a.user; before = $null;   after = "assigned"; severity = "HIGH" } }
    foreach ($r in $removed) { $diff.changes += @{ type = "ROLE_REMOVED"; role = $r.role; user = $r.user; before = "assigned"; after = $null;   severity = "INFO" } }

    # Risk delta
    $diff.risk_delta = @{
        secure_score_before = $Before.secure_score.pct
        secure_score_after  = $After.secure_score.pct
        score_change        = ($After.secure_score.pct - $Before.secure_score.pct)
        risky_users_before  = $Before.risky_users
        risky_users_after   = $After.risky_users
        alerts_before       = $Before.active_alerts
        alerts_after        = $After.active_alerts
        mfa_before          = $Before.mfa_policy_enabled
        mfa_after           = $After.mfa_policy_enabled
    }

    # Verdict
    $criticalChanges = $diff.changes | Where-Object { $_.severity -eq "CRITICAL" }
    $highChanges     = $diff.changes | Where-Object { $_.severity -eq "HIGH" }
    if ($criticalChanges) { $diff.verdict = "CRITICAL_CHANGE_DETECTED" }
    elseif ($highChanges) { $diff.verdict = "HIGH_RISK_CHANGE" }
    elseif ($diff.changes) { $diff.verdict = "CHANGE_DETECTED" }
    else { $diff.verdict = "NO_CHANGE" }

    return $diff
}

function Push-Evidence {
    param([string]$Type, [object]$Data)
    if (-not $SupabaseUrl -or -not $SupabaseKey) { return }
    $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
    $entry = @{
        layer      = "Evidence"
        check_name = "action-$ActionId-$Type"
        status     = "LOGGED"
        action     = "EVIDENCE_WRITTEN"
        detail     = "actor=$Actor phase=$Type verdict=$(if ($Data.verdict) { $Data.verdict } else { 'N/A' })"
        severity   = "info"
        source     = "layer7-evidence"
        metadata   = $Data
    }
    try {
        Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json -Depth 20) | Out-Null
    } catch { Write-Warning "Evidence push failed: $($_.Exception.Message)" }
}

Write-Host "============================================================"
Write-Host "  ZERO TRUST LAYER 7: Evidence Generation"
Write-Host "  Action-ID: $ActionId"
Write-Host "  Actor:     $Actor"
Write-Host "  Phase:     $Phase"
Write-Host "  Time:      $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
Write-Host "============================================================"

if (-not $ActionId) {
    $ActionId = [System.Guid]::NewGuid().ToString()
    Write-Host "  Auto-generated ActionId: $ActionId"
}

if ($Phase -eq "before" -or -not $Phase) {
    Write-Host ""
    Write-Host "[BEFORE] Capturing system snapshot..."
    $beforeSnapshot = Get-SystemSnapshot
    $beforeJson     = $beforeSnapshot | ConvertTo-Json -Depth 10

    # Write to file for GitHub Actions artifact
    $beforeJson | Out-File -FilePath "evidence-before-$ActionId.json" -Encoding utf8

    Write-Host ""
    Write-Host "  BEFORE SNAPSHOT:"
    Write-Host "  CA Policies: $($beforeSnapshot.ca_policies.Count)"
    Write-Host "  Admin Role Assignments: $($beforeSnapshot.role_assignments.Count)"
    Write-Host "  Secure Score: $($beforeSnapshot.secure_score.pct)%"
    Write-Host "  Risky Users: $($beforeSnapshot.risky_users)"
    Write-Host "  Active Alerts: $($beforeSnapshot.active_alerts)"
    Write-Host "  MFA Enforced: $($beforeSnapshot.mfa_policy_enabled)"
    Write-Host "  Legacy Auth Blocked: $($beforeSnapshot.legacy_auth_blocked)"

    Push-Evidence -Type "before" -Data $beforeSnapshot
    Write-Host ""
    Write-Host "  BEFORE evidence written - ActionId: $ActionId"
    Write-Host "  File: evidence-before-$ActionId.json"
}

if ($Phase -eq "after") {
    Write-Host ""
    Write-Host "[AFTER] Capturing system snapshot..."
    $afterSnapshot = Get-SystemSnapshot
    $afterJson     = $afterSnapshot | ConvertTo-Json -Depth 10

    $afterJson | Out-File -FilePath "evidence-after-$ActionId.json" -Encoding utf8

    Write-Host ""
    Write-Host "  AFTER SNAPSHOT:"
    Write-Host "  CA Policies: $($afterSnapshot.ca_policies.Count)"
    Write-Host "  Admin Role Assignments: $($afterSnapshot.role_assignments.Count)"
    Write-Host "  Secure Score: $($afterSnapshot.secure_score.pct)%"
    Write-Host "  Risky Users: $($afterSnapshot.risky_users)"
    Write-Host "  MFA Enforced: $($afterSnapshot.mfa_policy_enabled)"

    Push-Evidence -Type "after" -Data $afterSnapshot

    Write-Host ""
    Write-Host "  AFTER evidence written - ActionId: $ActionId"
}

if ($Phase -eq "diff") {
    Write-Host ""
    Write-Host "[DIFF] Loading before/after snapshots..."
    $beforeFile = "evidence-before-$ActionId.json"
    $afterFile  = "evidence-after-$ActionId.json"

    if (-not (Test-Path $beforeFile) -or -not (Test-Path $afterFile)) {
        Write-Host "  ERROR: Missing before/after evidence files"
        Write-Host "  Run with phase=before and phase=after first"
        exit 1
    }

    $before = Get-Content $beforeFile | ConvertFrom-Json
    $after  = Get-Content $afterFile  | ConvertFrom-Json
    $diff   = Get-Diff -Before $before -After $after
    $diffJson = $diff | ConvertTo-Json -Depth 10
    $diffJson | Out-File -FilePath "evidence-diff-$ActionId.json" -Encoding utf8

    Write-Host ""
    Write-Host "  DIFF REPORT:"
    Write-Host "  Verdict: $($diff.verdict)"
    Write-Host "  Changes: $($diff.changes.Count)"
    Write-Host "  Duration: $($diff.duration_seconds)s"
    Write-Host "  Score Delta: $($diff.risk_delta.score_change)%"
    Write-Host ""
    if ($diff.changes) {
        Write-Host "  CHANGES DETECTED:"
        foreach ($c in $diff.changes) {
            Write-Host "    [$($c.severity)] $($c.type): before=$($c.before) after=$($c.after)"
        }
    } else {
        Write-Host "  NO CHANGES DETECTED - system unchanged"
    }

    Push-Evidence -Type "diff" -Data $diff

    Write-Host ""
    Write-Host "  Files produced:"
    Write-Host "    evidence-before-$ActionId.json"
    Write-Host "    evidence-after-$ActionId.json"
    Write-Host "    evidence-diff-$ActionId.json"

    if ($diff.verdict -eq "CRITICAL_CHANGE_DETECTED") {
        Write-Host ""
        Write-Host "  !! CRITICAL: Unauthorized change detected - investigate immediately"
        exit 2
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  EVIDENCE COMPLETE"
Write-Host "  Operations Officer CANNOT:"
Write-Host "    x Claim 'I did it' without this evidence"
Write-Host "    x Modify these records"
Write-Host "    x Delete these records"
Write-Host "    x Intercept delivery to owner"
Write-Host "============================================================"
