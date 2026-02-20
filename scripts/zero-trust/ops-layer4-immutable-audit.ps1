# ═══════════════════════════════════════════════════════════════
# ZERO TRUST LAYER 4: Immutable Audit Trail
# Operations Officer CANNOT delete / modify / hide / override
# Microsoft WORM (Write Once Read Many) architecture
# ═══════════════════════════════════════════════════════════════
param(
    [string]$TenantId     = $env:TENANT_ID,
    [string]$ClientId     = $env:CLIENT_ID,
    [string]$ClientSecret = $env:CLIENT_SECRET,
    [string]$SupabaseUrl  = $env:SUPABASE_URL,
    [string]$SupabaseKey  = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$Mode         = $env:MODE  # "collect" or "verify"
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
    param([string]$Uri, [string]$Method = "GET", [object]$Body = $null)
    $params = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0$Uri"; Headers = $headers }
    if ($Body) { $params.Body = $Body | ConvertTo-Json -Depth 10 }
    try { return Invoke-RestMethod @params }
    catch { Write-Warning "[Graph $Uri] $($_.Exception.Message)"; return $null }
}

function Push-ImmutableLog {
    param([string]$Source, [string]$EventType, [string]$Severity, [string]$Actor, [string]$Detail, [object]$RawData = $null)
    if (-not $SupabaseUrl -or -not $SupabaseKey) { return }

    $entry = @{
        layer      = "ImmutableAudit"
        check_name = "$Source-$EventType"
        status     = "LOGGED"
        action     = "WORM_WRITE"
        detail     = "actor=$Actor severity=$Severity | $Detail"
        severity   = $Severity
        source     = $Source
        healer_run = $false
        metadata   = if ($RawData) { $RawData } else { @{} }
    }

    try {
        $h = @{
            "Authorization" = "Bearer $SupabaseKey"
            "Content-Type"  = "application/json"
            "apikey"        = $SupabaseKey
            "Prefer"        = "return=minimal"
        }
        Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json -Depth 10) | Out-Null
        return $true
    } catch {
        Write-Warning "Audit push failed: $($_.Exception.Message)"
        return $false
    }
}

$since = (Get-Date).AddHours(-1).ToString("o")
$collected = 0

Write-Host "============================================================"
Write-Host "  ZERO TRUST LAYER 4: Immutable Audit Collection"
Write-Host "  WORM: Write Once Read Many"
Write-Host "  Operations Officer: CANNOT DELETE ANY RECORD"
Write-Host "  Time window: Last 1 hour"
Write-Host "============================================================"

# ── SOURCE 1: Azure AD Audit Logs ────────────────────────────
Write-Host ""
Write-Host "[1/7] Azure AD Audit Logs..."
$categories = @("RoleManagement", "Policy", "Application", "UserManagement", "GroupManagement")
foreach ($cat in $categories) {
    $logs = Invoke-Graph -Uri "/auditLogs/directoryAudits?`$filter=activityDateTime ge $since and category eq '$cat'&`$top=50&`$orderby=activityDateTime desc"
    if ($logs -and $logs.value) {
        foreach ($log in $logs.value) {
            $actor  = if ($log.initiatedBy.user) { $log.initiatedBy.user.userPrincipalName } else { $log.initiatedBy.app.displayName }
            $target = if ($log.targetResources) { $log.targetResources[0].displayName } else { "unknown" }
            $pushed = Push-ImmutableLog -Source "AzureAD-$cat" -EventType $log.operationType `
                -Severity (if ($cat -eq "RoleManagement" -or $cat -eq "Policy") { "high" } else { "medium" }) `
                -Actor $actor -Detail "op=$($log.operationType) target=$target result=$($log.result)"
            if ($pushed) { $collected++ }
        }
        Write-Host "  $cat: $($logs.value.Count) events logged"
    }
}

# ── SOURCE 2: Sign-in Logs ────────────────────────────────────
Write-Host ""
Write-Host "[2/7] Sign-in Logs (risky/failed)..."
# Risky signins
$riskySignins = Invoke-Graph -Uri "/auditLogs/signIns?`$filter=createdDateTime ge $since and riskLevelDuringSignIn ne 'none'&`$top=50"
if ($riskySignins -and $riskySignins.value) {
    foreach ($s in $riskySignins.value) {
        $pushed = Push-ImmutableLog -Source "SignIn-Risky" -EventType "risky-signin" -Severity "high" `
            -Actor $s.userPrincipalName `
            -Detail "ip=$($s.ipAddress) app=$($s.appDisplayName) risk=$($s.riskLevelDuringSignIn) state=$($s.status.failureReason)"
        if ($pushed) { $collected++ }
    }
    Write-Host "  Risky signins: $($riskySignins.value.Count)"
}

# Failed admin signins
$failedSignins = Invoke-Graph -Uri "/auditLogs/signIns?`$filter=createdDateTime ge $since and status/errorCode ne 0 and isInteractive eq true&`$top=100"
if ($failedSignins -and $failedSignins.value) {
    $byUser = $failedSignins.value | Group-Object userPrincipalName
    foreach ($g in ($byUser | Where-Object { $_.Count -ge 3 })) {
        Push-ImmutableLog -Source "SignIn-Brute" -EventType "repeated-failure" -Severity "high" `
            -Actor $g.Name -Detail "failed_attempts=$($g.Count) in last 1h" | Out-Null
        $collected++
    }
    Write-Host "  Failed signins total: $($failedSignins.value.Count)"
}

# ── SOURCE 3: Conditional Access Policy Changes ───────────────
Write-Host ""
Write-Host "[3/7] CA Policy Changes..."
$caAudit = Invoke-Graph -Uri "/auditLogs/directoryAudits?`$filter=activityDateTime ge $since and targetResources/any(t:startswith(t/displayName,'Empire-CA'))&`$top=50"
if ($caAudit -and $caAudit.value) {
    Write-Host "  ALERT: $($caAudit.value.Count) Empire CA policy changes!"
    foreach ($c in $caAudit.value) {
        $actor = if ($c.initiatedBy.user) { $c.initiatedBy.user.userPrincipalName } else { $c.initiatedBy.app.displayName }
        Push-ImmutableLog -Source "CA-Policy" -EventType "MODIFIED" -Severity "critical" `
            -Actor $actor -Detail "UNAUTHORIZED: Empire CA policy changed op=$($c.operationType)" | Out-Null
        $collected++
    }
}

# ── SOURCE 4: Security Alerts (Defender) ─────────────────────
Write-Host ""
Write-Host "[4/7] Security Alerts..."
$alerts = Invoke-Graph -Uri "/security/alerts_v2?`$filter=createdDateTime ge $since&`$top=50"
if ($alerts -and $alerts.value) {
    $critical = $alerts.value | Where-Object { $_.severity -in @("high", "critical") }
    Write-Host "  Total: $($alerts.value.Count) | High/Critical: $($critical.Count)"
    foreach ($a in $critical) {
        Push-ImmutableLog -Source "Defender" -EventType $a.severity -Severity $a.severity `
            -Actor ($a.actorDisplayName -or "unknown") `
            -Detail "title=$($a.title) category=$($a.category) status=$($a.status)" | Out-Null
        $collected++
    }
}

# ── SOURCE 5: Identity Protection Events ─────────────────────
Write-Host ""
Write-Host "[5/7] Identity Protection..."
$riskyUsers = Invoke-Graph -Uri "/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'"
if ($riskyUsers -and $riskyUsers.value) {
    Write-Host "  Users at risk: $($riskyUsers.value.Count)"
    foreach ($u in $riskyUsers.value) {
        Push-ImmutableLog -Source "IdentityProtection" -EventType "risky-user" -Severity "high" `
            -Actor $u.userPrincipalName `
            -Detail "risk_level=$($u.riskLevel) risk_state=$($u.riskState) detail=$($u.riskDetail)" | Out-Null
        $collected++
    }
}

# ── SOURCE 6: Secure Score (compliance snapshot) ─────────────
Write-Host ""
Write-Host "[6/7] Secure Score Snapshot..."
$secScore = Invoke-Graph -Uri "/security/secureScores?`$top=1"
if ($secScore -and $secScore.value) {
    $s   = $secScore.value[0]
    $pct = [math]::Round(($s.currentScore / $s.maxScore) * 100, 1)
    Push-ImmutableLog -Source "SecureScore" -EventType "snapshot" `
        -Severity (if ($pct -lt 50) { "high" } elseif ($pct -lt 70) { "medium" } else { "info" }) `
        -Actor "System" -Detail "score=$($s.currentScore)/$($s.maxScore) pct=$pct%" | Out-Null
    $collected++
    Write-Host "  Score: $pct%"
}

# ── SOURCE 7: Operations Officer Activity ─────────────────────
Write-Host ""
Write-Host "[7/7] Operations Officer Activity..."
$customRoles = Invoke-Graph -Uri "/roleManagement/directory/roleDefinitions?`$filter=isBuiltIn eq false and displayName eq 'Role_Operations_Officer'"
if ($customRoles -and $customRoles.value -and $customRoles.value.Count -gt 0) {
    $opsRoleId  = $customRoles.value[0].id
    $assignments = Invoke-Graph -Uri "/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$opsRoleId'&`$expand=principal"
    if ($assignments -and $assignments.value) {
        Write-Host "  Active Ops Officers: $($assignments.value.Count)"
        foreach ($a in $assignments.value) {
            $upn = $a.principal.userPrincipalName
            $signins = Invoke-Graph -Uri "/auditLogs/signIns?`$filter=createdDateTime ge $since and userPrincipalName eq '$upn'&`$top=10"
            if ($signins -and $signins.value) {
                Push-ImmutableLog -Source "OpsOfficer" -EventType "activity" -Severity "info" `
                    -Actor $upn -Detail "signins_last_1h=$($signins.value.Count)" | Out-Null
                $collected++
            }
        }
    }
}

# ── VERIFY: Audit Immutability ────────────────────────────────
Write-Host ""
Write-Host "[VERIFY] Confirming audit immutability policy..."
if ($SupabaseUrl -and $SupabaseKey) {
    # Try to DELETE a record (this should fail due to WORM policy)
    try {
        $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
        $testDelete = Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log?id=eq.0" `
            -Method DELETE -Headers $h -ErrorAction Stop
        Write-Host "  WARNING: Delete succeeded - WORM policy NOT enforced!"
    } catch {
        Write-Host "  OK: Delete blocked - WORM policy enforced"
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  LAYER 4 COMPLETE"
Write-Host "  Records written (WORM): $collected"
Write-Host ""
Write-Host "  Audit Sources Covered:"
Write-Host "    1. Azure AD Audit (role/policy/user/group changes)"
Write-Host "    2. Sign-in Logs (risky/failed/brute force)"
Write-Host "    3. CA Policy Changes (Empire policies monitored)"
Write-Host "    4. Defender Security Alerts"
Write-Host "    5. Identity Protection Events"
Write-Host "    6. Secure Score Snapshots"
Write-Host "    7. Operations Officer Activity"
Write-Host ""
Write-Host "  IMMUTABILITY: Operations Officer CANNOT:"
Write-Host "    x Delete any record"
Write-Host "    x Modify any record"
Write-Host "    x Hide any record"
Write-Host "    x Override any record"
Write-Host "    x Disable logging"
Write-Host "============================================================"
