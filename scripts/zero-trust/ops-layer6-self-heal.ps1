# ═══════════════════════════════════════════════════════════════
# ZERO TRUST LAYER 6: Self-Heal (Maximum Coverage)
# Every 15 minutes. Operations Officer CANNOT stop this.
# Checks: Roles / MFA / CA / Defender / Policy / Automation / Audit
# ═══════════════════════════════════════════════════════════════
param(
    [string]$TenantId     = $env:TENANT_ID,
    [string]$ClientId     = $env:CLIENT_ID,
    [string]$ClientSecret = $env:CLIENT_SECRET,
    [string]$SupabaseUrl  = $env:SUPABASE_URL,
    [string]$SupabaseKey  = $env:SUPABASE_SERVICE_ROLE_KEY
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
    param([string]$Method, [string]$Uri, [object]$Body = $null)
    $params = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0$Uri"; Headers = $headers }
    if ($Body) { $params.Body = $Body | ConvertTo-Json -Depth 10 }
    try { return Invoke-RestMethod @params }
    catch { Write-Warning "[$Method $Uri] $($_.Exception.Message)"; return $null }
}

$driftCount = 0
$healCount  = 0
$alertCount = 0

function Write-Check {
    param([string]$Area, [string]$Check, [string]$Status, [string]$Action, [string]$Detail)
    $icon = switch ($Status) {
        "OK"     { "✓" }
        "DRIFT"  { "⚠" }
        "HEALED" { "↺" }
        "ALERT"  { "!" }
        default  { "?" }
    }
    Write-Host "  [$icon] $Area | $Check | $Status | $Action"
    if ($Detail -and $Status -ne "OK") { Write-Host "    Detail: $Detail" }

    if ($SupabaseUrl -and $SupabaseKey) {
        $entry = @{
            layer      = "SelfHeal-L6"
            check_name = "$Area-$Check"
            status     = $Status
            action     = $Action
            detail     = $Detail
            severity   = if ($Status -eq "DRIFT") { "high" } elseif ($Status -eq "ALERT") { "critical" } else { "info" }
            source     = "layer6-self-heal"
            healer_run = $true
        }
        try {
            $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
            Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null
        } catch {}
    }
}

Write-Host "============================================================"
Write-Host "  ZERO TRUST LAYER 6: Self-Heal Patrol"
Write-Host "  Schedule: Every 15 minutes"
Write-Host "  Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
Write-Host "  Operations Officer: CANNOT stop or modify this"
Write-Host "============================================================"

# ════════════════════════════════════════════════════════════
# CHECK 1: ROLE INTEGRITY
# ════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "[CHECK-1] Role Integrity..."

# 1a. Global Admin count
$gaAssign = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '62e90394-69f5-4237-9190-012177145e10'"
if ($gaAssign -and $gaAssign.value) {
    $gaCount = $gaAssign.value.Count
    if ($gaCount -gt 3) {
        $driftCount++; $alertCount++
        Write-Check "IAM" "GlobalAdmin-Count" "ALERT" "ALERT" "GA count=$gaCount exceeds limit of 3"
    } elseif ($gaCount -gt 2) {
        Write-Check "IAM" "GlobalAdmin-Count" "DRIFT" "MONITOR" "GA count=$gaCount (borderline)"
    } else {
        Write-Check "IAM" "GlobalAdmin-Count" "OK" "NONE" "count=$gaCount"
    }
}

# 1b. Role_Operations_Officer exists and is not tampered
$customRoles = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleDefinitions?`$filter=isBuiltIn eq false and displayName eq 'Role_Operations_Officer'"
if (-not $customRoles -or $customRoles.value.Count -eq 0) {
    $driftCount++
    Write-Check "IAM" "OpsRole-Exists" "DRIFT" "RECREATE_NEEDED" "Role_Operations_Officer missing - run layer2"
} else {
    $opsRole     = $customRoles.value[0]
    $permissions = $opsRole.rolePermissions[0].allowedResourceActions
    $dangerous   = $permissions | Where-Object { $_ -like "*allTasks*" -and $_ -notlike "*.read*" }
    if ($dangerous) {
        $driftCount++
        Write-Check "IAM" "OpsRole-Permissions" "DRIFT" "REVERT_NEEDED" "Dangerous permissions in OpsRole: $($dangerous -join ', ')"
    } else {
        Write-Check "IAM" "OpsRole-Permissions" "OK" "NONE" "No dangerous permissions"
    }
}

# ════════════════════════════════════════════════════════════
# CHECK 2: MFA ENFORCEMENT
# ════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "[CHECK-2] MFA Enforcement..."
$caPolicies = Invoke-Graph -Method "GET" -Uri "/identity/conditionalAccess/policies"

$mfaPolicy = $null
if ($caPolicies -and $caPolicies.value) {
    $mfaPolicy = $caPolicies.value | Where-Object { $_.displayName -eq "Empire-CA02-Require-MFA-AllUsers" }
}

if (-not $mfaPolicy) {
    $driftCount++
    Write-Check "MFA" "RequireMFA-AllUsers" "DRIFT" "RECREATE_NEEDED" "MFA enforcement policy missing entirely"
} elseif ($mfaPolicy.state -ne "enabled") {
    $driftCount++
    Invoke-Graph -Method "PATCH" -Uri "/identity/conditionalAccess/policies/$($mfaPolicy.id)" -Body @{ state = "enabled" } | Out-Null
    $healCount++
    Write-Check "MFA" "RequireMFA-AllUsers" "HEALED" "RE_ENABLED" "Was '$($mfaPolicy.state)' - restored to enabled"
} else {
    Write-Check "MFA" "RequireMFA-AllUsers" "OK" "NONE" "MFA enforcement active"
}

# MFA admin policy
$mfaAdminPolicy = $null
if ($caPolicies -and $caPolicies.value) {
    $mfaAdminPolicy = $caPolicies.value | Where-Object { $_.displayName -eq "Empire-CA03-MFA-GlobalAdmins-NoException" }
}
if (-not $mfaAdminPolicy -or $mfaAdminPolicy.state -ne "enabled") {
    $driftCount++
    if ($mfaAdminPolicy -and $mfaAdminPolicy.state -ne "enabled") {
        Invoke-Graph -Method "PATCH" -Uri "/identity/conditionalAccess/policies/$($mfaAdminPolicy.id)" -Body @{ state = "enabled" } | Out-Null
        $healCount++
        Write-Check "MFA" "Admin-MFA-NoException" "HEALED" "RE_ENABLED" "Admin MFA policy restored"
    } else {
        Write-Check "MFA" "Admin-MFA-NoException" "DRIFT" "RECREATE_NEEDED" "Admin MFA policy missing"
    }
} else {
    Write-Check "MFA" "Admin-MFA-NoException" "OK" "NONE" "Admin MFA active (no exceptions)"
}

# ════════════════════════════════════════════════════════════
# CHECK 3: CONDITIONAL ACCESS
# ════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "[CHECK-3] Conditional Access Policies..."

$requiredCAPolicies = @(
    "Empire-CA01-Block-Legacy-Auth"
    "Empire-CA02-Require-MFA-AllUsers"
    "Empire-CA03-MFA-GlobalAdmins-NoException"
)

foreach ($pName in $requiredCAPolicies) {
    $policy = $null
    if ($caPolicies -and $caPolicies.value) {
        $policy = $caPolicies.value | Where-Object { $_.displayName -eq $pName }
    }
    if (-not $policy) {
        $driftCount++
        Write-Check "CA" $pName "DRIFT" "RECREATE_NEEDED" "Policy completely missing"
    } elseif ($policy.state -ne "enabled") {
        $driftCount++
        Invoke-Graph -Method "PATCH" -Uri "/identity/conditionalAccess/policies/$($policy.id)" -Body @{ state = "enabled" } | Out-Null
        $healCount++
        Write-Check "CA" $pName "HEALED" "RE_ENABLED" "Was '$($policy.state)'"
    } else {
        Write-Check "CA" $pName "OK" "NONE" "Active"
    }
}

# ════════════════════════════════════════════════════════════
# CHECK 4: DEFENDER / SECURE SCORE
# ════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "[CHECK-4] Defender & Secure Score..."
$secScore = Invoke-Graph -Method "GET" -Uri "/security/secureScores?`$top=1"
if ($secScore -and $secScore.value) {
    $s   = $secScore.value[0]
    $pct = [math]::Round(($s.currentScore / $s.maxScore) * 100, 1)
    if ($pct -lt 40) {
        $driftCount++; $alertCount++
        Write-Check "Defender" "SecureScore" "ALERT" "IMMEDIATE_ACTION" "Score=$pct% CRITICAL"
    } elseif ($pct -lt 60) {
        Write-Check "Defender" "SecureScore" "DRIFT" "REVIEW" "Score=$pct% below 60%"
    } else {
        Write-Check "Defender" "SecureScore" "OK" "NONE" "Score=$pct%"
    }
}

$activeAlerts = Invoke-Graph -Method "GET" -Uri "/security/alerts_v2?`$filter=status eq 'active' and severity in ('high','critical')&`$top=5"
if ($activeAlerts -and $activeAlerts.value -and $activeAlerts.value.Count -gt 0) {
    $alertCount += $activeAlerts.value.Count
    Write-Check "Defender" "ActiveAlerts" "ALERT" "INVESTIGATE" "$($activeAlerts.value.Count) high/critical alerts active"
} else {
    Write-Check "Defender" "ActiveAlerts" "OK" "NONE" "No high/critical active alerts"
}

# ════════════════════════════════════════════════════════════
# CHECK 5: IDENTITY PROTECTION
# ════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "[CHECK-5] Identity Protection..."
$riskyUsers = Invoke-Graph -Method "GET" -Uri "/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'"
if ($riskyUsers -and $riskyUsers.value -and $riskyUsers.value.Count -gt 0) {
    $driftCount++
    Write-Check "IdP" "RiskyUsers" "DRIFT" "ALERT" "$($riskyUsers.value.Count) users at risk"

    # Auto-dismiss confirmed safe/low risk
    $lowRiskIds = ($riskyUsers.value | Where-Object { $_.riskLevel -eq "low" }).id
    if ($lowRiskIds) {
        Invoke-Graph -Method "POST" -Uri "/identityProtection/riskyUsers/dismiss" -Body @{ userIds = @($lowRiskIds) } | Out-Null
        $healCount++
        Write-Check "IdP" "AutoDismiss-Low" "HEALED" "DISMISSED" "Dismissed $($lowRiskIds.Count) low-risk users"
    }
} else {
    Write-Check "IdP" "RiskyUsers" "OK" "NONE" "No users at risk"
}

# ════════════════════════════════════════════════════════════
# CHECK 6: AUTOMATION INTEGRITY
# ════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "[CHECK-6] Automation Integrity..."
Write-Check "Automation" "SelfHeal-Running" "OK" "NONE" "This check proves automation is running (self-evident)"

# Check Empire-SystemHealer app
$healerApp = Invoke-Graph -Method "GET" -Uri "/applications?`$filter=displayName eq 'Empire-SystemHealer'"
if (-not $healerApp -or $healerApp.value.Count -eq 0) {
    $driftCount++
    Write-Check "Automation" "Empire-SystemHealer" "DRIFT" "RECREATE_NEEDED" "SystemHealer app missing"
} else {
    Write-Check "Automation" "Empire-SystemHealer" "OK" "NONE" "SystemHealer app exists"
}

# ════════════════════════════════════════════════════════════
# CHECK 7: OPERATIONS OFFICER COMPLIANCE
# ════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "[CHECK-7] Operations Officer Compliance..."
if ($customRoles -and $customRoles.value -and $customRoles.value.Count -gt 0) {
    $opsRoleId   = $customRoles.value[0].id
    $assignments = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$opsRoleId'&`$expand=principal"
    $officerCount = if ($assignments -and $assignments.value) { $assignments.value.Count } else { 0 }

    Write-Check "OpsOfficer" "Count" "OK" "NONE" "Active officers: $officerCount"

    if ($assignments -and $assignments.value) {
        $FORBIDDEN_ROLE_IDS = @(
            "62e90394-69f5-4237-9190-012177145e10"  # Global Admin
            "194ae4cb-b126-40b2-bd5b-6091b380977d"  # Security Admin
            "e8611ab8-c189-46e8-94e1-60213ab1f814"  # Privileged Role Admin
        )
        foreach ($a in $assignments.value) {
            $officerRoles = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($a.principalId)'"
            if ($officerRoles -and $officerRoles.value) {
                foreach ($r in $officerRoles.value) {
                    if ($r.roleDefinitionId -in $FORBIDDEN_ROLE_IDS) {
                        $driftCount++
                        Invoke-Graph -Method "DELETE" -Uri "/roleManagement/directory/roleAssignments/$($r.id)" | Out-Null
                        $healCount++
                        Write-Check "OpsOfficer" "ForbiddenRole" "HEALED" "REMOVED" "Officer $($a.principal.userPrincipalName) had forbidden role - REMOVED"
                    }
                }
            }
        }
        Write-Check "OpsOfficer" "RoleCompliance" "OK" "NONE" "All officers checked for forbidden roles"
    }
}

# ════════════════════════════════════════════════════════════
# FINAL SUMMARY
# ════════════════════════════════════════════════════════════
Write-Host ""
Write-Host "============================================================"
Write-Host "  SELF-HEAL PATROL COMPLETE"
Write-Host "  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
Write-Host ""
Write-Host "  Drifts detected: $driftCount"
Write-Host "  Auto-healed:     $healCount"
Write-Host "  Active alerts:   $alertCount"
Write-Host ""
if ($driftCount -eq 0) {
    Write-Host "  STATUS: ALL CLEAR — System operating within policy"
} else {
    Write-Host "  STATUS: DRIFT FOUND — $($driftCount - $healCount) remaining items need attention"
}
Write-Host ""
Write-Host "  System is self-governing."
Write-Host "  Operations Officer cannot stop, modify, or bypass this."
Write-Host "============================================================"

# Write summary to Supabase
if ($SupabaseUrl -and $SupabaseKey) {
    $summary = @{
        layer      = "SelfHeal-L6"
        check_name = "patrol-summary"
        status     = if ($driftCount -eq 0) { "OK" } else { "DRIFT" }
        action     = "SUMMARY"
        detail     = "drift=$driftCount healed=$healCount alerts=$alertCount"
        severity   = if ($alertCount -gt 0) { "critical" } elseif ($driftCount -gt 0) { "high" } else { "info" }
        source     = "layer6-self-heal"
        healer_run = $true
    }
    try {
        $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
        Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($summary | ConvertTo-Json) | Out-Null
    } catch {}
}

if ($alertCount -gt 0) { exit 2 }
if ($driftCount -gt $healCount) { exit 1 }
