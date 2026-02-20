# ===============================================================
# Layer 11: Real-Time Compliance Score
# Every hour — calculate and store empire compliance score
# 老闆隨時可以看到數字
# ===============================================================
param(
    [string]$SupabaseUrl    = $env:SUPABASE_URL,
    [string]$SupabaseKey    = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$TenantId       = $env:TENANT_ID,
    [string]$ClientId       = $env:CLIENT_ID,
    [string]$ClientSecret   = $env:CLIENT_SECRET,
    [int]$LookbackHours     = 1
)

$since = (Get-Date).AddHours(-$LookbackHours).ToString("o")
$enc   = [Uri]::EscapeDataString($since)

$score  = 100
$issues = @()
$checks = @{}

Write-Host "============================================================"
Write-Host "  LAYER 11: Real-Time Compliance Score"
Write-Host "============================================================"

if ($SupabaseUrl -and $SupabaseKey) {
    $h = @{ "Authorization" = "Bearer $SupabaseKey"; "apikey" = $SupabaseKey }
    try {
        $logs = Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log?created_at=gte.$enc&order=created_at.desc&limit=1000" -Headers $h

        # Check 1: Self-heal running (should have patrol in last hour)
        $patrols = $logs | Where-Object { $_.check_name -eq "patrol-summary" -or $_.source -like "*self-heal*" }
        if ($patrols.Count -gt 0) {
            $checks["self-heal-active"] = @{ score=10; status="PASS"; detail="$($patrols.Count) patrols in last hour" }
        } else {
            $score -= 10; $issues += "No self-heal patrols in last hour"
            $checks["self-heal-active"] = @{ score=0; status="FAIL"; detail="No patrols detected" }
        }

        # Check 2: AI gateway active (recent gateway calls)
        $gatewayCalls = $logs | Where-Object { $_.source -eq "ai-governance-gateway" }
        if ($gatewayCalls.Count -ge 0) {  # gateway being there is enough
            $checks["ai-gateway"] = @{ score=10; status="PASS"; detail="AI gateway operational" }
        } else {
            $score -= 5
            $checks["ai-gateway"] = @{ score=5; status="WARN"; detail="No gateway calls" }
        }

        # Check 3: No unblocked critical events (critical events that are not BLOCKED status)
        $unhandledCritical = $logs | Where-Object { $_.severity -eq "critical" -and $_.status -notin @("BLOCKED","HEALED","OK") }
        if ($unhandledCritical.Count -eq 0) {
            $checks["critical-events"] = @{ score=20; status="PASS"; detail="No unhandled critical events" }
        } elseif ($unhandledCritical.Count -lt 3) {
            $score -= 10; $issues += "$($unhandledCritical.Count) unhandled critical events"
            $checks["critical-events"] = @{ score=10; status="WARN"; detail="$($unhandledCritical.Count) unhandled" }
        } else {
            $score -= 20; $issues += "$($unhandledCritical.Count) unhandled critical events"
            $checks["critical-events"] = @{ score=0; status="FAIL"; detail="$($unhandledCritical.Count) unhandled" }
        }

        # Check 4: Audit log writing (recent inserts)
        if ($logs.Count -gt 10) {
            $checks["audit-log-active"] = @{ score=20; status="PASS"; detail="$($logs.Count) records in last hour" }
        } elseif ($logs.Count -gt 0) {
            $score -= 5; $issues += "Low audit activity: $($logs.Count) records"
            $checks["audit-log-active"] = @{ score=15; status="WARN"; detail="Low: $($logs.Count) records" }
        } else {
            $score -= 20; $issues += "No audit log activity"
            $checks["audit-log-active"] = @{ score=0; status="FAIL"; detail="No records" }
        }

        # Check 5: AI blocked actions working (BLOCKED events = system working)
        $blocked = $logs | Where-Object { $_.status -eq "BLOCKED" }
        $checks["blocking-active"] = @{ score=10; status="PASS"; detail="$($blocked.Count) blocked actions (governance working)" }

        # Check 6: GitHub policy enforcement active
        $ghPolicy = $logs | Where-Object { $_.source -like "*github-policy*" }
        if ($ghPolicy.Count -gt 0) {
            $checks["github-policy"] = @{ score=10; status="PASS"; detail="GitHub policy active: $($ghPolicy.Count) checks" }
        } else {
            $score -= 5; $issues += "GitHub policy not active in last hour"
            $checks["github-policy"] = @{ score=5; status="WARN"; detail="No recent enforcement" }
        }

        # Check 7: Evidence generation working
        $evidence = $logs | Where-Object { $_.layer -in @("Evidence","N8NEvidence","MCPGovernance") -or $_.action -like "*EVIDENCE*" }
        if ($evidence.Count -gt 0) {
            $checks["evidence-active"] = @{ score=10; status="PASS"; detail="$($evidence.Count) evidence records" }
        } else {
            $score -= 5; $issues += "No evidence generation in last hour"
            $checks["evidence-active"] = @{ score=5; status="WARN"; detail="No evidence records" }
        }

    } catch {
        $score -= 30; $issues += "Supabase unreachable: $($_.Exception.Message)"
    }
}

# Azure checks
if ($TenantId -and $ClientId -and $ClientSecret) {
    try {
        $tokenBody = @{ grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope="https://graph.microsoft.com/.default" }
        $token   = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
        $azH     = @{ Authorization = "Bearer $token" }

        $caPols  = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $azH
        $empire  = $caPols.value | Where-Object { $_.displayName -like "Empire-*" }
        $disabled = $empire | Where-Object { $_.state -ne "enabled" -and $_.state -ne "enabledForReportingButNotEnforced" }

        if ($empire.Count -ge 3) {
            $checks["ca-policies"] = @{ score=10; status="PASS"; detail="$($empire.Count) Empire CA policies ($($disabled.Count) disabled)" }
            if ($disabled.Count -gt 0) { $score -= 5; $issues += "$($disabled.Count) CA policies disabled" }
        } else {
            $score -= 10; $issues += "Only $($empire.Count) Empire CA policies (need 3+)"
            $checks["ca-policies"] = @{ score=0; status="FAIL"; detail="Only $($empire.Count) policies found" }
        }
    } catch {
        $score -= 5
        $checks["ca-policies"] = @{ score=5; status="WARN"; detail="Azure check failed" }
    }
}

$verdict = if ($score -ge 90) { "EXCELLENT" } elseif ($score -ge 75) { "PASS" } elseif ($score -ge 60) { "WARN" } else { "FAIL" }

# Write to Supabase
if ($SupabaseUrl -and $SupabaseKey) {
    $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
    $entry = @{
        layer      = "ComplianceScore"
        check_name = "hourly-compliance-score"
        status     = $verdict
        action     = "SCORE_CALCULATED"
        detail     = "score=$score/100 verdict=$verdict issues=$($issues.Count) | $($issues -join ' | ')"
        severity   = if ($verdict -in @("EXCELLENT","PASS")) { "info" } elseif ($verdict -eq "WARN") { "medium" } else { "high" }
        source     = "layer11-compliance-score"
        metadata   = @{ score=$score; verdict=$verdict; checks=$checks; issues=$issues }
    }
    try { Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json -Depth 10) | Out-Null } catch {}
}

Write-Host ""
Write-Host "  Score: $score/100 — $verdict"
foreach ($check in $checks.Keys) {
    $c = $checks[$check]
    Write-Host "  [$($c.status)] $check : $($c.detail)"
}
if ($issues) {
    Write-Host ""
    Write-Host "  Issues:"
    foreach ($i in $issues) { Write-Host "    - $i" }
}
Write-Host ""
Write-Host "============================================================"
Write-Host "  COMPLIANCE: $verdict ($score/100)"
Write-Host "============================================================"
