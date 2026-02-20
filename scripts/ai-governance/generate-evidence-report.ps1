# ===============================================================
# Evidence Report Generator
# Auto-generates comprehensive 3-hour summary for owner review
# "老闆 3 小時後回來給微軟看證據就好了"
# ===============================================================
param(
    [string]$SupabaseUrl  = $env:SUPABASE_URL,
    [string]$SupabaseKey  = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$TenantId     = $env:TENANT_ID,
    [string]$ClientId     = $env:CLIENT_ID,
    [string]$ClientSecret = $env:CLIENT_SECRET,
    [int]$HoursBack       = 3,
    [string]$OutputFile   = "empire-evidence-report.json"
)

$reportTime = Get-Date -Format "o"
$since      = (Get-Date).AddHours(-$HoursBack).ToString("o")
$report     = @{
    generated_at        = $reportTime
    period_hours        = $HoursBack
    period_from         = $since
    mandate             = "All AI and automated processes must use controlled entry and produce Before/After/Diff evidence. No evidence = Not executed."
    github_actions      = @{}
    azure_activity      = @{}
    evidence_summary    = @{}
    compliance_status   = "UNKNOWN"
    high_risk_events    = @()
    ai_activity         = @{}
    self_heal_summary   = @{}
    recommendations     = @()
}

Write-Host "============================================================"
Write-Host "  EMPIRE EVIDENCE REPORT"
Write-Host "  Period: Last $HoursBack hours"
Write-Host "  From:   $since"
Write-Host "  To:     $reportTime"
Write-Host "============================================================"

# ── 1. Supabase Governance Audit Log ─────────────────────────
Write-Host ""
Write-Host "[1/5] Querying governance_audit_log..."
if ($SupabaseUrl -and $SupabaseKey) {
    try {
        $h = @{ "Authorization" = "Bearer $SupabaseKey"; "apikey" = $SupabaseKey }
        $logs = Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log?created_at=gte.$since&order=created_at.desc&limit=1000" -Headers $h

        $totalLogs   = $logs.Count
        $bySeverity  = $logs | Group-Object severity | ForEach-Object { @{ $_.Name = $_.Count } }
        $bySource    = $logs | Group-Object source   | ForEach-Object { @{ $_.Name = $_.Count } }
        $byStatus    = $logs | Group-Object status   | ForEach-Object { @{ $_.Name = $_.Count } }
        $critical    = $logs | Where-Object { $_.severity -in @("critical", "high") }
        $evidenceLogs = $logs | Where-Object { $_.source -eq "layer7-evidence" -or $_.source -eq "ai-agent-wrapper" }
        $healLogs    = $logs | Where-Object { $_.healer_run -eq $true }

        $report.evidence_summary = @{
            total_records         = $totalLogs
            by_severity           = ($logs | Group-Object severity | ForEach-Object { [pscustomobject]@{ key = $_.Name; count = $_.Count } })
            by_source             = ($logs | Group-Object source   | ForEach-Object { [pscustomobject]@{ key = $_.Name; count = $_.Count } })
            evidence_triplets     = $evidenceLogs.Count
            self_heal_events      = $healLogs.Count
            critical_high_events  = $critical.Count
        }

        $report.high_risk_events = ($critical | Select-Object -First 10 | ForEach-Object {
            @{ time = $_.created_at; source = $_.source; check = $_.check_name; detail = $_.detail }
        })

        $healRuns = $logs | Where-Object { $_.check_name -eq "patrol-summary" }
        if ($healRuns) {
            $latestHeal = $healRuns | Sort-Object created_at -Descending | Select-Object -First 1
            $report.self_heal_summary = @{
                patrol_runs    = $healRuns.Count
                last_patrol    = $latestHeal.created_at
                last_status    = $latestHeal.status
                last_detail    = $latestHeal.detail
            }
        }

        $aiLogs = $logs | Where-Object { $_.source -eq "ai-agent-wrapper" }
        if ($aiLogs) {
            $report.ai_activity = @{
                total_ai_operations = $aiLogs.Count
                agents              = ($aiLogs | Group-Object { ($_.detail -split "agent=")[1].split(" ")[0] } | ForEach-Object { @{ $_.Name = $_.Count } })
                blocked             = ($aiLogs | Where-Object { $_.status -eq "BLOCKED" }).Count
                compliant           = ($aiLogs | Where-Object { $_.status -eq "PASS" }).Count
            }
        }

        Write-Host "  Total audit records: $totalLogs"
        Write-Host "  Critical/High events: $($critical.Count)"
        Write-Host "  Evidence triplets: $($evidenceLogs.Count)"
        Write-Host "  Self-heal events: $($healLogs.Count)"
    } catch {
        Write-Warning "  Supabase query failed: $($_.Exception.Message)"
        $report.evidence_summary = @{ error = $_.Exception.Message }
    }
}

# ── 2. GitHub Actions Activity ───────────────────────────────
Write-Host ""
Write-Host "[2/5] GitHub Actions Activity..."
if ($env:GH_TOKEN) {
    try {
        $ghHeaders = @{ "Authorization" = "Bearer $env:GH_TOKEN"; "Accept" = "application/vnd.github+json" }
        $repos = @("icanforyouthebest-bot/SEOBAIKE", "icanforyouthebest-bot/empire-ops", "icanforyouthebest-bot/e5-automation", "icanforyouthebest-bot/seobaike-saas")
        $ghSummary = @{}
        foreach ($repo in $repos) {
            try {
                $runs = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/actions/runs?per_page=20" -Headers $ghHeaders
                $recentRuns = $runs.workflow_runs | Where-Object { [datetime]$_.created_at -gt [datetime]$since }
                $ghSummary[$repo] = @{
                    total_runs  = $recentRuns.Count
                    success     = ($recentRuns | Where-Object { $_.conclusion -eq "success" }).Count
                    failure     = ($recentRuns | Where-Object { $_.conclusion -eq "failure" }).Count
                    in_progress = ($recentRuns | Where-Object { $_.status -eq "in_progress" }).Count
                }
            } catch { $ghSummary[$repo] = @{ error = $_.Exception.Message } }
        }
        $report.github_actions = $ghSummary
        foreach ($repo in $repos) {
            $s = $ghSummary[$repo]
            Write-Host "  $($repo.Split('/')[1]): runs=$($s.total_runs) ok=$($s.success) fail=$($s.failure)"
        }
    } catch {
        Write-Warning "  GitHub query failed: $($_.Exception.Message)"
    }
}

# ── 3. Azure Activity ────────────────────────────────────────
Write-Host ""
Write-Host "[3/5] Azure Activity (Microsoft Graph)..."
if ($TenantId -and $ClientId -and $ClientSecret) {
    try {
        $tokenBody = @{
            grant_type    = "client_credentials"; client_id = $ClientId
            client_secret = $ClientSecret; scope = "https://graph.microsoft.com/.default"
        }
        $token   = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
        $headers = @{ Authorization = "Bearer $token" }

        # Secure score
        $score = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1" -Headers $headers
        $secureScorePct = 0
        if ($score -and $score.value) {
            $s = $score.value[0]
            $secureScorePct = [math]::Round(($s.currentScore / $s.maxScore) * 100, 1)
        }

        # CA Policies
        $caPolicies = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers
        $empirePolicies = ($caPolicies.value | Where-Object { $_.displayName -like "Empire-*" })
        $disabledEmpire = ($empirePolicies | Where-Object { $_.state -ne "enabled" })

        # Risky users
        $risky = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'" -Headers $headers

        $report.azure_activity = @{
            secure_score_pct        = $secureScorePct
            empire_ca_policies      = $empirePolicies.Count
            disabled_empire_policies = $disabledEmpire.Count
            risky_users             = $risky.value.Count
            compliance              = if ($disabledEmpire.Count -eq 0 -and $risky.value.Count -eq 0) { "PASS" } else { "FAIL" }
        }

        Write-Host "  Secure Score: $secureScorePct%"
        Write-Host "  Empire CA Policies: $($empirePolicies.Count) ($($disabledEmpire.Count) disabled)"
        Write-Host "  Risky Users: $($risky.value.Count)"
    } catch {
        Write-Warning "  Azure query failed: $($_.Exception.Message)"
    }
}

# ── 4. Compliance Verdict ────────────────────────────────────
Write-Host ""
Write-Host "[4/5] Calculating compliance verdict..."
$complianceScore = 100
$issues = @()

if ($report.azure_activity.disabled_empire_policies -gt 0) {
    $complianceScore -= 30
    $issues += "CA policies disabled: $($report.azure_activity.disabled_empire_policies)"
}
if ($report.azure_activity.risky_users -gt 0) {
    $complianceScore -= 20
    $issues += "Risky users detected: $($report.azure_activity.risky_users)"
}
if ($report.azure_activity.secure_score_pct -lt 40) {
    $complianceScore -= 20
    $issues += "Secure score critical: $($report.azure_activity.secure_score_pct)%"
}
if ($report.evidence_summary.critical_high_events -gt 10) {
    $complianceScore -= 10
    $issues += "High volume critical events: $($report.evidence_summary.critical_high_events)"
}

$report.compliance_status = if ($complianceScore -ge 80) { "PASS" } elseif ($complianceScore -ge 60) { "WARN" } else { "FAIL" }
$report.compliance_score  = $complianceScore
$report.compliance_issues = $issues
$report.recommendations   = $issues | ForEach-Object { "RESOLVE: $_" }

Write-Host "  Compliance Score: $complianceScore/100"
Write-Host "  Status: $($report.compliance_status)"

# ── 5. Write Report ──────────────────────────────────────────
Write-Host ""
Write-Host "[5/5] Writing report..."
$report | ConvertTo-Json -Depth 15 | Out-File -FilePath $OutputFile -Encoding utf8

# Push report summary to Supabase
if ($SupabaseUrl -and $SupabaseKey) {
    try {
        $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
        $entry = @{
            layer      = "EvidenceReport"
            check_name = "3h-summary"
            status     = $report.compliance_status
            action     = "REPORT_GENERATED"
            detail     = "score=$complianceScore/100 issues=$($issues.Count) critical=$($report.evidence_summary.critical_high_events)"
            severity   = if ($report.compliance_status -eq "PASS") { "info" } elseif ($report.compliance_status -eq "WARN") { "medium" } else { "high" }
            source     = "evidence-report"
        }
        Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null
    } catch {}
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  EVIDENCE REPORT COMPLETE"
Write-Host "  File: $OutputFile"
Write-Host "  Compliance: $($report.compliance_status) ($complianceScore/100)"
Write-Host ""
Write-Host "  === WHAT THE OWNER SEES IN 3 HOURS ==="
Write-Host "  Mandate: All AI must use controlled entry + evidence"
Write-Host "  Audit Records: $($report.evidence_summary.total_records)"
Write-Host "  High-Risk Events: $($report.evidence_summary.critical_high_events)"
Write-Host "  Self-Heal Patrols: $($report.self_heal_summary.patrol_runs)"
Write-Host "  Compliance Score: $complianceScore/100"
if ($issues) {
    Write-Host "  Issues to resolve:"
    foreach ($i in $issues) { Write-Host "    - $i" }
}
Write-Host "============================================================"
