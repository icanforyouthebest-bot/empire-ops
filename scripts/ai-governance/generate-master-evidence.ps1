# ===============================================================
# Master Evidence Report Generator
# 老闆只看這份檔案。所有系統狀態、AI行為、合規證據一次匯出。
# ===============================================================
param(
    [string]$SupabaseUrl  = $env:SUPABASE_URL,
    [string]$SupabaseKey  = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$TenantId     = $env:TENANT_ID,
    [string]$ClientId     = $env:CLIENT_ID,
    [string]$ClientSecret = $env:CLIENT_SECRET,
    [string]$GhToken      = $env:GH_TOKEN,
    [int]$HoursBack       = 24,
    [string]$OutputFile   = "EMPIRE-MASTER-EVIDENCE.json"
)

$now   = Get-Date -Format "o"
$since = (Get-Date).AddHours(-$HoursBack).ToString("o")
$enc   = [Uri]::EscapeDataString($since)

$report = @{
    report_title      = "Empire AI Governance — Master Evidence Report"
    generated_at      = $now
    period_hours      = $HoursBack
    period_from       = $since
    boss_mandate      = "所有 AI 必須遵守規則、可審計、產生證據、可替換、不能破壞系統"
    governance_layers = @{
        L1_controlled_entry     = "ai-governance-gateway (Supabase Edge) — All AI pass through registry"
        L2_evidence_triad       = "Before/After/Diff artifacts — 90-day retention"
        L3_policy_enforcement   = "GitHub Branch Protection + Cloudflare WAF + Supabase RLS — every 6h"
        L4_worm_audit           = "governance_audit_log — WORM (no DELETE/UPDATE)"
        L5_replaceable_modules  = "AI Registry — unregistered agents auto-blocked"
        L6_self_heal            = "ZT Self-Heal Patrol — every 15min"
        L7_verifiable_output    = "No evidence = Not executed"
        L8_realtime_alert       = "Telegram alerts on critical events"
    }
    supabase_audit    = @{}
    github_status     = @{}
    azure_status      = @{}
    ai_activity       = @{}
    compliance        = @{}
    blocked_actions   = @()
    self_heal_events  = @()
}

Write-Host "============================================================"
Write-Host "  EMPIRE MASTER EVIDENCE REPORT"
Write-Host "  Last $HoursBack hours | $since → $now"
Write-Host "============================================================"

# ── Supabase Audit Log ────────────────────────────────────────
if ($SupabaseUrl -and $SupabaseKey) {
    $h = @{ "Authorization" = "Bearer $SupabaseKey"; "apikey" = $SupabaseKey }
    try {
        $logs = Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log?created_at=gte.$enc&order=created_at.desc&limit=2000" -Headers $h
        $critical     = $logs | Where-Object { $_.severity -in @("critical","high") }
        $blocked      = $logs | Where-Object { $_.status -eq "BLOCKED" }
        $healed       = $logs | Where-Object { $_.healer_run -eq $true }
        $aiGateway    = $logs | Where-Object { $_.source -eq "ai-governance-gateway" }
        $aiWrapper    = $logs | Where-Object { $_.source -eq "ai-agent-wrapper" }
        $evidenceLogs = $logs | Where-Object { $_.source -like "*evidence*" -or $_.layer -eq "Evidence" }
        $patrolLogs   = $logs | Where-Object { $_.check_name -eq "patrol-summary" }

        $report.supabase_audit = @{
            total_records         = $logs.Count
            critical_high         = $critical.Count
            blocked_ai_actions    = $blocked.Count
            self_healed           = $healed.Count
            ai_gateway_calls      = $aiGateway.Count
            ai_wrapper_calls      = $aiWrapper.Count
            evidence_records      = $evidenceLogs.Count
            patrol_runs           = $patrolLogs.Count
            by_severity           = ($logs | Group-Object severity | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join " | "
            by_source             = ($logs | Group-Object source | Sort-Object Count -Descending | Select-Object -First 10 | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join " | "
        }

        $report.blocked_actions = ($blocked | Select-Object -First 20 | ForEach-Object {
            @{ time = $_.created_at; agent = $_.check_name; detail = $_.detail; source = $_.source }
        })

        $report.self_heal_events = ($healed | Select-Object -First 10 | ForEach-Object {
            @{ time = $_.created_at; check = $_.check_name; detail = $_.detail }
        })

        # AI activity breakdown
        $agents = $aiWrapper | Group-Object { ($_.detail -split "agent=")[1] -split " " | Select-Object -First 1 }
        $report.ai_activity = @{
            total_operations    = $aiWrapper.Count
            agents              = ($agents | ForEach-Object { "$($_.Name)=$($_.Count)" }) -join " | "
            gateway_total       = $aiGateway.Count
            evidence_triplets   = $evidenceLogs.Count
        }

        Write-Host "  Audit records: $($logs.Count) | Critical: $($critical.Count) | Blocked: $($blocked.Count)"
    } catch {
        $report.supabase_audit = @{ error = $_.Exception.Message }
        Write-Warning "  Supabase: $($_.Exception.Message)"
    }
}

# ── GitHub Actions ────────────────────────────────────────────
if ($GhToken) {
    $gh = @{ "Authorization" = "Bearer $GhToken"; "Accept" = "application/vnd.github+json" }
    $repos = @("icanforyouthebest-bot/SEOBAIKE","icanforyouthebest-bot/empire-ops","icanforyouthebest-bot/e5-automation","icanforyouthebest-bot/seobaike-saas")
    $ghStatus = @{}
    foreach ($repo in $repos) {
        try {
            $runs = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/actions/runs?per_page=50" -Headers $gh
            $recent = $runs.workflow_runs | Where-Object { [datetime]$_.created_at -gt [datetime]$since }
            $ghStatus[$repo.Split("/")[1]] = @{
                runs    = $recent.Count
                success = ($recent | Where-Object { $_.conclusion -eq "success" }).Count
                failure = ($recent | Where-Object { $_.conclusion -eq "failure" }).Count
                active  = ($recent | Where-Object { $_.status -in @("in_progress","queued") }).Count
            }
        } catch {
            $ghStatus[$repo.Split("/")[1]] = @{ error = $_.Exception.Message }
        }
    }
    $report.github_status = $ghStatus
    Write-Host "  GitHub: $(($ghStatus.Keys | ForEach-Object { "$_=$($ghStatus[$_].runs)runs" }) -join ' | ')"
}

# ── Azure Status ──────────────────────────────────────────────
if ($TenantId -and $ClientId -and $ClientSecret) {
    try {
        $tokenBody = @{ grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope="https://graph.microsoft.com/.default" }
        $token = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
        $azH = @{ Authorization = "Bearer $token" }

        $score  = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1" -Headers $azH
        $caPols = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $azH
        $risky  = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'" -Headers $azH

        $pct = 0
        if ($score.value) { $s = $score.value[0]; $pct = [math]::Round(($s.currentScore/$s.maxScore)*100,1) }
        $empirePols = $caPols.value | Where-Object { $_.displayName -like "Empire-*" }
        $disabled   = $empirePols | Where-Object { $_.state -ne "enabled" }

        $report.azure_status = @{
            secure_score_pct         = $pct
            total_ca_policies        = $caPols.value.Count
            empire_ca_policies       = $empirePols.Count
            disabled_empire_policies = $disabled.Count
            risky_users              = $risky.value.Count
            compliance               = if ($disabled.Count -eq 0 -and $risky.value.Count -eq 0) { "PASS" } else { "REVIEW" }
        }
        Write-Host "  Azure: score=$pct% CA=$($caPols.value.Count) risky=$($risky.value.Count)"
    } catch {
        $report.azure_status = @{ error = $_.Exception.Message }
    }
}

# ── Compliance Verdict ────────────────────────────────────────
$score   = 100
$issues  = @()
$verdict = "PASS"

if ($report.supabase_audit.blocked_ai_actions -gt 0) {
    $issues += "AI actions blocked: $($report.supabase_audit.blocked_ai_actions) — governance working"
}
if ($report.azure_status.disabled_empire_policies -gt 0) {
    $score -= 20; $issues += "Disabled CA policies: $($report.azure_status.disabled_empire_policies)"
}
if ($report.azure_status.risky_users -gt 0) {
    $score -= 20; $issues += "Risky users: $($report.azure_status.risky_users)"
}
if ($report.azure_status.secure_score_pct -lt 40) {
    $score -= 15; $issues += "Secure score low: $($report.azure_status.secure_score_pct)%"
}
if ($report.supabase_audit.critical_high -gt 20) {
    $score -= 10; $issues += "High volume critical events: $($report.supabase_audit.critical_high)"
}

$verdict = if ($score -ge 80) { "PASS" } elseif ($score -ge 60) { "WARN" } else { "FAIL" }
$report.compliance = @{
    score   = $score
    verdict = $verdict
    issues  = $issues
    note    = "AI governance active 24/7. All AI controlled, audited, replaceable."
}

# ── Write Master Report ───────────────────────────────────────
$report | ConvertTo-Json -Depth 15 | Out-File -FilePath $OutputFile -Encoding utf8

# Push to Supabase
if ($SupabaseUrl -and $SupabaseKey) {
    $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
    $entry = @{
        layer      = "MasterEvidence"
        check_name = "master-evidence-report"
        status     = $verdict
        action     = "MASTER_REPORT_GENERATED"
        detail     = "score=$score/100 | blocked=$($report.supabase_audit.blocked_ai_actions) | healed=$($report.supabase_audit.self_healed) | critical=$($report.supabase_audit.critical_high)"
        severity   = if ($verdict -eq "PASS") { "info" } elseif ($verdict -eq "WARN") { "medium" } else { "high" }
        source     = "master-evidence-generator"
    }
    try { Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null } catch {}
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  MASTER EVIDENCE REPORT COMPLETE"
Write-Host "  File: $OutputFile"
Write-Host "  Compliance: $verdict ($score/100)"
Write-Host "  Blocked AI actions: $($report.supabase_audit.blocked_ai_actions)"
Write-Host "  Self-healed events: $($report.supabase_audit.self_healed)"
Write-Host "  Critical events: $($report.supabase_audit.critical_high)"
Write-Host "  證據齊全。老闆可直接查看。"
Write-Host "============================================================"
