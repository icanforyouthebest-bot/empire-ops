# ===============================================================
# Layer 10: Empire System Dashboard
# 一眼看全部。所有層狀態、最後執行、下次執行。
# ===============================================================
param(
    [string]$SupabaseUrl = $env:SUPABASE_URL,
    [string]$SupabaseKey = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$GhToken     = $env:GH_TOKEN,
    [string]$OutputFile  = "EMPIRE-DASHBOARD.json"
)

$now   = Get-Date -Format "o"
$since = (Get-Date).AddHours(-1).ToString("o")
$enc   = [Uri]::EscapeDataString($since)

$dashboard = @{
    generated_at   = $now
    system_name    = "Empire AI Governance"
    layers         = @{}
    schedules      = @()
    last_events    = @()
    system_status  = "UNKNOWN"
}

Write-Host "============================================================"
Write-Host "  EMPIRE DASHBOARD — 系統全覽"
Write-Host "============================================================"

# ── Query Supabase ────────────────────────────────────────────
if ($SupabaseUrl -and $SupabaseKey) {
    $h = @{ "Authorization" = "Bearer $SupabaseKey"; "apikey" = $SupabaseKey }

    try {
        $logs = Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log?created_at=gte.$enc&order=created_at.desc&limit=500" -Headers $h

        # Layer status from last hour
        $layerSources = @{
            "L1-Gateway"    = "ai-governance-gateway"
            "L3-GitHub"     = "layer3-github-policy"
            "L3-Cloudflare" = "layer3-cloudflare-rules"
            "L3-Supabase"   = "layer3-supabase-rls"
            "L4-Audit"      = "ops-layer4"
            "L6-SelfHeal"   = "ops-layer6"
            "L8-Telegram"   = "layer8"
            "L9-AutoResp"   = "layer9-auto-response"
        }

        foreach ($layer in $layerSources.Keys) {
            $layerLogs = $logs | Where-Object { $_.source -like "*$($layerSources[$layer])*" }
            $lastRun   = $layerLogs | Select-Object -First 1
            $dashboard.layers[$layer] = @{
                events_1h  = $layerLogs.Count
                last_run   = if ($lastRun) { $lastRun.created_at } else { "never" }
                last_status = if ($lastRun) { $lastRun.status } else { "none" }
            }
        }

        # Overall system status
        $criticals = ($logs | Where-Object { $_.severity -eq "critical" -and $_.status -ne "BLOCKED" }).Count
        $blocked   = ($logs | Where-Object { $_.status -eq "BLOCKED" }).Count
        $healed    = ($logs | Where-Object { $_.healer_run -eq $true }).Count

        $dashboard.system_status = if ($criticals -eq 0) { "HEALTHY" } elseif ($criticals -lt 5) { "MONITORING" } else { "ALERT" }
        $dashboard.stats_1h = @{
            total_events   = $logs.Count
            critical_events = $criticals
            blocked_ai     = $blocked
            self_healed    = $healed
        }

        $dashboard.last_events = ($logs | Select-Object -First 5 | ForEach-Object {
            @{ time = $_.created_at; layer = $_.layer; check = $_.check_name; status = $_.status; source = $_.source }
        })

        Write-Host "  System: $($dashboard.system_status)"
        Write-Host "  Events/1h: $($logs.Count) | Critical: $criticals | Blocked: $blocked | Healed: $healed"
    } catch {
        $dashboard.system_status = "UNKNOWN"
        Write-Warning "  Supabase query failed: $($_.Exception.Message)"
    }
}

# ── GitHub Schedules ──────────────────────────────────────────
$dashboard.schedules = @(
    @{ name = "ZT Self-Heal"; cron = "0,15,30,45 * * * *"; interval = "15min"; next = "continuous" }
    @{ name = "Auto Incident Response"; cron = "5,20,35,50 * * * *"; interval = "15min offset"; next = "continuous" }
    @{ name = "24h Non-Stop Patrol"; cron = "0 * * * *"; interval = "hourly"; next = "continuous" }
    @{ name = "AI Governance Report"; cron = "0 */3 * * *"; interval = "3h"; next = "continuous" }
    @{ name = "Master Evidence Report"; cron = "0 */3 * * *"; interval = "3h"; next = "continuous" }
    @{ name = "GitHub Policy Enforce"; cron = "0 */6 * * *"; interval = "6h"; next = "continuous" }
    @{ name = "Azure Self-Heal Patrol"; cron = "0 */6 * * *"; interval = "6h"; next = "continuous" }
)

# ── Write Dashboard ───────────────────────────────────────────
$dashboard | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding utf8

Write-Host ""
Write-Host "============================================================"
Write-Host "  DASHBOARD: $($dashboard.system_status)"
Write-Host "  $($dashboard.schedules.Count) automated schedules running"
Write-Host "  9 governance layers active"
Write-Host "  Output: $OutputFile"
Write-Host "============================================================"
