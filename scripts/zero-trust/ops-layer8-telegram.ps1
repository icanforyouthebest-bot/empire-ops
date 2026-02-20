# ===============================================================
# Layer 8: Telegram Real-Time Alert System
# Critical governance events → Telegram immediately
# Replaces human monitoring with automated notification
# ===============================================================
param(
    [string]$BotToken    = $env:TELEGRAM_BOT_TOKEN,
    [string]$ChatId      = $env:TELEGRAM_CHAT_ID,
    [string]$SupabaseUrl = $env:SUPABASE_URL,
    [string]$SupabaseKey = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$EventType   = "patrol",   # patrol | deploy | block | report
    [string]$Summary     = "",
    [string]$Status      = "OK",       # OK | WARN | DRIFT | CRITICAL
    [int]$LookbackMinutes = 20
)

function Send-Telegram {
    param([string]$Text)
    if (-not $BotToken -or -not $ChatId) { return }
    $payload = @{
        chat_id    = $ChatId
        text       = $Text
        parse_mode = "Markdown"
    } | ConvertTo-Json
    try {
        Invoke-RestMethod -Uri "https://api.telegram.org/bot$BotToken/sendMessage" `
            -Method POST -Body $payload -ContentType "application/json" | Out-Null
        Write-Host "  [TELEGRAM] Sent to chat $ChatId"
    } catch {
        Write-Warning "  [TELEGRAM] Send failed: $($_.Exception.Message)"
    }
}

$icon = switch ($Status) {
    "CRITICAL" { "🔴" }
    "DRIFT"    { "🟠" }
    "WARN"     { "🟡" }
    default    { "🟢" }
}

$time = Get-Date -Format "yyyy-MM-dd HH:mm"

# ── Query recent critical events ──────────────────────────────
$criticalCount = 0
$blockedCount  = 0
$healedCount   = 0
$eventLines    = @()

if ($SupabaseUrl -and $SupabaseKey) {
    $h = @{ "Authorization" = "Bearer $SupabaseKey"; "apikey" = $SupabaseKey }
    $since = (Get-Date).AddMinutes(-$LookbackMinutes).ToString("o")
    $enc   = [Uri]::EscapeDataString($since)

    try {
        $logs = Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log?created_at=gte.$enc&order=created_at.desc&limit=200" -Headers $h
        $criticalCount = ($logs | Where-Object { $_.severity -in @("critical","high") }).Count
        $blockedCount  = ($logs | Where-Object { $_.status -eq "BLOCKED" }).Count
        $healedCount   = ($logs | Where-Object { $_.healer_run -eq $true }).Count

        # Top critical events
        $topCritical = $logs | Where-Object { $_.severity -in @("critical","high") } | Select-Object -First 3
        foreach ($e in $topCritical) {
            $eIcon = if ($e.severity -eq "critical") { "🔴" } else { "🟠" }
            $detail = if ($e.detail) { $e.detail.Substring(0, [Math]::Min(60, $e.detail.Length)) } else { "" }
            $eventLines += "$eIcon $($e.source): $detail"
        }
    } catch {}
}

# ── Build message ─────────────────────────────────────────────
$lines = @(
    "$icon *Empire Governance — $EventType*"
    "⏰ $time UTC | Status: *$Status*"
    ""
)

if ($Summary) { $lines += "📋 $Summary"; $lines += "" }

$lines += "📊 Last ${LookbackMinutes}min:"
$lines += "  🔴 Critical/High: $criticalCount"
$lines += "  🚫 Blocked AI actions: $blockedCount"
$lines += "  🔧 Self-healed: $healedCount"

if ($eventLines) {
    $lines += ""
    $lines += "*Top Events:*"
    $lines += $eventLines
}

$lines += ""
$lines += "🔗 [Audit Log](https://supabase.com/dashboard/project/vmyrivxxibqydccurxug/editor)"

Send-Telegram -Text ($lines -join "`n")

# ── Always alert on any CRITICAL ──────────────────────────────
if ($criticalCount -gt 0 -and $Status -ne "CRITICAL") {
    Send-Telegram -Text "🚨 *URGENT* $criticalCount critical event(s) detected! Review immediately."
}

Write-Host "  [L8] Telegram alert sent: $Status | critical=$criticalCount blocked=$blockedCount healed=$healedCount"
