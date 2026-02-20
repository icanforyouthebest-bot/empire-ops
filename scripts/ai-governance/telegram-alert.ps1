# ===============================================================
# Telegram Alert Integration — Empire Governance
# Sends critical/high governance events to Telegram
# Runs after every patrol cycle
# ===============================================================
param(
    [string]$BotToken    = $env:TELEGRAM_BOT_TOKEN,
    [string]$ChatId      = $env:TELEGRAM_CHAT_ID,
    [string]$SupabaseUrl = $env:SUPABASE_URL,
    [string]$SupabaseKey = $env:SUPABASE_SERVICE_ROLE_KEY,
    [int]$LookbackMinutes = 20
)

if (-not $BotToken -or -not $ChatId) {
    Write-Host "  [SKIP] No Telegram credentials — set TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID"
    exit 0
}

$since = (Get-Date).AddMinutes(-$LookbackMinutes).ToString("o")

# Query recent critical/high events from Supabase
$h = @{ "Authorization" = "Bearer $SupabaseKey"; "apikey" = $SupabaseKey }
$encoded_since = [Uri]::EscapeDataString($since)
try {
    $logs = Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log?severity=in.(critical,high)&created_at=gte.$encoded_since&order=created_at.desc&limit=10" -Headers $h
} catch {
    Write-Warning "  Supabase query failed: $($_.Exception.Message)"
    exit 0
}

if (-not $logs -or $logs.Count -eq 0) {
    Write-Host "  [OK] No critical/high events in last $LookbackMinutes minutes"
    exit 0
}

# Format message
$lines = @(
    "🚨 *Empire Governance Alert*"
    "⏰ $(Get-Date -Format 'yyyy-MM-dd HH:mm') UTC"
    "🔍 $($logs.Count) critical/high event(s) in last $LookbackMinutes min"
    ""
)

foreach ($log in $logs | Select-Object -First 5) {
    $icon = if ($log.severity -eq "critical") { "🔴" } else { "🟠" }
    $lines += "$icon [$($log.source)] $($log.check_name)"
    $lines += "   Status: $($log.status) | $($log.detail.Substring(0, [Math]::Min(80, $log.detail.Length)))"
    $lines += ""
}

if ($logs.Count -gt 5) {
    $lines += "_(+$($logs.Count - 5) more events)_"
}

$lines += ""
$lines += "🔗 View: https://supabase.com/dashboard/project/vmyrivxxibqydccurxug"

$message = $lines -join "`n"

# Send to Telegram
$tgUrl = "https://api.telegram.org/bot$BotToken/sendMessage"
$payload = @{
    chat_id    = $ChatId
    text       = $message
    parse_mode = "Markdown"
} | ConvertTo-Json

try {
    $result = Invoke-RestMethod -Uri $tgUrl -Method POST -Body $payload -ContentType "application/json"
    Write-Host "  [SENT] Telegram alert: $($logs.Count) events -> chat $ChatId"
} catch {
    Write-Warning "  Telegram send failed: $($_.Exception.Message)"
}
