# ===============================================================
# Setup Secretary Bot — Register Telegram Webhook
# 把小白秘書接到你的 Telegram
# ===============================================================
param(
    [string]$BotToken  = $env:TELEGRAM_BOT_TOKEN,
    [string]$SupabaseRef = "vmyrivxxibqydccurxug",
    [string]$FunctionName = "secretary-bot"
)

if (-not $BotToken) {
    Write-Host "SKIP: Set TELEGRAM_BOT_TOKEN"
    exit 0
}

$webhookUrl = "https://$SupabaseRef.supabase.co/functions/v1/$FunctionName"

Write-Host "============================================================"
Write-Host "  SETUP SECRETARY BOT"
Write-Host "  Bot Token: $($BotToken.Substring(0,10))..."
Write-Host "  Webhook: $webhookUrl"
Write-Host "============================================================"

# Set webhook
$setWebhook = "https://api.telegram.org/bot$BotToken/setWebhook"
$payload    = @{ url = $webhookUrl; allowed_updates = @("message") } | ConvertTo-Json

try {
    $result = Invoke-RestMethod -Uri $setWebhook -Method POST -Body $payload -ContentType "application/json"
    if ($result.ok) {
        Write-Host "  [OK] Webhook set: $webhookUrl"
        Write-Host "  小白秘書已連接 Telegram"
        Write-Host ""
        Write-Host "  使用方式："
        Write-Host "  → 直接傳訊息給 Bot"
        Write-Host "  → 例如：系統狀態如何？"
        Write-Host "  → 例如：最新合規分數？"
        Write-Host "  → 例如：有沒有被封鎖的 AI？"
        Write-Host "  → 例如：切換 AI 到 nvidia-ai"
    } else {
        Write-Warning "  Webhook failed: $($result.description)"
    }
} catch {
    Write-Warning "  Error: $($_.Exception.Message)"
}

# Get bot info
try {
    $me = Invoke-RestMethod -Uri "https://api.telegram.org/bot$BotToken/getMe"
    Write-Host ""
    Write-Host "  Bot: @$($me.result.username)"
    Write-Host "  Name: $($me.result.first_name)"
} catch {}

Write-Host "============================================================"
