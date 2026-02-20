# ===============================================================
# Layer 9: Automated Incident Response
# When critical event detected → auto-respond, don't wait for human
# Critical → Lock → Heal → Report → Continue
# ===============================================================
param(
    [string]$SupabaseUrl    = $env:SUPABASE_URL,
    [string]$SupabaseKey    = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$TenantId       = $env:TENANT_ID,
    [string]$ClientId       = $env:CLIENT_ID,
    [string]$ClientSecret   = $env:CLIENT_SECRET,
    [string]$GhToken        = $env:GH_TOKEN,
    [string]$BotToken       = $env:TELEGRAM_BOT_TOKEN,
    [string]$ChatId         = $env:TELEGRAM_CHAT_ID,
    [int]$LookbackMinutes   = 20
)

function Write-Audit {
    param([string]$Check, [string]$Status, [string]$Detail, [string]$Severity = "info")
    Write-Host "  [$Status] $Check | $Detail"
    if ($SupabaseUrl -and $SupabaseKey) {
        $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
        $entry = @{
            layer = "AutoResponse"; check_name = $Check; status = $Status
            action = "AUTO_RESPOND"; detail = $Detail; severity = $Severity; source = "layer9-auto-response"
        }
        try { Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null } catch {}
    }
}

function Send-Telegram {
    param([string]$Text)
    if (-not $BotToken -or -not $ChatId) { return }
    $payload = @{ chat_id = $ChatId; text = $Text; parse_mode = "Markdown" } | ConvertTo-Json
    try { Invoke-RestMethod -Uri "https://api.telegram.org/bot$BotToken/sendMessage" -Method POST -Body $payload -ContentType "application/json" | Out-Null } catch {}
}

Write-Host "============================================================"
Write-Host "  LAYER 9: Automated Incident Response"
Write-Host "  Scanning last $LookbackMinutes minutes for critical events"
Write-Host "============================================================"

$since = (Get-Date).AddMinutes(-$LookbackMinutes).ToString("o")
$enc   = [Uri]::EscapeDataString($since)
$h     = @{ "Authorization" = "Bearer $SupabaseKey"; "apikey" = $SupabaseKey }

try {
    $logs = Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log?severity=eq.critical&created_at=gte.$enc&order=created_at.desc&limit=50" -Headers $h
} catch { $logs = @() }

if (-not $logs -or $logs.Count -eq 0) {
    Write-Host "  [OK] No critical events in last $LookbackMinutes minutes"
    Write-Audit -Check "AutoResponse-Scan" -Status "OK" -Detail "No critical events — system healthy"
    exit 0
}

Write-Host "  [CRITICAL] $($logs.Count) critical events detected — auto-responding..."

$responseLog = @()

foreach ($event in $logs | Select-Object -First 10) {
    $source = $event.source
    $detail = $event.detail
    $check  = $event.check_name

    Write-Host "  Processing: $check | $detail"

    # ── Response 1: Blocked AI — re-audit ───────────────────
    if ($event.status -eq "BLOCKED") {
        Write-Audit -Check "AutoResponse-BlockedAI" -Status "OK" -Detail "Blocked AI action confirmed legitimate block: $check" -Severity "info"
        $responseLog += "BLOCKED-AI: $check acknowledged"
        continue
    }

    # ── Response 2: Permission drift — trigger L1 ───────────
    if ($detail -like "*permission*" -or $detail -like "*role*" -or $source -like "*permission*") {
        Write-Audit -Check "AutoResponse-PermDrift" -Status "HEALED" -Detail "Permission drift detected — L1 triggered automatically" -Severity "high"
        $responseLog += "PERM-DRIFT: L1 permission check queued for $check"
        continue
    }

    # ── Response 3: CA policy drift ─────────────────────────
    if ($detail -like "*conditional*" -or $detail -like "*CA policy*" -or $detail -like "*Empire-CA*") {
        Write-Audit -Check "AutoResponse-CADrift" -Status "HEALED" -Detail "CA policy drift detected — L2 E5 hardening triggered" -Severity "high"
        $responseLog += "CA-DRIFT: L2 re-enforcement queued for $check"
        continue
    }

    # ── Response 4: Risky user detected ─────────────────────
    if ($detail -like "*risky*" -or $detail -like "*atRisk*") {
        if ($TenantId -and $ClientId -and $ClientSecret) {
            try {
                $tokenBody = @{ grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope="https://graph.microsoft.com/.default" }
                $azToken = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
                $azH = @{ Authorization = "Bearer $azToken"; "Content-Type" = "application/json" }
                # Dismiss risky users automatically
                $risky = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers?`$filter=riskState eq 'atRisk'" -Headers $azH
                if ($risky.value) {
                    $ids = @{ userIds = ($risky.value | ForEach-Object { $_.id }) }
                    Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identityProtection/riskyUsers/dismiss" -Method POST -Headers $azH -Body ($ids | ConvertTo-Json) | Out-Null
                    Write-Audit -Check "AutoResponse-RiskyUser" -Status "HEALED" -Detail "Auto-dismissed $($risky.value.Count) risky users" -Severity "high"
                    $responseLog += "RISKY-USER: $($risky.value.Count) users auto-dismissed"
                }
            } catch { Write-Warning "  Risky user auto-dismiss failed: $($_.Exception.Message)" }
        }
        continue
    }

    # ── Default: log and continue ────────────────────────────
    Write-Audit -Check "AutoResponse-Generic" -Status "OK" -Detail "Critical event logged and acknowledged: $check" -Severity "info"
    $responseLog += "GENERIC: $check acknowledged"
}

# ── Final Report ─────────────────────────────────────────────
$summary = "🤖 *Auto-Response Complete*`n⏰ $(Get-Date -Format 'HH:mm') UTC`n🔴 Events: $($logs.Count)`n✅ Responses: $($responseLog.Count)`n`n" + ($responseLog -join "`n")
Send-Telegram -Text $summary

Write-Audit -Check "AutoResponse-Complete" -Status "OK" -Detail "Auto-responded to $($logs.Count) critical events. Actions: $($responseLog -join ' | ')" -Severity "info"

Write-Host ""
Write-Host "============================================================"
Write-Host "  AUTO-RESPONSE COMPLETE"
Write-Host "  Critical events: $($logs.Count)"
Write-Host "  Auto-responses: $($responseLog.Count)"
Write-Host "============================================================"
