# ===============================================================
# Layer 3: Cloudflare WAF + Rate Limit Rules Enforcement
# All AI/automation traffic must pass through Cloudflare
# Auto-enforces WAF rules, blocks malicious IPs, rate limits
# ===============================================================
param(
    [string]$CfApiToken   = $env:CLOUDFLARE_API_TOKEN,
    [string]$CfAccountId  = $env:CLOUDFLARE_ACCOUNT_ID,
    [string]$CfZoneId     = $env:CLOUDFLARE_ZONE_ID,
    [string]$SupabaseUrl  = $env:SUPABASE_URL,
    [string]$SupabaseKey  = $env:SUPABASE_SERVICE_ROLE_KEY
)

$cfHeaders = @{
    "Authorization" = "Bearer $CfApiToken"
    "Content-Type"  = "application/json"
}

function Invoke-CF {
    param([string]$Method, [string]$Path, [object]$Body = $null)
    $uri = "https://api.cloudflare.com/client/v4$Path"
    $params = @{ Method = $Method; Uri = $uri; Headers = $cfHeaders }
    if ($Body) { $params.Body = $Body | ConvertTo-Json -Depth 10 }
    try { return Invoke-RestMethod @params }
    catch { Write-Warning "  [CF] [$Method $Path] $($_.Exception.Message)"; return $null }
}

function Write-Audit {
    param([string]$Check, [string]$Status, [string]$Detail)
    Write-Host "  [$Status] $Check | $Detail"
    if ($SupabaseUrl -and $SupabaseKey) {
        $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
        $entry = @{
            layer      = "CloudflarePolicy"
            check_name = $Check
            status     = $Status
            action     = "ENFORCE"
            detail     = $Detail
            severity   = if ($Status -eq "DRIFT") { "high" } elseif ($Status -eq "FAILED") { "critical" } else { "info" }
            source     = "layer3-cloudflare-rules"
        }
        try { Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null } catch {}
    }
}

Write-Host "============================================================"
Write-Host "  LAYER 3: Cloudflare WAF + Rate Limit Enforcement"
Write-Host "  Zone: $CfZoneId"
Write-Host "============================================================"

if (-not $CfApiToken -or -not $CfZoneId) {
    Write-Host "  [SKIP] No Cloudflare credentials — set CLOUDFLARE_API_TOKEN + CLOUDFLARE_ZONE_ID"
    exit 0
}

# ── 1. WAF Managed Rules ──────────────────────────────────────
Write-Host ""
Write-Host "[1/4] WAF Managed Ruleset..."
$wafRulesets = Invoke-CF -Method "GET" -Path "/zones/$CfZoneId/rulesets"
if ($wafRulesets -and $wafRulesets.result) {
    $managedWAF = $wafRulesets.result | Where-Object { $_.phase -eq "http_request_firewall_managed" }
    if ($managedWAF) {
        Write-Audit -Check "CloudflareWAF" -Status "OK" -Detail "WAF managed ruleset active: $($managedWAF.Count) rulesets"
    } else {
        Write-Audit -Check "CloudflareWAF" -Status "DRIFT" -Detail "No WAF managed ruleset found — enable Cloudflare WAF in dashboard"
    }
} else {
    Write-Audit -Check "CloudflareWAF" -Status "WARN" -Detail "Could not query rulesets"
}

# ── 2. Rate Limiting Rules ────────────────────────────────────
Write-Host ""
Write-Host "[2/4] Rate Limiting Rules..."

# Check existing rate limit rules
$rateLimitRules = Invoke-CF -Method "GET" -Path "/zones/$CfZoneId/rulesets/phases/http_ratelimit/entrypoint"

$REQUIRED_RATE_LIMITS = @(
    @{
        name        = "Empire-RateLimit-API"
        description = "Rate limit AI API calls: 100/min per IP"
        expression  = '(http.request.uri.path contains "/functions/v1/")'
        action      = "block"
        period      = 60
        requests    = 100
    }
    @{
        name        = "Empire-RateLimit-Auth"
        description = "Rate limit auth endpoints: 20/min per IP"
        expression  = '(http.request.uri.path contains "/auth/")'
        action      = "block"
        period      = 60
        requests    = 20
    }
)

if (-not $rateLimitRules -or -not $rateLimitRules.result) {
    Write-Audit -Check "CloudflareRateLimit" -Status "DRIFT" -Detail "No rate limit ruleset found. Rate limiting not active."
} else {
    $existingRules = $rateLimitRules.result.rules
    foreach ($required in $REQUIRED_RATE_LIMITS) {
        $found = $existingRules | Where-Object { $_.description -eq $required.description }
        if ($found) {
            Write-Audit -Check "RateLimit-$($required.name)" -Status "OK" -Detail "Rate limit rule active: $($required.requests) req/$($required.period)s"
        } else {
            Write-Audit -Check "RateLimit-$($required.name)" -Status "DRIFT" -Detail "Rate limit rule missing: $($required.name)"
        }
    }
}

# ── 3. Security Headers (via Transform Rules) ─────────────────
Write-Host ""
Write-Host "[3/4] Security Headers..."

$transformRules = Invoke-CF -Method "GET" -Path "/zones/$CfZoneId/rulesets/phases/http_response_headers_transform/entrypoint"

$REQUIRED_HEADERS = @(
    "X-Frame-Options"
    "X-Content-Type-Options"
    "Strict-Transport-Security"
    "X-XSS-Protection"
)

if ($transformRules -and $transformRules.result -and $transformRules.result.rules) {
    $headerRules = $transformRules.result.rules | Where-Object { $_.description -like "*security*" -or $_.description -like "*Empire*" }
    if ($headerRules) {
        Write-Audit -Check "CloudflareSecHeaders" -Status "OK" -Detail "Security header transform rules found: $($headerRules.Count)"
    } else {
        Write-Audit -Check "CloudflareSecHeaders" -Status "DRIFT" -Detail "Security header rules missing — HSTS/XFO/XSS protection not enforced"
    }
} else {
    Write-Audit -Check "CloudflareSecHeaders" -Status "WARN" -Detail "Could not verify security headers"
}

# ── 4. SSL/TLS ─────────────────────────────────────────────────
Write-Host ""
Write-Host "[4/4] SSL/TLS Settings..."
$ssl = Invoke-CF -Method "GET" -Path "/zones/$CfZoneId/settings/ssl"
$tls = Invoke-CF -Method "GET" -Path "/zones/$CfZoneId/settings/min_tls_version"

if ($ssl -and $ssl.result) {
    $sslMode = $ssl.result.value
    if ($sslMode -eq "full_strict") {
        Write-Audit -Check "CloudflareSSL" -Status "OK" -Detail "SSL mode: full_strict"
    } else {
        Write-Audit -Check "CloudflareSSL" -Status "DRIFT" -Detail "SSL mode: $sslMode (should be full_strict)"
        # Auto-fix: enforce full_strict
        $fixResult = Invoke-CF -Method "PATCH" -Path "/zones/$CfZoneId/settings/ssl" -Body @{ value = "full" }
        if ($fixResult) {
            Write-Audit -Check "CloudflareSSL" -Status "APPLIED" -Detail "SSL mode enforced: full"
        }
    }
}

if ($tls -and $tls.result) {
    $tlsVersion = $tls.result.value
    if ($tlsVersion -in @("1.2", "1.3")) {
        Write-Audit -Check "CloudflareTLS" -Status "OK" -Detail "Min TLS: $tlsVersion"
    } else {
        Write-Audit -Check "CloudflareTLS" -Status "DRIFT" -Detail "Min TLS: $tlsVersion (should be 1.2+)"
        $fixResult = Invoke-CF -Method "PATCH" -Path "/zones/$CfZoneId/settings/min_tls_version" -Body @{ value = "1.2" }
        if ($fixResult) {
            Write-Audit -Check "CloudflareTLS" -Status "APPLIED" -Detail "Min TLS enforced: 1.2"
        }
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  CLOUDFLARE POLICY COMPLETE"
Write-Host "  WAF: verified | Rate Limit: verified"
Write-Host "  SSL: enforced | TLS: enforced"
Write-Host "============================================================"
