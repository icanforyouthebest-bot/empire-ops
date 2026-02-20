# ===============================================================
# SEOBAIKE Website Health Monitor
# Checks all endpoints, workers, edge functions, APIs
# Reports to Supabase WORM audit log
# ===============================================================
param(
    [string]$SupabaseUrl = $env:SUPABASE_URL,
    [string]$SupabaseKey = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$SiteUrl     = "https://seobaike.com",
    [string]$WorkerUrl   = "https://seobaike-remote-control.icanforyouthebest.workers.dev"
)

function Write-Audit {
    param([string]$Check, [string]$Status, [string]$Detail, [string]$Severity = "info")
    Write-Host "  [$Status] $Check | $Detail"
    if ($SupabaseUrl -and $SupabaseKey) {
        $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
        $entry = @{ layer="WebsiteHealth"; check_name=$Check; status=$Status; action="MONITOR"; detail=$Detail; severity=$Severity; source="seobaike-health-monitor" }
        try { Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null } catch {}
    }
}

function Test-Endpoint {
    param([string]$Url, [string]$Name, [int]$ExpectedStatus = 200)
    try {
        $start = Get-Date
        $resp  = Invoke-WebRequest -Uri $Url -Method GET -TimeoutSec 15 -UseBasicParsing -SkipCertificateCheck 2>&1
        $ms    = [int]((Get-Date) - $start).TotalMilliseconds
        if ($resp.StatusCode -eq $ExpectedStatus) {
            Write-Audit -Check $Name -Status "OK" -Detail "HTTP $($resp.StatusCode) in ${ms}ms"
            return @{ ok = $true; status = $resp.StatusCode; ms = $ms }
        } else {
            Write-Audit -Check $Name -Status "DRIFT" -Detail "HTTP $($resp.StatusCode) (expected $ExpectedStatus) in ${ms}ms" -Severity "high"
            return @{ ok = $false; status = $resp.StatusCode; ms = $ms }
        }
    } catch {
        Write-Audit -Check $Name -Status "FAILED" -Detail "Error: $($_.Exception.Message)" -Severity "critical"
        return @{ ok = $false; status = 0; ms = -1 }
    }
}

Write-Host "============================================================"
Write-Host "  SEOBAIKE HEALTH MONITOR"
Write-Host "  Site: $SiteUrl"
Write-Host "  Worker: $WorkerUrl"
Write-Host "============================================================"

$results = @{}

# ── 1. Main site ──────────────────────────────────────────────
Write-Host ""
Write-Host "[1/5] Main site..."
$results["main-site"] = Test-Endpoint -Url $SiteUrl -Name "SEOBAIKE-Main"

# ── 2. Worker health ──────────────────────────────────────────
Write-Host ""
Write-Host "[2/5] Cloudflare Worker..."
$results["worker"] = Test-Endpoint -Url "$WorkerUrl/health" -Name "CF-Worker-Health"

# ── 3. Supabase API ───────────────────────────────────────────
Write-Host ""
Write-Host "[3/5] Supabase API..."
if ($SupabaseUrl) {
    $results["supabase"] = Test-Endpoint -Url "$SupabaseUrl/rest/v1/" -Name "Supabase-API" -ExpectedStatus 200
}

# ── 4. AI Gateway Edge Function ───────────────────────────────
Write-Host ""
Write-Host "[4/5] AI Governance Gateway..."
if ($SupabaseUrl) {
    $results["ai-gateway"] = Test-Endpoint -Url "$SupabaseUrl/functions/v1/ai-governance-gateway" -Name "AI-Gateway"
}

# ── 5. Governance audit log accessibility ─────────────────────
Write-Host ""
Write-Host "[5/5] Governance Audit Log..."
if ($SupabaseUrl -and $SupabaseKey) {
    $h = @{ "Authorization" = "Bearer $SupabaseKey"; "apikey" = $SupabaseKey }
    try {
        $count = Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log?select=id&limit=1" -Headers $h
        Write-Audit -Check "AuditLog-Health" -Status "OK" -Detail "WORM audit log accessible and healthy"
        $results["audit-log"] = @{ ok = $true }
    } catch {
        Write-Audit -Check "AuditLog-Health" -Status "FAILED" -Detail "Audit log unreachable: $($_.Exception.Message)" -Severity "critical"
        $results["audit-log"] = @{ ok = $false }
    }
}

# ── Summary ───────────────────────────────────────────────────
$ok    = ($results.Values | Where-Object { $_.ok }).Count
$total = $results.Count

$overallStatus = if ($ok -eq $total) { "OK" } elseif ($ok -ge ($total * 0.8)) { "WARN" } else { "CRITICAL" }
Write-Audit -Check "WebsiteHealth-Summary" -Status $overallStatus -Detail "$ok/$total endpoints healthy" -Severity $(if ($overallStatus -eq "CRITICAL") { "critical" } else { "info" })

Write-Host ""
Write-Host "============================================================"
Write-Host "  HEALTH CHECK: $overallStatus ($ok/$total healthy)"
Write-Host "============================================================"

if ($overallStatus -ne "OK") { exit 1 }
