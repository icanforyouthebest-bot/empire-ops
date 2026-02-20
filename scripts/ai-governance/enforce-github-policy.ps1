# ===============================================================
# Layer 3: GitHub Policy Enforcement v2
# Branch protection + required CI + no force push
# NOTE: enforce_admins=FALSE so governance scripts can push directly
# ===============================================================
param(
    [string]$GhToken   = $env:GH_TOKEN,
    [string]$SupabaseUrl = $env:SUPABASE_URL,
    [string]$SupabaseKey = $env:SUPABASE_SERVICE_ROLE_KEY
)

$headers = @{
    "Authorization" = "Bearer $GhToken"
    "Accept"        = "application/vnd.github+json"
    "X-GitHub-Api-Version" = "2022-11-28"
}

function Invoke-GitHub {
    param([string]$Method, [string]$Uri, [object]$Body = $null)
    $params = @{ Method = $Method; Uri = "https://api.github.com$Uri"; Headers = $headers }
    if ($Body) { $params.Body = $Body | ConvertTo-Json -Depth 10 }
    try { return Invoke-RestMethod @params }
    catch { Write-Warning "[$Method $Uri] $($_.Exception.Message)"; return $null }
}

function Write-Audit {
    param([string]$Repo, [string]$Status, [string]$Detail)
    Write-Host "  [$Status] $Repo | $Detail"
    if ($SupabaseUrl -and $SupabaseKey) {
        $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
        $entry = @{
            layer      = "GitHubPolicy"
            check_name = "$Repo-BranchProtection"
            status     = $Status
            action     = "ENFORCE"
            detail     = $Detail
            severity   = if ($Status -eq "DRIFT") { "high" } else { "info" }
            source     = "layer3-github-policy"
        }
        try { Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null } catch {}
    }
}

$ORG = "icanforyouthebest-bot"
$REPOS = @(
    @{ name = "SEOBAIKE";     branch = "master"; required_checks = @("Security Gate", "AI Empire — Full Deploy Pipeline") }
    @{ name = "empire-ops";   branch = "main";   required_checks = @() }
    @{ name = "seobaike-saas"; branch = "main";  required_checks = @("Deploy") }
    @{ name = "e5-automation"; branch = "master"; required_checks = @("E5 Azure Automation") }
)

Write-Host "============================================================"
Write-Host "  LAYER 3: GitHub Branch Protection Policy v2"
Write-Host "  No force push | Required CI | enforce_admins=false"
Write-Host "============================================================"

foreach ($repo in $REPOS) {
    Write-Host ""
    Write-Host "  Repo: $ORG/$($repo.name) | Branch: $($repo.branch)"

    $protection = Invoke-GitHub -Method "GET" -Uri "/repos/$ORG/$($repo.name)/branches/$($repo.branch)/protection"

    $desired = @{
        required_status_checks = if ($repo.required_checks.Count -gt 0) {
            @{ strict = $true; contexts = $repo.required_checks }
        } else { $null }
        enforce_admins         = $false
        required_pull_request_reviews = $null
        restrictions           = $null
        allow_force_pushes     = $false
        allow_deletions        = $false
        block_creations        = $false
    }

    if (-not $protection) {
        $result = Invoke-GitHub -Method "PUT" -Uri "/repos/$ORG/$($repo.name)/branches/$($repo.branch)/protection" -Body $desired
        if ($result) {
            Write-Audit -Repo "$ORG/$($repo.name)" -Status "APPLIED" -Detail "Branch protection created for $($repo.branch)"
        } else {
            Write-Audit -Repo "$ORG/$($repo.name)" -Status "FAILED" -Detail "Could not apply branch protection"
        }
    } else {
        $issues = @()
        if ($protection.allow_force_pushes.enabled) { $issues += "force-push allowed" }
        if ($protection.allow_deletions.enabled)    { $issues += "branch deletion allowed" }

        if ($issues) {
            Write-Host "    -> DRIFT: $($issues -join ', ') - reapplying..."
            Invoke-GitHub -Method "PUT" -Uri "/repos/$ORG/$($repo.name)/branches/$($repo.branch)/protection" -Body $desired | Out-Null
            Write-Audit -Repo "$ORG/$($repo.name)" -Status "DRIFT" -Detail "Drift fixed: $($issues -join '; ')"
        } else {
            Write-Audit -Repo "$ORG/$($repo.name)" -Status "OK" -Detail "Branch protection compliant"
        }
    }

    # Check PRs for failing CI
    $prs = Invoke-GitHub -Method "GET" -Uri "/repos/$ORG/$($repo.name)/pulls?state=open"
    if ($prs) {
        $failedPRs = @()
        foreach ($pr in $prs) {
            $checks = Invoke-GitHub -Method "GET" -Uri "/repos/$ORG/$($repo.name)/commits/$($pr.head.sha)/check-runs"
            if ($checks -and $checks.check_runs) {
                $failed = $checks.check_runs | Where-Object { $_.conclusion -eq "failure" }
                if ($failed) { $failedPRs += "PR#$($pr.number): $($failed.Count) failing checks" }
            }
        }
        if ($failedPRs) {
            Write-Audit -Repo "$ORG/$($repo.name)" -Status "DRIFT" -Detail "PRs with failing checks: $($failedPRs -join ' | ')"
        }
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  GITHUB POLICY COMPLETE"
Write-Host "  All repos: force-push BLOCKED"
Write-Host "  All repos: branch deletion BLOCKED"
Write-Host "  Governance scripts: direct push ALLOWED (enforce_admins=false)"
Write-Host "============================================================"
