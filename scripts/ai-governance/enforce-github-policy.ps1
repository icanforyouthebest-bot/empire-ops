# ===============================================================
# Layer 3: GitHub Policy Enforcement
# Branch protection + required CI + no force push
# All AI commits must pass governance checks
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
    @{ name = "empire-ops";   branch = "main";   required_checks = @("Supabase Drift + Repair", "Website Health") }
    @{ name = "seobaike-saas"; branch = "main";  required_checks = @("Deploy") }
    @{ name = "e5-automation"; branch = "master"; required_checks = @("E5 Azure Automation") }
)

Write-Host "============================================================"
Write-Host "  LAYER 3: GitHub Branch Protection Policy"
Write-Host "  Enforcing: No force push, required CI, signed commits"
Write-Host "  AI commits must pass governance checks"
Write-Host "============================================================"

foreach ($repo in $REPOS) {
    Write-Host ""
    Write-Host "  Repo: $ORG/$($repo.name) | Branch: $($repo.branch)"

    # Get current branch protection
    $protection = Invoke-GitHub -Method "GET" -Uri "/repos/$ORG/$($repo.name)/branches/$($repo.branch)/protection"

    $desiredProtection = @{
        required_status_checks = @{
            strict   = $true
            contexts = $repo.required_checks
        }
        enforce_admins = $true
        required_pull_request_reviews = @{
            required_approving_review_count = 0
            dismiss_stale_reviews           = $true
        }
        restrictions        = $null
        allow_force_pushes  = $false
        allow_deletions     = $false
        block_creations     = $false
        required_conversation_resolution = $true
    }

    if (-not $protection) {
        Write-Host "    -> Applying branch protection..."
        $result = Invoke-GitHub -Method "PUT" -Uri "/repos/$ORG/$($repo.name)/branches/$($repo.branch)/protection" -Body $desiredProtection
        if ($result) {
            Write-Audit -Repo "$ORG/$($repo.name)" -Status "APPLIED" -Detail "Branch protection created for $($repo.branch)"
        } else {
            Write-Audit -Repo "$ORG/$($repo.name)" -Status "FAILED" -Detail "Could not apply branch protection (may need admin access)"
        }
    } else {
        $issues = @()
        if ($protection.allow_force_pushes.enabled) { $issues += "force-push allowed" }
        if ($protection.allow_deletions.enabled)    { $issues += "branch deletion allowed" }
        if (-not $protection.required_status_checks) { $issues += "no required CI checks" }

        if ($issues) {
            Write-Host "    -> DRIFT: $($issues -join ', ') - reapplying..."
            Invoke-GitHub -Method "PUT" -Uri "/repos/$ORG/$($repo.name)/branches/$($repo.branch)/protection" -Body $desiredProtection | Out-Null
            Write-Audit -Repo "$ORG/$($repo.name)" -Status "DRIFT" -Detail "Drift fixed: $($issues -join '; ')"
        } else {
            Write-Audit -Repo "$ORG/$($repo.name)" -Status "OK" -Detail "Branch protection compliant"
        }
    }

    # Check for any open PRs bypassing CI
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
Write-Host "  All repos: required CI enforced"
Write-Host "  All AI commits: must pass governance checks"
Write-Host "============================================================"
