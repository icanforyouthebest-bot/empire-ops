# ===============================================================
# AI Agent Wrapper - Empire AI Governance Framework
# Every AI action must go through this wrapper
# Enforces: Controlled Entry + Before/After/Diff + Audit
# ===============================================================
param(
    [string]$AgentName      = $env:AI_AGENT_NAME,       # e.g. "claude-code", "github-actions"
    [string]$AgentVersion   = $env:AI_AGENT_VERSION,    # e.g. "claude-sonnet-4-6"
    [string]$ActionName     = $env:AI_ACTION_NAME,       # what this agent is doing
    [string]$TriggerSource  = $env:TRIGGER_SOURCE,      # "schedule" | "webhook" | "manual" | "ai-decision"
    [string]$TriggerBy      = $env:TRIGGER_BY,          # UPN or "system"
    [string]$TenantId       = $env:TENANT_ID,
    [string]$ClientId       = $env:CLIENT_ID,
    [string]$ClientSecret   = $env:CLIENT_SECRET,
    [string]$SupabaseUrl    = $env:SUPABASE_URL,
    [string]$SupabaseKey    = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$WorkflowRunId  = $env:GITHUB_RUN_ID,
    [string]$CommitSha      = $env:GITHUB_SHA
)

# ── AI Registry (only registered agents allowed) ─────────────
$REGISTERED_AGENTS = @(
    "claude-code"
    "github-actions"
    "azure-automation"
    "supabase-edge"
    "empire-self-heal"
    "empire-governance"
    "e5-automation"
    "seobaike-deploy"
    "seobaike-security-gate"
)

$ACTION_ID = [System.Guid]::NewGuid().ToString()
$CHAIN_ID  = [System.Guid]::NewGuid().ToString()

function Write-AuditEntry {
    param([string]$Step, [string]$Status, [string]$Detail, [string]$Severity = "info")
    $entry = @{
        layer      = "AIGovernance"
        check_name = "$AgentName-$Step"
        status     = $Status
        action     = $ActionName
        detail     = "agent=$AgentName action=$ActionName trigger=$TriggerSource by=$TriggerBy chain=$CHAIN_ID | $Detail"
        severity   = $Severity
        source     = "ai-agent-wrapper"
        metadata   = @{
            agent_name      = $AgentName
            agent_version   = $AgentVersion
            action_id       = $ACTION_ID
            chain_id        = $CHAIN_ID
            workflow_run_id = $WorkflowRunId
            commit_sha      = $CommitSha
            trigger_source  = $TriggerSource
            trigger_by      = $TriggerBy
        }
    }
    Write-Host "  [$($Status.PadRight(8))] $AgentName | $Step | $Detail"
    if ($SupabaseUrl -and $SupabaseKey) {
        try {
            $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
            Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json -Depth 10) | Out-Null
        } catch {}
    }
}

function Block-Agent {
    param([string]$Reason)
    Write-AuditEntry -Step "BLOCKED" -Status "BLOCKED" -Detail $Reason -Severity "critical"
    Write-Host ""
    Write-Host "============================================================"
    Write-Host "  AI AGENT BLOCKED"
    Write-Host "  Agent:  $AgentName"
    Write-Host "  Action: $ActionName"
    Write-Host "  Reason: $Reason"
    Write-Host "============================================================"
    exit 1
}

function Get-SystemSnapshot {
    param([string]$Phase)
    $snapshot = @{
        phase          = $Phase
        action_id      = $ACTION_ID
        chain_id       = $CHAIN_ID
        ai_agent       = $AgentName
        ai_version     = $AgentVersion
        triggered_by   = $TriggerBy
        trigger_source = $TriggerSource
        workflow_run   = $WorkflowRunId
        timestamp      = (Get-Date -Format "o")
        ca_policies    = @()
        admin_roles    = @()
        secure_score   = $null
        risky_users    = 0
    }

    if ($TenantId -and $ClientId -and $ClientSecret) {
        try {
            $tokenBody = @{
                grant_type = "client_credentials"; client_id = $ClientId
                client_secret = $ClientSecret; scope = "https://graph.microsoft.com/.default"
            }
            $token   = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
            $headers = @{ Authorization = "Bearer $token" }

            $ca = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/identity/conditionalAccess/policies" -Headers $headers
            if ($ca -and $ca.value) {
                $snapshot.ca_policies = $ca.value | ForEach-Object { @{ name = $_.displayName; state = $_.state } }
            }
            $score = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/security/secureScores?`$top=1" -Headers $headers
            if ($score -and $score.value) {
                $s = $score.value[0]
                $snapshot.secure_score = @{ current = $s.currentScore; max = $s.maxScore; pct = [math]::Round(($s.currentScore/$s.maxScore)*100,1) }
            }
        } catch {
            $snapshot.graph_error = $_.Exception.Message
        }
    }
    return $snapshot
}

Write-Host "============================================================"
Write-Host "  EMPIRE AI GOVERNANCE WRAPPER"
Write-Host "  Agent:   $AgentName v$AgentVersion"
Write-Host "  Action:  $ActionName"
Write-Host "  Trigger: $TriggerSource by $TriggerBy"
Write-Host "  ChainID: $CHAIN_ID"
Write-Host "  Time:    $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') UTC"
Write-Host "============================================================"

# ── GATE 1: AI Registry Check ────────────────────────────────
Write-Host ""
Write-Host "[GATE-1] AI Registry Check..."
if (-not $AgentName) {
    Block-Agent "No AI agent name provided. All AI must identify themselves."
}
if ($AgentName -notin $REGISTERED_AGENTS) {
    Block-Agent "AI agent '$AgentName' is NOT in the registry. Register first."
}
Write-AuditEntry -Step "Registry" -Status "PASS" -Detail "Agent registered and verified"

# ── GATE 2: Action must be declared ──────────────────────────
Write-Host "[GATE-2] Action Declaration Check..."
if (-not $ActionName) {
    Block-Agent "AI must declare what action it is performing."
}
Write-AuditEntry -Step "Declaration" -Status "PASS" -Detail "Action declared: $ActionName"

# ── GATE 3: Trigger source must be declared ───────────────────
Write-Host "[GATE-3] Trigger Source Check..."
$VALID_TRIGGERS = @("schedule", "webhook", "manual", "ai-decision", "self-heal", "governance")
if ($TriggerSource -notin $VALID_TRIGGERS) {
    Block-Agent "Invalid trigger source: '$TriggerSource'. Must be one of: $($VALID_TRIGGERS -join ', ')"
}
Write-AuditEntry -Step "Trigger" -Status "PASS" -Detail "Trigger source valid: $TriggerSource"

# ── CAPTURE: Before Snapshot ─────────────────────────────────
Write-Host ""
Write-Host "[EVIDENCE] Capturing BEFORE snapshot..."
$beforeSnapshot = Get-SystemSnapshot -Phase "before"
$beforeSnapshot | ConvertTo-Json -Depth 10 | Out-File -FilePath "evidence-before-$ACTION_ID.json" -Encoding utf8
Write-AuditEntry -Step "Before" -Status "CAPTURED" -Detail "Before snapshot: action_id=$ACTION_ID"
Write-Host "  Before evidence: evidence-before-$ACTION_ID.json"

# ── EXECUTION GATE ────────────────────────────────────────────
Write-Host ""
Write-Host "============================================================"
Write-Host "  ALL GATES PASSED"
Write-Host "  AI Agent '$AgentName' is authorized to proceed"
Write-Host "  Evidence chain started: $CHAIN_ID"
Write-Host "  Before snapshot captured"
Write-Host "  >>> AI ACTION BEGINS NOW <<<"
Write-Host "============================================================"

# Return the ACTION_ID so the caller can use it for After + Diff
$env:EMPIRE_ACTION_ID = $ACTION_ID
$env:EMPIRE_CHAIN_ID  = $CHAIN_ID

# Write to output for GitHub Actions
if ($env:GITHUB_OUTPUT) {
    "action_id=$ACTION_ID" | Out-File -FilePath $env:GITHUB_OUTPUT -Append
    "chain_id=$CHAIN_ID"   | Out-File -FilePath $env:GITHUB_OUTPUT -Append
}

Write-Host ""
Write-Host "  ACTION_ID: $ACTION_ID"
Write-Host "  CHAIN_ID:  $CHAIN_ID"
Write-Host "  Use these IDs for After + Diff evidence capture"
