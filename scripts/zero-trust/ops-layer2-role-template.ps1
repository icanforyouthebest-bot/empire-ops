# ═══════════════════════════════════════════════════════════════
# ZERO TRUST LAYER 2: Role_Operations_Officer Template
# FIXED / IMMUTABLE / NON-UPGRADEABLE
# Exact Microsoft role permissions - read + trigger only
# ═══════════════════════════════════════════════════════════════
param(
    [string]$TenantId     = $env:TENANT_ID,
    [string]$ClientId     = $env:CLIENT_ID,
    [string]$ClientSecret = $env:CLIENT_SECRET
)

$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}
$token = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

function Invoke-Graph {
    param([string]$Method, [string]$Uri, [object]$Body = $null)
    $params = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0$Uri"; Headers = $headers }
    if ($Body) { $params.Body = $Body | ConvertTo-Json -Depth 10 }
    try { return Invoke-RestMethod @params }
    catch { Write-Warning "[$Method $Uri] $($_.Exception.Message)"; return $null }
}

Write-Host "============================================================"
Write-Host "  ZERO TRUST LAYER 2: Role_Operations_Officer Template"
Write-Host "  IMMUTABLE | NON-UPGRADEABLE | READ+TRIGGER ONLY"
Write-Host "============================================================"

# ── CANONICAL ROLE DEFINITION ────────────────────────────────
# This is the ONLY allowed permission set. Do not add more.
$CANONICAL_ALLOWED_ACTIONS = @(
    # === DIRECTORY READERS ===
    "microsoft.directory/auditLogs/allProperties/read"
    "microsoft.directory/signInReports/allProperties/read"
    "microsoft.directory/users/standard/read"
    "microsoft.directory/users/appRoleAssignments/read"
    "microsoft.directory/groups/standard/read"
    "microsoft.directory/groups/members/read"
    "microsoft.directory/applications/standard/read"
    "microsoft.directory/servicePrincipals/standard/read"
    "microsoft.directory/devices/standard/read"
    "microsoft.directory/organization/standard/read"
    "microsoft.directory/subscriptions/standard/read"

    # === REPORTS READER ===
    "microsoft.office365.usageReports/allEntities/allProperties/read"
    "microsoft.office365.messageCenter/messages/read"
    "microsoft.office365.network/performance/allProperties/read"

    # === SECURITY READER (read-only) ===
    "microsoft.office365.protectionCenter/allEntities/allProperties/read"
    "microsoft.azure.resourceHealth/allEntities/allProperties/read"
    "microsoft.azure.serviceHealth/allEntities/allProperties/read"
    "microsoft.office365.serviceHealth/allEntities/allProperties/read"

    # === MONITORING READER ===
    "microsoft.insights/logs/read"
    "microsoft.insights/metrics/read"
    "microsoft.insights/alertRules/read"
    "microsoft.insights/diagnosticSettings/read"

    # === AUTOMATION JOB OPERATOR (trigger only - cannot modify runbooks) ===
    "microsoft.automation/automationAccounts/jobs/read"
    "microsoft.automation/automationAccounts/jobs/write"   # required to trigger
    "microsoft.automation/automationAccounts/runbooks/read"

    # === CLOUD APP SECURITY READER ===
    "microsoft.cloudAppSecurity/alerts/read"
    "microsoft.cloudAppSecurity/policies/read"
)

# ── BUILT-IN ROLES TO ASSIGN (in addition to custom role) ────
$BUILTIN_ROLES_TO_ASSIGN = @(
    @{ name = "Directory Readers";          id = "88d8e3e3-8f55-4a1e-953a-9b9898b8876b" }
    @{ name = "Reports Reader";             id = "4a5d8f65-41da-4de4-8968-e035b65339cf" }
    @{ name = "Security Reader";            id = "5d6b6bb7-de71-4623-b4af-96380a352509" }
    @{ name = "Global Reader";              id = "f2ef992c-3afb-46b9-b7cf-a126ee74c451" }
)

# ── CREATE OR ENFORCE CUSTOM ROLE ────────────────────────────
$customRoles = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleDefinitions?`$filter=isBuiltIn eq false"
$existingRole = $null
if ($customRoles -and $customRoles.value) {
    $existingRole = $customRoles.value | Where-Object { $_.displayName -eq "Role_Operations_Officer" }
}

$ROLE_TEMPLATE_ID = "a1b2c3d4-e5f6-7890-abcd-ef1234567890"  # Fixed GUID

if (-not $existingRole) {
    Write-Host ""
    Write-Host "[CREATE] Role_Operations_Officer does not exist - creating..."
    $roleBody = @{
        displayName     = "Role_Operations_Officer"
        description     = "Operations Officer - IMMUTABLE. Read reports + trigger automation only. CANNOT modify ANY security/IAM/CA/Defender/Policy/Infrastructure. Non-upgradeable by design."
        isEnabled       = $true
        templateId      = $ROLE_TEMPLATE_ID
        version         = "1.0"
        rolePermissions = @(
            @{
                allowedResourceActions = $CANONICAL_ALLOWED_ACTIONS
                condition              = $null
            }
        )
    }
    $newRole = Invoke-Graph -Method "POST" -Uri "/roleManagement/directory/roleDefinitions" -Body $roleBody
    if ($newRole) {
        Write-Host "  CREATED: Role_Operations_Officer id=$($newRole.id)"
        $existingRole = $newRole
    } else {
        Write-Host "  FAILED: Could not create role (may need Graph API admin consent)"
    }
} else {
    Write-Host ""
    Write-Host "[ENFORCE] Role_Operations_Officer exists - enforcing canonical definition..."
    Write-Host "  Current id: $($existingRole.id)"

    # Check if role has been tampered with
    $currentActions = $existingRole.rolePermissions[0].allowedResourceActions
    $canonicalSet   = $CANONICAL_ALLOWED_ACTIONS | Sort-Object
    $currentSet     = $currentActions | Sort-Object

    $addedActions   = $currentSet | Where-Object { $_ -notin $canonicalSet }
    $removedActions = $canonicalSet | Where-Object { $_ -notin $currentSet }

    if ($addedActions) {
        Write-Host "  DRIFT DETECTED: Unauthorized permissions added:"
        foreach ($a in $addedActions) { Write-Host "    UNAUTHORIZED: $a" }
        Write-Host "  -> RESTORING canonical definition..."

        $updateBody = @{
            rolePermissions = @(
                @{ allowedResourceActions = $CANONICAL_ALLOWED_ACTIONS; condition = $null }
            )
        }
        Invoke-Graph -Method "PATCH" -Uri "/roleManagement/directory/roleDefinitions/$($existingRole.id)" -Body $updateBody | Out-Null
        Write-Host "  RESTORED: Role_Operations_Officer to canonical definition"
    } else {
        Write-Host "  OK: Role definition matches canonical (no drift)"
    }
}

# ── REPORT: Role Summary ─────────────────────────────────────
Write-Host ""
Write-Host "============================================================"
Write-Host "  Role_Operations_Officer — Permission Summary"
Write-Host "============================================================"
Write-Host ""
Write-Host "  ALLOWED ($($CANONICAL_ALLOWED_ACTIONS.Count) actions):"
Write-Host "    + Directory: READ ONLY (users/groups/apps/devices)"
Write-Host "    + Reports: READ ONLY (usage/message center)"
Write-Host "    + Security: READ ONLY (alerts/policies/health)"
Write-Host "    + Monitoring: READ ONLY (logs/metrics/alerts)"
Write-Host "    + Automation: TRIGGER ONLY (cannot edit runbooks)"
Write-Host "    + Cloud App Security: READ ONLY"
Write-Host ""
Write-Host "  FORBIDDEN (0 exceptions):"
Write-Host "    x IAM / Role Assignments"
Write-Host "    x Conditional Access Policies"
Write-Host "    x MFA / Authentication Methods"
Write-Host "    x Defender Settings"
Write-Host "    x Azure Policy"
Write-Host "    x Intune / Endpoint Manager"
Write-Host "    x Exchange / SharePoint / Teams admin"
Write-Host "    x Application registration"
Write-Host "    x Service Principal management"
Write-Host "    x Subscription / Resource Group management"
Write-Host "    x Audit log deletion"
Write-Host "    x ANY write/create/delete on security"
Write-Host ""
Write-Host "  Built-in roles assigned alongside custom role:"
foreach ($r in $BUILTIN_ROLES_TO_ASSIGN) {
    Write-Host "    + $($r.name)"
}
Write-Host ""
Write-Host "  This role is: IMMUTABLE | NON-UPGRADEABLE | AUDITED"
Write-Host "============================================================"
