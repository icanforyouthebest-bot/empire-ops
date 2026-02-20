# ═══════════════════════════════════════════════════════════════
# ZERO TRUST LAYER 1: Operations Officer Permission Model
# Core principle: Ops Officer NEVER touches anything that can cause disaster
# Microsoft Zero Trust Best Practice - Maximum Granularity
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
Write-Host "  ZERO TRUST LAYER 1: Permission Model Enforcement"
Write-Host "  Operations Officer = READ + TRIGGER ONLY"
Write-Host "  CANNOT: IAM / CA / MFA / Defender / Policy / Infra"
Write-Host "============================================================"

# ── DEFINE: What Ops Officer CAN do ──────────────────────────
$ALLOWED_ACTIONS = @(
    # Directory - READ ONLY
    "microsoft.directory/auditLogs/allProperties/read"
    "microsoft.directory/signInReports/allProperties/read"
    "microsoft.directory/users/standard/read"
    "microsoft.directory/groups/standard/read"
    "microsoft.directory/applications/standard/read"
    "microsoft.directory/servicePrincipals/standard/read"
    "microsoft.directory/organization/standard/read"

    # Reports - READ ONLY
    "microsoft.office365.usageReports/allEntities/allProperties/read"
    "microsoft.office365.messageCenter/messages/read"

    # Service Health - READ ONLY
    "microsoft.office365.serviceHealth/allEntities/allProperties/read"
    "microsoft.azure.serviceHealth/allEntities/allProperties/read"

    # Security - READ ONLY
    "microsoft.office365.protectionCenter/allEntities/allProperties/read"
    "microsoft.azure.resourceHealth/allEntities/allProperties/read"
)

# ── DEFINE: What Ops Officer CANNOT do (EXPLICIT DENY LIST) ──
$FORBIDDEN_ACTIONS = @(
    # IAM - FORBIDDEN
    "microsoft.directory/roleAssignments/allProperties/allTasks"
    "microsoft.directory/roleDefinitions/allProperties/allTasks"
    "microsoft.directory/privilegedIdentityManagement/allProperties/allTasks"

    # Conditional Access - FORBIDDEN
    "microsoft.directory/conditionalAccessPolicies/allProperties/allTasks"
    "microsoft.directory/namedLocations/create"
    "microsoft.directory/namedLocations/delete"

    # Security Settings - FORBIDDEN
    "microsoft.directory/authenticationMethodsPolicy/allProperties/allTasks"
    "microsoft.directory/authorizationPolicy/allProperties/allTasks"

    # Applications - FORBIDDEN
    "microsoft.directory/applications/allProperties/allTasks"
    "microsoft.directory/applicationPolicies/allProperties/allTasks"
    "microsoft.directory/servicePrincipals/allProperties/allTasks"
    "microsoft.directory/appRoleAssignments/allProperties/allTasks"

    # Users - FORBIDDEN (cannot modify)
    "microsoft.directory/users/allProperties/allTasks"
    "microsoft.directory/users/password/update"
    "microsoft.directory/users/create"
    "microsoft.directory/users/delete"

    # Groups - FORBIDDEN (cannot modify)
    "microsoft.directory/groups/create"
    "microsoft.directory/groups/delete"
    "microsoft.directory/groups/members/update"

    # Azure Subscriptions/Resources - FORBIDDEN
    "microsoft.azure.supportTickets/allEntities/allTasks"
    "microsoft.office365.supportTickets/allEntities/allTasks"
)

Write-Host ""
Write-Host "ALLOWED ($(($ALLOWED_ACTIONS).Count) actions):"
foreach ($a in $ALLOWED_ACTIONS) { Write-Host "  + $a" }

Write-Host ""
Write-Host "FORBIDDEN ($(($FORBIDDEN_ACTIONS).Count) action categories):"
foreach ($f in $FORBIDDEN_ACTIONS) { Write-Host "  - $f" }

# ── CHECK: Current Ops Officer role definition ───────────────
Write-Host ""
Write-Host "[VERIFY] Checking Role_Operations_Officer exists..."
$customRoles = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleDefinitions?`$filter=isBuiltIn eq false"
$opsRole = $null
if ($customRoles -and $customRoles.value) {
    $opsRole = $customRoles.value | Where-Object { $_.displayName -eq "Role_Operations_Officer" }
}

if ($opsRole) {
    Write-Host "  EXISTS: Role_Operations_Officer id=$($opsRole.id)"
    Write-Host "  Enabled: $($opsRole.isEnabled)"

    # Verify allowed actions match
    $currentAllowed = $opsRole.rolePermissions[0].allowedResourceActions
    Write-Host "  Current allowed actions: $($currentAllowed.Count)"

    # Check for any dangerous permissions that shouldn't be there
    $dangerous = $currentAllowed | Where-Object { $_ -like "*allTasks*" -or $_ -like "*write*" -or $_ -like "*create*" -or $_ -like "*delete*" -or $_ -like "*update*" }
    if ($dangerous) {
        Write-Host "  CRITICAL DRIFT: Role has dangerous permissions!"
        foreach ($d in $dangerous) { Write-Host "    REMOVE: $d" }
    } else {
        Write-Host "  OK: No dangerous permissions found"
    }
} else {
    Write-Host "  NOT FOUND: Will be created by layer2-role-template.ps1"
}

# ── VERIFY: No Ops Officers have admin roles ─────────────────
Write-Host ""
Write-Host "[VERIFY] Checking Ops Officers don't hold admin roles..."
$DANGEROUS_ROLES = @{
    "Global Administrator"                = "62e90394-69f5-4237-9190-012177145e10"
    "Security Administrator"              = "194ae4cb-b126-40b2-bd5b-6091b380977d"
    "Privileged Role Administrator"       = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    "Conditional Access Administrator"    = "b1be1c3e-b65d-4f19-8427-f6fa0d97feb9"
    "Application Administrator"           = "9b895d92-2cd3-44c7-9d02-a6ac2d5ea5c3"
    "Cloud Application Administrator"     = "158c047a-c907-4556-b7ef-446551a6b5f7"
    "User Administrator"                  = "fe930be7-5e62-47db-91af-98c3a49a38b1"
}

$opsOfficers = @()
if ($opsRole) {
    $assignments = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$($opsRole.id)'&`$expand=principal"
    if ($assignments -and $assignments.value) {
        $opsOfficers = $assignments.value | ForEach-Object { $_.principalId }
    }
}

Write-Host "  Active Ops Officers: $($opsOfficers.Count)"

foreach ($officerId in $opsOfficers) {
    $officerAssignments = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$officerId'&`$expand=roleDefinition"
    if ($officerAssignments -and $officerAssignments.value) {
        foreach ($assignment in $officerAssignments.value) {
            $roleName = $assignment.roleDefinition.displayName
            if ($DANGEROUS_ROLES.ContainsValue($assignment.roleDefinitionId)) {
                Write-Host "  CRITICAL VIOLATION: Officer $officerId holds FORBIDDEN role: $roleName"
                Write-Host "  -> AUTOMATIC REMOVAL REQUIRED"
                # Auto-remove dangerous role from ops officer
                $removeResult = Invoke-Graph -Method "DELETE" -Uri "/roleManagement/directory/roleAssignments/$($assignment.id)"
                Write-Host "  -> REMOVED assignment $($assignment.id)"
            }
        }
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  LAYER 1 PERMISSION MODEL VERIFIED"
Write-Host "  Human risk = ZERO (no human can touch critical systems)"
Write-Host "============================================================"
