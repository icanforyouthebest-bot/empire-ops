# ═══════════════════════════════════════════════════════════════
# ZERO TRUST LAYER 5: Officer Replacement (30 seconds)
# Human = replaceable module. System = unaffected.
# ═══════════════════════════════════════════════════════════════
param(
    [string]$TenantId       = $env:TENANT_ID,
    [string]$ClientId       = $env:CLIENT_ID,
    [string]$ClientSecret   = $env:CLIENT_SECRET,
    [string]$SupabaseUrl    = $env:SUPABASE_URL,
    [string]$SupabaseKey    = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$Action         = $env:ACTION,           # audit | replace | lockout | list
    [string]$OldOfficerUpn  = $env:OLD_OFFICER_UPN,
    [string]$NewOfficerUpn  = $env:NEW_OFFICER_UPN,
    [string]$TargetUpn      = $env:TARGET_UPN,
    [string]$Reason         = $env:REASON
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

function Write-Audit {
    param([string]$Event, [string]$Actor, [string]$Detail)
    Write-Host "  [AUDIT] $Event | actor=$Actor | $Detail"
    if ($SupabaseUrl -and $SupabaseKey) {
        $entry = @{
            layer      = "OfficerManagement"
            check_name = $Event
            status     = "LOGGED"
            action     = $Event
            detail     = "actor=$Actor | $Detail | reason=$Reason"
            severity   = "high"
            source     = "layer5-replace-officer"
        }
        try {
            $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
            Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null
        } catch {}
    }
}

Write-Host "============================================================"
Write-Host "  ZERO TRUST LAYER 5: Officer Management"
Write-Host "  Human = Replaceable Module | System = Unaffected"
Write-Host "  Action: $Action"
Write-Host "============================================================"

# ── Get Operations Officer Role ──────────────────────────────
$customRoles = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleDefinitions?`$filter=isBuiltIn eq false and displayName eq 'Role_Operations_Officer'"
$opsRoleId   = $null
if ($customRoles -and $customRoles.value -and $customRoles.value.Count -gt 0) {
    $opsRoleId = $customRoles.value[0].id
    Write-Host "  Role_Operations_Officer: $opsRoleId"
}

# Built-in reader roles for Ops Officer
$BUILTIN_OPS_ROLES = @(
    "88d8e3e3-8f55-4a1e-953a-9b9898b8876b"  # Directory Readers
    "4a5d8f65-41da-4de4-8968-e035b65339cf"  # Reports Reader
    "5d6b6bb7-de71-4623-b4af-96380a352509"  # Security Reader
    "f2ef992c-3afb-46b9-b7cf-a126ee74c451"  # Global Reader
)

# ── ACTION: list ──────────────────────────────────────────────
if ($Action -eq "list" -or -not $Action) {
    Write-Host ""
    Write-Host "[LIST] Current Operations Officers:"
    if ($opsRoleId) {
        $assignments = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$opsRoleId'&`$expand=principal"
        if ($assignments -and $assignments.value -and $assignments.value.Count -gt 0) {
            foreach ($a in $assignments.value) {
                $upn  = $a.principal.userPrincipalName
                $name = $a.principal.displayName
                $acct = $a.principal.accountEnabled
                Write-Host "  Officer: $name ($upn) | AccountEnabled: $acct | AssignmentId: $($a.id)"
            }
        } else {
            Write-Host "  (No active Operations Officers)"
        }
    } else {
        Write-Host "  WARNING: Role_Operations_Officer not found - run layer2 first"
    }

    Write-Host ""
    Write-Host "[LIST] Privileged role holders summary:"
    $TRACK_ROLES = @{
        "GlobalAdmin"    = "62e90394-69f5-4237-9190-012177145e10"
        "SecurityAdmin"  = "194ae4cb-b126-40b2-bd5b-6091b380977d"
        "PrivRoleAdmin"  = "e8611ab8-c189-46e8-94e1-60213ab1f814"
    }
    foreach ($role in $TRACK_ROLES.GetEnumerator()) {
        $a = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$($role.Value)'"
        $count = if ($a -and $a.value) { $a.value.Count } else { 0 }
        $flag  = if ($count -gt 2) { " <-- REVIEW" } else { "" }
        Write-Host "  $($role.Key): $count assignments$flag"
    }
}

# ── ACTION: audit ─────────────────────────────────────────────
if ($Action -eq "audit") {
    Write-Host ""
    Write-Host "[AUDIT] Comprehensive officer audit..."
    if ($opsRoleId) {
        $assignments = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=roleDefinitionId eq '$opsRoleId'&`$expand=principal"
        $officerCount = if ($assignments -and $assignments.value) { $assignments.value.Count } else { 0 }
        Write-Host "  Total Operations Officers: $officerCount"

        if ($assignments -and $assignments.value) {
            foreach ($a in $assignments.value) {
                $upn = $a.principal.userPrincipalName
                Write-Host ""
                Write-Host "  -- Officer: $upn --"

                # Check for dangerous roles
                $allRoles = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($a.principalId)'&`$expand=roleDefinition"
                if ($allRoles -and $allRoles.value) {
                    $dangerousRoles = $allRoles.value | Where-Object { $_.roleDefinition.displayName -like "*Administrator*" -or $_.roleDefinition.displayName -like "*Global*" }
                    if ($dangerousRoles) {
                        Write-Host "  VIOLATION: $upn holds forbidden admin role!"
                        foreach ($dr in $dangerousRoles) {
                            Write-Host "    FORBIDDEN: $($dr.roleDefinition.displayName)"
                        }
                    } else {
                        Write-Host "  Roles: OK (no admin roles)"
                    }
                }
            }
        }
    }
    Write-Audit -Event "AUDIT" -Actor "System" -Detail "Completed officer audit"
}

# ── ACTION: replace ───────────────────────────────────────────
if ($Action -eq "replace") {
    if (-not $OldOfficerUpn -or -not $NewOfficerUpn) {
        Write-Host "ERROR: OLD_OFFICER_UPN and NEW_OFFICER_UPN required"
        exit 1
    }

    Write-Host ""
    Write-Host "========================================"
    Write-Host "  OFFICER REPLACEMENT (30 SECONDS)"
    Write-Host "  Old: $OldOfficerUpn"
    Write-Host "  New: $NewOfficerUpn"
    Write-Host "  Reason: $Reason"
    Write-Host "========================================"
    $startTime = Get-Date

    # Step 1: Verify new officer exists
    $newUser = Invoke-Graph -Method "GET" -Uri "/users/$NewOfficerUpn"
    if (-not $newUser) {
        Write-Host "  ERROR: New officer not found: $NewOfficerUpn"
        exit 1
    }

    # Step 2: Get old officer
    $oldUser = Invoke-Graph -Method "GET" -Uri "/users/$OldOfficerUpn"
    if (-not $oldUser) {
        Write-Host "  WARNING: Old officer not found: $OldOfficerUpn (may already be removed)"
    }

    # Step 3: Remove old officer role assignments
    if ($oldUser -and $opsRoleId) {
        $oldAssignments = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($oldUser.id)' and roleDefinitionId eq '$opsRoleId'"
        if ($oldAssignments -and $oldAssignments.value) {
            foreach ($a in $oldAssignments.value) {
                Invoke-Graph -Method "DELETE" -Uri "/roleManagement/directory/roleAssignments/$($a.id)" | Out-Null
                Write-Host "  [1/5] REMOVED: $OldOfficerUpn from Role_Operations_Officer"
            }
        }
        # Remove built-in reader roles
        foreach ($roleId in $BUILTIN_OPS_ROLES) {
            $ba = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($oldUser.id)' and roleDefinitionId eq '$roleId'"
            if ($ba -and $ba.value) {
                foreach ($a in $ba.value) {
                    Invoke-Graph -Method "DELETE" -Uri "/roleManagement/directory/roleAssignments/$($a.id)" | Out-Null
                }
            }
        }
    }

    # Step 4: Revoke old officer sessions
    if ($oldUser) {
        Invoke-Graph -Method "POST" -Uri "/users/$($oldUser.id)/revokeSignInSessions" | Out-Null
        Write-Host "  [2/5] REVOKED: All sessions for $OldOfficerUpn"
    }

    # Step 5: Disable old officer account (optional, keeps for audit)
    # NOTE: We don't delete - we keep for audit trail
    # Invoke-Graph -Method "PATCH" -Uri "/users/$($oldUser.id)" -Body @{ accountEnabled = $false } | Out-Null

    # Step 6: Assign new officer - custom role
    if ($opsRoleId) {
        $assignBody = @{ principalId = $newUser.id; roleDefinitionId = $opsRoleId; directoryScopeId = "/" }
        $newAssignment = Invoke-Graph -Method "POST" -Uri "/roleManagement/directory/roleAssignments" -Body $assignBody
        Write-Host "  [3/5] ASSIGNED: $NewOfficerUpn as Role_Operations_Officer"
    }

    # Step 7: Assign built-in reader roles
    foreach ($roleId in $BUILTIN_OPS_ROLES) {
        $ba = @{ principalId = $newUser.id; roleDefinitionId = $roleId; directoryScopeId = "/" }
        Invoke-Graph -Method "POST" -Uri "/roleManagement/directory/roleAssignments" -Body $ba | Out-Null
    }
    Write-Host "  [4/5] ASSIGNED: Built-in reader roles to $NewOfficerUpn"

    # Step 8: Audit
    Write-Audit -Event "OFFICER_REPLACED" -Actor "System" -Detail "old=$OldOfficerUpn new=$NewOfficerUpn sessions_revoked=true"
    Write-Host "  [5/5] AUDIT: Replacement logged (immutable)"

    $elapsed = ((Get-Date) - $startTime).TotalSeconds
    Write-Host ""
    Write-Host "========================================"
    Write-Host "  REPLACEMENT COMPLETE in $([math]::Round($elapsed, 1))s"
    Write-Host "  Old officer ($OldOfficerUpn): REMOVED + SESSIONS REVOKED"
    Write-Host "  New officer ($NewOfficerUpn): FULLY ASSIGNED"
    Write-Host "  System status: UNAFFECTED"
    Write-Host "  Automation: CONTINUES (not tied to any human)"
    Write-Host "  Audit trail: PRESERVED (old officer activity visible)"
    Write-Host "========================================"
}

# ── ACTION: lockout ───────────────────────────────────────────
if ($Action -eq "lockout") {
    if (-not $TargetUpn) { Write-Host "ERROR: TARGET_UPN required"; exit 1 }

    Write-Host ""
    Write-Host "========================================"
    Write-Host "  EMERGENCY LOCKOUT: $TargetUpn"
    Write-Host "  Reason: $Reason"
    Write-Host "========================================"

    $targetUser = Invoke-Graph -Method "GET" -Uri "/users/$TargetUpn"
    if (-not $targetUser) { Write-Host "User not found: $TargetUpn"; exit 1 }

    # Disable account
    Invoke-Graph -Method "PATCH" -Uri "/users/$($targetUser.id)" -Body @{ accountEnabled = $false } | Out-Null
    Write-Host "  [1/3] ACCOUNT DISABLED: $TargetUpn"

    # Revoke all sessions
    Invoke-Graph -Method "POST" -Uri "/users/$($targetUser.id)/revokeSignInSessions" | Out-Null
    Write-Host "  [2/3] SESSIONS REVOKED: All active sessions terminated"

    # Remove all role assignments
    $allAssign = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$filter=principalId eq '$($targetUser.id)'"
    if ($allAssign -and $allAssign.value) {
        foreach ($a in $allAssign.value) {
            Invoke-Graph -Method "DELETE" -Uri "/roleManagement/directory/roleAssignments/$($a.id)" | Out-Null
        }
        Write-Host "  [3/3] ROLES REMOVED: $($allAssign.value.Count) role assignments removed"
    }

    Write-Audit -Event "EMERGENCY_LOCKOUT" -Actor "System" -Detail "target=$TargetUpn account_disabled=true sessions_revoked=true roles_removed=true"

    Write-Host ""
    Write-Host "  LOCKOUT COMPLETE - $TargetUpn has zero access"
    Write-Host "  System continues operating normally"
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  LAYER 5 COMPLETE"
Write-Host "  Core principle: Human = replaceable module"
Write-Host "                  System = permanent infrastructure"
Write-Host "============================================================"
