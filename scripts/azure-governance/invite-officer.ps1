# ===============================================================
# Invite External Officer to Azure AD
# 解決外部組織（輝達集團）切換問題
# Sends B2B invitation → guest can then be assigned officer role
# ===============================================================
param(
    [string]$TenantId       = $env:TENANT_ID,
    [string]$ClientId       = $env:CLIENT_ID,
    [string]$ClientSecret   = $env:CLIENT_SECRET,
    [string]$SupabaseUrl    = $env:SUPABASE_URL,
    [string]$SupabaseKey    = $env:SUPABASE_SERVICE_ROLE_KEY,
    [string]$InviteEmail    = $env:INVITE_EMAIL,       # e.g. admin@huida-group.com
    [string]$InviteOrg      = $env:INVITE_ORG,         # e.g. 輝達集團
    [string]$InviteRole     = "Role_Operations_Officer",
    [string]$RedirectUrl    = "https://myapps.microsoft.com"
)

function Write-Audit {
    param([string]$Check, [string]$Status, [string]$Detail, [string]$Severity = "info")
    Write-Host "  [$Status] $Check | $Detail"
    if ($SupabaseUrl -and $SupabaseKey) {
        $h = @{ "Authorization" = "Bearer $SupabaseKey"; "Content-Type" = "application/json"; "apikey" = $SupabaseKey }
        $entry = @{ layer="OfficerInvite"; check_name=$Check; status=$Status; action="INVITE"; detail=$Detail; severity=$Severity; source="invite-officer" }
        try { Invoke-RestMethod -Uri "$SupabaseUrl/rest/v1/governance_audit_log" -Method POST -Headers $h -Body ($entry | ConvertTo-Json) | Out-Null } catch {}
    }
}

if (-not $InviteEmail) {
    Write-Host "  [SKIP] Set INVITE_EMAIL environment variable"
    Write-Host "  Example: INVITE_EMAIL=admin@huida-group.com INVITE_ORG=輝達集團"
    exit 0
}

Write-Host "============================================================"
Write-Host "  INVITE EXTERNAL OFFICER"
Write-Host "  Email: $InviteEmail"
Write-Host "  Org:   $InviteOrg"
Write-Host "  Role:  $InviteRole"
Write-Host "============================================================"

# Get token
$tokenBody = @{ grant_type="client_credentials"; client_id=$ClientId; client_secret=$ClientSecret; scope="https://graph.microsoft.com/.default" }
try {
    $token = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
} catch {
    Write-Warning "  Token failed: $($_.Exception.Message)"; exit 1
}

$azH = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

# ── Check if user already exists ─────────────────────────────
$existing = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/users?`$filter=mail eq '$InviteEmail' or otherMails/any(e:e eq '$InviteEmail')" -Headers $azH

if ($existing.value -and $existing.value.Count -gt 0) {
    $user = $existing.value[0]
    Write-Host "  User already exists: $($user.id)"
    Write-Audit -Check "InviteCheck" -Status "OK" -Detail "User $InviteEmail already in tenant: $($user.id)"

    # Assign officer role immediately
    $roleDef = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleDefinitions?`$filter=displayName eq '$InviteRole'" -Headers $azH
    if ($roleDef.value) {
        $roleId   = $roleDef.value[0].id
        $assignment = @{
            "@odata.type"    = "#microsoft.graph.unifiedRoleAssignment"
            roleDefinitionId = $roleId
            principalId      = $user.id
            directoryScopeId = "/"
        }
        try {
            Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments" -Method POST -Headers $azH -Body ($assignment | ConvertTo-Json) | Out-Null
            Write-Audit -Check "RoleAssign" -Status "APPLIED" -Detail "Assigned $InviteRole to $InviteEmail ($InviteOrg)"
            Write-Host "  [DONE] $InviteEmail assigned as $InviteRole"
        } catch {
            Write-Audit -Check "RoleAssign" -Status "FAILED" -Detail "Role assign failed: $($_.Exception.Message)" -Severity "high"
        }
    }
} else {
    # Send B2B invitation
    $invite = @{
        invitedUserEmailAddress = $InviteEmail
        inviteRedirectUrl       = $RedirectUrl
        invitedUserDisplayName  = "$InviteOrg Officer"
        sendInvitationMessage   = $true
        invitedUserMessageInfo  = @{
            customizedMessageBody = "您被邀請成為 Empire AI Governance 系統的營運長 ($InviteRole)。請接受邀請後系統將自動完成角色指派。"
        }
    }

    try {
        $result = Invoke-RestMethod -Uri "https://graph.microsoft.com/v1.0/invitations" -Method POST -Headers $azH -Body ($invite | ConvertTo-Json -Depth 5)
        Write-Host "  [INVITED] $InviteEmail → Status: $($result.status)"
        Write-Host "  Invitation URL: $($result.inviteRedeemUrl)"
        Write-Audit -Check "GuestInvite" -Status "APPLIED" -Detail "B2B invitation sent to $InviteEmail ($InviteOrg). Status: $($result.status). InvitedUserId: $($result.invitedUser.id)"

        # Note: role can only be assigned after guest accepts invitation
        Write-Host ""
        Write-Host "  NEXT STEP:"
        Write-Host "  After $InviteEmail accepts invitation, run:"
        Write-Host "  gh workflow run 'Zero Trust Ops Officer Governance' --repo icanforyouthebest-bot/empire-ops -f layer=5 -f action=replace -f new_officer=$InviteEmail"
    } catch {
        Write-Audit -Check "GuestInvite" -Status "FAILED" -Detail "Invitation failed: $($_.Exception.Message)" -Severity "critical"
        Write-Warning "  Invitation failed: $($_.Exception.Message)"
    }
}

Write-Host ""
Write-Host "============================================================"
Write-Host "  INVITE COMPLETE"
Write-Host "  $InviteOrg officer onboarding initiated"
Write-Host "============================================================"
