# ═══════════════════════════════════════════════════════════════
# LAYER 1: Azure AD 角色模板化
# Empire Governance — 帝國治理第一層
# 4 核心角色：主權者 / 安全守門人 / 營運長 / 系統治癒者
# ═══════════════════════════════════════════════════════════════

param(
    [string]$TenantId     = $env:TENANT_ID,
    [string]$ClientId     = $env:CLIENT_ID,
    [string]$ClientSecret = $env:CLIENT_SECRET
)

# ── Connect ──────────────────────────────────────────────────
$tokenBody = @{
    grant_type    = "client_credentials"
    client_id     = $ClientId
    client_secret = $ClientSecret
    scope         = "https://graph.microsoft.com/.default"
}
$token = (Invoke-RestMethod -Uri "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token" -Method POST -Body $tokenBody).access_token
$headers = @{ Authorization = "Bearer $token"; "Content-Type" = "application/json" }

function Invoke-Graph {
    param([string]$Method, [string]$Uri, [hashtable]$Body = $null)
    $params = @{ Method = $Method; Uri = "https://graph.microsoft.com/v1.0$Uri"; Headers = $headers }
    if ($Body) { $params.Body = $Body | ConvertTo-Json -Depth 10 }
    try { return Invoke-RestMethod @params }
    catch { Write-Warning "[$Method $Uri] $($_.Exception.Message)"; return $null }
}

Write-Host "═══════════════════════════════════════════════"
Write-Host "  LAYER 1: Azure AD 角色模板化"
Write-Host "  Tenant: $TenantId"
Write-Host "═══════════════════════════════════════════════"

# ── 角色定義 ─────────────────────────────────────────────────
$BUILT_IN_ROLES = @{
    "GlobalAdministrator"    = "62e90394-69f5-4237-9190-012177145e10"  # 主權者：緊急用
    "SecurityAdministrator"  = "194ae4cb-b126-40b2-bd5b-6091b380977d"  # 安全守門人
    "ReportsReader"          = "4a5d8f65-41da-4de4-8968-e035b65339cf"  # 基礎報表
    "ServiceSupportAdmin"    = "f023fd81-a637-4b56-95fd-791ac0226033"  # 服務支援
    "ComplianceAdmin"        = "17315797-102d-40b4-93e0-432062caca18"  # 合規管理
    "HelpdeskAdmin"          = "729827e3-9c14-49f7-bb1b-9608f156bbb8"  # 服務台
    "SecurityReader"         = "5d6b6bb7-de71-4623-b4af-96380a352509"  # 安全唯讀
    "GlobalReader"           = "f2ef992c-3afb-46b9-b7cf-a126ee74c451"  # 全域唯讀
}

# ── 查詢所有使用者 ───────────────────────────────────────────
Write-Host ""
Write-Host "📋 查詢現有角色指派..."
$currentAssignments = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleAssignments?`$expand=principal,roleDefinition"

# ── 創建「系統治癒者」服務主體 ──────────────────────────────
Write-Host ""
Write-Host "🤖 確認系統治癒者 Service Principal..."
$apps = Invoke-Graph -Method "GET" -Uri "/applications?`$filter=displayName eq 'Empire-SystemHealer'"
if ($apps.value.Count -eq 0) {
    Write-Host "  → 創建 Empire-SystemHealer Application..."
    $appBody = @{
        displayName            = "Empire-SystemHealer"
        description            = "帝國自動修復系統 — 不可停用，不可刪除"
        signInAudience         = "AzureADMyOrg"
        requiredResourceAccess = @(@{
            resourceAppId  = "00000003-0000-0000-c000-000000000000"  # Microsoft Graph
            resourceAccess = @(
                @{ id = "7ab1d382-f21e-4acd-a863-ba3e13f7da61"; type = "Role" }  # Directory.Read.All
                @{ id = "9e3f62cf-ca93-4989-b6ce-bf83c28f9fe8"; type = "Role" }  # RoleManagement.ReadWrite.Directory
                @{ id = "06b708a9-e830-4db3-a914-8e69da51d44f"; type = "Role" }  # AppRoleAssignment.ReadWrite.All
            )
        })
    }
    $newApp = Invoke-Graph -Method "POST" -Uri "/applications" -Body $appBody
    Write-Host "  ✅ Empire-SystemHealer 已創建: $($newApp.id)"
} else {
    Write-Host "  ✅ Empire-SystemHealer 已存在: $($apps.value[0].id)"
}

# ── 創建「營運長」自訂角色 ───────────────────────────────────
Write-Host ""
Write-Host "👔 確認營運長自訂角色..."
$customRoles = Invoke-Graph -Method "GET" -Uri "/roleManagement/directory/roleDefinitions?`$filter=isBuiltIn eq false"
$opRole = $customRoles.value | Where-Object { $_.displayName -eq "Empire-OperationsOfficer" }

if (-not $opRole) {
    Write-Host "  → 創建 Empire-OperationsOfficer 角色..."
    $roleBody = @{
        displayName     = "Empire-OperationsOfficer"
        description     = "帝國營運長 — 只能查看和觸發流程，不能改任何安全設定"
        isEnabled       = $true
        rolePermissions = @(@{
            allowedResourceActions = @(
                "microsoft.directory/auditLogs/allProperties/read"
                "microsoft.directory/signInReports/allProperties/read"
                "microsoft.office365.usageReports/allEntities/allProperties/read"
                "microsoft.office365.serviceHealth/allEntities/allProperties/read"
                "microsoft.azure.serviceHealth/allEntities/allProperties/read"
            )
        })
        templateId      = [System.Guid]::NewGuid().ToString()
        version         = "1"
    }
    $newRole = Invoke-Graph -Method "POST" -Uri "/roleManagement/directory/roleDefinitions" -Body $roleBody
    Write-Host "  ✅ Empire-OperationsOfficer 已創建: $($newRole.id)"
} else {
    Write-Host "  ✅ Empire-OperationsOfficer 已存在: $($opRole.id)"
}

# ── 角色摘要 ─────────────────────────────────────────────────
Write-Host ""
Write-Host "═══════════════════════════════════════════════"
Write-Host "  📊 角色模板摘要"
Write-Host "═══════════════════════════════════════════════"
Write-Host "  🔴 主權者 (GlobalAdmin)     → 緊急用，平常不登入"
Write-Host "  🔵 安全守門人 (SecurityAdmin)→ 管 MFA/CA/Defender，營運長不可碰"
Write-Host "  🟡 營運長 (OperationsOfficer)→ 只能查報表和觸發流程"
Write-Host "  🟢 系統治癒者 (SystemHealer) → 自動修復，比營運長大"
Write-Host "═══════════════════════════════════════════════"
Write-Host "  LAYER 1 完成"
