# 創辦人操作手冊 — Empire AI Governance
# Founder Operations Manual
# 老闆最高指令手冊：只看證據，隨時切換

## 查看系統證據

### GitHub Actions (所有執行紀錄)
- empire-ops Actions: https://github.com/icanforyouthebest-bot/empire-ops/actions
- SEOBAIKE Actions: https://github.com/icanforyouthebest-bot/SEOBAIKE/actions

### 下載主要證據報告
- 到 empire-ops → Actions → Empire Master Evidence Report → Artifacts → EMPIRE-MASTER-EVIDENCE-*.json
- 到 empire-ops → Actions → Empire Master Evidence Report → Artifacts → EMPIRE-DASHBOARD.json

### Supabase 即時查看
- 審計紀錄: https://supabase.com/dashboard/project/vmyrivxxibqydccurxug/editor → governance_audit_log
- AI 代理人清單: https://supabase.com/dashboard/project/vmyrivxxibqydccurxug/editor → ai_agent_registry

---

## 隨時切換 AI 代理人

### API 呼叫方式
```
POST https://vmyrivxxibqydccurxug.supabase.co/functions/v1/switch-agent
Headers:
  x-founder-key: [你的 FOUNDER_API_KEY]
  Content-Type: application/json

Body:
{
  "action": "switch",
  "old_agent": "claude-code",
  "new_agent": "nvidia-ai",
  "owner_org": "輝達集團",
  "reason": "founder-mandatory-switch"
}
```

### 立即生效
- 切換後所有 Gateway 立刻讀取新名單
- 舊 AI → status=suspended (紀錄保留)
- 新 AI → status=active
- 全部寫入 WORM 審計紀錄

### 查看目前代理人清單
```
GET https://vmyrivxxibqydccurxug.supabase.co/functions/v1/switch-agent
x-founder-key: [你的 FOUNDER_API_KEY]
```

---

## 隨時切換營運長

### 前提條件
新營運長必須先在 Azure AD 有帳號或 Guest 帳號

### 執行方式
1. 到 GitHub: empire-ops → Actions → Zero Trust Ops Officer Governance
2. Run workflow:
   - layer: 5
   - action: replace
   - old_officer: [目前營運長 UPN]
   - new_officer: [新營運長 UPN]
   - reason: founder-mandatory-switch

### 30 秒完成
- 舊營運長: 移除角色 + 撤銷 session
- 新營運長: 完整角色分配
- 全部寫入 WORM 審計紀錄

---

## 自動化排程 (24/7 不停止)

| 頻率 | 系統 | 功能 |
|------|------|------|
| 每 15 分鐘 | Zero Trust Self-Heal | 自動修復所有漂移 |
| 每 15 分鐘 | Auto Incident Response | 自動回應重大事件 |
| 每小時 | Empire 24h Non-Stop Patrol | 完整 11 層巡邏 |
| 每 3 小時 | Master Evidence Report | 主要證據報告 |
| 每 6 小時 | GitHub Policy Enforcement | 分支保護強制 |
| 每 6 小時 | Azure Self-Heal Patrol | Azure 自動修復 |

---

## 緊急聯絡

所有行動都自動 Telegram 通知 (設定 TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID)

---

*系統完全自動化。老闆只需查看證據。*
*證據不會被刪除。所有 AI 都受控制。*
