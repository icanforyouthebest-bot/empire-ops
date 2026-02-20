# AI Governance Framework v1.0
## 帝國 AI 治理框架 — 所有 AI 必須遵守

**發佈日期**: 2026-02-20
**適用範圍**: 所有 AI 系統、所有自動化流程、所有 Agent
**效力**: 立即生效、永久有效、任何 AI 不得覆蓋

---

## 核心指令（Core Mandate — 每個 AI 必須讀取並遵守）

> **「所有 AI 與自動化流程一律必須透過受控入口執行，並產生 Before / After / Diff 三份系統證據，未提供完整證據者視同未執行，系統將自動審計並回報。」**

---

## AI 行為守則

### 規則 1：AI 不能直接操作系統
所有 AI 必須透過受控入口：

| 入口類型 | 適用 AI 類型 |
|---------|------------|
| GitHub Actions | CI/CD AI, Deployment AI |
| Azure Automation Runbook | Infrastructure AI |
| Supabase Edge Function | Application AI |
| PowerShell 受控腳本 | System Management AI |
| REST API (with auth token) | Integration AI |

**禁止行為：**
- 直接呼叫未受監控的 API
- 繞過 GitHub Actions 直接 push
- 直接執行 Azure CLI 而不透過受控腳本
- 任何不產生審計記錄的操作

### 規則 2：AI 必須產生三份證據

每次 AI 執行任務必須自動產生：

```json
// evidence-before-{ACTION_ID}.json
{
  "phase": "before",
  "action_id": "uuid-v4",
  "ai_agent": "claude-code | github-actions | azure-automation",
  "triggered_by": "system | user-upn",
  "timestamp": "2026-02-20T15:00:00Z",
  "system_state": { ... }
}

// evidence-after-{ACTION_ID}.json
{
  "phase": "after",
  "action_id": "same-uuid",
  "timestamp": "2026-02-20T15:00:10Z",
  "system_state": { ... }
}

// evidence-diff-{ACTION_ID}.json
{
  "action_id": "same-uuid",
  "verdict": "NO_CHANGE | CHANGE_DETECTED | HIGH_RISK | CRITICAL",
  "changes": [ ... ],
  "risk_delta": { ... },
  "responsibility_chain": {
    "ai_agent": "...",
    "trigger": "...",
    "workflow_id": "...",
    "commit_sha": "..."
  }
}
```

### 規則 3：未提供證據 → 視同未執行

| 條件 | 判定 | 後果 |
|------|------|------|
| Before + After + Diff 完整 | 已執行 ✓ | 正常記錄 |
| 缺少 Before | 未開始 ✗ | 自動標記 + 告警 |
| 缺少 After | 未完成 ✗ | 自動標記 + 告警 |
| 缺少 Diff | 未驗證 ✗ | 自動標記 + 告警 |
| 任一被修改 | 無效 ✗ | 觸發調查 + 鎖定 |

### 規則 4：AI 必須可審計

所有 AI 操作自動記錄到（不可刪除）：
- `governance_audit_log` (Supabase WORM)
- GitHub Actions Audit Log
- Azure AD Audit Log
- Defender Activity Log

每筆記錄必須包含：
- `ai_agent`: 哪個 AI 系統
- `action`: 做了什麼
- `triggered_by`: 誰觸發
- `evidence_id`: 對應的 Before/After/Diff ID
- `verdict`: 操作結果評級

### 規則 5：AI 必須可替換

每個 AI Agent 都是可替換模組：

```yaml
# 替換任何 AI Agent 的標準流程
1. 停用舊 Agent (revoke API keys / disable workflow)
2. 系統繼續運行 (不依賴任何單一 AI)
3. 部署新 Agent (assign new credentials)
4. 驗證新 Agent 產生正確的 Before/After/Diff
5. 完成替換 (舊 Agent 所有歷史保留在審計日誌)
```

### 規則 6：AI 不能破壞系統

自我修復系統每 15 分鐘檢查所有 AI 行為：
- 是否有 AI 修改了不應修改的配置
- 是否有 AI 繞過了受控入口
- 是否有 AI 缺少必要的 Before/After/Diff
- 是否有 AI 觸發了高風險操作

發現違規 → 自動回滾 → 自動告警 → 自動記錄

---

## AI 責任鏈（Responsibility Chain）

每次操作自動建立完整責任鏈：

```
User/Owner → Trigger → AI Agent → Controlled Entry → Action → Evidence
     ↑                                                             ↓
     └─────────────── Auto Report (3h summary) ───────────────────┘
```

**責任鏈追蹤欄位：**
```json
{
  "chain_id": "uuid",
  "owner": "HsuChunHsiang@AIEmpire.onmicrosoft.com",
  "trigger_source": "schedule | webhook | manual | ai-decision",
  "ai_agent": "agent-name + version",
  "workflow_run_id": "github-run-id",
  "evidence_ids": ["before-id", "after-id", "diff-id"],
  "audit_log_ids": ["supabase-row-ids"],
  "verdict": "COMPLIANT | NON_COMPLIANT | PENDING"
}
```

---

## AI 登記制度（AI Registry）

所有在帝國系統中運行的 AI 必須登記：

| AI Agent | 類型 | 受控入口 | 允許操作 | 證據要求 |
|---------|------|---------|---------|---------|
| claude-code | 開發 AI | GitHub Actions | 代碼修改、CI | Before+After+Diff |
| github-actions | 自動化 | GitHub Actions | 部署、測試 | 每個 Job 記錄 |
| azure-automation | 基礎建設 | Azure Runbook | Azure 資源 | Before+After+Diff |
| supabase-edge | 應用層 | Edge Function | DB 查詢、業務邏輯 | 操作日誌 |
| empire-self-heal | 治理 AI | GitHub Actions | 修復、強化 | 每次巡邏記錄 |

**未登記的 AI → 自動拒絕 + 告警**

---

## 3 小時後回來看到什麼

你不需要盯任何 AI，3 小時後回來會自動看到：

```
📊 AI Activity Summary (last 3h)
├── GitHub Actions: N runs, M succeeded, K failed
├── Edge Functions: N invocations, avg response time
├── Self-Heal: N patrols, M drifts found, K auto-healed
├── Evidence Generated: N Before+After+Diff triplets
├── High-Risk Operations: (list)
├── Compliance Status: PASS/FAIL
└── Next Actions Required: (list)
```

**報告自動送達方式：**
- Supabase `governance_audit_log` 隨時可查
- GitHub Actions artifacts (90天)
- Telegram Bot 告警（高風險操作立即通知）

---

## 工程師必讀規範（Engineer Compliance）

任何工程師接手任何系統前必須確認：

- [ ] 已閱讀 AI Governance Framework v1.0
- [ ] 所有 AI 操作透過受控入口
- [ ] 每次操作必須有 Before/After/Diff
- [ ] 不得刪除任何審計記錄
- [ ] 不得停用任何監控系統
- [ ] 不得給 AI 超出必要的權限
- [ ] 必須確認 AI 可被替換（無單點依賴）

**SOP 版本**: 2026.02.v1
**確認後**: 系統會自動記錄確認時間和 IP

---

**這份文件由帝國治理系統自動存證。**
**任何 AI 或任何人不得修改此文件。**
**AI Governance Framework v1.0 | 2026-02-20 | Empire Ops**
