# Empire Governance Mandate v1.0
## 帝國治理正式指令

**發佈日期**: 2026-02-20
**適用範圍**: 所有系統、所有角色、所有操作
**效力**: 立即生效、永久有效、不可覆蓋

---

## 核心指令（Core Mandate）

> **「所有營運相關操作一律必須透過受控入口執行，並產生 Before / After / Diff 三份系統證據，未提供完整證據者視同未執行，系統將自動審計並回報。」**

This mandate applies to ALL roles without exception.

---

## 第一條：受控入口（Controlled Entry）

所有操作必須透過以下其中一個受控入口：

| 入口類型 | 用途 | 允許角色 |
|---------|------|---------|
| Azure Automation Runbook | Azure 資源操作 | SystemHealer only |
| GitHub Actions Workflow | CI/CD 和治理流程 | SystemHealer only |
| PowerShell 受控腳本 | 診斷和修復 | SystemHealer only |
| Supabase Edge Function | 應用層操作 | Authorized services |

**禁止直接操作：**
- Azure Portal 直接操作
- Azure CLI 直接操作
- Graph API 直接呼叫（非透過受控腳本）
- 任何未登記的入口

---

## 第二條：三份證據（Evidence Triad）

每次操作必須自動產生以下三份證據：

```
evidence-{ACTION_ID}-before.json  → 操作前系統狀態
evidence-{ACTION_ID}-after.json   → 操作後系統狀態
evidence-{ACTION_ID}-diff.json    → 差異報告 + 風險評估 + 責任鏈
```

### 2.1 Before.json 必須包含：
- 所有 CA Policy 狀態
- 所有特權角色指派
- 安全分數
- 風險用戶數量
- 活躍安全告警
- 時間戳記（UTC）

### 2.2 After.json 必須包含：
- 同 Before.json 所有欄位
- 操作後當下快照
- 操作者 UPN
- 時間戳記（UTC）

### 2.3 Diff.json 必須包含：
- `verdict`: NO_CHANGE | CHANGE_DETECTED | HIGH_RISK_CHANGE | CRITICAL_CHANGE_DETECTED
- `changes[]`: 每個變更的 before/after/severity
- `risk_delta`: 安全分數變化、風險用戶變化
- `duration_seconds`: 操作耗時
- `actor`: 操作者（不可匿名）
- `action_id`: 唯一操作 ID（追蹤用）

---

## 第三條：未提供證據 → 視同未執行

| 情況 | 判定 |
|------|------|
| 有 Before + After + Diff | 視同已執行 ✓ |
| 缺少 Before | 視同未開始 ✗ |
| 缺少 After | 視同未完成 ✗ |
| 缺少 Diff | 視同未驗證 ✗ |
| Before/After/Diff 任一被修改 | 視同無效 + 觸發調查 ✗ |

**系統行為：**
- 自動標記為「未完成」
- 自動記錄於不可刪除審計日誌
- 自動回報給系統持有者

---

## 第四條：自動審計（Immutable Audit）

以下系統自動記錄所有操作，不可停用、不可刪除：

1. **Azure AD Audit** — 角色/CA/政策變更
2. **Sign-in Logs** — 誰在何時從哪裡登入
3. **Defender Alerts** — 可疑行為告警
4. **Unified Audit Log** — M365 所有操作
5. **GitHub Audit Log** — 所有 CI/CD 操作
6. **Supabase governance_audit_log** — 治理層審計（WORM）

**不可刪除原則：**
- Operations Officer: 0 個刪除權限
- System Healer: 僅可寫入，不可刪除
- Global Admin: 刪除任何審計記錄 → 自動告警

---

## 第五條：角色權限矩陣

| 操作類型 | GlobalAdmin | SecurityAdmin | OperationsOfficer | SystemHealer |
|---------|------------|---------------|------------------|-------------|
| 查看報表 | ✓ | ✓ | ✓ | ✓ |
| 修改 CA Policy | ✓ | ✓ | ✗ | 自動修復用 |
| 修改 IAM | ✓ | ✗ | ✗ | 緊急修復用 |
| 修改 Defender | ✓ | ✓ | ✗ | ✗ |
| 觸發 Runbook | ✗ | ✗ | ✓ (唯讀結果) | ✓ |
| 刪除審計記錄 | ✗ | ✗ | ✗ | ✗ |
| 換掉營運長 | ✓ | ✗ | ✗ | 自動執行 |

---

## 第六條：自我修復（Self-Heal）

系統每 15 分鐘自動執行以下檢查：

1. CA Policies — 是否啟用
2. MFA 強制 — 是否啟用
3. Role_Operations_Officer — 是否被竄改
4. GlobalAdmin 數量 — 是否超過 3
5. 高風險用戶 — 是否存在
6. 安全分數 — 是否低於 40%
7. SystemHealer App — 是否存在

發現 Drift → 自動修復 → 自動記錄 → 自動回報

---

## 第七條：違規處理

| 違規行為 | 自動處理 |
|---------|---------|
| 嘗試直接修改 CA Policy | 自動告警 + 自動回滾 + 自動記錄 |
| 嘗試刪除審計記錄 | 自動告警 + 拒絕 + 帳號鎖定觸發 |
| 繞過受控入口 | 自動告警 + 操作記錄 + 回報持有者 |
| 口頭聲稱「我有做」但無證據 | 系統自動判定為未完成 |
| 操作後未產生 Diff.json | 自動標記為「未驗證」 |
| 持有禁止角色 | 自動移除 + 告警 |

---

## 執行狀態

| 系統 | 部署狀態 | 自動巡檢 |
|------|---------|---------|
| empire-ops ZT Governance | ✅ 已部署 (L1-L7) | 每 15 分鐘 |
| SEOBAIKE Security Gate | ✅ 已部署 | 每次 push |
| e5-automation | ✅ 已修復 | 每日 |
| Supabase governance_audit_log | ✅ 已建立 (WORM) | 持續寫入 |
| Evidence artifact retention | ✅ 90 天 | 每次操作 |

---

**這份文件由系統自動存證。任何角色不得修改。**
**Empire Governance System v1.0 | 2026-02-20**
