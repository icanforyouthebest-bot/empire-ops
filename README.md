# empire-ops
帝國治理 | Pre-check + Drift + Repair + Harden + Audit
台灣專利 115100981 | 小路光有限公司 | 許竣翔

## 範圍
- Supabase / GitHub / Cloudflare / Azure / Windows

## 快速執行
```bash
python scripts/self_heal.py --target all
```

## 24h 自動巡檢
GitHub Actions 每 6 小時自動跑一次

## 目錄結構
- /scripts: 自我修復腳本
- /SOP: 強制閱讀手冊
- /policies: 期望狀態定義
- /.github/workflows: 自動巡檢