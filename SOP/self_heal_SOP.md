# SOP: Empire Self-Heal
台灣專利 115100981 | 小路光有限公司

## 強制閱讀
1. 所有變更只能透過腳本
2. 禁止 Dashboard 手動修改
3. 全程留 audit log

## 執行
```bash
export SUPABASE_ACCESS_TOKEN=xxx
python scripts/self_heal.py --target all
```

## 期望狀態
- no_rls_tables: 0
- mutable_search_path_fns: 0
- aiforseo.vip: HTTP 200
- Azure CLIENT_SECRET: valid