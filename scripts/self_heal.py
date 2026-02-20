import os,sys,json,logging,argparse,urllib.request
from datetime import datetime,timezone
logging.basicConfig(level=logging.INFO,format="%(asctime)s [%(levelname)s] %(message)s")
log=logging.getLogger("empire-ops")
AUDIT=[]

def audit(action,target,status,detail=""):
    AUDIT.append({"ts":datetime.now(timezone.utc).isoformat(),"action":action,"target":target,"status":status,"detail":detail})
    log.info(f"[{'OK' if status in ('OK','FIXED','pass') else '!!!'}] {action}|{target}|{status}|{detail}")

def sb(sql):
    token=os.getenv("SUPABASE_ACCESS_TOKEN")
    ref=os.getenv("SUPABASE_PROJECT_REF","vmyrivxxibqydccurxug")
    body=json.dumps({"query":sql}).encode()
    req=urllib.request.Request(f"https://api.supabase.com/v1/projects/{ref}/database/query",data=body,method="POST",headers={"Authorization":f"Bearer {token}","Content-Type":"application/json"})
    with urllib.request.urlopen(req,timeout=30) as r: return json.loads(r.read())

def run():
    audit("pre_check","env","pass" if os.getenv("SUPABASE_ACCESS_TOKEN") else "FAIL")
    checks=[("SELECT COUNT(*) FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid WHERE n.nspname='public' AND c.relkind='r' AND NOT c.relrowsecurity","no_rls_tables",0),("SELECT COUNT(*) FROM pg_proc WHERE pronamespace='public'::regnamespace AND NOT (proconfig @> ARRAY['search_path=public']) AND NOT (proconfig @> ARRAY['search_path=public,extensions'])","mutable_fns",0)]
    for sql,name,expected in checks:
        try:
            actual=int(sb(sql)[0].get("count",0))
            if actual!=expected:
                audit("drift",f"supabase/{name}","DRIFT",f"expected={expected} actual={actual}")
                if name=="mutable_fns":
                    sb("DO $$ DECLARE r RECORD; BEGIN FOR r IN SELECT proname,pg_get_function_identity_arguments(oid) AS args FROM pg_proc WHERE pronamespace='public'::regnamespace AND NOT (proconfig @> ARRAY['search_path=public']) AND NOT (proconfig @> ARRAY['search_path=public,extensions']) LOOP EXECUTE format('ALTER FUNCTION public.%I(%s) SET search_path = public',r.proname,r.args); END LOOP; END $$")
                    audit("repair",f"supabase/{name}","FIXED")
            else:
                audit("drift",f"supabase/{name}","OK")
        except Exception as e:
            audit("drift",f"supabase/{name}","ERROR",str(e))
    ts=datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    with open(f"audit_{ts}.json","w") as f: json.dump(AUDIT,f,indent=2,ensure_ascii=False)
    log.info(f"Done. {len(AUDIT)} entries")

if __name__=="__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument("--target",default="all")
    args=parser.parse_args()
    run()
