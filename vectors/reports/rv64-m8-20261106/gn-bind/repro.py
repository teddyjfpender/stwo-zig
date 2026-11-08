import json,os,subprocess,sys,shutil
g=json.load(open("/workspace/m3/runs/m8-gn-bind/gate-6/gate.json"))
a=g["steps"][3]["argv"]
env={k:v for k,v in os.environ.items() if not k.startswith("STWO_")}
env.update(json.load(open("/workspace/m3/runs/m8-gn-bind/daemon-26235156-r2-gate-gate-6-00-baseline/plan.json"))["environment"])
for kv in sys.argv[2:]:
    k,_,v=kv.partition("="); env[k]=v
d="/workspace/m3/runs/m8-gn-bind/daemon-26235156-r2-gate-gate-6-00-baseline"
spool=f"/workspace/m3/runs/m8-gn-bind/repro-{sys.argv[1]}"
shutil.rmtree(spool,ignore_errors=True); os.makedirs(spool+"/inbox"); open(spool+"/inbox/STOP","w").close()
drv=a[a.index("--driver")+1]
r=subprocess.run([drv,"combined-serve",d+"/manifest.json",spool],env=env,cwd=d,capture_output=True,text=True,timeout=900)
print("exit",r.returncode)
print("\n".join(l[:250] for l in r.stderr.splitlines() if "GPU_ARENA" not in l and "GPU_POOL" not in l and "GPU_STAG" not in l and "GPU_SYNC" not in l and "PROCESS_MEMORY" not in l)[-12000:])
