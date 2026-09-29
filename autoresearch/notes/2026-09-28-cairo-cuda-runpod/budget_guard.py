import datetime,json,subprocess,time
from pathlib import Path
root=Path(__file__).resolve().parent
policy=json.loads((root/'session-policy.json').read_text())
end=datetime.datetime.fromisoformat(policy['auto_terminate_utc'])
pod=policy['pod_id']
while True:
    if (root/'budget-guard-stop').exists(): break
    reason=None
    if datetime.datetime.now(datetime.timezone.utc)>=end: reason='session deadline'
    try:
        result=subprocess.run(['runpodctl','user'],capture_output=True,text=True,timeout=20)
        if result.returncode==0:
            balance=json.loads(result.stdout).get('clientBalance')
            if balance is not None and policy['initial_balance_usd']-balance>=policy['initial_session_budget_usd']: reason='session budget'
    except Exception: pass
    if reason:
        result=subprocess.run(['runpodctl','pod','delete',pod],capture_output=True,text=True,timeout=30)
        print(json.dumps({'reason':reason,'pod_id':pod,'delete_exit_code':result.returncode}),flush=True)
        if result.returncode==0: break
    time.sleep(30)
