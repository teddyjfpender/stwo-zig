from pathlib import Path
import json,re,hashlib
h=Path(__file__).resolve().parent
rows=[]
for n in (16,32,64):
    old=json.loads((h/f'auth-{n}-cohort.json').read_text())
    new=json.loads((h/f'auth-{n}-memory-lifetimes.json').read_text())
    invocation=json.loads((h/f'auth-{n}-memory-lifetimes-invocation.json').read_text())
    assert invocation['exit_code']==0
    assert new['verified'] and new['recursive'] and new['queries']==70 and new['pow_bits']==26
    assert new['output']==old['output'] and new['cycles']==old['cycles']
    oldproof=(h/f'auth-{n}-cohort.proof').read_bytes()
    newproof=(h/f'auth-{n}-memory-lifetimes.proof').read_bytes()
    assert oldproof==newproof
    def footprint(stem):
        return int(re.search(r'(\d+)\s+peak memory footprint',(h/(stem+'.log')).read_text())[1])
    rows.append(dict(transactions=n,old_worker_peak_bytes=old['worker_peak_bytes'],worker_peak_bytes=new['worker_peak_bytes'],old_process_peak_bytes=footprint(f'auth-{n}-cohort'),process_peak_bytes=footprint(f'auth-{n}-memory-lifetimes'),old_total_ns=old['total_ns'],total_ns=new['total_ns'],proof_byte_identical=True,proof_sha256=hashlib.sha256(newproof).hexdigest()))
result=dict(scope='Ethereum transaction authentication with one execution leaf and one recursive parent; not full block execution',queries=70,pow_bits=26,rows=rows)
(h/'memory-lifetimes-summary.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
