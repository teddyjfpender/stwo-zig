from pathlib import Path
import hashlib,json,re
h=Path(__file__).resolve().parent
rows=[]
for batch in (16,32,64):
    stem=f'auth-{batch}-cohort'
    report=json.loads((h/(stem+'.json')).read_text())
    invocation=json.loads((h/(stem+'-invocation.json')).read_text())
    assert invocation['exit_code']==0 and report['verified'] and report['recursive']
    assert (report['queries'],report['pow_bits'])==(70,26)
    peak=int(re.search(r'(\d+)\s+peak memory footprint',(h/(stem+'.log')).read_text())[1])
    digest=hashlib.sha256((h/(stem+'.proof')).read_bytes()).hexdigest()
    rows.append(dict(transactions=batch,execution_segments=report['segments'],verified=True,process_peak_bytes=peak,worker_peak_bytes=report['worker_peak_bytes'],wall_seconds=invocation['wall_seconds'],parent_seconds=report['parent_proving_ns']/1e9,proof_sha256=digest))
unchanged=(h/'auth-64-cohort.proof').read_bytes()==(h/'auth-64-constant.proof').read_bytes()
assert unchanged, 'Lifetime-only change must preserve the canonical 64-transaction proof'
result=dict(queries=70,pow_bits=26,scope='Authentication plus one recursive wrapper; not multi-segment or full block proving',single_observations=True,cohort_release_preserves_64_transaction_proof=unchanged,results=rows)
(h/'cohort-scaling-summary.json').write_text(json.dumps(result,indent=2)+'\n')
print(json.dumps(result,indent=2))
