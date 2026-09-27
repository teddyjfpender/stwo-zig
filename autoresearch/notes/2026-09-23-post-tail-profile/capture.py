import hashlib,json,os,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
r=next(x for x in json.loads((ROOT/'autoresearch/notes/2026-09-23-compact-range-provider/suite-cpu/results.json').read_text()) if x['case']=='cpu-keccak-128')
c=r['command'][:];c[0]=str(HERE.parent/'2026-09-23-bulk-tail-updates/candidate-products/bin/stwo-zig-riscv-cpu')
for k,v in [('--samples','6'),('--report-out',str(HERE/'report.json')),('--proof-out',str(HERE/'proof.b3proof'))]:c[c.index(k)+1]=v
e=os.environ.copy();e.update(STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_RISCV_EXECUTION_PROFILE='1')
for k in ['STWO_ZIG_SCALAR_TAIL_UPDATES','STWO_ZIG_REPLAY_BOUNDED_MERKLE_TAIL']:e.pop(k,None)
(HERE/'command.json').write_text(json.dumps(dict(command=c,binary_sha256=hashlib.sha256(Path(c[0]).read_bytes()).hexdigest(),workers=16,sample_seconds=12),indent=2))
with (HERE/'run.log').open('w') as f:
 p=subprocess.Popen(c,cwd=ROOT,env=e,stdout=f,stderr=subprocess.STDOUT)
 with (HERE/'sample.log').open('w') as sf:subprocess.run(['/usr/bin/sample',str(p.pid),'12','-file',str(HERE/'sample.txt')],stdout=sf,stderr=subprocess.STDOUT,check=True)
 result=p.wait()
 if result:raise RuntimeError(result)
assert json.loads((HERE/'report.json').read_text())['proof_sha256']==r['proof_sha256']
print('Six diagnostic proofs completed; retained hash matches canonical baseline.')
