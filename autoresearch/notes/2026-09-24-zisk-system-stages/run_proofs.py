from pathlib import Path
import json,subprocess,shutil,hashlib,sys,re,statistics
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
mirror=Path(json.loads((H/'proof-baseline-mirror.json').read_text())['path'])
canonical='--canonical' in sys.argv
needle=b'Keccak-f BLAKE3 canonical system benchmark' if canonical else b'Keccak-f typed shard and lookup tables prove and independently verify'
tag='canonical-' if canonical else ''
for arm,root in [('before',mirror),('after',R)]:
 candidates=[]
 for p in (root/'src/integrations/riscv_cpu/.zig-cache/o').glob('*/test'):
  if p.stat().st_size and needle in p.read_bytes():candidates.append(p)
 assert candidates,(arm,'proof binary missing')
 p=max(candidates,key=lambda p:p.stat().st_mtime_ns);shutil.copy2(p,H/(tag+arm+'-proof'))
pattern=re.compile(r'Keccak-f proof timings: witness=([\d.]+)ms pp=([\d.]+)ms main=([\d.]+)ms interaction-gen=([\d.]+)ms interaction-commit=([\d.]+)ms prove=([\d.]+)ms verify=([\d.]+)ms')
rows=[]
with build_lock(label='keccak-verified-proof-comparison'):
 power=subprocess.check_output(['pmset','-g','batt'],text=True)
 for i,arm in enumerate(['after','before','before','after','before','after','after','before']):
  result=subprocess.run([str(H/(tag+arm+'-proof'))],capture_output=True,text=True,check=True);output=result.stdout+result.stderr;(H/f'{tag}proof-{i}-{arm}.log').write_text(output)
  m=pattern.search(output);assert m
  if canonical:assert 'queries=70 pow=26 workers=16' in output
  values=list(map(float,m.groups()));row=dict(arm=arm,witness_ms=values[0],prove_production_ms=sum(values[:6]),verify_ms=values[6],total_ms=sum(values),stages_ms=values);rows.append(row);print(row,flush=True)
 end=subprocess.check_output(['pmset','-g','batt'],text=True);assert ("'AC Power'" in power)==("'AC Power'" in end)
 data=dict(profile='BLAKE3 Keccak typed shard, 70 queries, PoW 26, blowup log 1, 16 scoped workers; standalone precompile, not full CSP guest' if canonical else 'Blake2s diagnostic Keccak typed shard, 3 queries, PoW 0, blowup log 1; not canonical CSP',power_before=power,power_after=end,samples=rows,median={arm:{k:statistics.median(r[k] for r in rows if r['arm']==arm) for k in ('witness_ms','prove_production_ms','verify_ms','total_ms')} for arm in ('before','after')},binaries={arm:hashlib.sha256((H/(tag+arm+'-proof')).read_bytes()).hexdigest() for arm in ('before','after')})
 (H/(tag+'proof-results.json')).write_text(json.dumps(data,indent=2)+'\n')
