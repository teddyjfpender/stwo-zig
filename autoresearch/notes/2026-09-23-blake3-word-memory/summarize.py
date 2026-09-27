"""Summarize only complete, independently verified diagnostic evidence."""
import hashlib,json,statistics
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
BASE=HERE.parent/'2026-09-23-blake3-csp-regression'
old=json.loads((BASE/'suite/results.json').read_text())
new=json.loads((HERE/'suite/results.json').read_text())
pairs=json.loads((HERE/'ecdsa-pairs/results.json').read_text())
assert len(old)==len(new)==32 and len(pairs)==8
assert all(r.get('independent_verified') for r in old+new) and all(r['verified'] for r in pairs)
a={r['case']:r for r in old}; b={r['case']:r for r in new}
assert a.keys()==b.keys()
summary={}
for backend in ['cpu','metal']:
 arms={arm:statistics.median(r['seconds'] for r in pairs if r['backend']==backend and r['arm']==arm) for arm in ['baseline','candidate']}
 arms['speedup']=arms['baseline']/arms['candidate'];summary[backend]=arms
(HERE/'ecdsa-summary.json').write_text(json.dumps(summary,indent=2)+'\n')
text='''# Canonical CSP word-memory results

Source-pinned dirty-tree diagnostics on Apple M5 Max / 64 GiB, ReleaseFast,
16 workers, canonical inputs and ELF routes, 70 queries / 26 PoW bits. One cold
sample per full-suite case, all 32 independently verified. Baseline and candidate
use the same parallel lookup counting and bounded coefficient retention. Candidate
adds authenticated public-program preprocessing and full-word memory commitments;
this is an architectural comparison across explicitly versioned root contracts,
not an isolated hash-algorithm comparison or clean-source release qualification.

| Workload | CPU seconds | CPU speedup | Metal seconds | Metal speedup |
| --- | ---: | ---: | ---: | ---: |
'''
for key in a:
 if not key.startswith('cpu-'):continue
 name=key[4:]; ck='cpu-'+name;mk='metal-'+name
 text+=f"| {name} | {b[ck]['total_seconds']:.6f} | {a[ck]['total_seconds']/b[ck]['total_seconds']:.2f}x | {b[mk]['total_seconds']:.6f} | {a[mk]['total_seconds']/b[mk]['total_seconds']:.2f}x |\n"
text+='''
## Matched ECDSA measurements

Separate baseline/candidate/candidate/baseline runs, two cold processes per arm
and backend, with identical stage diagnostics enabled in both arms and each
artifact freshly verified using its matching CLI. Both
use the pinned odd-parity precompile ELF and 1,828 execution steps. Medians:

| Backend | Baseline seconds | Candidate seconds | Speedup |
| --- | ---: | ---: | ---: |
'''
for backend,s in summary.items():text+=f"| {backend} | {s['baseline']:.6f} | {s['candidate']:.6f} | {s['speedup']:.2f}x |\n"
text+='''
Raw reports include execution, witness, admission, proving, artifact encoding,
fresh verification and process-lifetime memory. Historical 0.881876 s CPU ECDSA
used an earlier execution-memory contract; these results do not redefine that
historical measurement. Recursive qualification is recorded separately and must
not be presented as a matched recursion speedup.
'''
(HERE/'RESULTS.md').write_text(text)
readme=ROOT/'vectors/riscv_csp/README.md'
s=readme.read_text();marker='### Word-memory CSP recovery (2026-09-23)'
assert marker not in s
s+='\n\n'+marker+'\n\n'+text[text.index('Source-pinned'):]
s+='\n[Source, qualification and raw benchmark evidence](../../autoresearch/notes/2026-09-23-blake3-word-memory/README.md).\n'
readme.write_text(s)
for directory in [HERE/'suite',HERE/'ecdsa-pairs']:
 entries=[hashlib.sha256(p.read_bytes()).hexdigest()+'  '+str(p.relative_to(directory)) for p in sorted(directory.rglob('*')) if p.is_file() and p.name!='SHA256SUMS']
 (directory/'SHA256SUMS').write_text('\n'.join(entries)+'\n')
print(json.dumps(summary,indent=2))
