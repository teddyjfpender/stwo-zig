"""Old authenticated-layout artifacts must not pass the new verifier."""
import json,subprocess
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[2]
prior=ROOT/'autoresearch/notes/2026-09-24-overlapped-metal-stream-leaves'
case='metal-ecdsa_secp256k1-32-candidate-first'
report=json.loads((prior/f'{case}.json').read_text())
records=json.loads((prior/'metal-results.json').read_text())
r=next(x for x in records if x['case']=='metal-ecdsa_secp256k1-32' and x['arm']=='candidate-first')
cmd=r['command']
verify=[str(HERE/'candidate-products/bin/stwo-zig-riscv-metal'),'ecdsa-csp-verify','--artifact',str(prior/f'{case}.b3proof'),'--elf',cmd[cmd.index('--elf')+1],'--input',cmd[cmd.index('--input')+1],'--expect-statement-digest',report['statement_blake3']]
result=subprocess.run(verify,cwd=ROOT,capture_output=True,text=True)
(HERE/'old-layout-rejection.json').write_text(json.dumps(dict(command=verify,exit_code=result.returncode,stdout=result.stdout,stderr=result.stderr),indent=2)+'\n')
assert result.returncode!=0, 'Old layout unexpectedly accepted'
assert 'Untrusted' in result.stderr or 'Invalid' in result.stderr, 'Not an admission/verification rejection'
print('Old layout rejected:',result.stderr.strip())
