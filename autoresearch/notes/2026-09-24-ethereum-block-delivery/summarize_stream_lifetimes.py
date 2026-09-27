from pathlib import Path
import json,re
h=Path(__file__).resolve().parent
oldstem='stream-auth1-canonical-2048';newstem='stream-memory-lifetimes-auth1-canonical-2048'
o=json.loads((h/(oldstem+'.json')).read_text());n=json.loads((h/(newstem+'.json')).read_text())
assert n['complete_execution_proof_verified'] and n['canonical'] and n['queries']==70 and n['pow_bits']==26
for key in ('segments','cycles','elf_sha256','input_sha256','output_sha256','proof_sha256','statement','admission'):assert n[key]==o[key],key
assert (h/(oldstem+'.proof')).read_bytes()==(h/(newstem+'.proof')).read_bytes()
inv=json.loads((h/(newstem+'-invocation.json')).read_text());assert inv['exit_code']==0
foot=lambda s:int(re.search(r'(\d+)\s+peak memory footprint',(h/(s+'.log')).read_text())[1])
r=dict(scope='Complete one-transaction authentication guest, 16 actual execution leaves and four aggregation levels; not a full Ethereum block',queries=70,pow_bits=26,segments=n['segments'],cycles=n['cycles'],old_peak_bytes=o['peak_bytes'],peak_bytes=n['peak_bytes'],old_process_peak_bytes=foot(oldstem),process_peak_bytes=foot(newstem),old_total_ns=o['total_ns'],total_ns=n['total_ns'],proof_byte_identical=True,proof_sha256=n['proof_sha256'])
(h/'stream-lifetimes-summary.json').write_text(json.dumps(r,indent=2)+'\n');print(json.dumps(r,indent=2))
