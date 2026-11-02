import subprocess,re,collections,json,pathlib
files={'baseline':'/tmp/rv64-classic-inline-prefix4-ab-v1/baseline.bin','candidate':'/private/tmp/stwo-rv64-classic-packed-inline/zig-out/bin/rv64-word16-ethereum-gkr'}
r={}
for kind,fn in files.items():
 p=subprocess.Popen(['/opt/homebrew/opt/llvm/bin/llvm-objdump','-d','--no-show-raw-insn',fn],stdout=subprocess.PIPE,text=True)
 method=collections.Counter();calls=collections.Counter(); caller=''
 for line in p.stdout:
  m=re.match(r'^[0-9a-f]+ <(.+)>:',line)
  if m:caller=m[1]
  if '\tbl\t' in line and 'Quadratic(fields.packed_qm31.PackedQM31,fields.packed_om31.Ops).mul>' in line:calls[caller]+=1
  if '\tbl\t' in line and 'PackedOmSecure.mulBase>' in line:method[caller]+=1
 p.wait();r[kind]={'packed_full_mul_calls':dict(calls),'packed_full_mul_call_count':sum(calls.values()),'wide_512B_mulBase_calls':dict(method),'wide_512B_mulBase_call_count':sum(method.values())}
pathlib.Path('/tmp/rv64-classic-inline-abi.json').write_text(json.dumps(r,indent=2)+'\n')
print(json.dumps({k:{'mul':v['packed_full_mul_call_count'],'512BmulBase':v['wide_512B_mulBase_call_count'],'air_full_mul':sum(n for c,n in v['packed_full_mul_calls'].items() if 'rv64.air.' in c or 'gkr_local' in c)} for k,v in r.items()}))
