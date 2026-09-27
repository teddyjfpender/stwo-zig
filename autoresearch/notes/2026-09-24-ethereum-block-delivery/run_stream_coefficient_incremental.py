from pathlib import Path
import argparse,subprocess,sys,time,json,hashlib,os
h=Path(__file__).resolve().parent;r=h.parents[2];m=h.parent/'2026-09-24-recursive-memory'
sys.path.insert(0,str(r/'scripts'))
from zig_serial_build import build_lock
p=argparse.ArgumentParser();p.add_argument('--profile',choices=['canonical','diagnostic'],default='diagnostic');p.add_argument('--limit',type=int,default=4096);p.add_argument('--paired',action='store_true');args=p.parse_args()
stem=f'stream-coefficient-incremental-auth1-{args.profile}-{args.limit}' + ('-paired' if args.paired else '')
with build_lock(label='stream-complete-guest'):
 paths=[h/'block-stream-coefficient-incremental',m/'eth-auth-stwo-expanded.elf',m/'fixtures/batch-1.input',m/'fixtures/batch-1.expected']
 hashes={str(x.relative_to(r)):hashlib.sha256(x.read_bytes()).hexdigest() for x in paths}
 cmd=['/usr/bin/time','-l',*[str(x) for x in paths],str(args.limit),str(h/(stem+'.proof')),str(h/(stem+'.json')),args.profile]
 if args.paired: cmd.append('paired')
 start=time.monotonic()
 with (h/(stem+'.log')).open('x') as log: result=subprocess.run(cmd,cwd=r,stdout=log,stderr=subprocess.STDOUT,env={**os.environ,'STWO_RISCV_COMPACT_POLYNOMIALS':'1'})
 (h/(stem+'-invocation.json')).write_text(json.dumps(dict(command=cmd,exit_code=result.returncode,wall_seconds=time.monotonic()-start,sha256=hashes),indent=2)+'\n')
 sys.exit(result.returncode)
