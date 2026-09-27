from pathlib import Path
import argparse,subprocess,sys,time,json,hashlib,os,re
h=Path(__file__).resolve().parent;r=h.parents[2];m=h.parent/'2026-09-24-recursive-memory'
sys.path.insert(0,str(r/'scripts'))
from zig_serial_build import build_lock
p=argparse.ArgumentParser();p.add_argument('--profile',choices=['canonical','diagnostic'],default='canonical');p.add_argument('--limit',type=int,default=4096);p.add_argument('--paired',action='store_true');p.add_argument('--run-id',default='',help='Unique suffix for repeat measurements');args=p.parse_args()
if args.run_id and not re.fullmatch(r'[A-Za-z0-9_-]+', args.run_id): p.error('--run-id must contain only letters, digits, underscores or hyphens')
stem=f'stream-terminal-planning-auth1-{args.profile}-{args.limit}' + ('-paired' if args.paired else '') + (f'-{args.run_id}' if args.run_id else '')
with build_lock(label='stream-complete-guest'):
 paths=[h/'block-stream-terminal-planning',m/'eth-auth-stwo-expanded.elf',m/'fixtures/batch-1.input',m/'fixtures/batch-1.expected']
 hashes={str(x.relative_to(r)):hashlib.sha256(x.read_bytes()).hexdigest() for x in paths}
 cmd=['/usr/bin/time','-l',*[str(x) for x in paths],str(args.limit),str(h/(stem+'.proof')),str(h/(stem+'.json')),args.profile]
 if args.paired: cmd.append('paired')
 start=time.monotonic()
 with (h/(stem+'.log')).open('x') as log: result=subprocess.run(cmd,cwd=r,stdout=log,stderr=subprocess.STDOUT,env=os.environ.copy())
 (h/(stem+'-invocation.json')).write_text(json.dumps(dict(environment={k:v for k,v in os.environ.items() if k.startswith('STWO_')},command=cmd,exit_code=result.returncode,wall_seconds=time.monotonic()-start,sha256=hashes),indent=2)+'\n')
 sys.exit(result.returncode)
