from pathlib import Path
import json,subprocess,sys
count=int(sys.argv[1]);backend=sys.argv[2];tree=Path(f'/tmp/pr198-canonical-{count}-{backend}-tree-20260918-v1');report=json.loads((tree/'report.json').read_text());assert report['passed']
other=Path('/tmp/pr198-'+('two' if count==2 else 'eight')+'-segment-expected-seed14-20260918-v1')
for step in report['steps']:
 if not step['name'].startswith('verify-leaf-'):continue
 i=int(step['name'].split('-')[-1]);args=step['argv'].copy();out=tree/f'substitution-{i}.json';args[args.index('--output')+1]=str(out);args+=['--other-expected-wire',str(other/f'child-{i}-expected-wire.json')]
 with (tree/f'substitution-{i}.log').open('x') as log:r=subprocess.run(args,stdout=log,stderr=subprocess.STDOUT)
 assert r.returncode==0 and json.loads(out.read_text())['passed']
print(count,backend,'all leaf statement substitutions rejected')
