import pathlib,subprocess,json,hashlib,statistics,time
repo=pathlib.Path('/private/tmp/stwo-rv64-arith')
bs=[repo/'.zig-cache/products/riscv_cpu/o/b4f483e5f4c0108016adf1c3b57f00d4/rv64-word16-ethereum-gkr',repo/'.zig-cache/products/riscv_cpu/o/abef7680771edcf32658d46da5ed348b/rv64-word16-ethereum-gkr']
base=pathlib.Path('/tmp/rv64-wide-deep-rows-ab-v1');base.mkdir(exist_ok=True)
rows=[]
for i,k in enumerate([0,1,1,0,0,1]):
 out=base/f'{i}-{k}'
 cmd=[str(bs[k]),'produce-control','/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/request.json','/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/jobs',str(out),'1','/tmp/rv64-om-ethereum-prefix-resident16-resources.json']
 with (base/f'{i}.time.log').open('w') as log:subprocess.run(['/usr/bin/time','-l',*cmd],cwd=repo,stdout=log,stderr=log,check=True)
 r=json.loads((out/'report.json').read_text());s=json.loads((out/'physical-0000.stages.json').read_text())
 hashes={n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in ['cpu-0.bin','stage-one.bin','bundle.json','cells.bin']}
 with (base/f'{i}.fresh.json').open('w') as log:subprocess.run([str(bs[1]),'verify-prefix-control',cmd[2],str(out)],cwd=repo,stdout=log,check=True)
 rows.append({'index':i,'variant':['baseline','row_packed'][k],'binary_sha256':hashlib.sha256(bs[k].read_bytes()).hexdigest(),'report':r,'top_level_stages':{x['id']:x['seconds'] for x in s['stages'] if x['id'] in ['fri_quotient_build_and_commit','composition_evaluation','trace_decommit']},'artifact_sha256':hashes,'fresh':json.load(open(base/f'{i}.fresh.json'))})
 (base/'progress.json').write_text(json.dumps(rows,indent=2)+'\n')
med={}
for name in ['baseline','row_packed']:
 xs=[x for x in rows if x['variant']==name]
 med[name]={'prove_seconds':statistics.median(x['report']['prove_ns']/1e9 for x in xs),'quotient_seconds':statistics.median(x['top_level_stages']['fri_quotient_build_and_commit'] for x in xs)}
res={'runs':rows,'medians':med,'all_artifacts_identical':all(x['artifact_sha256']==rows[0]['artifact_sha256'] for x in rows),'all_fresh_accepted':all(x['fresh']['accepted'] for x in rows),'security_qualified':False,'scope':'Same4.19M-step prefix, q70/P26/fold4/16workers. Control profiles differ in core row executor only; baseline fixed cache source differs but unused by control. Shared-host observations, not isolated hardware.'}
(base/'summary.json').write_text(json.dumps(res,indent=2)+'\n')
print(json.dumps({'medians':med,'all_artifacts_identical':res['all_artifacts_identical'],'all_fresh_accepted':res['all_fresh_accepted']}))
