import pathlib,subprocess,os,json,re,hashlib,statistics,shutil
repo=pathlib.Path('/private/tmp/stwo-rv64-gkr-lazy-checkpoint');base=pathlib.Path('/tmp/rv64-gkr-lazy-cpu0-v1');shutil.copyfile(repo/'zig-out/bin/rv64-word16-ethereum-gkr',base/'candidate.bin');(base/'candidate.bin').chmod(0o755)
bins=[base/'baseline.bin',base/'candidate.bin'];rows=[];authority=None
for i,k in enumerate([0,1,1,0]):
 out=base/f'{i}-{k}';env=dict(os.environ);env['STWO_ZIG_GKR_TREE_CHECKPOINTS']='2';env['STWO_ZIG_GKR_TREE_METRICS']='1'
 cmd=[str(bins[k]),'produce-control','/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/request.json','/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/jobs',str(out),'1','/tmp/rv64-om-ethereum-prefix-resident16-resources.json']
 with (base/f'{i}.time.log').open('w') as log:subprocess.run(['/usr/bin/time','-l',*cmd],cwd=repo,env=env,stdout=log,stderr=log,check=True)
 names=sorted([p.name for p in out.iterdir() if p.suffix=='.bin']+['bundle.json']);sha={n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in names}
 if authority is None:authority=sha
 if sha!=authority:raise RuntimeError(f'ARTIFACTS DIFFER {i}')
 with (base/f'{i}.fresh.json').open('w') as log:subprocess.run([str(bins[1]),'verify-prefix-control',cmd[2],str(out)],cwd=repo,stdout=log,check=True)
 fresh=json.loads((base/f'{i}.fresh.json').read_text());assert fresh['accepted']
 report=json.loads((out/'report.json').read_text());text=(base/f'{i}.time.log').read_text();metric=re.search(r'GKR_TREE_POLICY stride=(\d+) numerical_requested_peak=(\d+) including_binding_peak=(\d+) raw_input_bytes=(\d+)',text);assert metric
 row={'run':i,'variant':['retained_odd','lazy_odd'][k],'binary_sha256':hashlib.sha256(bins[k].read_bytes()).hexdigest(),'numerical_requested_peak':int(metric[2]),'including_binding_requested_peak':int(metric[3]),'raw_input_bytes':int(metric[4]),'prove_seconds':report['prove_ns']/1e9,'numerical_seconds':report['workers'][0]['numerical_ns']/1e9,'gkr_seconds':report['workers'][0]['gkr_ns']/1e9,'binding_seconds':report['workers'][0]['binding_ns']/1e9,'artifact_sha256':sha,'fresh':fresh,'report':report};rows.append(row);(base/'progress.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps({k:v for k,v in row.items() if k not in ['fresh','report','artifact_sha256']}),flush=True)
med={v:{key:statistics.median(r[key] for r in rows if r['variant']==v) for key in ['numerical_requested_peak','including_binding_requested_peak','prove_seconds','numerical_seconds','gkr_seconds','binding_seconds']} for v in ['retained_odd','lazy_odd']}
(base/'summary.json').write_text(json.dumps({'source':'51e952592','base':'63ab7e2c6','scope':'realCPU0 4194303steps matchedq70/P26/f4/16workers/stride2/parkfalse; sharedhost, notwholeblock/128qualification','runs':rows,'medians':med,'all_artifacts_identical':True,'all_fresh_accepted':True},indent=2)+'\n');print(json.dumps(med),flush=True)
