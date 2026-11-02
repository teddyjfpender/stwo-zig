import pathlib,subprocess,json,hashlib,statistics,time,shutil,os,re
repo=pathlib.Path('/private/tmp/stwo-rv64-gkr-public-aux')
base=pathlib.Path('/tmp/rv64-active-om-air-prefix4-ab-v1');base.mkdir(exist_ok=True)
original=pathlib.Path('/tmp/rv64-om-grouped-prefix4-ab-v1/candidate.bin')
candidate=repo/'zig-out/bin/rv64-word16-ethereum-gkr'
bs=[base/'baseline.bin',base/'candidate.bin']
for a,b in zip([original,candidate],bs):shutil.copyfile(a,b);b.chmod(0o755)
rows=[];authority=None
for i,k in enumerate([0,1,1,0,0,1]):
 out=base/f'{i}-{k}'
 cmd=[str(bs[k]),'produce-control','/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/request.json','/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/jobs',str(out),'4','/tmp/rv64-om-ethereum-prefix-resident16-resources.json']
 env=dict(os.environ);env['STWO_ZIG_PROFILE_OM_DOMAIN']='1'
 with (base/f'{i}.time.log').open('w') as log:subprocess.run(['/usr/bin/time','-l',*cmd],cwd=repo,env=env,stdout=log,stderr=log,check=True)
 r=json.loads((out/'report.json').read_text());s=json.loads((out/'physical-0000.stages.json').read_text())
 declarations=json.loads((out/'bundle.json').read_text())
 if not any(t['declaration']['family']=='keccak' for t in declarations['truths']):raise RuntimeError('prefix4 has no Keccak; stop for larger coverage rather than claim service qualification')
 hashes={n:hashlib.sha256((out/n).read_bytes()).hexdigest() for n in sorted([p.name for p in out.iterdir() if p.suffix=='.bin']+['bundle.json'])}
 if authority is None:authority=hashes
 if hashes!=authority:raise RuntimeError(f'ARTIFACT MISMATCH in run{i}, variant{k}')
 with (base/f'{i}.fresh.json').open('w') as log:subprocess.run([str(bs[1]),'verify-prefix-control',cmd[2],str(out)],cwd=repo,stdout=log,check=True)
 fresh=json.load(open(base/f'{i}.fresh.json'))
 if not fresh['accepted']:raise RuntimeError(f'fresh reject {i}')
 w={key:sum(v[key] for v in r['workers'][:4]) for key in ['numerical_ns','gkr_ns','inputs_ns','binding_ns','native_complete_ns','source_ns']}
 record={'index':i,'variant':['baseline','active_air_fused'][k],'binary_sha256':hashlib.sha256(bs[k].read_bytes()).hexdigest(),'prove_seconds':r['prove_ns']/1e9,'numerical_seconds':w['numerical_ns']/1e9,'gkr_seconds':w['gkr_ns']/1e9,'inputs_seconds':w['inputs_ns']/1e9,'binding_seconds':w['binding_ns']/1e9,'native_complete_seconds':w['native_complete_ns']/1e9,'truth_native_complete_seconds':sum(x['native_complete_ns'] for x in r['workers'][4:])/1e9,'truth_inventory':[t['declaration'] for t in declarations['truths']],'source_seconds':w['source_ns']/1e9,'report':r,'top_level_stages':{x['id']:x['seconds'] for x in s['stages'] if x['id'] in ['fri_quotient_build_and_commit','composition_evaluation','trace_decommit']},'artifact_sha256':hashes,'fresh':fresh}
 rows.append(record);(base/'progress.json').write_text(json.dumps(rows,indent=2)+'\n');print(json.dumps({x:y for x,y in record.items() if x not in ['report','fresh','artifact_sha256']}),flush=True)
med={}
for name in ['baseline','active_air_fused']:
 xs=[x for x in rows if x['variant']==name];med[name]={key:statistics.median(x[key] for x in xs) for key in ['prove_seconds','numerical_seconds','gkr_seconds','inputs_seconds','binding_seconds','native_complete_seconds','truth_native_complete_seconds']}
res={'source_commit':'0d5f8fa4d','runs':rows,'medians':med,'all_artifacts_identical':True,'all_fresh_accepted':True,'security_qualified':False,'scope':'Same real four-CPU service prefix, q70/P26/fold4/16workers. Both have prior rank-two gates, numerical packed inlining, row-packed DEEP and public-aux. Candidate adds actual PackedOmSecure multiplication inlining and pointer weighted-base accumulation. Archived core-only helper is present on both and is not attributed. Control fixed-setup source changes are unselected by q70 control. Shared-host observations, not isolated hardware. Prefix completion is not full Ethereum acceptance.'}
(base/'summary.json').write_text(json.dumps(res,indent=2)+'\n');print(json.dumps({'medians':med,'all_artifacts_identical':True,'all_fresh_accepted':True}),flush=True)
