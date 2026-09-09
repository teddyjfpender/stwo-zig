import collections,hashlib,json,pathlib,struct
repo=pathlib.Path.cwd();evidence=repo/'autoresearch/notes/2026-09-05-pr198-local-ethereum-plan/evidence/2026-09-07-real-campaign-v1'
proof=repo/'.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907/cpu-field4-segment9-selected-v5/segment-000009.stwief04'
b=proof.read_bytes();sha=hashlib.sha256(b).hexdigest();assert sha=='43aa15db272bfb6fdac201c5bf682dbc0887444ada440d9721afe5d099a2c2d8'
assert b[:8]==b'STWIEF04';version,schema,reserved,total,*lengths=struct.unpack_from('<HHIQ6Q',b,8);assert(version,schema,reserved,total)==(4,2,0,len(b))
p=72;sections=[]
for length in lengths:sections.append(b[p:p+length]);p+=length
assert p+32==len(b)
old=json.loads((evidence/'real-selected-component-geometry.json').read_text())['rows'];trees=[collections.Counter() for _ in range(3)];sources=[]
def record(group,index,log,rows,pp,main,interaction):
 previous=next(r for r in old if r['group']==group and r['index']==index)
 assert(previous['log_size'],previous['rows'],previous['columns'])==(log,rows,pp+main+interaction)
 for t,c in zip(trees,(pp,main,interaction)):t[log]+=c
 sources.append({'group':group,'index':index,'kind':previous['kind'],'rows':rows,'log_size':log,'columns':[pp,main,interaction]})
s=sections[0];assert struct.unpack_from('<H',s)[0]==1;p=2;n=struct.unpack_from('<I',s,p)[0];p+=4
for i in range(n):
 family,log,rows,main=struct.unpack_from('<BIII',s,p);p+=13;prior=next(r for r in old if r['group']=='core' and r['index']==i);record('core',i,log,rows,2,main,prior['columns']-main-2)
initial,final,steps,ninfra=struct.unpack_from('<4I',s,p);p+=16
for i in range(ninfra):
 kind,log,rows,main=struct.unpack_from('<4I',s,p);p+=16;pp=2 if kind<5 else {5:5,6:2,7:3,8:4,9:3,10:3}[kind];prior=next(r for r in old if r['group']=='infra' and r['index']==i);record('infra',i,log,rows,pp,main,prior['columns']-main-pp)
s=sections[2];assert len(s)==456;p=2+2+2+32+12
for i in range(14):
 kind,log,rows,pp,main,interaction=struct.unpack_from('<B5I',s,p);p+=21;record('ethereum',i,log,rows,pp,main,interaction)
bridge=next(r for r in old if r['group']=='bridge');record('bridge',0,bridge['log_size'],bridge['rows'],2,7,4)
result={'scope':'Diagnostic extraction from independently fresh-verified native artifact; not a verifier/admission constructor. Geometry is cross-checked against retained preflight descriptors and exact live Tree1/alltrees totals.','proof_sha256':sha,'blowup_log':1,'sources':sources,'trees':[]}
for i,t in enumerate(trees):result['trees'].append({'tree':i,'columns':sum(t.values()),'source_log_histogram':dict(sorted(t.items())),'lde_log_histogram':{str(k+1):v for k,v in sorted(t.items())},'retained_lde_bytes':sum(v*(1<<(k+1))*4 for k,v in t.items())})
assert sum(t['columns'] for t in result['trees'])==16894
assert sum(t['retained_lde_bytes'] for t in result['trees'])==20550093056
assert(result['trees'][1]['columns'],result['trees'][1]['retained_lde_bytes'])==(8458,17253064448)
result['source_contracts']=['src/frontends/riscv/prover/guest_precompile/ethereum_segment_artifact_statement_wire.zig','src/frontends/riscv/prover/guest_precompile/ethereum_proof_artifact_wire.zig','src/frontends/riscv/air/statement.zig:nPreprocessedColumnsForInfra','src/frontends/riscv/air/lookups/tables/schema.zig:arity','retained component geometry supplies exact authenticated physical interaction widths; bridge uses shared2/7/4columns']
(evidence/'real-selected-cpu-success-column-histograms.json').write_text(json.dumps(result,indent=2)+'\n');print(json.dumps(result['trees'],indent=2))
