import json,pathlib,subprocess,hashlib,os,time
repo=pathlib.Path('/private/tmp/stwo-rv64-truth-range-source')
base=pathlib.Path('/tmp/rv64-truth-range-service-prefix-v1');base.mkdir(exist_ok=True)
reference=pathlib.Path('/tmp/rv64-classic-inline-prefix4-ab-v1/1-1')
output=base/'produced'
binary=repo/'zig-out/bin/rv64-word16-ethereum-gkr'
config='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/request.json'
jobs='/tmp/stwo-rv64-ethereum-round5-native-jobs-v1/jobs'
resources='/tmp/rv64-om-ethereum-prefix-resident16-resources.json'
env={k:v for k,v in os.environ.items() if not k.startswith('STWO_ZIG_GKR_')}
with (base/'produce.log').open('w') as log:
 subprocess.run([str(binary),'produce-control',config,jobs,str(output),'4',resources],cwd=repo,env=env,stdout=log,stderr=log,check=True)
def hashes(path):return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in path.iterdir() if p.suffix=='.bin' or p.name=='bundle.json'}
expected=hashes(reference);actual=hashes(output)
if expected!=actual:raise RuntimeError('authoritative artifact mismatch')
with (base/'fresh.json').open('w') as log:subprocess.run([str(binary),'verify-prefix-control',config,str(output)],cwd=repo,env=env,stdout=log,check=True)
fresh=json.load(open(base/'fresh.json'))
if not fresh['accepted']:raise RuntimeError('fresh receiver rejection')
bundle=json.load(open(output/'bundle.json'))
assert any(t['declaration']['family']=='keccak' for t in bundle['truths'])
report={'source_base':'1e6e98ed0','binary_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(),'reference_source':'49eb1e679 through7da90cea2','reference_artifacts':str(reference),'artifacts':actual,'all_authoritative_artifacts_identical':True,'fresh':fresh,'candidate_report':json.load(open(output/'report.json')),'performance_claim':False,'scope':'Functional-only real4CPU serviceprefix; default materialized GKR flags cleared. No same-source timing comparison. Not complete Ethereum acceptance or new security qualification.'}
(base/'receipt.json').write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps({'all_authoritative_artifacts_identical':True,'fresh':fresh,'artifacts':len(actual)}),flush=True)
