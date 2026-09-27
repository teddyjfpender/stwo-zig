"""Canonical full-custody qualification of geometry-screened real block leaves."""
from pathlib import Path
import argparse,hashlib,json,subprocess,sys,time
H=Path(__file__).resolve().parent;R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
parser=argparse.ArgumentParser()
parser.add_argument('--name',default='segment-proof-sizing-v1')
parser.add_argument('--binary',default='block-stream-sizing')
parser.add_argument('--max-log',type=int,default=24,choices=(24,25))
parser.add_argument('--work-directory',type=Path)
options=parser.parse_args()
out=H/options.name;out.mkdir(exist_ok=False)
binary=H/options.binary;elf=H/'ethereum-block-sha-default-v3.elf' 
input_path=H/'fixture/stwo-runner-input-evm-hints.bin';oracle=H/'fixture/expected-output.bin'
records=[]
schedule_path=None
def measure(geometry):
    leaves=geometry['segments'];target=geometry['target'];stem=f'{leaves}-{target}'
    report_path=out/(stem+'.json');proof_path=out/(stem+'.unused-proof')
    command=[str(binary),str(elf),str(input_path),str(oracle),str(geometry['maximum_cycles']),str(proof_path),str(report_path),'canonical',f'segment={target}']
    if schedule_path is not None: command.append('schedule='+str(schedule_path))
    start=time.monotonic()
    with (out/(stem+'.log')).open('x') as log:
        try: code=subprocess.run(command,cwd=R,stdout=log,stderr=subprocess.STDOUT,timeout=900).returncode
        except subprocess.TimeoutExpired: code='timeout'
    record={'segments':leaves,'target':target,'command':command,'exit_code':code,'wall_seconds':time.monotonic()-start}
    if code==0:
        report=json.loads(report_path.read_text())
        assert report['segment_recursive_proof_verified'] and not report['complete_execution_proof_verified']
        assert report['canonical'] and report['queries']==70 and report['pow_bits']==26
        assert report['segments']==leaves and report['segment_index']==target
        assert report['cycles']==geometry['cycles'] and report['global_first_cycle']==geometry['global_first_cycle']
        assert report.get('explicit_segment_schedule',False)==(schedule_path is not None)
        assert not proof_path.exists()
        stages=report['stage_ns']
        proof_ns=sum(stages[k] for k in ('witness_preparation','verifier_preparation','leaf_proof_and_recursive_witness','recursive_proving_and_aggregation'))
        record.update(report=report,proof_ns=proof_ns,proof_ns_per_cycle=proof_ns/report['cycles'])
    records.append(record)
    save()
    print(stem,code,record.get('proof_ns_per_cycle'),flush=True)
    return record

def save():
    (out/'results.json').write_text(json.dumps({'scope':'selected full-custody recursive leaf proofs; not a complete block or aggregate benchmark','admission_log_cap':options.max_log,'records':records,'sha256':{str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in [binary,elf,input_path,oracle,R/'src/frontends/riscv/ethereum_block_stream.zig']+([schedule_path] if schedule_path else [])}},indent=2)+'\n')

with build_lock(label='ethereum-segment-proof-sizing'):
    if options.work_directory:
        candidate=json.loads((options.work_directory/'candidate.json').read_text())
        leaves=candidate['segments']
        schedule_path=out/'schedule.json'
        schedule_path.write_bytes(Path(candidate['schedule']).read_bytes())
        rows=[json.loads(line) for line in (options.work_directory/f'geometry-{leaves}.jsonl').read_text().splitlines()]
        summary=rows.pop()
        assert summary['kind']=='summary' and len(rows)==leaves
        assert max(summary['maximum_commitment_rows'])<=1<<options.max_log
        selected=[]
        for key in (lambda r:max(r['commitment_rows']),lambda r:r['cycles'],lambda r:r['keccak_calls'],lambda r:r['recovery_calls'],lambda r:r['target']):
            row=max(rows,key=key)
            if row['target'] not in [r['target'] for r in selected]: selected.append(row)
        for row in selected:
            result=measure(row)
            if result['exit_code']!=0: raise RuntimeError('work schedule representative proof failed; inspect stage log')
        (out/'selection.json').write_text(json.dumps({'selected_segments':leaves,'scope':'all-segment geometry and selected worst-case canonical full-custody leaf proofs; complete block root still required','schedule':str(schedule_path),'targets':[r['target'] for r in selected]},indent=2)+'\n')
        sys.exit(0)
    screening=json.loads((H/'segment-geometry-v1/results.json').read_text())['results']
    groups={}
    for item in screening:
        if item['exit_code']==0:
            g=item['geometry'];groups.setdefault(g['segments'],[]).append(g)
    candidates=[gs for gs in groups.values() if len(gs)==3 and all(max(g['commitment_rows']) <= 1 << options.max_log for g in gs)]
    measured=[]
    for gs in sorted(candidates,key=lambda gs:gs[0]['segments']):
        # Terminal geometry was the largest measured case; qualify it first.
        terminal=measure(gs[2])
        if terminal['exit_code']!=0: continue
        r=measure(gs[0])
        if r['exit_code']==0: measured.append((r['proof_ns_per_cycle'],gs))
    qualified=None
    for _,gs in sorted(measured,key=lambda item:item[0]):
        if all(measure(g)['exit_code']==0 for g in gs[1:2]):
            qualified=gs[0]['segments'];break
    (out/'selection.json').write_text(json.dumps({'selected_segments':qualified,'scope':'best measured entry throughput among screened sizes, then qualified EVM and terminal leaves; full block still required','records':'results.json'},indent=2)+'\n')
    if qualified is None: raise RuntimeError('No larger size qualified; inspect failures before full run')
