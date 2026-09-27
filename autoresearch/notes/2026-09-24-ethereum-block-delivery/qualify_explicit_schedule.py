"""Complete canonical root and fresh receiver check across unequal execution leaves."""
from pathlib import Path
import hashlib,json,subprocess,sys,time
H=Path(__file__).resolve().parent;R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
out=H/'explicit-schedule-root-v1';out.mkdir(exist_ok=False)
# This is the previously qualified complete authentication fixture, not a block.
fixture=json.loads((H/'measurements-auth1-canonical-stages/measurement.json').read_text())
elf,input_path,oracle=map(Path,fixture['command'][3:6])
binary=H/'block-stream-sizing-log25-stages'
receiver=H/'block-receiver-qualification-v1/block-verify'
schedule=out/'schedule.json';schedule.write_text('[8000,13635]\n')
proof=out/'root.proof';report=out/'report.json'
command=[str(binary),str(elf),str(input_path),str(oracle),'16384',str(proof),str(report),'canonical','schedule='+str(schedule)]
with build_lock(label='explicit-schedule-root-qualification'):
    rejected=[]
    for name,budgets in [('missing-cycle',[8000,13634]),('invalid-slot-count',[8000,8000,5635])]:
        bad=out/(name+'.json');bad.write_text(json.dumps(budgets))
        bad_proof=out/(name+'.proof');bad_report=out/(name+'.report')
        bad_command=[str(binary),str(elf),str(input_path),str(oracle),'16384',str(bad_proof),str(bad_report),'canonical','schedule='+str(bad)]
        result=subprocess.run(bad_command,cwd=R,capture_output=True,text=True)
        (out/(name+'.stderr')).write_text(result.stderr)
        assert result.returncode and 'InvalidSegmentSchedule' in result.stderr
        assert not bad_proof.exists() and not bad_report.exists()
        rejected.append(name)
    start=time.monotonic()
    with (out/'prove.log').open('x') as log:
        result=subprocess.run(command,cwd=R,stdout=log,stderr=subprocess.STDOUT)
    if result.returncode: raise RuntimeError('explicit schedule proof failed; see prove.log')
    claimed=json.loads(report.read_text())
    assert claimed['complete_execution_proof_verified'] and claimed['explicit_segment_schedule']
    assert claimed['segments']==2 and claimed['cycles']==21635
    assert claimed['queries']==70 and claimed['pow_bits']==26
    pin=bytes(claimed['admission']['expected_id']).hex()
    checked=subprocess.run([str(receiver),str(proof),str(report),pin],cwd=R,capture_output=True,text=True)
    (out/'receiver.stdout').write_text(checked.stdout);(out/'receiver.stderr').write_text(checked.stderr)
    assert checked.returncode==0 and json.loads(checked.stdout)['complete_execution_proof_verified']
    (out/'qualification.json').write_text(json.dumps({'scope':'complete authentication fixture with unequal explicit leaf budgets and fresh-process receiver; not a mainnet block proof','command':command,'wall_seconds':time.monotonic()-start,'proof_verified':True,'rejected_invalid_schedules':rejected,'sha256':{str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (binary,receiver,elf,input_path,oracle,schedule,proof,report)}},indent=2)+'\n')
print('explicit schedule full root and independent receiver passed',flush=True)
