"""Build and independently replay interpolated work schedules before any proof run."""
from pathlib import Path
import hashlib,json,subprocess,sys,time
H=Path(__file__).resolve().parent;R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
out=H/'work-schedule-qualification-v1';out.mkdir(exist_ok=False)
binary=H/'segment-geometry-work-schedules'
with (out/'build.log').open('x') as log:
    subprocess.run([sys.executable,str(H/'build_stream_memory_lifetimes.py'),'--root',str(R/'src/frontends/riscv/ethereum_segment_geometry.zig'),'--output',str(binary)],cwd=R,stdout=log,stderr=subprocess.STDOUT,check=True)
source=H/'segment-geometry-all-512-log25/segments.jsonl'
paths=[binary,H/'ethereum-block-sha-default-v3.elf',H/'fixture/stwo-runner-input-evm-hints.bin',H/'fixture/expected-output.bin']
with build_lock(label='work-schedule-replay'):
    for leaves in (256,512):
        schedule=out/f'schedule-{leaves}.json'
        subprocess.run([sys.executable,str(H/'plan_work_segments.py'),str(source),str(schedule),'--leaves',str(leaves)],cwd=R,check=True)
        command=[str(p) for p in paths]+['4194304','all',str(schedule)]
        start=time.monotonic()
        with (out/f'geometry-{leaves}.jsonl').open('x') as log,(out/f'geometry-{leaves}.stderr').open('x') as err:
            result=subprocess.run(command,cwd=R,stdout=log,stderr=err)
        records=[json.loads(line) for line in (out/f'geometry-{leaves}.jsonl').read_text().splitlines()]
        summary=records[-1] if records and records[-1].get('kind')=='summary' else None
        accepted=False
        if result.returncode==0:
            assert summary and summary['segments_checked']==leaves and len(records)==leaves+1
            assert [r['target'] for r in records[:-1]]==list(range(leaves))
            # Log25 was admitted but exhausted the 48GiB proof budget. Prefer
            # candidates that keep every commitment component at log24 or lower.
            accepted=max(summary['maximum_commitment_rows'])<=1<<24
        report={'command':command,'exit_code':result.returncode,'wall_seconds':time.monotonic()-start,'summary':summary,'every_commitment_component_at_most_log24':accepted,'proof_verified':False,'sha256':{str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in paths+[schedule]}}
        (out/f'replay-{leaves}.json').write_text(json.dumps(report,indent=2)+'\n')
        print(leaves,accepted,result.returncode,flush=True)
        if accepted:
            (out/'candidate.json').write_text(json.dumps({'segments':leaves,'schedule':str(schedule),'scope':'every segment geometry checked; canonical native and recursive proof qualification still required','proof_verified':False},indent=2)+'\n')
            break
