"""Screen larger leaves before spending time on their canonical proofs."""
from pathlib import Path
import hashlib,json,subprocess,sys,time
H=Path(__file__).resolve().parent
R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
out=H/'segment-geometry-v1'
out.mkdir(exist_ok=False)
binary=H/'segment-geometry'
elf=H/'ethereum-block-sha-default-v3.elf'
input_path=H/'fixture/stwo-runner-input-evm-hints.bin'
oracle=H/'fixture/expected-output.bin'
# SHA-profile execution independently measured this total. Assert the planner's
# count below; the preflight itself re-executes and validates the output oracle.
cycles=139214856
recovery_cycle=55074081
results=[]
with build_lock(label='ethereum-segment-geometry'):
    for limit in (2097152,1048576,524288):
        needed=(cycles+limit-1)//limit
        leaves=1<<(needed-1).bit_length()
        base,extra=divmod(cycles,leaves)
        def first(i): return 1+base*i+min(i,extra)
        recovery=max(i for i in range(leaves) if first(i)<=recovery_cycle)
        for label,target in [('entry',0),('evm-recovery',recovery),('terminal',leaves-1)]:
            command=[str(binary),str(elf),str(input_path),str(oracle),str(limit),str(target)]
            start=time.monotonic()
            result=subprocess.run(command,cwd=R,capture_output=True,text=True)
            stem=f'{leaves}-{label}'
            (out/(stem+'.stdout')).write_text(result.stdout)
            (out/(stem+'.stderr')).write_text(result.stderr)
            record={'command':command,'exit_code':result.returncode,'wall_seconds':time.monotonic()-start}
            if result.returncode==0:
                report=json.loads(result.stdout)
                assert report['segments']==leaves and report['target']==target
                assert report['proof_verified'] is False
                record['geometry']=report
            results.append(record)
            (out/'results.json').write_text(json.dumps({'scope':'geometry screening only; no proofs or speedup claims','results':results,'sha256':{str(p.relative_to(R)):hashlib.sha256(p.read_bytes()).hexdigest() for p in (binary,elf,input_path,oracle)}},indent=2)+'\n')
            print(stem,record.get('geometry',{}).get('commitment_trace_fits'),result.returncode,flush=True)
            if result.returncode or not report['commitment_trace_fits']:
                break  # Already fails; do not spend time on further regions.
