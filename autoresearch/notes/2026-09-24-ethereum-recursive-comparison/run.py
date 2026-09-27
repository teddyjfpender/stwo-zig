"""Serial, retained CPU comparison. Usage: run.py local|peer CASE execute|prove LABEL."""
from pathlib import Path
import hashlib,json,os,signal,subprocess,sys,time
H=Path(__file__).resolve().parent
R=H.parents[2]
sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock

side,case,mode,label=sys.argv[1:]
assert side in ('local','peer') and mode in ('execute','prove','prepare')
assert mode!='prepare' or side=='local', 'Preparation diagnostics are local-only.'
assert all(x and all(c.isalnum() or c in '-_' for c in x) for x in (case,label))
stem=H/f'{side}-{case}-{mode}-{label}'
report=Path(str(stem)+'.json');proof=Path(str(stem)+'.proof');log=Path(str(stem)+'.log')
assert not any(x.exists() for x in (report,proof,log)), 'Choose a fresh label; retained evidence is immutable.'
input_path=H/'fixtures'/f'{case}.input';expected_path=H/'fixtures'/f'{case}.expected'
if side=='local':
    binary=H/'local-host';elf=H/'guest-stwo/target/riscv32im-unknown-none-elf/release/eth-auth-stwo'
    command=[str(binary),str(elf),str(input_path),str(expected_path),str(proof),str(report),mode]
else:
    binary=Path('/tmp/stwo-zisk-guest-e2e-20260924/target/release/zisk-eth-auth-benchmark')
    elf=H/'guest-zisk/target/riscv64ima-zisk-zkvm-elf/release/eth-auth-zisk'
    command=[str(binary),str(elf),str(input_path),str(expected_path),'/tmp/stwo-zisk-guest-e2e-20260924/provingKey',str(proof),str(report),mode]
env=os.environ.copy()
env.update(RAYON_NUM_THREADS='16',OMP_NUM_THREADS='16',STWO_ZIG_WORKERS='16',STWO_ZIG_MERKLE_WORKERS='16',STWO_RISCV_SEGMENT_PARENT_PROFILE='1')
metadata={'command':command,'side':side,'mode':mode,'requested_workers':16,'timeout_seconds':1800,'hardware_track':'same-host CPU; no CUDA','peer_stage_profile':bool(os.environ.get('ETH_AUTH_PROFILE'))}
with build_lock(label='ethereum-auth-'+side+'-'+mode):
    metadata['sha256']={str(p.relative_to(H)) if p.is_relative_to(H) else str(p):hashlib.sha256(p.read_bytes()).hexdigest() for p in (binary,elf,input_path,expected_path)}
    metadata['swap_before']=subprocess.check_output(['sysctl','vm.swapusage'],text=True)
    metadata['power_before']=subprocess.check_output(['pmset','-g','batt'],text=True)
    started=time.monotonic()
    with log.open('x') as output:
        process=subprocess.Popen(['/usr/bin/time','-l',*command],cwd=R,env=env,stdout=output,stderr=subprocess.STDOUT,start_new_session=True)
        try: metadata['exit_code']=process.wait(timeout=1800)
        except subprocess.TimeoutExpired:
            os.killpg(process.pid,signal.SIGKILL);process.wait();metadata['timed_out']=True
    metadata['process_wall_seconds']=time.monotonic()-started
    metadata['swap_after']=subprocess.check_output(['sysctl','vm.swapusage'],text=True)
    metadata['power_after']=subprocess.check_output(['pmset','-g','batt'],text=True)
    if metadata.get('exit_code')==0:
        expected=expected_path.read_bytes()
        if side=='peer':
            value=json.loads(report.read_text());assert bytes(value['output_bytes'])==expected
            if mode=='prove':assert value['verified'] and value['aggregation'] and proof.stat().st_size>0
        elif mode=='prove':
            value=json.loads(report.read_text());assert value['verified'] and value['recursive'] and bytes.fromhex(value['output'])==expected
            assert value['queries']==70 and value['pow_bits']==26 and proof.stat().st_size>0
        elif mode=='prepare':
            value=json.loads(report.read_text());assert value['preparation_only'] and bytes.fromhex(value['output'])==expected
        else:assert 'ETH_AUTH_EXECUTION' in log.read_text()
        metadata['output_checked']=True
    Path(str(stem)+'.invocation.json').write_text(json.dumps(metadata,indent=2)+'\n')
    print(json.dumps(metadata,indent=2),flush=True)
if metadata.get('exit_code')!=0:sys.exit(1)
