"""Local dirty-tree proof qualification; deliberately not a publication report."""
from pathlib import Path
from dataclasses import replace
import hashlib, json, os, shutil, subprocess, sys
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
sys.path.insert(0, str(ROOT))
from scripts.riscv_csp_benchmark_lib.contract import MANIFEST, validate_manifest
from scripts.riscv_csp_benchmark_lib.precompile import validate_manifest as precompile_manifest
from scripts.riscv_csp_benchmark_lib.full_width import artifact_sections, policy, PHASES, PARTITION
from scripts.riscv_csp_benchmark_lib.build_identity import read_trace_provenance
from scripts.riscv_csp_benchmark import execute_case, native_benchmark_environment

def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def run(command, destination, env):
    with destination.open('w') as out:
        subprocess.run(command, cwd=ROOT, env=env, stdout=out, stderr=subprocess.STDOUT, check=True)

manifest, cases, negatives = validate_manifest(MANIFEST)
precompile = precompile_manifest()
head = subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=ROOT, text=True).strip()
trace = HERE / 'clean-trace'
if not trace.exists(): shutil.copy2('/private/tmp/stwo-recursion-baseline-20260921/zig-out/bin/riscv-trace-dump', trace)
env, overrides, removed = native_benchmark_environment(os.environ, 16)
env['STWO_RISCV_METAL_AOT_BUNDLE'] = str(HERE / 'core')
env['STWO_RISCV_EXECUTION_PROFILE'] = '1'
provenance = read_trace_provenance(trace, min(cases, key=lambda c:c.expected_cycles), repository_head=head, max_steps=10_000_000, timeout=3600, env=env)
(HERE / 'trace-provenance.json').write_text(json.dumps(provenance, indent=2)+'\n')
results = json.loads((HERE/'csp-results.json').read_text()) if (HERE/'csp-results.json').exists() else []
for backend in ['cpu', 'metal']:
    binary = HERE / 'products/bin' / f'stwo-zig-riscv-{backend}'
    binary.parent.mkdir(parents=True, exist_ok=True)
    if not binary.exists(): shutil.copy2(ROOT/'zig-out/bin'/binary.name, binary)
    binary_sha = sha(binary)
    records = json.loads((ROOT/f'autoresearch/notes/2026-09-23-compact-range-provider/suite-{backend}/results.json').read_text())
    directory = HERE / f'suite-{backend}'; directory.mkdir(exist_ok=True)
    for record in records:
        name = record['case']
        prior = next((r for r in results if r['case']==name), None)
        if prior:
            assert prior['binary_sha256']==binary_sha
            continue
        negative = record['negative']
        source = next(c for c in negatives if backend+'-'+c.name==name) if negative else next(c for c in cases if f'{backend}-{c.target}-{c.input_size}'==name)
        command = record['command'][:]
        command[0] = str(binary)
        prefix = directory/name
        for key,value in [('--samples','1'),('--warmups','0'),('--report-out',str(prefix.with_suffix('.json'))),('--proof-out',str(prefix.with_suffix('.b3proof')))]: command[command.index(key)+1]=value
        command[1:1] = ['--proof-suite','blake3']
        elf = Path(command[command.index('--elf')+1]); data = Path(command[command.index('--input')+1])
        assert sha(data)==source.input_sha256
        accelerated = 'ecdsa-csp-bench' in command
        cycles = 1828 if accelerated else source.expected_cycles
        if accelerated:
            assert sha(elf) in [g['sha256'] for g in precompile['guests'].values()]
        else: assert elf.resolve()==source.guest_path.resolve()
        # A separately built clean reference executes the exact proved guest.
        from types import SimpleNamespace
        checked = SimpleNamespace(target=source.target,input_size=0,guest_path=elf,input_path=data,expected_cycles=cycles,expected_digest=source.expected_digest)
        # The clean base trace product does not expose typed ECDSA recovery.
        # As in the maintained runner, the accelerated cycle/output claim is
        # bound by fresh proof verification, not a substituted software trace.
        if not accelerated:
            trace_result = execute_case(checked, trace, 3600, env=env)
            prefix.with_suffix('.trace.json').write_text(json.dumps(trace_result,indent=2)+'\n')
        run(command, prefix.with_suffix('.log'), env)
        report = json.loads(prefix.with_suffix('.json').read_text())
        expected = dict(schema='riscv_full_width_execution_v2', mode='bench', backend=backend, proof_suite='blake3', security_policy='secure', verified_in_process=True, recursion_enabled=False, samples=1, warmups=0, verified_samples=1, total_steps=cycles, output_len=32, output_sha256=hashlib.sha256(bytes.fromhex(source.expected_digest)).hexdigest(), elf_sha256=sha(elf), input_sha256=source.input_sha256, implementation_commit=head, implementation_dirty=True, executable_sha256=binary_sha, timing_unit='nanoseconds', timing_partition=PARTITION)
        for k,v in expected.items(): assert type(report[k]) is type(v) and report[k]==v,(name,k,report.get(k),v)
        policy(report['pcs_config'])
        assert len(report['timings'])==len(report['proof_device_counts'])==1
        timing=report['timings'][0]
        assert set(timing)==set(PHASES)|{'total_ns'} and all(type(v) is int and v>=0 for v in timing.values())
        assert sum(timing[p] for p in PHASES)==timing['total_ns']
        assert abs(report['median_seconds']-timing['total_ns']/1e9)<1e-12
        artifact=prefix.with_suffix('.b3proof'); raw=artifact.read_bytes()
        magic,elf_hash,input_hash,stark=artifact_sections(raw)
        assert elf_hash==sha(elf) and input_hash==source.input_sha256
        assert report['artifact_magic']==magic and report['proof_bytes']==len(raw) and report['proof_sha256']==sha(artifact)
        verification=[str(binary),'--proof-suite','blake3','ecdsa-csp-verify' if accelerated else 'verify','--artifact',str(artifact),'--elf',str(elf),'--input',str(data),'--expect-statement-digest',report['statement_blake3']]
        if not accelerated: verification+=['--protocol','secure']
        run(verification,prefix.with_suffix('.verify.json'),env)
        receipt=json.loads(prefix.with_suffix('.verify.json').read_text()); assert receipt['status']=='verified'
        for k in ['artifact_magic','proof_suite','security_policy','statement_blake3','transcript_digest_blake3','proof_sha256','proof_bytes','total_steps','elf_sha256','input_sha256','output_sha256','implementation_commit','implementation_dirty','executable_sha256']: assert receipt[k]==report[k],(name,k)
        policy(receipt['pcs_config'])
        if accelerated: assert report['csp_ecdsa'] and receipt['csp_ecdsa'] and report['signer_calls']==receipt['signer_calls']==1
        devices=report['proof_device_counts'][0]
        if backend=='metal':
            log=prefix.with_suffix('.log').read_text()
            assert devices['dispatches']>0 and 'batches=28 ' in log, 'Missing GPU G dispatch'
        else: assert devices=={'dispatches':0,'cpu_fallbacks':0}
        result=dict(case=name,negative=negative,command=command,binary_sha256=binary_sha,implementation_dirty=True,local_qualification_only=True,independent_verified=True,complete_seconds=report['median_seconds'],execution_witness_prove_seconds=sum(timing[k] for k in ['execution_ns','witness_ns','proving_ns'])/1e9,proof_sha256=report['proof_sha256'],parameters=report['pcs_config'],timing=timing,device=devices,resources=report['resources'])
        results.append(result); (HERE/'csp-results.json').write_text(json.dumps(results,indent=2)+'\n')
        print(name, round(result['execution_witness_prove_seconds'],6), 'verified', flush=True)
assert len(results)==34 and all(r['independent_verified'] for r in results)
print('Qualified 32 positives and 2 negative proofs; all independently verified.',flush=True)
