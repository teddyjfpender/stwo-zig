import hashlib,json,os,pathlib,shutil,subprocess,sys,time
root=pathlib.Path.cwd(); sys.path.insert(0,str(root))
from scripts.zig_serial_build import build_lock
run=root/'.git/local-ethereum/native19-stack-reset-v1'
campaign=root/'.git/local-ethereum/retained-campaign-v2-rw-heap-121x2097152-20260907'
old=campaign/'metal-field5-block-v2/attempts/leaf-000019-0000'
def digest(p):
    with pathlib.Path(p).open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()
def write(name,value): (run/name).write_text(json.dumps(value,indent=2)+'\n')
source=json.loads((run/'source.json').read_text())
def check_source():
    assert subprocess.check_output(['git','rev-parse','HEAD']).decode().strip()==source['head']
    for p,h in source['changed_sources'].items(): assert digest(root/p)==h,p
check_source()
assert digest(old/'request.json')=='15fb81cfa70583fda5df4d24eca0fe8547ec12a6490277434fcc08b367d90c09'
candidate=run/'candidate'; candidate.mkdir()
selected=candidate/'selected-leaf-admission'
shutil.copytree(campaign/'metal-field5-block-selected-admissions-v1/leaf-000019',selected)
argv=json.loads((old/'request.json').read_text())['argv']
argv[0]=str(run/'product/bin/ethereum-prepared-leaf-metal-v1')
for flag,value in {'--output':candidate/'proof.bin','--global-metadata-output':candidate/'leaf.json','--selected-leaf-admission-root':selected}.items(): argv[argv.index(flag)+1]=str(value)
env=dict(os.environ)
for name in ('STWO_ZIG_BUILD_HELD_LOCK','STWO_ZIG_RISCV_METAL_COMPOSITION_PARITY','STWO_ZIG_RISCV_METAL_SEMANTICS'): env.pop(name,None)
env['STWO_ZIG_STAGE101_STAGE_PROFILE']='1'; env['STWO_ZIG_RISCV_METAL_COMPOSITION_TIMING']='1'
inputs=[old/'request.json',campaign/'authority/materialization-v2.json',*sorted(selected.rglob('*'))]
inputs={str(p):digest(p) for p in inputs if p.is_file()}
write('request.json',{'argv':argv,'source':source,'binary_sha256':digest(argv[0]),'input_sha256':inputs,'diagnostics':{k:env[k] for k in ('STWO_ZIG_STAGE101_STAGE_PROFILE','STWO_ZIG_RISCV_METAL_COMPOSITION_TIMING')},'purpose':'ordinary native19 timing, no campaign promotion'})
receipt={'status':'waiting_for_lock','supervisor_pid':os.getpid()}; write('execution.json',receipt)
with build_lock(label='native19-stack-reset'):
    check_source(); started=time.monotonic()
    with (candidate/'stdout.log').open('xb') as stdout,(candidate/'stderr-and-time.log').open('xb') as stderr:
        child=subprocess.Popen(['/usr/bin/time','-l',*argv],cwd=root,env=env,stdout=stdout,stderr=stderr)
        receipt.update(status='running',child_pid=child.pid); write('execution.json',receipt)
        code=child.wait()
    receipt.update(status='producer_passed' if code==0 else 'failed',exit_code=code,wall_seconds=time.monotonic()-started); write('execution.json',receipt)
    if code: sys.exit(code)
    check_source()
    for p,h in inputs.items(): assert digest(p)==h,p
    actual=json.loads((candidate/'leaf.json').read_text()); expected=json.loads((old/'leaf.json').read_text())
    assert actual['metadata']==expected['metadata'],'public metadata changed'
    log=(candidate/'stderr-and-time.log').read_text()
    assert 'independently_cold_verified=true' in log and 'metal composition wall: completed=true' in log
    parser=root/'autoresearch/notes/2026-09-08-riscv-proving-stack-reset/report_composition.py'
    report=subprocess.check_output([sys.executable,str(parser),str(candidate/'stderr-and-time.log')],cwd=root)
    (run/'composition-report.json').write_bytes(report)
    verifier=root/'.git/local-ethereum/fixed-program-native-verifier-v6/bin/ethereum-full-leaf-bundle-verify-v1'
    assert digest(verifier)=='7492946e72587e719cbd254de7b337bc381a63d62c4561eb61e6298c7e99c62c'
    materialization=campaign/'authority/materialization-v2.json'
    assert digest(materialization)=='e9d9ba5619d5780155bf7f23e3475a1af0aae85ec74a0660b837c0cdbb237f4e'
    verify_argv=[str(verifier),'verify-leaf-fixed-program-v5',str(candidate/'proof.bin'),str(candidate/'leaf.json'),str(materialization),digest(materialization),'--workers','1']
    proof_before=digest(candidate/'proof.bin'); metadata_before=digest(candidate/'leaf.json')
    write('verification-request.json',{'argv':verify_argv,'proof_sha256':proof_before,'metadata_sha256':metadata_before})
    started=time.monotonic()
    with (candidate/'verify.json').open('xb') as stdout,(candidate/'verify.stderr').open('xb') as stderr:
        checked=subprocess.run(verify_argv,cwd=root,env=env,stdout=stdout,stderr=stderr)
    if checked.returncode==0:
        vr=json.loads((candidate/'verify.json').read_text())
        assert vr['endpoint']=='verified_native_selected_leaf_fixed_program_v5'
        v=vr['verification']
        assert v['segment_index']==19 and v['segment_count']==121 and v['worker_count']==1
        assert bytes(v['proof_sha256']).hex()==proof_before and bytes(v['metadata_file_sha256']).hex()==metadata_before
        assert bytes(v['materialization_sha256']).hex()==digest(materialization)
        assert v['retained_admission_destroyed_before_proof'] is True
    receipt.update(status='fresh_verification_passed' if checked.returncode==0 else 'verification_failed',verification_exit_code=checked.returncode,verification_wall_seconds=time.monotonic()-started,proof_sha256=proof_before,metadata_sha256=metadata_before)
    assert proof_before==digest(candidate/'proof.bin') and metadata_before==digest(candidate/'leaf.json')
    check_source(); write('execution.json',receipt)
    print(json.dumps(receipt),flush=True)
    sys.exit(checked.returncode)
