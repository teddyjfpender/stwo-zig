import subprocess,os,signal,shlex,json,hashlib,time
from pathlib import Path
root=Path('/workspace/m3/src/m7-admission');out=Path('/workspace/m3/runs/m7-admission')
env=dict(os.environ,TMPDIR='/workspace/m3/tmp',ZIG_GLOBAL_CACHE_DIR='/workspace/m3/cache/zig-global')
files=['admission_runtime','global_admission','admission_retention','pcs_native','resident_pool','outer_source','trace_commit','trace_commit_cost','composition_cost','outer_source_cost']
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
hashes={f:sha(root/f'src/integrations/riscv_cuda/rv64/{f}.zig') for f in files}
results={}
for module in ['admission_runtime','admission_retention','trace_commit_cost','composition_cost','outer_source_cost']:
 p=out/f'final-{module}.log'
 with p.open('w') as log:r=subprocess.run(['/workspace/zig/zig','test',f'src/integrations/riscv_cuda/rv64/{module}.zig','-OReleaseSafe'],cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT)
 results[module]=r.returncode
 if r.returncode:break
cmd=['/workspace/zig/zig','build','build-rv64-ethereum-gpu-combined','--build-file','src/integrations/riscv_cuda/build.zig','-Dtarget=x86_64-linux-gnu','-Dcpu=x86_64_v4+sha','-Doptimize=ReleaseFast','--cache-dir','.zig-cache','--prefix','/workspace/m3/build/m7-admission/zig-out','--verbose']
semantic=None
if not any(results.values()):
 # Discover the generated module command, then stop our just-created process
 # group before LLVM work. The second invocation checks the same module graph
 # with -fno-emit-bin and records exact current-source semantic qualification.
 p=subprocess.Popen(cmd,cwd=root,env=env,stderr=subprocess.PIPE,stdout=subprocess.DEVNULL,text=True,start_new_session=True)
 lines=[];argv=None
 for line in p.stderr:
  lines.append(line)
  if '/workspace/zig/zig build-exe ' in line and '--name rv64-word16-ethereum-gpu-combined ' in line:
   argv=shlex.split(line.strip());break
 if argv:
  os.killpg(p.pid,signal.SIGINT)
  try:p.wait(timeout=10)
  except subprocess.TimeoutExpired:os.killpg(p.pid,signal.SIGKILL);p.wait()
  argv=[arg for arg in argv if arg!='--listen=-']+['-fno-emit-bin']
  with (out/'final-driver-semantic.log').open('w') as log:semantic=subprocess.run(argv,cwd=root,env=env,stdout=log,stderr=subprocess.STDOUT).returncode
 else:semantic=1
 (out/'final-driver-command-discovery.log').write_text(''.join(lines))
else:argv=None
assert hashes=={f:sha(root/f'src/integrations/riscv_cuda/rv64/{f}.zig') for f in files}, 'source changed during gate'
receipt={'schema':'rv64-m7-admission-current-source-check/v1','label':'M','unit_exit':results,'driver_semantic_exit':semantic,'driver_semantic_command':argv,'source_sha256':hashes,'scope':'Host unit and no-emit semantic checks only; no new executable or full request qualification. Existing GPU guard14 cases and matched image remain separate.'}
(out/'final-source-check.json').write_text(json.dumps(receipt,indent=2)+'\n')
print(json.dumps(receipt))
raise SystemExit(0 if semantic==0 and not any(results.values()) else 1)
