"""Build the pre-change Keccak proof gate in a source-only isolated mirror."""
from pathlib import Path
import os,shutil,subprocess,sys,tempfile,json
H=Path(__file__).resolve().parent;R=H.parents[2];sys.path.insert(0,str(R/'scripts'))
from zig_serial_build import build_lock
mirror=Path(tempfile.mkdtemp(prefix='stwo-keccak-stage-before-'))
(mirror/"design").symlink_to(R/"design",target_is_directory=True)
count=0
for base,dirs,files in os.walk(R/'src'):
 dirs[:]=[d for d in dirs if d not in ('.zig-cache','zig-out','target','node_modules','.git','__pycache__')]
 for name in files:
  p=Path(base)/name
  if p.suffix not in ('.zig','.zon','.c','.h','.m','.metal','.S'):continue
  dest=mirror/p.relative_to(R);dest.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(p,dest);count+=1
for rel,snapshot in [('src/frontends/riscv/air/guest_precompile/keccakf_authority.zig','keccakf_authority.before.zig'),('src/frontends/riscv/air/guest_precompile/keccakf_witness.zig','keccakf_witness.before.zig'),('src/core/channel/blake3_frame.zig','blake3_frame.before.zig')]:
 shutil.copy2(H/snapshot,mirror/rel)
(H/'proof-baseline-mirror.json').write_text(json.dumps(dict(path=str(mirror),source_files=count),indent=2)+'\n')
with build_lock(label='keccak-before-proof'):
 subprocess.run(['/opt/homebrew/opt/zig@0.15/bin/zig','build','test-keccakf-precompile-proof','-Doptimize=ReleaseFast','-j1','--summary','all'],cwd=mirror/'src/integrations/riscv_cpu',check=True)
