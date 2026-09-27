from pathlib import Path
import subprocess,sys,urllib.request,hashlib,json
H=Path(__file__).resolve().parent;ROOT=H.parents[2];sys.path.insert(0,str(ROOT/'scripts'))
from zig_serial_build import build_lock
p=Path('/tmp/stwo-recursion-peer-research-20260921/pil2-proofman/pil2-stark/src');g=p/'goldilocks/src'
j=H/'dependencies/nlohmann/json.hpp'
if not j.exists():
 j.parent.mkdir(parents=True,exist_ok=True);j.write_bytes(urllib.request.urlopen('https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp').read())
(H/'dependencies/provenance.json').write_text(json.dumps({'json_url':'https://raw.githubusercontent.com/nlohmann/json/v3.11.3/single_include/nlohmann/json.hpp','sha256':hashlib.sha256(j.read_bytes()).hexdigest()},indent=2)+'\n')
includes=sorted({str(f.parent) for f in p.rglob('*.hpp')} | {str(p/'bn128/src')})
with build_lock(label='zisk-fri-build'):
 subprocess.run(['/opt/homebrew/opt/zig@0.15/bin/zig','c++','-O3','-std=c++17','-mcpu=native','-dynamiclib','-fPIC',*['-I'+i for i in includes],'-I'+str(H/'dependencies'),'-I/opt/homebrew/opt/gmp/include','-I/opt/homebrew/opt/libomp/include',str(H/'peer_fri.cpp'),str(g/'goldilocks_base_field.cpp'),str(g/'ntt_goldilocks.cpp'),'-L/opt/homebrew/opt/gmp/lib','-lgmp','-L/opt/homebrew/opt/libomp/lib','-lomp','-o',str(H/'peer_fri.dylib')],check=True)

with build_lock(label='zisk-local-fri-build'):
 subprocess.run(['/opt/homebrew/opt/zig@0.15/bin/zig','build-lib','-dynamic','-OReleaseFast','-mcpu=native','--dep','stwo_core','-Mroot=src/frontends/riscv/zisk_fri_benchmark.zig','-Mstwo_core=src/core/mod.zig','-femit-bin='+str(H/'local_fri.dylib')],cwd=ROOT,check=True)
