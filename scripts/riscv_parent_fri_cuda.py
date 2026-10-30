#!/usr/bin/env python3
"""Lower canonical core FRI subset folds, retaining only the exact circle table."""
import argparse,json,re,subprocess
from pathlib import Path
from riscv_native_witness_cuda import decorate,sha,integer_runtime
from zig_protocol_lib.command import protocol_module_args
ROOT=Path(__file__).resolve().parents[1]
def main():
 p=argparse.ArgumentParser(description=__doc__);p.add_argument('--out-dir',type=Path,required=True);p.add_argument('--zig',default='zig');o=p.parse_args()
 d=o.out_dir.resolve();d.mkdir(parents=True,exist_ok=False)
 if subprocess.check_output([o.zig,'version'],text=True).strip()!='0.15.2':raise ValueError('pinned compiler required')
 env=subprocess.check_output([o.zig,'env'],text=True);m=re.search(r'^\s*\.lib_dir = ("(?:[^"\\]|\\.)*"),$',env,re.M)
 header=(Path(json.loads(m[1]))/'zig.h').read_text();c=d/'fold.c'
 cmd=[o.zig,'build-obj','-ofmt=c',f'-femit-bin={c}',*protocol_module_args('src/riscv_cuda_resident_fri_export_v1.zig',optimize='ReleaseFast',target='x86_64-linux-gnu.2.39',cpu_only=True)]
 subprocess.run(cmd,cwd=ROOT,check=True);source=c.read_text()
 constants=frozenset(re.findall(r'^static struct circle_CirclePoint[^\n]* const (circle_GENERATOR_DOUBLES__\d+)\[31\];$',source,re.M))
 if len(constants)!=1:raise ValueError('original 31-element circle constant table not unique')
 code,counts=decorate(source,header,export_prefix='stwo_parent_fri_subset_',families=('fold',),constant_symbols=constants)
 extra='#define zig_has_builtin(x) 0\n'+header[header.index('static inline uint8_t zig_bit_reverse_u8'):header.index('/* ======================== 128-bit Integer Support')]
 code=code.replace(integer_runtime(header),integer_runtime(header)+'\n'+extra.replace('static inline','static __device__ inline'),1)
 kernel=ROOT/'src/integrations/riscv_cuda/native/resident_parent_fri_expand_v1.cu';code+='\n'+kernel.read_text();payload=code.encode();(d/'fri.cu').write_bytes(payload)
 (d/'manifest.json').write_text(json.dumps({'schema':'stwo-parent-fri-cuda-v1','generated_c_sha256':sha(source.encode()),'cuda_sha256':sha(payload),'compiler_header_sha256':sha(header.encode()),'kernel_sha256':sha(kernel.read_bytes()),'counts':counts,'constant_symbols':sorted(constants),'command':cmd},indent=2)+'\n')
 print(json.dumps({'out_dir':str(d),'cuda_sha256':sha(payload),**counts}))
if __name__=='__main__':main()
