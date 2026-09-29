"""Authenticate unchanged in-session compiled cubins before a generator update."""
import hashlib,json,sys
from pathlib import Path
sys.path.insert(0,'/workspace/stwo-zig/scripts')
from cuda_build_lib.builder import BuildConfig, Toolchain, build_plan, load_source_closure, load_product_selection, aot_compile_command
from cuda_build_lib import aot_cache
root=Path('/workspace/stwo-zig');base=root/'.zig-cache/products/cairo_cuda/o'
cuda=root/'src/backends/cuda'
config=BuildConfig(source_root=cuda/'authority/active',source_manifest=cuda/'active_source_manifest.json',product_manifest=cuda/'product_manifest.json',native_root=cuda/'native',native_aot_root=cuda/'aot/native',output_dir=Path('/workspace/seed'),toolchain=Toolchain(nvcc=Path('/usr/local/cuda/bin/nvcc'),host_cxx=Path('/usr/bin/g++'),archiver=Path('/usr/bin/ar'),cuda_home=Path('/usr/local/cuda'),cuda_library_dir=Path('/usr/local/cuda/lib64'),sms=(90,),jobs=12),frontend='cairo',aot_sets=('.', 'cairo_canonical_eval','cairo_witness'),aot_set_roots=(('.',base/'06060a30c46cd1f0e2463fc4f6b20311/native-cuda-product/aot/native'),('cairo_canonical_eval',base/'e3f637142dfb155db636cbec4e6409be/cairo-canonical-cuda-eval'),('cairo_witness',base/'c34dfcac8e9938fa64ba2060afb19dd1/cairo-canonical-cuda-witness')))
plan=build_plan(config,probe_tools=True)
product=load_product_selection(config,load_source_closure(config.source_root,config.source_manifest))
count=0
for metadata,source in zip(product.aot_manifest,product.aot_sources,strict=True):
 source_hash=hashlib.sha256(source.read_bytes()).hexdigest()
 key=hashlib.sha256(f"{plan['build_identity_sha256']}:aot:90:{source_hash}".encode()).hexdigest()[:24]
 filename=f'{source.stem}-sm_90-{key}.cubin'
 matches=list(base.glob(f'*/stwo-native-cuda-runtime/.work/{plan["build_identity_sha256"]}/cubins/{filename}'))
 if len(matches)!=1:continue
 artifact=matches[0]
 command=aot_compile_command(config.toolchain,source,artifact,90)
 unit=aot_cache.identity(source,90,plan,command)
 aot_cache.publish(Path('/workspace/cuda-archive-cache/cubin-units-v1'),unit,artifact)
 count+=1
Path('/workspace/seeded-units.json').write_text(json.dumps({'build_identity':plan['build_identity_sha256'],'source_authenticated_entries':count,'scope':'completed cubins from this session only'},indent=2)+'\n')
print(count,'authenticated units seeded',flush=True)
