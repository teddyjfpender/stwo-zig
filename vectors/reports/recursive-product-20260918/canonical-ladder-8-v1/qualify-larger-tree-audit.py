from pathlib import Path
import json,hashlib,subprocess,sys
sha=lambda p:hashlib.sha256(p.read_bytes()).hexdigest()
count=int(sys.argv[1]);backend=sys.argv[2]
setup=Path(f'/tmp/pr198-canonical-{count}-setup-20260918-v1');admission=setup/'admission.json';meta=json.loads((setup/'setup.json').read_text());assert sha(admission)==meta['admission_sha256']
base=Path(f'/tmp/pr198-product-{backend}-leaf-setup-20260918-v1');cpu=Path('/tmp/pr198-product-cpu-leaf-setup-20260918-v1/cpu/bin');producers=cpu if backend=='cpu' else base/'metal/bin';suffix='' if backend=='cpu' else '-metal'
roles={'leaf-producer':producers/('recursive-segment-v2-concrete-outer-proof'+suffix),'parent-producer':producers/('recursive-segment-v2-detached-parent-prove'+suffix),'leaf-verifier':cpu/'recursive-segment-v2-detached-verify','parent-verifier':cpu/'recursive-segment-v2-detached-parent-verify'}
out=Path(f'/tmp/pr198-canonical-{count}-{backend}-tree-20260918-v1')
args=['python3','scripts/riscv_segment_v2_detached_tree_gate.py','--admission',str(admission),'--admission-sha256',sha(admission),'--backend',backend,'--output',str(out)]
for role,p in roles.items():args+=['--'+role,str(p),'--'+role+'-sha256',sha(p)]
if backend=='metal':args+=['--aot-bundle',str(base/'aot'),'--aot-manifest-sha256',sha(base/'aot/stwo_zig_core.manifest.json'),'--aot-profile','recursive-framework-v1']
r=subprocess.run(args);raise SystemExit(r.returncode)
