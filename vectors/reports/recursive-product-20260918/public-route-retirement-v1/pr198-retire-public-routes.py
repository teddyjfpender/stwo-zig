from pathlib import Path
import re,json
root=Path.cwd(); base=root/'src/integrations/riscv_cpu'
evidence=root/'vectors/reports/recursive-product-20260918/public-route-retirement-v1'; evidence.mkdir(parents=True,exist_ok=True)
x=json.loads(Path('/tmp/pr198-recursive-export-consumers.json').read_text())
selected={n:v for n,v in x.items() if n.startswith(('recursive_segment_v2_','recursive_temporal_','recursive_parent_')) and 'detached' not in n}
changes={}
for p in base.glob('*.zig'):
 if p.name=='mod.zig': continue
 s=p.read_text(); old=s
 for n,v in selected.items():
  # All member consumers were checked to be in this integration directory.
  s=re.sub(r'\bintegration\.'+n+r'\b',lambda m:'@import("'+v['target']+'")',s)
 if s!=old:
  changes[str(p.relative_to(root))]=old
  p.write_text(s)
p=base/'mod.zig'; s=p.read_text(); changes[str(p.relative_to(root))]=s
for n,v in selected.items():
 s,count=re.subn(r'pub const '+n+r'\s*=\s*@import\("'+re.escape(v['target'])+r'"\);\n','',s)
 assert count==1,(n,count)
p.write_text(s)
p=base/'build_segment_steps.zig'; s=p.read_text(); changes[str(p.relative_to(root))]=s
for start,end in [('    const segment_v2_poseidon_ingress_runner_root =','    const segment_v2_outer_engine_root ='),('    const temporal_parent_real_runner_root =','    // Export the same lean driver for the Metal dependency-boundary shim.')]:
 a=s.index(start); b=s.index(end,a); s=s[:a]+s[b:]
p.write_text(s)
for name in ['recursive_temporal_parent_real_proof_runner.zig','recursive_segment_v2_poseidon_ingress_runner.zig']:
 p=base/name; changes[str(p.relative_to(root))]=p.read_text(); p.unlink()
(evidence/'before.json').write_text(json.dumps(changes,indent=2)+'\n')
(evidence/'retired-exports.json').write_text(json.dumps(selected,indent=2)+'\n')
(evidence/'source-edit-summary.json').write_text(json.dumps({'removed_public_exports':len(selected),'changed_files':list(changes),'removed_test_gate_executables':2},indent=2)+'\n')
print(len(selected),'exports;',len(changes),'files')
