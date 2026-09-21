from pathlib import Path
import re,json
base=Path('src/integrations/riscv_cpu'); evidence=Path('vectors/reports/recursive-product-20260918/canonical-producer-modules-v1');evidence.mkdir(parents=True,exist_ok=True)
before={}
def write(p,s):
 before[str(p)]=p.read_text();p.write_text(s)
p=base/'recursive_segment_v2_detached_parent_producer_runner.zig';write(p,'//! Canonical CPU entry for the shared detached parent producer.\npub fn main() !void {\n    return @import("stwo_riscv_detached_parent_producer").main();\n}\n')
p=Path('src/integrations/riscv_metal/recursive_segment_v2_detached_parent_producer_runner.zig');write(p,p.read_text().replace('@import("stwo_riscv_cpu_integration").recursive_segment_v2_detached_parent_producer','@import("stwo_riscv_detached_parent_producer")'))
p=base/'build_segment_steps.zig';s=p.read_text();old='    const detached_parent_producer = support.createHarnessModule(b, "recursive_segment_v2_detached_parent_producer_runner.zig", target, optimize, core, cpu_backend, frontend, integration);'
new='''    const detached_parent_owner = b.addModule("stwo_riscv_detached_parent_producer", .{
        .root_source_file = b.path("recursive_segment_v2_detached_parent_producer.zig"),
        .target = target,
        .optimize = optimize,
    });
    detached_parent_owner.addImport("stwo_core", core);
    detached_parent_owner.addImport("stwo_cpu_backend", cpu_backend);
    detached_parent_owner.addImport("stwo_riscv_frontend", frontend);
    detached_parent_owner.addImport("stwo_prover_api", prover_api);
    detached_parent_owner.addImport("stwo_prover_engine", prover);
    detached_parent_owner.addImport("interop_postcard", postcard);
    const detached_parent_producer = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_detached_parent_producer_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    detached_parent_producer.addImport("stwo_riscv_detached_parent_producer", detached_parent_owner);'''
assert old in s;s=s.replace(old,new)
old='    const leaf_key_setup_root = support.createHarnessModule(b, "recursive_segment_v2_leaf_key_setup_runner.zig", target, optimize, core, cpu_backend, frontend, integration);'
new='''    const leaf_key_setup_root = b.createModule(.{
        .root_source_file = b.path("recursive_segment_v2_leaf_key_setup_runner.zig"),
        .target = target,
        .optimize = optimize,
    });
    leaf_key_setup_root.addImport("stwo_core", core);
    leaf_key_setup_root.addImport("stwo_cpu_backend", cpu_backend);
    leaf_key_setup_root.addImport("stwo_riscv_frontend", frontend);'''
assert old in s;s=s.replace(old,new);write(p,s)
p=Path('src/integrations/riscv_metal/build.zig');s=p.read_text();old='''    detached_parent_runner.addImport("stwo_riscv_cpu_integration", b.dependency(
        "stwo_riscv_cpu_integration",
        dependency_options,
    ).module("stwo_riscv_cpu_integration"));''';new=old.replace('addImport("stwo_riscv_cpu_integration"','addImport("stwo_riscv_detached_parent_producer"').replace('.module("stwo_riscv_cpu_integration")','.module("stwo_riscv_detached_parent_producer")');assert old in s;s=s.replace(old,new);write(p,s)
p=base/'mod.zig';s=p.read_text();s,n=re.subn(r'\npub const recursive_segment_v2_detached_\w+ = @import\("[^"\n]+"\);\n','',s);assert n==5,n;write(p,s)
(evidence/'before.json').write_text(json.dumps(before,indent=2)+'\n')
print('Dedicated CPU/Metal parent module, isolated key setup bindings, five obsolete facade exports removed.')
