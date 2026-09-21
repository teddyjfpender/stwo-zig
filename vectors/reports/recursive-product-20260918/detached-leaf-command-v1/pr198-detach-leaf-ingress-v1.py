from pathlib import Path
r=Path('src/integrations/riscv_cpu');p=r/'recursive_segment_v2_leaf_outer_proof_test.zig';s=p.read_text();original=s
start=s.index('pub fn prepareTemporalNativeLeaf(');end=s.index('\nconst NoOpHook',start);body=s[start:end]
a=s.index('pub fn leafStatement(');b=s.index('\nfn milliseconds',a);helpers=s[a:b].replace('fn encode(','pub fn encode(')
config=s[s.index('const test_config ='):s.index('\ntest "generic Poseidon2')].replace('const test_config =','pub const DEVELOPMENT_CONFIG =')
header='''//! Canonical native SegmentV2 producer destruction, fresh verification and owned leaf preparation.
const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const postcard = @import("interop_postcard");
const subject = @import("recursive_segment_v2_leaf_outer.zig");
const M31 = stwo_core.fields.m31.M31;
const prover = frontend.prover_mod;
const runner = frontend.runner;
const recursion = frontend.recursion;
const segment_v2 = recursion.segment_statement_v2;
const span = recursion.span_statement;
const protocol = recursion.protocol;
const channel = recursion.poseidon2_channel;
const schedule = recursion.air.verifier_schedule;
const Engine = subject.Engine;
'''
body=body.replace('integration.recursive_segment_v2_outer_engine.ProducerAllocator','@import("stwo_prover_engine").tracked_smp_allocator.TrackedSmpAllocator').replace('=> test_config','=> DEVELOPMENT_CONFIG')
renames={'prepareTemporalNativeLeafWithProfile':'prepareWithProfile','prepareTemporalNativeLeafWithEngine':'prepareWithEngine','prepareTemporalNativeLeaf':'prepare'}
for old,new in renames.items():body=body.replace(old,new)
(r/'recursive_segment_v2_native_ingress.zig').write_text(header+config+'\n'+body+'\n'+helpers+'\n')
s=s[:a]+''.join('pub const '+n+' = native_ingress.'+n+';\n' for n in ['leafStatement','machineState','encode','digest','scalarDigest'])+s[b:]
s=s[:start]+''.join('pub const '+old+' = native_ingress.'+new+';\n' for old,new in renames.items())+'pub const NativeProfile = native_ingress.NativeProfile;\n'+s[end:]
# Replace the original local configuration with the canonical ingress configuration.
a=s.index('const test_config =');b=s.index('\ntest "generic Poseidon2',a);s=s[:a]+'const native_ingress = @import("recursive_segment_v2_native_ingress.zig");\nconst test_config = native_ingress.DEVELOPMENT_CONFIG;\n'+s[b:];p.write_text(s)
backup=Path('/tmp/pr198-leaf-command-originals');backup.mkdir(exist_ok=True);(backup/p.name).write_text(original)
# Production owners replace misleading test-support ownership; all existing consumers follow the move.
moves={'recursive_segment_v2_two_segment_proof_test_support.zig':'recursive_segment_v2_detached_leaf_producer.zig','recursive_segment_v2_two_segment_test_support.zig':'recursive_segment_v2_workload.zig','recursive_segment_v2_memory_workload_test_support.zig':'recursive_segment_v2_memory_workload.zig','recursive_segment_v2_concrete_outer_proof_runner.zig':'recursive_segment_v2_detached_leaf_runner.zig'}
for old,new in moves.items():
 (backup/old).write_bytes((r/old).read_bytes());(r/old).rename(r/new)
for base in [Path('src'),Path('scripts')]:
 for p in base.rglob('*'):
  if p.suffix not in ('.zig','.py') or '.zig-cache' in p.parts:continue
  s=p.read_text();t=s
  for old,new in moves.items():t=t.replace(old,new)
  if t!=s:p.write_text(t)
# The Metal entry shim moved through the above references, so move its physical path too.
m=Path('src/integrations/riscv_metal');(m/'recursive_segment_v2_concrete_outer_proof_runner.zig').rename(m/'recursive_segment_v2_detached_leaf_runner.zig')
p=r/'recursive_segment_v2_detached_leaf_producer.zig';s=p.read_text().replace('@import("recursive_segment_v2_leaf_outer_proof_test.zig")','@import("recursive_segment_v2_native_ingress.zig")').replace('ingress.prepareTemporalNativeLeafWithProfile','ingress.prepareWithProfile');p.write_text(s)
p=r/'recursive_segment_v2_detached_parent_prepare.zig';s=p.read_text().replace('@import("recursive_segment_v2_outer_engine.zig").Engine','@import("recursive_segment_v2_detached_parent_proof.zig").CpuEngine');p.write_text(s)
