//! Actual body retention only; no proof, child verifier or stage is invoked.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Plan = @import("recursion/block_v5_memory_source_page_forest_plan_v1.zig");
const Bus = @import("recursion/block_v5_memory_source_page_forest_bus_v1.zig");
const Leaves = @import("recursion/block_v5_memory_source_page_forest_leaf_v1.zig");
const Rows = @import("recursion/block_v5_memory_source_page_forest_preparation_v1.zig");
const Receiver = @import("recursion/block_v5_memory_source_page_forest_receiver_v1.zig");
const Source = @import("recursion/block_v5_memory_source_page_forest_source_v1.zig");
const Stage = @import("prover/block_v5_memory_source_page_forest_stage_v1.zig").ForBackend(Cpu);
const Run = @import("prover/block_v5_memory_source_page_forest_run_v1.zig").ForBackend(Cpu);
pub export fn stwo_source_page_forest_body_gate() void {
    inline for (.{ &Plan.Owned.init, &Plan.Owned.node, &Plan.Owned.deinit, &Bus.Owner.prepareSources, &Bus.Owner.init, &Bus.Owner.validate, &Leaves.ForKind(.raw).verify, &Leaves.ForKind(.fold).verify, &Rows.prepare, &Rows.Prepared.deinit, &Stage.deriveTemplate, &Stage.publish, &Receiver.verify, &Receiver.verifyRoot, &Receiver.Fresh.deinit, &Source.Source.init, &Source.Source.validate, &Source.Source.deinit, &Run.run }) |body| std.mem.doNotOptimizeAway(body);
}
