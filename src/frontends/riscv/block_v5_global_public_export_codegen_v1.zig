//! Retain actual construction, unchanged B5SS AIR, generic cache publisher and
//! fresh root receiver bodies. No retained function is executed by this root.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Stage = @import("prover/block_v5_global_public_export_stage_v1.zig").ForBackend(Cpu);
pub export fn stwo_global_public_export_body_gate() void {
    inline for (.{
        &@import("recursion/block_v5_global_public_fields_v1.zig").init,
        &@import("recursion/block_v5_global_public_fields_v1.zig").Fields.validate,
        &@import("recursion/block_v5_global_public_export_policy_v1.zig").init,
        &@import("recursion/block_v5_global_public_export_policy_v1.zig").Owner.validate,
        &@import("recursion/block_v5_global_public_export_policy_v1.zig").Owner.deinit,
        &@import("recursion/air/block_v5_global_public_export_composition_v1.zig").prepare,
        &@import("recursion/air/block_v5_global_public_export_rows_v1.zig").prepare,
        &@import("recursion/block_v5_global_public_export_parent_v1.zig").extend,
        &@import("recursion/block_v5_global_public_export_parent_v1.zig").Prepared.deinit,
        &@import("recursion/block_v5_global_public_export_parent_v1.zig").Prepared.requireComplete,
        &@import("recursion/block_v5_global_public_export_receiver_v1.zig").verify,
        &@import("recursion/block_v5_global_public_export_receiver_v1.zig").OpenEquation.deinit,
        &@import("recursion/block_v5_reusable_global_public_export_protocol_v1.zig").Admission.exportCells,
        &Stage.publishPrepared,
        &Stage.Cache.provePreparedConsuming,
        &@import("prover/block_v5_global_public_export_stage_v1.zig").Artifact.deinit,
    }) |body| std.mem.doNotOptimizeAway(body);
}
