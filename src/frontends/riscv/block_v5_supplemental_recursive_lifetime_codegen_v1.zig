//! Retains the genuine original captures, cold/worker producers, preflight,
//! mandatory fresh receivers and both borrowing/consuming caller APIs. Taking
//! addresses does not execute proof, commitment, capture or artifact I/O.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
fn keep(comptime Stage: type) void {
    inline for (.{ &Stage.publish, &Stage.SetupCache.provePreparedConsumingWithPreflight, &Stage.SetupCache.provePreparedConsuming }) |body| std.mem.doNotOptimizeAway(body);
}
pub export fn stwo_supplemental_recursive_lifetime_body_gate() void {
    @setEvalBranchQuota(1_000_000);
    keep(@import("prover/block_v5_program_table_recursive_stage_v1.zig").ForBackend(Cpu));
    keep(@import("prover/block_v5_native_lookup_recursive_stage_v1.zig").ForBackend(Cpu));
    const Arithmetic = @import("prover/block_v5_caller_arithmetic_recursive_stage_v1.zig").ForBackend(Cpu);
    const Fused = @import("prover/block_v5_caller_fused_recursive_stage_v1.zig").ForBackend(Cpu);
    keep(Arithmetic);
    keep(Fused);
    keep(@import("prover/block_v5_native_capacity_fused_recursive_stage_v1.zig").ForBackend(Cpu));
    inline for (.{ &Arithmetic.publishFromVerifiedCapture, &Arithmetic.publishConsumingVerifiedCapture, &Fused.publishFromVerifiedCapture, &Fused.publishConsumingVerifiedCapture }) |body| std.mem.doNotOptimizeAway(body);
    const Pipeline = @import("prover/block_v5_caller_recursive_pipeline_v1.zig").ForBackend(Cpu);
    inline for (.{ &Pipeline.proveStagedWithAdmissions, &Pipeline.proveSegmentWithAdmissions, &Pipeline.Session.hooks, &Pipeline.Session.sink }) |body| std.mem.doNotOptimizeAway(body);
}
