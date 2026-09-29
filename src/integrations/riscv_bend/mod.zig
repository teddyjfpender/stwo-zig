//! Experimental RISC-V engine binding: Bend transforms/folds and CPU host services.
const std = @import("std");
const bend = @import("stwo_bend_backend");
const cpu = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");
pub fn Engine(comptime config: bend.runtime.Config) type {
    return frontend.prover_mod.ProverEngineForBackend(bend.BendBackendWithHost(config, cpu));
}
test "api signature: experimental engine exposes the prover backend" {
    const E = Engine(.{ .executable = "/not-installed" });
    try std.testing.expect(E.Backend.capabilities.fri_folding);
}
test "api invariant: experimental engine retains Circle and multi-fold" {
    const E = Engine(.{ .executable = "/not-installed" });
    try std.testing.expect(E.Backend.capabilities.circle_transform and E.Backend.capabilities.fri_multi_fold);
}
