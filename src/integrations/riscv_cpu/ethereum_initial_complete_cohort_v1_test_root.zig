//! Compile the real selected assembly methods without allocating a block.
//! Runtime correctness remains the genuine writer/closure and complete-proof gates.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const complete = @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4_complete.zig");
const Engine = frontend.recursion.engine.ProverEngineForBackend(@import("stwo_cpu_backend").CpuBackend);
comptime {
    _ = @import("recursive_common_ethereum_incremental_leaf_universal_closure_v4.zig");
    _ = @import("recursive_common_ethereum_initial_input_rows_v1.zig");
    _ = @import("recursive_common_ethereum_initial_public_sums_v1_test.zig");
}
fn compileRoute(comptime Selected: type, comptime Manifest: type) !void {
    var execute = false;
    std.mem.doNotOptimizeAway(&execute);
    if (execute) {
        const geometry: *@import("recursive_common_ethereum_incremental_leaf_universal_geometry_authority_v4.zig").OwnerV4(Engine) = undefined;
        const cohort = try Selected.Cohort(Engine).init(std.testing.allocator, geometry);
        defer cohort.deinit();
        const manifest = try cohort.manifest();
        const relations = frontend.recursion.air.universal_challenges.UniversalRelations.dummy();
        const providers = try frontend.recursion.air.universal_shared_provider.SharedProviderRelations.init(&relations);
        const columns: []const []@import("stwo_core").fields.m31.M31 = &.{};
        try cohort.fillPreprocessedInto(columns);
        try cohort.fillMainInto(columns);
        const generated = try cohort.fillInteractionInto(&relations, &providers, columns);
        try cohort.validateGenerated(&generated, &relations, &providers);
        var components = try cohort.initComponents(&generated, &relations, &providers);
        defer components.deinit();
        var gate = try Manifest.ProofGate.init(manifest);
        try components.appendToGate(manifest, &gate);
        try gate.sealGate(manifest);
    }
}
test "Ethereum initial complete assembly compiles both explicit production routes" {
    try compileRoute(complete.Ordinary, @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig"));
    try compileRoute(complete.Initial38, frontend.recursion.air.ethereum_initial_input_manifest_v1);
}
