//! Fast RISC-V runner, witness, and AIR unit coverage.

const std = @import("std");

pub const runner = @import("stwo_riscv_frontend").runner;
const infra_trace = @import("stwo_riscv_frontend").infra_trace;
const StateChainTracker = @import("stwo_riscv_frontend").runner.state_chain.StateChainTracker;

test {
    std.testing.refAllDeclsRecursive(runner);
    _ = @import("stwo_riscv_frontend").testing.clock_update_component_test;
    _ = @import("stwo_riscv_frontend").air.component_order;
    _ = @import("stwo_riscv_frontend").air.extract;
    _ = @import("stwo_riscv_frontend").air.logup;
    _ = @import("stwo_riscv_frontend").air.interaction;
    _ = @import("stwo_riscv_frontend").air.memory_commitment;
    _ = @import("stwo_riscv_frontend").air.program;
    _ = @import("stwo_riscv_frontend").air.relation_export;
    _ = @import("stwo_riscv_frontend").air.relation_export_components;
    _ = @import("stwo_riscv_frontend").testing.relation_export_components_test;
    _ = @import("stwo_riscv_frontend").testing.relation_export_test;
    _ = @import("stwo_riscv_frontend").air.relation_evidence;
    _ = @import("stwo_riscv_frontend").air.relations;
    _ = @import("stwo_riscv_frontend").testing.semantic_component_test;
    _ = @import("stwo_riscv_frontend").air.semantics;
    _ = @import("stwo_riscv_frontend").air.transcript;
    _ = @import("stwo_riscv_frontend").diagnostics.public_values;
}

test "sail_oracle: absence skips by default, fails under the gate switch, and never reads as disagreement" {
    // Lives here rather than beside the code because `zig test` only collects
    // tests from its root module, and every step reaches `sail_oracle.zig` as
    // an imported dependency.
    //
    // Nothing here consults Sail: this is the enforcement flag's policy alone,
    // which is the part a host without the pinned oracle can still prove.
    const sail_oracle = runner.sail_oracle;
    const Policy = sail_oracle.AbsencePolicy;

    try std.testing.expectEqual(Policy.skip, Policy.fromEnvValue(null));
    for ([_][]const u8{ "", "   ", "0", "false", "FALSE", "no", "Off", " off " }) |unset| {
        try std.testing.expectEqual(Policy.skip, Policy.fromEnvValue(unset));
    }
    // Anything unrecognised requires the oracle: a gate switch must not be
    // disarmed by a typo in the value a CI job passed it.
    for ([_][]const u8{ "1", "true", "YES", "on", " 1 ", "ture" }) |set| {
        try std.testing.expectEqual(Policy.fail, Policy.fromEnvValue(set));
    }

    // The distinct-error property the module header promises: enforcement
    // reports the ABSENCE, and never borrows the disagreement error.
    const Unavailable = sail_oracle.UnavailableError;
    try std.testing.expectEqual(Unavailable.SkipZigTest, Policy.skip.err());
    try std.testing.expectEqual(Unavailable.SailOracleUnavailable, Policy.fail.err());
    const required: anyerror = Policy.fail.err();
    try std.testing.expect(required != error.SkipZigTest);
    try std.testing.expect(required != error.SailDisagreesWithRunner);
}

test "infra_trace: genMemoryColumns caps rows at the domain size" {
    const allocator = std.testing.allocator;
    var chain = StateChainTracker.init(allocator);
    defer chain.deinit();
    try chain.recordRegAccess(1, 0, 42);
    try chain.recordRegAccess(2, 2, 100);
    try chain.recordMemAccess(0x1000, 4, 0xDEADBEEF);
    try chain.recordMemAccess(0x2000, 6, 0xCAFEBABE);
    try chain.recordMemAccess(0x1000, 8, 0x12345678);

    const log_size: u32 = 2;
    var result = try infra_trace.genMemoryColumns(allocator, &chain, log_size);
    defer infra_trace.freeMemoryColumns(allocator, &result.columns);
    try std.testing.expectEqual(@as(usize, 4), result.n_real_rows);
}
