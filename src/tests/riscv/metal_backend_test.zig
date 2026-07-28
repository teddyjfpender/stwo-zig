//! End-to-end RV32IM proof coverage for the fail-closed Metal engine.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const stwo_riscv_metal = @import("stwo_riscv_metal");
const riscv_metal = stwo_riscv_metal.integrations.riscv_metal;
const runner = stwo_riscv_metal.frontends.riscv.runner;

const TEST_CONFIG = pcs.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
    },
};

test "metal: RV32IM retirement trace proves and verifies without fallback" {
    const allocator = std.testing.allocator;
    const elf = runner.trace_dump.buildTestElf(9, .{
        0x00100093, // ADDI x1, x0, 1
        0x00100093,
        0x00100093,
        0x00100093,
        0x00100093,
        0x00100093,
        0x00100093,
        0x00100093,
        0x0000006f, // JAL x0, 0: completion sentinel, not a retirement
    });
    var run = try runner.run(allocator, &elf, 1000);
    defer run.deinit();

    const output = try riscv_metal.proveRiscV(
        allocator,
        TEST_CONFIG,
        &run.execution_trace,
        null,
        null,
    );
    defer output.deinitAfterProofMoved(allocator);
    try riscv_metal.verifyRiscV(
        allocator,
        TEST_CONFIG,
        output.statement,
        output.proof,
        output.interaction_claim,
    );
    try std.testing.expect(output.statement.n_components > 0);

    // Sample the exact backend-neutral runner trace the Metal engine proved.
    // This is last so an unavailable pinned oracle skips only the Sail leg;
    // a configured, answering Sail disagreement remains a hard failure.
    try runner.sail_oracle.requireAgreement(
        allocator,
        "Metal backend eight-ADDI runner guest",
        &elf,
        &run.execution_trace,
        run.cpu_final,
        &.{},
    );
}
