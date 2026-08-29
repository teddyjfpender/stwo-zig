//! End-to-end RV32IM proof coverage for the fail-closed Metal engine.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const metal_aot_config = @import("metal_aot_config");
const prover_api = @import("stwo_prover_api");
const stwo_riscv_metal = @import("stwo_riscv_metal");
const riscv = stwo_riscv_metal.frontends.riscv;
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
    const bundle_path = try std.process.getEnvVarOwned(
        allocator,
        "STWO_RISCV_METAL_AOT_BUNDLE",
    );
    defer allocator.free(bundle_path);
    try riscv_metal.MetalProverEngine.initializeRuntime(allocator, .{
        .authenticated_aot = .{
            .bundle_path = bundle_path,
            .manifest_sha256 = metal_aot_config.manifest_sha256,
        },
    });
    defer riscv_metal.MetalProverEngine.Backend.shutdown() catch unreachable;

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

    var recorder = prover_api.stage_profile.Recorder.initWithOptions(
        allocator,
        "test",
        "riscv-metal-exact-work",
        .{ .capture_work = true },
    );
    defer recorder.deinit();
    const telemetry_before = try riscv_metal.MetalProverEngine.telemetrySnapshot();
    const output = try riscv_metal.proveRiscVWithRecorder(
        allocator,
        TEST_CONFIG,
        &run.execution_trace,
        null,
        null,
        &recorder,
    );
    defer output.deinitAfterProofMoved(allocator);
    const telemetry_after = try riscv_metal.MetalProverEngine.telemetrySnapshot();
    const telemetry_delta = telemetry_after.delta(telemetry_before);
    try telemetry_delta.requireResidentRiscPolynomialExecution();
    try std.testing.expect(
        telemetry_delta.counters.riscv_base_polynomial_eligible_components > 0,
    );
    try std.testing.expect(
        telemetry_delta.counters.riscv_lookup_polynomial_eligible_components > 0,
    );
    try std.testing.expect(
        telemetry_delta.counters.metal_riscv_base_polynomial_batch_dispatches > 0,
    );
    try std.testing.expect(
        telemetry_delta.counters.metal_riscv_lookup_polynomial_batch_dispatches > 0,
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        telemetry_delta.counters.cpu_riscv_polynomial_composition_declines,
    );
    const work = recorder.workCaptureRecorder() orelse unreachable;
    for ([_]prover_api.work_profile.Site{
        .oods_seed_to_point,
        .oods_mask_points,
        .oods_constraint_evaluation,
        .relation_challenges_and_interaction_traces,
        .quotient_sample_preparation,
        .quotient_row_execution,
        .air_composition_on_domain,
        .pcs_transcript_shell,
    }) |site| {
        const index = @intFromEnum(site);
        try std.testing.expectEqual(@as(u64, 1), work.planned_sites[index]);
        try std.testing.expectEqual(@as(u64, 1), work.completed_sites[index]);
    }
    const work_snapshot = try recorder.workSnapshot();
    try work_snapshot.validate();
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

test "metal: typed Poseidon2 artifacts prove and verify without fallback" {
    const allocator = std.testing.allocator;
    const bundle_path = try std.process.getEnvVarOwned(
        allocator,
        "STWO_RISCV_METAL_AOT_BUNDLE",
    );
    defer allocator.free(bundle_path);
    try riscv_metal.MetalProverEngine.initializeRuntime(allocator, .{
        .authenticated_aot = .{
            .bundle_path = bundle_path,
            .manifest_sha256 = metal_aot_config.manifest_sha256,
        },
    });
    defer riscv_metal.MetalProverEngine.Backend.shutdown() catch unreachable;

    const telemetry_before = try riscv_metal.MetalProverEngine.telemetrySnapshot();
    const receipt = try riscv.testing.typed_poseidon2_proof_test.exerciseBackend(
        riscv_metal.MetalProverEngine.Backend,
        allocator,
    );
    const telemetry_after = try riscv_metal.MetalProverEngine.telemetrySnapshot();
    const telemetry_delta = telemetry_after.delta(telemetry_before);

    try receipt.validate();
    try std.testing.expectEqualStrings(
        @typeName(riscv_metal.MetalProverEngine.Backend),
        receipt.backend_name,
    );
    try std.testing.expectEqual(@as(usize, 46), receipt.active_rows);
    try std.testing.expectEqual(receipt.active_rows, receipt.narrow_rows);
    try std.testing.expectEqual(@as(usize, 0), receipt.wide_rows);
    try std.testing.expectEqual(@as(usize, 0), receipt.io_rows);
    try std.testing.expectEqualSlices(
        u8,
        &riscv.testing.typed_poseidon2_proof_test.CANONICAL_PROGRAM_IDENTITY_DIGEST,
        &receipt.program_identity.combined_digest,
    );
    try telemetry_delta.requireResidentRiscPolynomialExecution();
    try std.testing.expectEqual(
        @as(u64, 0),
        telemetry_delta.counters.cpu_riscv_polynomial_composition_declines,
    );
}

test "metal: AOT source matches every production RISC-V polynomial DAG" {
    const codegen = riscv_metal.riscv_polynomial_codegen;
    const runtime_program = riscv.air.extract.runtime_program;
    const semantic_eval = riscv.air.semantic_eval;
    const trace = riscv.runner.trace;

    var base_entries = std.ArrayList(codegen.base.Entry).empty;
    defer {
        for (base_entries.items) |*item| item.program.deinit();
        base_entries.deinit(std.testing.allocator);
    }
    var lookup_entries = std.ArrayList(codegen.lookup.Entry).empty;
    defer {
        for (lookup_entries.items) |*item| item.program.deinit();
        lookup_entries.deinit(std.testing.allocator);
    }
    var lookup_v2_entries = std.ArrayList(codegen.lookup_v2.Entry).empty;
    defer {
        for (lookup_v2_entries.items) |*item| item.program.deinit();
        lookup_v2_entries.deinit(std.testing.allocator);
    }
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        if (!semantic_eval.isTraceCompatible(family)) continue;
        try base_entries.append(std.testing.allocator, .{
            .program_id = (@as(u64, 1) << 32) | @as(u64, @intCast(family_index)),
            .program = try runtime_program.build(std.testing.allocator, family),
        });
        try lookup_entries.append(std.testing.allocator, .{
            .program_id = (@as(u64, 2) << 32) | @as(u64, @intCast(family_index)),
            .program = try runtime_program.buildLookups(std.testing.allocator, family),
        });
        var plan = try riscv.air.lookup_batch_execution.FamilyPlan.initNativeV1(
            std.testing.allocator,
            family,
        );
        defer plan.deinit();
        var selected = try riscv.air.lookup_polynomial_program_v2.lowerSelected(
            std.testing.allocator,
            &plan,
        );
        errdefer selected.deinit();
        try lookup_v2_entries.append(std.testing.allocator, .{
            .authority = try selected.authority(),
            .program = selected,
        });
    }
    const hash_program = riscv.air.memory_commitment.hash_runtime_program;
    for (0..hash_program.DIRECT_PARTITION_COUNT) |partition| {
        try base_entries.append(std.testing.allocator, .{
            .program_id = (@as(u64, 3) << 32) |
                @as(u64, @intCast(partition)),
            .program = try hash_program.buildPoseidonDirectRange(
                std.testing.allocator,
                .narrow_memory,
                hash_program.directPartitionRange(.narrow_memory, partition),
            ),
        });
    }
    try lookup_entries.append(std.testing.allocator, .{
        .program_id = (@as(u64, 4) << 32) | 1,
        .program = try hash_program.buildPoseidonLookups(std.testing.allocator),
    });
    const source = try codegen.aot.generateLibrary(
        std.testing.allocator,
        base_entries.items,
        lookup_entries.items,
        lookup_v2_entries.items,
    );
    defer std.testing.allocator.free(source);

    if (std.posix.getenv("STWO_ZIG_REGENERATE_RISCV_POLYNOMIAL_AOT") != null) {
        try std.fs.cwd().writeFile(.{
            .sub_path = ".zig-cache/riscv_polynomials.generated.metal",
            .data = source,
        });
        return;
    }
    try std.testing.expectEqualStrings(riscv_metal.riscv_polynomial_codegen.source, source);
}
