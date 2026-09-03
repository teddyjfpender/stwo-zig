//! End-to-end RV32IM proof coverage for the fail-closed Metal engine.

const std = @import("std");
const pcs = @import("stwo_core").pcs;
const metal_aot_config = @import("metal_aot_config");
const metal_backend = @import("stwo_metal_backend");
const prover_api = @import("stwo_prover_api");
const prover_component = @import("stwo_prover_engine").air.component_prover;
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
    // Candidate degree-five provider proofs use a distinct 239-column AIR.
    // Keep its four direct partitions and complete LogUp program in the
    // authenticated AOT inventory even while production activation remains
    // fail-closed; a retained candidate benchmark may not source-JIT them.
    const degree5_candidate_mod = riscv.air.typed_poseidon2_degree_bounded_candidate;
    const degree5_backend = riscv.air.typed_poseidon2_degree5_backend;
    var degree5_candidate = try degree5_candidate_mod.Candidate.init(
        std.testing.allocator,
        .degree5,
    );
    defer degree5_candidate.deinit();
    for (0..degree5_backend.DIRECT_PARTITION_COUNT) |partition| {
        try base_entries.append(std.testing.allocator, .{
            .program_id = (@as(u64, 5) << 32) |
                @as(u64, @intCast(partition)),
            .program = try degree5_backend.exportDirectProgram(
                std.testing.allocator,
                &degree5_candidate,
                degree5_backend.directPartitionRange(partition),
            ),
        });
    }
    try lookup_entries.append(std.testing.allocator, .{
        .program_id = (@as(u64, 6) << 32) | 1,
        .program = try degree5_backend.exportLookupProgram(
            std.testing.allocator,
            &degree5_candidate,
        ),
    });
    const source = try codegen.aot.generateLibrary(
        std.testing.allocator,
        base_entries.items,
        lookup_entries.items,
        lookup_v2_entries.items,
    );
    defer std.testing.allocator.free(source);

    // Production currently has exactly three programs whose reachable main
    // columns cross the u32/log-24 alias boundary. Keep this inventory exact:
    // a newly wide program must not silently bypass the address-width gate.
    var wide_base_count: usize = 0;
    var saw_base_max_339 = false;
    var saw_base_max_444 = false;
    for (base_entries.items) |entry| {
        const maximum = (try maximumReachableBaseMainColumn(entry.program)) orelse continue;
        if (maximum < 256) continue;
        wide_base_count += 1;
        saw_base_max_339 = saw_base_max_339 or maximum == 339;
        saw_base_max_444 = saw_base_max_444 or maximum == 444;
        const name = try codegen.base.kernelName(std.testing.allocator, entry.program);
        defer std.testing.allocator.free(name);
        try expectKernelUsesWideColumn(source, name, maximum);
    }
    var wide_lookup_count: usize = 0;
    for (lookup_entries.items) |entry| {
        const maximum = (try maximumReachableLookupMainColumn(entry.program)) orelse continue;
        if (maximum < 256) continue;
        wide_lookup_count += 1;
        try std.testing.expectEqual(@as(u32, 444), maximum);
        const name = try codegen.lookup.kernelName(std.testing.allocator, entry.program);
        defer std.testing.allocator.free(name);
        try expectKernelUsesWideColumn(source, name, maximum);
    }
    var wide_lookup_v2_count: usize = 0;
    for (lookup_v2_entries.items) |entry| {
        const maximum = (try maximumReachableLookupV2MainColumn(&entry.program)) orelse
            continue;
        if (maximum >= 256) wide_lookup_v2_count += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), wide_base_count);
    try std.testing.expect(saw_base_max_339 and saw_base_max_444);
    try std.testing.expectEqual(@as(usize, 1), wide_lookup_count);
    try std.testing.expectEqual(@as(usize, 0), wide_lookup_v2_count);
    try std.testing.expect(std.mem.indexOf(u8, source, "u * row_count + row]") == null);
    try std.testing.expect(std.mem.indexOf(u8, source, ")*rows+row]") == null);

    if (std.posix.getenv("STWO_ZIG_REGENERATE_RISCV_POLYNOMIAL_AOT") != null) {
        try std.fs.cwd().writeFile(.{
            .sub_path = ".zig-cache/riscv_polynomials.generated.metal",
            .data = source,
        });
        return;
    }
    const embedded_source = riscv_metal.riscv_polynomial_codegen.source;
    const runtime_bootstrap = @embedFile("../../backends/metal/runtime.m");
    const shader_manifest = metal_backend.shaders.manifest;
    const manifest_testing = shader_manifest.testing;
    try std.testing.expectEqualStrings(embedded_source, source);

    const runtime_kernel_count =
        base_entries.items.len + lookup_entries.items.len + lookup_v2_entries.items.len;
    var manifest_kernel_count: usize = 0;
    for (shader_manifest.exports) |entry| {
        if (entry.owner != .riscv_polynomials) continue;
        manifest_kernel_count += 1;
        try std.testing.expectEqual(
            @as(usize, 1),
            manifest_testing.countKernelDeclarations(source, entry.name),
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            manifest_testing.countKernelDeclarations(embedded_source, entry.name),
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            std.mem.count(u8, runtime_bootstrap, entry.name),
        );
    }
    try std.testing.expectEqual(runtime_kernel_count, manifest_kernel_count);
    try std.testing.expectEqual(
        runtime_kernel_count,
        std.mem.count(u8, runtime_bootstrap, "NSString *riscvPolynomialName"),
    );

    for (base_entries.items) |entry| {
        const name = try codegen.base.kernelName(std.testing.allocator, entry.program);
        defer std.testing.allocator.free(name);
        try std.testing.expect(manifest_testing.manifestContains(name));
        try std.testing.expectEqual(
            @as(usize, 1),
            manifest_testing.countKernelDeclarations(embedded_source, name),
        );
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, runtime_bootstrap, name));
    }
    for (lookup_entries.items) |entry| {
        const name = try codegen.lookup.kernelName(std.testing.allocator, entry.program);
        defer std.testing.allocator.free(name);
        try std.testing.expect(manifest_testing.manifestContains(name));
        try std.testing.expectEqual(
            @as(usize, 1),
            manifest_testing.countKernelDeclarations(embedded_source, name),
        );
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, runtime_bootstrap, name));
    }
    for (lookup_v2_entries.items) |*entry| {
        const name = try codegen.lookup_v2.kernelName(std.testing.allocator, &entry.program);
        defer std.testing.allocator.free(name);
        try std.testing.expect(manifest_testing.manifestContains(name));
        try std.testing.expectEqual(
            @as(usize, 1),
            manifest_testing.countKernelDeclarations(embedded_source, name),
        );
        try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, runtime_bootstrap, name));
    }

    const stale_names = [_][]const u8{
        "stwo_zig_base_poly_373e28e4ebf898ce291ed734807dfa00",
        "stwo_zig_lookup_poly_60da0a81177c1f7c118d91080a104856",
        // ABI 18 names for the three kernels whose u32 column addressing
        // aliased 256->0 and 339->83 at log 24.
        "stwo_zig_base_poly_ca24287d77f5fc63504b53801a2b2274",
        "stwo_zig_base_poly_0f4cf9db0689add32aaa333e736a8cab",
        "stwo_zig_lookup_poly_092020ad7fba2603f1ea5eec7d354c27",
        "stwo_zig_lookup_poly_v2_4495e1dc5d58d71f640d011e5e267fc06fe6adfe54e6405fa20aab1ab4a4f496",
        "stwo_zig_lookup_poly_v2_faadbe548bfa104ae056599d5e4910f9812fc7ddf9179da65d5d5e6fba234d35",
        "stwo_zig_lookup_poly_v2_9ed05c9eac769627c64b0e915e2630d0a51bb6325410ea144d9669b85c480514",
        "stwo_zig_lookup_poly_v2_198678cb3ba8974d902c91452544c7f63c81fc0d10de3a87f612c1e9cb9437a8",
        "stwo_zig_lookup_poly_v2_ec1cb673e29351c380eb472b19293e7ea97ab2030393f54c7bcbb1426ae83aa2",
        "stwo_zig_lookup_poly_v2_edade529adf1f7eb6b09313aad8cc71ff739a71d11e2b40cb6101daf378d8489",
        "stwo_zig_lookup_poly_v2_c95e5383b34ea4ad55aaff5bc8ca9054b9fb9abe15db39e6409374e0dd3b5617",
        "stwo_zig_lookup_poly_v2_b64e1478588595c7a3f7c71371ef1e6f1ceae3dd055c9eb56aa4081cf93e97d1",
        "stwo_zig_lookup_poly_v2_b9e7c8afba03add7dd116b67fd791e19256bc093b6eb47e41ca9ee411608c58a",
        "stwo_zig_lookup_poly_v2_b777199dcff0d3dbb81372f98612beda7bd12bf2d2bc7725f1dab500e07c39d9",
        "stwo_zig_lookup_poly_v2_a0710166b8b3057556c2f5907836c0c82fe3b92fccff4633d504c0ff510b6d93",
        "stwo_zig_lookup_poly_v2_bd8284d4f0c5a7d0cd9dd1f4879d721c70992754e1d5aadf02df9e4f86c15d2c",
        "stwo_zig_lookup_poly_v2_099cc5bddab2ff60effcbef0d7863f6a78e0d7a9fcc78fa43d9603f6798904b3",
        "stwo_zig_lookup_poly_v2_e622d001a5cd368b6efef022e0db61a1ab9e30842ef91e4135c0dc5cbd18eb19",
        "stwo_zig_lookup_poly_v2_1cab02ea628504e58cb4a0dbf15dbca36cccc7cad4f36949bb10265a08cd44cc",
        "stwo_zig_lookup_poly_v2_74e0c5ba6845f3d863a1b821d0f22ea76e38570ccd234b537ea4fb9e8f19bf77",
        "stwo_zig_lookup_poly_v2_e9b9d5d433a734c48921694aa7185fafe3fb15e7bd89dc42261cc4290f894352",
    };
    for (stale_names) |name| {
        try std.testing.expect(!manifest_testing.manifestContains(name));
        try std.testing.expectEqual(
            @as(usize, 0),
            manifest_testing.countKernelDeclarations(embedded_source, name),
        );
        try std.testing.expectEqual(@as(usize, 0), std.mem.count(u8, runtime_bootstrap, name));
    }
}

fn maximumReachableBaseMainColumn(
    program: prover_component.OwnedBasePolynomialProgram,
) !?u32 {
    const reachable = try std.testing.allocator.alloc(bool, program.nodes.len);
    defer std.testing.allocator.free(reachable);
    @memset(reachable, false);
    for (program.roots) |root| reachable[root] = true;
    closeReachable(program.nodes, reachable);
    return maximumReachableMainColumn(
        program.nodes,
        reachable,
        program.column_count - 1,
    );
}

fn maximumReachableLookupMainColumn(
    program: prover_component.OwnedLookupPolynomialProgram,
) !?u32 {
    const reachable = try std.testing.allocator.alloc(bool, program.nodes.len);
    defer std.testing.allocator.free(reachable);
    @memset(reachable, false);
    for (program.entries) |entry| {
        reachable[entry.numerator] = true;
        for (entry.values[0..entry.arity]) |value| reachable[value] = true;
    }
    closeReachable(program.nodes, reachable);
    return maximumReachableMainColumn(program.nodes, reachable, null);
}

fn maximumReachableLookupV2MainColumn(
    program: *const prover_component.OwnedLookupPolynomialProgramV2,
) !?u32 {
    const reachable = try std.testing.allocator.alloc(bool, program.nodes.len);
    defer std.testing.allocator.free(reachable);
    @memset(reachable, false);
    for (program.entries) |entry| {
        reachable[entry.numerator] = true;
        for (entry.values[0..entry.arity]) |value| reachable[value] = true;
    }
    closeReachable(program.nodes, reachable);
    return maximumReachableMainColumn(program.nodes, reachable, null);
}

fn closeReachable(nodes: []const prover_component.BasePolynomialNode, reachable: []bool) void {
    var cursor = nodes.len;
    while (cursor != 0) {
        cursor -= 1;
        if (!reachable[cursor]) continue;
        const node = nodes[cursor];
        switch (node.op) {
            .constant, .column => {},
            .add, .sub, .mul => {
                reachable[node.lhs] = true;
                reachable[node.rhs] = true;
            },
            .neg => reachable[node.lhs] = true,
        }
    }
}

fn maximumReachableMainColumn(
    nodes: []const prover_component.BasePolynomialNode,
    reachable: []const bool,
    selector_column: ?usize,
) ?u32 {
    var maximum: ?u32 = null;
    for (nodes, reachable) |node, is_reachable| {
        if (!is_reachable or node.op != .column) continue;
        if (selector_column) |selector| {
            if (@as(usize, node.value) == selector) continue;
        }
        maximum = @max(maximum orelse 0, node.value);
    }
    return maximum;
}

fn expectKernelUsesWideColumn(source: []const u8, name: []const u8, column: u32) !void {
    var declaration_buffer: [160]u8 = undefined;
    const declaration = try std.fmt.bufPrint(
        &declaration_buffer,
        "kernel void {s}(",
        .{name},
    );
    const start = std.mem.indexOf(u8, source, declaration) orelse
        return error.MissingWidePolynomialKernel;
    const tail = source[start..];
    const end = std.mem.indexOf(u8, tail, "\n}\n") orelse
        return error.MalformedWidePolynomialKernel;
    var access_buffer: [96]u8 = undefined;
    const access = try std.fmt.bufPrint(
        &access_buffer,
        "main_columns[riscv_column_offset({}u, row_count, row)]",
        .{column},
    );
    try std.testing.expect(std.mem.indexOf(u8, tail[0 .. end + 3], access) != null);
}
