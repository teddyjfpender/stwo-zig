const std = @import("std");
const CpuBackend = @import("stwo_cpu_backend").CpuBackend;
const frontend = @import("stwo_riscv_frontend");

const manifest_mod =
    @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const materializer =
    @import("recursive_common_ethereum_incremental_leaf_materializer_v4.zig");
const runtime_mod =
    @import("recursive_common_ethereum_incremental_leaf_genuine_runtime_v4.zig");
const public_semantics =
    @import("recursive_common_ethereum_incremental_leaf_public_semantics_v4.zig");
const cohort =
    @import("recursive_common_ethereum_incremental_leaf_universal_cohort_v4.zig");

const Engine = frontend.recursion.engine.ProverEngineForBackend(CpuBackend);
const bridge_external = frontend.prover_mod.incremental_bridge_external_v3;
const parallel_projection =
    frontend.recursion.vm_air_composition_circuit_parallel_v4;
const process_usage = @import("stwo_prover_engine").measurement.process_usage;
const M31 = @import("stwo_core").fields.m31.M31;
const QM31 = @import("stwo_core").fields.qm31.QM31;

test "stage102 V4 manifest preserves universal physical layout" {
    const provider = manifest_mod.LiveProviderGeometryV4{
        .role_io_tuple_count = 1,
        .role_io_tuple_capacity = 1,
        .role_io_word_count = 24,
        .role_io_call_count = 4,
        .provider_active_row_count = 129,
        .provider_log_size = 8,
        .provider_row_capacity = 256,
    };
    try provider.validate();
    var logs = [_]u32{4} ** manifest_mod.COMPONENT_COUNT;
    logs[@intFromEnum(manifest_mod.ComponentKey.poseidon2)] =
        provider.provider_log_size;
    logs[@intFromEnum(manifest_mod.ComponentKey.range_check_8_8)] =
        manifest_mod.RANGE_LOG_SIZE;
    const manifest = try manifest_mod.buildForLiveProviderGeometry(
        logs,
        provider,
    );
    try manifest_mod.validateExactForLiveProvider(&manifest, logs, provider);
    try std.testing.expectEqual(@as(u8, 36), manifest.roster_count);
    try std.testing.expectEqual(
        @as(u32, 570),
        manifest.total_preprocessed_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 1044),
        manifest.total_main_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 560),
        manifest.total_interaction_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 1312),
        manifest.total_constraints,
    );

    var wrong_poseidon = logs;
    wrong_poseidon[@intFromEnum(manifest_mod.ComponentKey.poseidon2)] -= 1;
    try std.testing.expectError(
        error.EthereumIncrementalUniversalManifestMismatchV4,
        manifest_mod.buildForDerivedLogSizes(wrong_poseidon),
    );
    var wrong_range = logs;
    wrong_range[@intFromEnum(manifest_mod.ComponentKey.range_check_8_8)] -= 1;
    try std.testing.expectError(
        error.EthereumIncrementalUniversalManifestMismatchV4,
        manifest_mod.buildForDerivedLogSizes(wrong_range),
    );

    const identity = try manifest_mod.unfrozenContractIdentity(logs, provider);
    var changed = logs;
    changed[@intFromEnum(manifest_mod.ComponentKey.control)] += 1;
    try std.testing.expect(!std.mem.eql(
        u8,
        &identity,
        &try manifest_mod.unfrozenContractIdentity(changed, provider),
    ));

    var wrong_provider = provider;
    wrong_provider.role_io_tuple_capacity = 2;
    try std.testing.expectError(
        error.EthereumIncrementalFieldScheduleMismatchV4Schema3,
        manifest_mod.buildForLiveProviderGeometry(logs, wrong_provider),
    );
    var different_active_count = provider;
    different_active_count.role_io_tuple_count = 0;
    try std.testing.expectEqualSlices(
        u8,
        &identity,
        &try manifest_mod.unfrozenContractIdentity(
            logs,
            different_active_count,
        ),
    );
}

test "stage102 V4 bridge projection pins the missing graph authority" {
    const geometry = try bridge_external.GeometryV3.canonicalAfterPrefix(
        17,
        .{ .preprocessed = 100, .main = 200, .interaction = 300 },
    );
    const Profile = struct {
        bridge_geometry: bridge_external.GeometryV3,
    };
    const profile = Profile{ .bridge_geometry = geometry };
    const projection = try materializer.BridgeProjectionV4.init(&profile);
    try projection.validateAgainst(&profile);
    try std.testing.expectEqual(@as(u32, 17), projection.n_rows);
    try std.testing.expectEqual(
        @as(u32, 17),
        projection.trace_sampled_value_count,
    );
    try std.testing.expectEqual(@as(u32, 1), projection.detailed_claim_count);
    try std.testing.expectEqual(@as(u32, 1), projection.transcript_claim_count);
    try std.testing.expectEqual(@as(u32, 6), projection.direct_constraint_count);

    var wrong = projection;
    wrong.geometry_identity_sha256[31] ^= 1;
    try std.testing.expectError(
        error.EthereumIncrementalMaterializerMismatchV4,
        wrong.validateAgainst(&profile),
    );
}

test "stage102 V4 materializer type retains live capture ownership" {
    const Prepared = materializer.PreparedCaptureV4(Engine);
    std.testing.refAllDecls(Prepared);
    try std.testing.expectEqual(@as(u32, 43), materializer.FULL_TRANSCRIPT_CLAIM_COUNT);
    try std.testing.expect(!materializer.PRODUCTION_ACTIVATION);
    try std.testing.expect(!materializer.UNIVERSAL_COHORT_AVAILABLE);
    try std.testing.expect(materializer.V4_TRANSCRIPT_SOURCE_AVAILABLE);
    try std.testing.expect(materializer.BRIDGE_COMPOSITION_GRAPH_AVAILABLE);
    try std.testing.expect(cohort.ROLE_AWARE_IO_WITNESS_AVAILABLE);
    try std.testing.expect(!cohort.CAMPAIGN_PROVIDER_GEOMETRY_FROZEN);
    try std.testing.expect(cohort.COMPLETION_PROGRAM_GRAPH_AVAILABLE);
    try std.testing.expect(!public_semantics.LEGACY_SELF_LOOP_ASSUMED);
    try std.testing.expect(!public_semantics.CALLER_AUTHORED_TUPLE_ADMITTED);
    try std.testing.expect(!materializer.WRAPPER_PROOF_AVAILABLE);
    try std.testing.expect(!materializer.SERIALIZABLE_FRESH_CAPABILITY);
    const metrics = materializer.MaterializationMetricsV4{};
    try std.testing.expectEqual(@as(u8, 0), metrics.graph_schedule_compile_count);
    try std.testing.expectEqual(@as(u8, 0), metrics.retained_graph_copy_count);
    try std.testing.expectEqual(
        @as(u16, 1),
        metrics.schedule_projection_worker_count,
    );
}

test "stage102 V4 fresh program custody rejects pointer and identity drift" {
    var nodes = [_]u8{1};
    var outputs = [_]u8{2};
    var bindings = [_]u8{3};
    const FakeProgram = struct {
        nodes: []u8,
        outputs: []u8,
        bindings: []u8,
        graph_sha256: [32]u8,
        reference_sha256: [32]u8,
        schedule_sha256: [32]u8,
        air_program_identity: [32]u8,
        verifier_program_authority: [32]u8,
    };
    var program = FakeProgram{
        .nodes = &nodes,
        .outputs = &outputs,
        .bindings = &bindings,
        .graph_sha256 = [_]u8{1} ** 32,
        .reference_sha256 = [_]u8{2} ** 32,
        .schedule_sha256 = [_]u8{3} ** 32,
        .air_program_identity = [_]u8{4} ** 32,
        .verifier_program_authority = [_]u8{5} ** 32,
    };
    var custody = try materializer.ProgramConstructionCustodyV4.mint(&program);
    try custody.validateBorrowed(&program);
    var metrics = materializer.MaterializationMetricsV4{};
    var schedule_rows = [_]u8{ 6, 7 };
    try @import("recursive_common_ethereum_incremental_leaf_materializer_v4_support.zig")
        .recordProgramResources(
        &metrics,
        &program,
        &.{ .rows = &schedule_rows },
    );
    try std.testing.expectEqual(@as(u8, 1), metrics.graph_schedule_compile_count);
    try std.testing.expectEqual(@as(u8, 0), metrics.retained_graph_copy_count);

    program.graph_sha256[0] ^= 1;
    try std.testing.expectError(
        error.InvalidFreshProgramConstructionCustodyV4,
        custody.validateBorrowed(&program),
    );
    program.graph_sha256[0] ^= 1;
    custody.nodes_ptr +%= 1;
    try std.testing.expectError(
        error.InvalidFreshProgramConstructionCustodyV4,
        custody.validateBorrowed(&program),
    );
}

test "role0 genuine runtime allocator counts ownership and host workers" {
    var tracked = runtime_mod.TrackedSmpAllocatorV4{};
    const allocator = tracked.allocator();
    var bytes = try allocator.alloc(u8, 31);
    bytes = try allocator.realloc(bytes, 4097);
    const live = tracked.snapshot();
    try std.testing.expectEqual(@as(usize, 1), live.active_allocations);
    try std.testing.expectEqual(@as(usize, 4097), live.active_bytes);
    try std.testing.expectEqual(@as(usize, 0), live.untracked_active_allocations);
    allocator.free(bytes);
    try std.testing.expect(tracked.isEmpty());
    try std.testing.expect(tracked.peakBytes() >= 4097);
    const before_report = tracked.snapshot();
    tracked.dumpLeaks();
    try std.testing.expectEqualDeep(before_report, tracked.snapshot());

    var threads: [4]std.Thread = undefined;
    for (&threads, 0..) |*thread, index| thread.* = try std.Thread.spawn(
        .{},
        exerciseTrackedAllocator,
        .{ &tracked, index },
    );
    for (&threads) |*thread| thread.join();
    try std.testing.expect(tracked.isEmpty());

    const policy = try runtime_mod.WorkerPolicyV4.hostDefault(1 << 30);
    try std.testing.expect(policy.worker_count > 0);
    try std.testing.expect(policy.worker_count <= runtime_mod.MAXIMUM_WORKER_COUNT);
    const request = try policy.cpuRequest();
    try std.testing.expectEqual(policy.worker_count, request.worker_count);
    try std.testing.expectEqual(@as(usize, 1 << 30), request.host_byte_budget);
    try std.testing.expectEqual(
        @import("stwo_prover_api").CpuCompositionContentionPolicy.strict,
        request.contention_policy,
    );
    const receipt = try runtime_mod.Stage101ExecutionReceiptV4.mint(request, 2);
    try receipt.validate();
    try std.testing.expectEqual(@as(u32, 2), receipt.proof_count);
    try std.testing.expect(!std.mem.allEqual(u8, &receipt.identity_sha256, 0));
    var wrong_receipt = receipt;
    wrong_receipt.host_byte_budget += 1;
    try std.testing.expectError(
        error.InvalidRole0GenuineExecutionReceipt,
        wrong_receipt.validate(),
    );
    var usage = try runtime_mod.PhaseUsageReceiptV4.fromDelta(
        .materialize,
        policy,
        4_000_000_000,
        process_usage.Delta{
            .source = .darwin_proc_pid_rusage_v6,
            .lifetime_peak_physical_footprint_bytes = 42 * 1024 * 1024,
            .process_cpu_ns = 36_000_000_000,
            .energy_nj = 17,
            .instructions = 19,
            .cycles = 23,
            .unavailable_reason = null,
        },
    );
    try usage.validate();
    try std.testing.expectEqual(
        @as(?u64, 9_000),
        usage.average_parallelism_milli,
    );
    usage.average_parallelism_milli.? += 1;
    try std.testing.expectError(
        error.InvalidRole0GenuinePhaseUsage,
        usage.validate(),
    );
    try std.testing.expectError(
        error.InvalidMaterializationWorkerCountV4,
        (materializer.MaterializationExecutionV4{ .worker_count = 0 }).validate(),
    );
}

fn exerciseTrackedAllocator(
    tracked: *runtime_mod.TrackedSmpAllocatorV4,
    worker_index: usize,
) void {
    const allocator = tracked.allocator();
    for (0..256) |iteration| {
        const initial_len = 33 + ((worker_index + iteration) % 97);
        var bytes = allocator.alloc(u8, initial_len) catch
            @panic("tracked allocator concurrency fixture allocation failed");
        const grown_len = 4097 + ((worker_index * 257 + iteration) % 1021);
        bytes = allocator.realloc(bytes, grown_len) catch
            @panic("tracked allocator concurrency fixture resize failed");
        allocator.free(bytes);
    }
}

test "fresh composition schedule projection is deterministic across workers" {
    const allocator = std.testing.allocator;
    const rows = try allocator.alloc(parallel_projection.ProjectionRow, 4097);
    defer allocator.free(rows);
    for (rows) |*row| row.* = .{
        .classification = .{ .vm_input = .segment_selector },
        .circuit_id = 1,
        .node_id = 0,
        .use_count = 1,
    };
    const evaluation = [_]QM31{QM31.fromBase(M31.fromCanonical(19))};
    const serial = try allocator.alloc(M31, rows.len);
    defer allocator.free(serial);
    const parallel = try allocator.alloc(M31, rows.len);
    defer allocator.free(parallel);

    try parallel_projection.fillScheduleValues(
        allocator,
        rows,
        &evaluation,
        serial,
        1,
        1,
    );
    try parallel_projection.fillScheduleValues(
        allocator,
        rows,
        &evaluation,
        parallel,
        1,
        4,
    );
    try std.testing.expectEqualSlices(M31, serial, parallel);
}
