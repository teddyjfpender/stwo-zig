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

test "role0 recorded payload preserves legacy layout and constant-word metadata" {
    const program = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");
    const support = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4_support.zig");
    const witness = frontend.recursion.air.transcript_payload_witness;
    const rows_support = @import("recursive_common_ethereum_incremental_leaf_transcript_rows_v4_support.zig");
    const rate = frontend.recursion.recording_poseidon_channel_v4.RATE;
    const operation = program.OperationV4{
        .recording_index = 0,
        .context = .profile_pre_tree0,
        .context_ordinal = 0,
        .effect = .mix,
        .verifier_sequence = 0,
        .tag = 512,
        .args = .{ 0, 0, 0, 0 },
        .payload = .constant,
        .draw = .none,
    };
    // The first case is the exact first rejected row in the pinned proof
    // replay: value 16, source word 8. Later words exercise long fixed frames.
    for (0..33) |index| {
        const metadata = try support.metadata(operation, @intCast(index));
        var row = witness.Row{
            .row_mask = 1,
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = 0,
            .sequence = 0,
            .tag = 512,
            .args = .{ 0, 0, 0, 0 },
            .payload_index = @intCast(index),
            .source_kind = .protocol,
            .item_index = metadata.item_index,
            .limb_index = metadata.limb_index,
            .constant_mask = metadata.constant_mask,
            .input_use_count = metadata.input_use_count,
            .constant_value = 16,
            .source_hash_id = 0,
            .source_word_index = @intCast(rate + index),
        };
        const value = M31.fromCanonical(16);
        const logical = try witness.logicalRowForRecordedFrame(row, value, .segment_leaf);
        const parameters_at = frontend.recursion.air.transcript_payload.PHYSICAL_MAIN_COLUMN_COUNT + frontend.recursion.air.transcript_payload.PREPROCESSED_COLUMN_COUNT;
        try std.testing.expectEqualDeep(logical[0..parameters_at].* ++ ([_]M31{M31.zero()} ** 6) ++ logical[parameters_at..].*, try rows_support.payloadLogicalRow(.{ .preprocessing = row, .value = value }));
        try std.testing.expectError(error.InvalidTraceRow, witness.logicalRow(row, value, .segment_leaf));
        row.source_word_index = @intCast(witness.PAYLOAD_WORD_OFFSET + index);
        try std.testing.expectEqualDeep(logical, try witness.logicalRow(row, value, .segment_leaf));
        try std.testing.expectError(error.InvalidTraceRow, witness.logicalRowForRecordedFrame(row, value, .segment_leaf));
        row.source_word_index = @intCast(rate + index);
        row.segment_mask = 0;
        row.binary_mask = 1;
        row.verifier_id = 1;
        try std.testing.expectEqualDeep((try witness.mainRow(value)) ++ row.values() ++ .{ M31.zero(), M31.one() }, try witness.logicalRowForRecordedFrame(row, value, .binary_node));
        row.input_use_count = 1;
        try std.testing.expectError(error.InvalidTraceRow, witness.logicalRowForRecordedFrame(row, value, .binary_node));
        row.input_use_count = 0;
        row.constant_mask = 0;
        try std.testing.expectError(error.InvalidTraceRow, witness.logicalRowForRecordedFrame(row, value, .binary_node));
        row.constant_mask = 1;
        row.source_word_index = @intCast(witness.PAYLOAD_WORD_OFFSET + index);
        row.constant_value = 369535897;
        const inactive = try witness.logicalRow(row, M31.zero(), .segment_leaf);
        try std.testing.expectEqualDeep(inactive[0..parameters_at].* ++ ([_]M31{M31.zero()} ** 6) ++ inactive[parameters_at..].*, try rows_support.payloadLogicalRow(.{ .preprocessing = row, .value = M31.zero() }));
    }
    // Exact first common-fold row rejected by the legacy-only adapter.
    var fixed_root = witness.Row{
        .row_mask = 1,
        .segment_mask = 0,
        .binary_mask = 1,
        .verifier_id = 1,
        .sequence = 0,
        .tag = 1398013953,
        .args = .{ 1, 8, 0, 0 },
        .payload_index = 0,
        .source_kind = .commitment,
        .item_index = 0,
        .limb_index = 0,
        .constant_mask = 1,
        .input_use_count = 1,
        .constant_value = 954990678,
        .source_hash_id = 0,
        .source_word_index = rate,
    };
    const value = M31.fromCanonical(fixed_root.constant_value);
    try std.testing.expectEqualDeep((try witness.mainRow(value)) ++ fixed_root.values() ++ .{ M31.zero(), M31.one() }, try witness.logicalRowForRecordedFrame(fixed_root, value, .binary_node));
    fixed_root.item_index = 1;
    try std.testing.expectError(error.InvalidTraceRow, witness.logicalRowForRecordedFrame(fixed_root, value, .binary_node));
    fixed_root.source_kind = .protocol;
    fixed_root.input_use_count = 0;
    fixed_root.item_index = 3;
    fixed_root.limb_index = 3;
    _ = try witness.logicalRowForRecordedFrame(fixed_root, value, .binary_node);
    fixed_root.source_word_index = witness.PAYLOAD_WORD_OFFSET;
    try std.testing.expectError(error.InvalidTraceRow, witness.logicalRow(fixed_root, value, .binary_node));
}

test "role0 post-tree1 profile retains every native mix operation" {
    const recording = frontend.recursion.recording_poseidon_channel_v4;
    const support = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4_support.zig");
    var channel = recording.Channel.init(std.testing.allocator);
    defer channel.deinit();
    channel.setContextTag(4);
    channel.mixU32s(&.{1});
    channel.mixU32s(&.{2});
    _ = channel.drawU32s();
    var execution = try channel.finish();
    defer execution.deinit();
    try support.requireMixContext(&execution, .{ .first = 0, .count = 2 });
    try std.testing.expectError(error.EthereumIncrementalTranscriptProgramMismatchV4, support.requireMixContext(&execution, .{ .first = 0, .count = 3 }));
}

test "role0 relation rows preserve both values from each native draw" {
    const recording = frontend.recursion.recording_poseidon_channel_v4;
    const program = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");
    const rows = @import("recursive_common_ethereum_incremental_leaf_transcript_rows_v4_support.zig");
    const allocator = std.testing.allocator;
    var channel = recording.Channel.init(allocator);
    defer channel.deinit();
    channel.setContextTag(6);
    var expected: [program.RELATION_CHALLENGE_COUNT][8]M31 = undefined;
    var operations: [program.RELATION_CHALLENGE_COUNT]program.OperationV4 = undefined;
    for (&expected, &operations, 0..) |*draw, *operation, index| {
        const values = try channel.drawSecureFelts(allocator, 2);
        defer allocator.free(values);
        draw.* = values[0].toM31Array() ++ values[1].toM31Array();
        const challenge: u32 = @intCast(index);
        operation.* = .{
            .recording_index = challenge,
            .context = .relation_draws,
            .context_ordinal = challenge,
            .effect = .draw,
            .verifier_sequence = challenge,
            .tag = 7,
            .args = .{ challenge, 0, 0, 0 },
            .payload = .none,
            .draw = .{ .relation_challenge = challenge },
        };
    }
    var execution = try channel.finish();
    defer execution.deinit();
    try std.testing.expectEqual(program.RELATION_CHALLENGE_COUNT, execution.operations.len);
    const actual = try rows.relationDrawsAlloc(allocator, &execution, &operations);
    defer allocator.free(actual);
    try std.testing.expectEqualDeep(&expected, actual);
    operations[1].draw = .{ .relation_challenge = 0 };
    try std.testing.expectError(error.EthereumIncrementalTranscriptRowsMismatchV4, rows.relationDrawsAlloc(allocator, &execution, &operations));
    operations[1].draw = .none;
    try std.testing.expectError(error.EthereumIncrementalTranscriptRowsMismatchV4, rows.relationDrawsAlloc(allocator, &execution, &operations));
}

test "role0 public logup owners propagate authenticated native view rejection" {
    const native_core = @import("recursive_common_ethereum_incremental_leaf_native_core_v4.zig");
    const row16 = @import("recursive_common_ethereum_incremental_leaf_public_logup_input_v4.zig");
    const row17 = @import("recursive_common_ethereum_incremental_leaf_public_logup_control_v4.zig");
    // No separate validate method: each native getter must authenticate its
    // owner and its returned view, just as the real native core does.
    const RejectedNative = struct {
        pub fn publicInputView(_: *const @This()) !native_core.PublicInputViewV4 {
            return error.AuthenticatedNativeViewRejected;
        }
        pub fn scheduleView(_: *const @This()) !native_core.ScheduleViewV4 {
            return error.AuthenticatedNativeViewRejected;
        }
    };
    const native = RejectedNative{};
    try std.testing.expectError(error.AuthenticatedNativeViewRejected, row16.OwnerV4(RejectedNative).init(std.testing.allocator, &native));
    try std.testing.expectError(error.AuthenticatedNativeViewRejected, row17.OwnerV4(RejectedNative).init(std.testing.allocator, &native));
}

test "role0 transcript statement metadata matches the shared AIR input" {
    const program = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");
    const support = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4_support.zig");
    const row10 = frontend.recursion.air.statement_input;
    const operation = program.OperationV4{
        .recording_index = 3,
        .context = .profile_pre_tree0,
        .context_ordinal = 3,
        .effect = .mix,
        .verifier_sequence = 0,
        .tag = 0,
        .args = .{ 0, 0, 0, 0 },
        .payload = .{ .statement_span = .{
            .wire_offset = program.BASE_STATEMENT_WIRE_OFFSET,
            .word_count = program.BASE_STATEMENT_WORD_COUNT,
        } },
        .draw = .none,
    };
    for (0..program.BASE_STATEMENT_WORD_COUNT) |index| {
        const metadata = try support.metadata(operation, program.BASE_STATEMENT_WIRE_OFFSET + @as(u32, @intCast(index)));
        try std.testing.expectEqual(row10.STATEMENT_INPUT_KIND, @intFromEnum(metadata.source_kind));
        try std.testing.expectEqual(row10.STATEMENT_INPUT_ITEM, metadata.item_index);
        try std.testing.expectEqual(index, metadata.limb_index);
        try std.testing.expectEqual(@as(u32, 0), metadata.constant_mask);
        try std.testing.expectEqual(@as(u32, 1), metadata.input_use_count);
    }
    for ([_]u32{ program.BASE_STATEMENT_WIRE_OFFSET - 1, program.BASE_STATEMENT_WIRE_OFFSET + program.BASE_STATEMENT_WORD_COUNT }) |index| {
        const metadata = try support.metadata(operation, index);
        try std.testing.expectEqual(@as(u32, 1), metadata.constant_mask);
        try std.testing.expectEqual(@as(u32, 0), metadata.input_use_count);
    }
}

test "role0 default claim shape builds its complete semantics graph" {
    var reference = try frontend.recursion.vm_public_semantics_circuit.ClaimReference.init(
        std.testing.allocator,
        try frontend.recursion.vm_public_claim.defaultShape(),
        40,
    );
    defer reference.deinit();
    try reference.validate();
    const defaults = frontend.recursion.arithmetic_circuit.Limits{};
    try std.testing.expectEqual(defaults.max_nodes, reference.circuit.limits.max_nodes);
    try std.testing.expectEqual(defaults.max_nodes, reference.circuit.limits.max_outputs);
    try std.testing.expect(reference.circuit.outputs().len > defaults.max_outputs);
}

test "role0 public sum reservation does not reject an admitted graph" {
    const sums = @import("recursive_common_ethereum_incremental_leaf_public_sums_v4_support.zig");
    const limits = sums.arithmetic.Limits{};
    for ([_]u32{ 2, sums.role_binding.MAX_TUPLE_CAPACITY }) |capacity| {
        var program = try sums.build(std.testing.allocator, capacity);
        defer program.deinit(std.testing.allocator);
        try std.testing.expectEqualDeep(limits, program.circuit.limits);
        try std.testing.expect(program.circuit.outputs().len < limits.max_outputs);
        try program.circuit.validate();
    }
    try std.testing.expectError(error.EthereumRoleBindingCapacityExceeded, sums.build(std.testing.allocator, sums.role_binding.MAX_TUPLE_CAPACITY * 2));
}

test "stage102 V4 manifest admits statement-root physical layout" {
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
        @as(u32, 619),
        manifest.total_preprocessed_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 1054),
        manifest.total_main_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 616),
        manifest.total_interaction_columns,
    );
    try std.testing.expectEqual(
        @as(u32, 1343),
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

test "role0 genuine runtime accounts host workers" {
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

test "role0 Ethereum detailed claim frames authenticate exact input routing" {
    const recording = frontend.recursion.recording_poseidon_channel_v4;
    const program = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");
    const support = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4_support.zig");
    const rows_support = @import("recursive_common_ethereum_incremental_leaf_transcript_rows_v4_support.zig");
    const air = frontend.recursion.air;
    const witness = air.transcript_payload_witness;
    const allocator = std.testing.allocator;
    var channel = recording.Channel.init(allocator);
    defer channel.deinit();
    const claims = [_]QM31{
        QM31.fromU32Unchecked(3, 5, 7, 11),
        QM31.fromU32Unchecked(13, 17, 19, 23),
    };
    channel.setContextTag(7);
    channel.mixFelts(&claims);
    var execution = try channel.finish();
    defer execution.deinit();
    var operations = [_]program.OperationV4{.{
        .recording_index = 0,
        .context = .interaction_claims,
        .context_ordinal = 0,
        .effect = .mix,
        .verifier_sequence = 0,
        .tag = 0,
        .args = .{ 0, 0, 0, 0 },
        .payload = .constant,
        .draw = .none,
    }};
    var local: usize = 0;
    try support.consumeDetailedClaims(&execution, .{ .first = 0, .count = 1 }, &local, &operations, 7, 137, &claims);
    try std.testing.expectEqual(@as(usize, 1), local);
    try std.testing.expectEqual(@as(u16, 9), program.SCHEMA_VERSION);
    var definition = try air.ethereum_transcript_payload_raw_v1.build(allocator);
    defer definition.deinit();
    const relation = try air.universal_relation_binding.Binding(air.ethereum_transcript_payload_raw_v1).authenticate(&definition);
    for (0..8) |index| {
        const metadata = try support.metadata(operations[0], @intCast(index));
        try std.testing.expectEqual(@as(u32, 12), @intFromEnum(metadata.source_kind));
        try std.testing.expectEqual(@as(u32, @intCast(137 + index / 4)), metadata.item_index);
        try std.testing.expectEqual(@as(u32, @intCast(index % 4)), metadata.limb_index);
        var row = witness.Row{
            .row_mask = 1,
            .segment_mask = 1,
            .binary_mask = 0,
            .verifier_id = 0,
            .sequence = 7,
            .tag = 0,
            .args = .{ 0, 0, 0, 0 },
            .payload_index = @intCast(index),
            .source_kind = .vm_air_claimed_sum,
            .item_index = metadata.item_index,
            .limb_index = metadata.limb_index,
            .constant_mask = metadata.constant_mask,
            .input_use_count = metadata.input_use_count,
            .constant_value = 0,
            .source_hash_id = 0,
            .source_word_index = @intCast(recording.RATE + index),
        };
        const value = claims[index / 4].toM31Array()[index % 4];
        const logical = try rows_support.payloadLogicalRow(.{ .preprocessing = row, .value = value });
        const emitted = relation.preparedEntries(logical)[1];
        try std.testing.expectEqual(@as(u32, 12), emitted.values[1].toM31Array()[0].toU32());
        try std.testing.expectEqual(metadata.item_index, emitted.values[2].toM31Array()[0].toU32());
        try std.testing.expectEqual(metadata.limb_index, emitted.values[3].toM31Array()[0].toU32());
        try std.testing.expectEqual(value.toU32(), emitted.values[4].toM31Array()[0].toU32());
        try std.testing.expectEqual(@as(u32, 1), emitted.numerator.toM31Array()[0].toU32());
        // Existing profile entrypoints must continue to reject kind 12.
        try std.testing.expectError(error.InvalidTraceRow, witness.logicalRowForRecordedFrame(row, value, .segment_leaf));
        row.source_word_index = @intCast(witness.PAYLOAD_WORD_OFFSET + index);
        try std.testing.expectError(error.InvalidTraceRow, witness.logicalRow(row, value, .segment_leaf));
        row.source_word_index = @intCast(recording.RATE + index);
        row.input_use_count = 0;
        try std.testing.expectError(error.InvalidTraceRow, rows_support.payloadLogicalRow(.{ .preprocessing = row, .value = value }));
        row.input_use_count = 1;
        row.constant_mask = 1;
        try std.testing.expectError(error.InvalidTraceRow, rows_support.payloadLogicalRow(.{ .preprocessing = row, .value = value }));
    }
    try std.testing.expectError(error.EthereumIncrementalTranscriptProgramMismatchV4, support.metadata(operations[0], 8));
    // A compensating change preserves the aggregate but cannot be admitted
    // against the genuine native frame already bound before randomness.
    var changed = claims;
    changed[0] = changed[0].add(QM31.one());
    changed[1] = changed[1].sub(QM31.one());
    try std.testing.expect(changed[0].add(changed[1]).eql(claims[0].add(claims[1])));
    local = 0;
    const before = operations;
    try std.testing.expectError(error.EthereumIncrementalTranscriptProgramMismatchV4, support.consumeDetailedClaims(&execution, .{ .first = 0, .count = 1 }, &local, &operations, 7, 137, &changed));
    try std.testing.expectEqual(@as(usize, 0), local);
    try std.testing.expectEqualDeep(before, operations);
    try std.testing.expectError(error.EthereumIncrementalTranscriptProgramMismatchV4, support.consumeDetailedClaims(&execution, .{ .first = 0, .count = 1 }, &local, &operations, 7, 137, claims[0..1]));
}

test "role0 Ethereum shared claim view preserves native transcript bytes and offsets" {
    const types = frontend.prover_mod.guest_precompile.ethereum_types;
    const recording = frontend.recursion.recording_poseidon_channel_v4;
    const program = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");
    const support = @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4_support.zig");
    const allocator = std.testing.allocator;
    var claims = std.mem.zeroes(types.ExtensionClaim);
    // Give every field and every limb a distinct value. Zero fixtures would
    // hide both component reordering and a wrong detailed-claim offset.
    inline for (std.meta.fields(types.ExtensionClaim), 0..) |field, index| {
        const marker: u32 = @intCast(10000 * (index + 1));
        if (field.type == QM31) {
            @field(claims, field.name) = QM31.fromU32Unchecked(marker, marker + 1, marker + 2, marker + 3);
        } else {
            const claim = &@field(claims, field.name);
            for (&claim.batch_sums, 0..) |*batch, item| {
                const value = marker + @as(u32, @intCast(4 * item));
                batch.* = QM31.fromU32Unchecked(value, value + 1, value + 2, value + 3);
            }
            claim.component_sum = QM31.fromU32Unchecked(marker + 9000, marker + 9001, marker + 9002, marker + 9003);
        }
    }
    var native = recording.Channel.init(allocator);
    defer native.deinit();
    claims.mixInto(&native);
    var actual = try native.finish();
    defer actual.deinit();

    // Frozen pre-consolidation native call sequence: an independent protocol
    // compatibility fixture, not a second production routing authority.
    var legacy = recording.Channel.init(allocator);
    defer legacy.deinit();
    legacy.mixU32s(&.{ 0x4757_5453, 0x3143_5445, 14 });
    legacy.mixU32s(&.{@intCast(claims.keccak_shard.batch_sums.len)});
    legacy.mixFelts(&claims.keccak_shard.batch_sums);
    legacy.mixFelts(&.{claims.keccak_shard.component_sum});
    legacy.mixFelts(&.{claims.keccak_chi_table});
    legacy.mixFelts(&.{claims.keccak_xor5_table});
    inline for (.{ claims.product_base, claims.product_scalar, claims.linear_base, claims.linear_scalar, claims.point, claims.split, claims.scalar, claims.table, claims.recovery, claims.byte, claims.recovery_caller }) |claim| {
        legacy.mixU32s(&.{@intCast(claim.batch_sums.len)});
        legacy.mixFelts(&claim.batch_sums);
        legacy.mixFelts(&.{claim.component_sum});
    }
    var expected = try legacy.finish();
    defer expected.deinit();
    try std.testing.expectEqual(@as(usize, 39), actual.operations.len);
    try std.testing.expectEqualDeep(expected.operations, actual.operations);
    try std.testing.expectEqual(expected.hash_frames.len, actual.hash_frames.len);
    for (expected.hash_frames, actual.hash_frames) |before, after| {
        try std.testing.expectEqualSlices(M31, before.words, after.words);
        try std.testing.expectEqualDeep(before.output, after.output);
    }

    var operations: [39]program.OperationV4 = undefined;
    for (&operations, 0..) |*operation, index| operation.* = .{
        .recording_index = @intCast(index),
        .context = .interaction_claims,
        .context_ordinal = @intCast(index),
        .effect = .mix,
        .verifier_sequence = 0,
        .tag = 0,
        .args = .{ 0, 0, 0, 0 },
        .payload = .constant,
        .draw = .none,
    };
    var component_counts: [14]u32 = undefined;
    for (claims.componentClaims(), &component_counts) |claim, *count| count.* = @intCast(claim.detailed.len);
    const routing = try frontend.recursion.incremental_ethereum_composition_profile_v4.ClaimRoutingPlan.init(137, component_counts);
    var native_at: usize = 1;
    var detailed_at: u32 = routing.base_count;
    var batch_count: u32 = 0;
    var scalar_count: u32 = 0;
    for (claims.componentClaims(), 0..) |claim, index| {
        try std.testing.expectEqual(@as(u8, @intCast(index + 1)), @intFromEnum(claim.kind));
        try std.testing.expectEqual(index != 1 and index != 2, claim.has_batch_frame);
        if (claim.has_batch_frame) {
            batch_count += 1;
            native_at += 1; // Count header precedes the detailed native frame.
            const payload = expected.hash_frames[expected.operations[native_at].first_hash_id].words[recording.RATE..];
            try std.testing.expectEqual(payload.len / 4, claim.detailed.len);
            const operation_index = native_at;
            const physical_first = try routing.physicalRange(detailed_at, @intCast(claim.detailed.len));
            try support.consumeDetailedClaims(&actual, .{ .first = 0, .count = 39 }, &native_at, &operations, 7, physical_first, claim.detailed);
            for (0..payload.len) |limb| {
                const metadata = try support.metadata(operations[operation_index], @intCast(limb));
                const expected_source = try routing.sourceForWord(detailed_at + @as(u32, @intCast(limb / 4)), @intCast(limb % 4));
                try std.testing.expectEqual(expected_source.claimed_sum.item_index, metadata.item_index);
                try std.testing.expectEqual(@as(u32, @intCast(limb % 4)), metadata.limb_index);
                try std.testing.expectEqual(@as(u32, 12), @intFromEnum(metadata.source_kind));
            }
            native_at += 1; // Canonical aggregate is its own native frame.
        } else {
            scalar_count += 1;
            try std.testing.expectEqual(@as(usize, 1), claim.detailed.len);
            try std.testing.expect(claim.total.eql(claim.detailed[0]));
            const source = try routing.sourceForWord(detailed_at, 0);
            try std.testing.expectEqual(@as(u32, @intCast(28 + index)), source.transcript_claimed_sum.item_index);
            native_at += 1;
        }
        detailed_at += @intCast(claim.detailed.len);
    }
    try std.testing.expectEqual(@as(u32, 12), batch_count);
    try std.testing.expectEqual(@as(u32, 2), scalar_count);
    try std.testing.expectEqual(actual.operations.len, native_at);
    // The bridge's singleton comes after all fourteen extension claims and
    // remains owned by the incremental transcript, outside ExtensionClaim.
    try std.testing.expectEqual(routing.logical_count, detailed_at + 1);
    try std.testing.expectEqual(@as(u32, 42), (try routing.sourceForWord(detailed_at, 0)).transcript_claimed_sum.item_index);
}

test "role0 Ethereum singleton claim plan preserves native shape and base inputs" {
    const admission = frontend.recursion.incremental_ethereum_composition_profile_v4;
    const graph = frontend.recursion.air.composition_circuit;
    // Distinct component lengths expose shifted mapping. Native chi, xor5 and
    // bridge are singleton claims even when other components have one batch.
    const counts = [14]u32{ 7, 1, 1, 3, 5, 2, 1, 4, 2, 6, 1, 3, 1, 2 };
    const plan = try admission.ClaimRoutingPlan.init(35, counts);
    try plan.validate();
    try std.testing.expectEqual(@as(u32, 75), plan.logical_count);
    try std.testing.expectEqual(@as(u32, 72), plan.physical_count);
    const expected_aliases = [3]admission.ClaimRoutingPlan.Alias{
        .{ .logical = 42, .canonical = 29 },
        .{ .logical = 43, .canonical = 30 },
        .{ .logical = 74, .canonical = 42 },
    };
    try std.testing.expectEqualDeep(expected_aliases, plan.aliases);
    for (0..plan.logical_count) |logical| {
        const route = try plan.route(@intCast(logical));
        switch (route) {
            .detailed => |physical| {
                try std.testing.expectEqual(@as(u32, @intCast(logical)), try plan.logicalForPhysical(physical));
                for (0..4) |limb| try std.testing.expectEqualDeep(graph.VmSource{ .claimed_sum = .{ .item_index = physical, .word_index = @intCast(limb) } }, try plan.sourceForWord(@intCast(logical), @intCast(limb)));
                if (logical < 35) try std.testing.expectEqual(@as(u32, @intCast(logical)), physical);
            },
            .canonical => |item| {
                try std.testing.expect(logical == 42 or logical == 43 or logical == 74);
                for (0..4) |limb| try std.testing.expectEqualDeep(graph.VmSource{ .transcript_claimed_sum = .{ .item_index = item, .word_index = @intCast(limb) } }, try plan.sourceForWord(@intCast(logical), @intCast(limb)));
            },
        }
    }
    // The canonical node now supplies both uses. No extra physical input or
    // transcript emission exists for an aliased singleton.
    const dense = graph.InputProfile{ .sampled_value_count = 0, .claimed_sum_count = plan.physical_count, .relation_challenge_count = 0, .transcript_claimed_sum_count = 43 };
    const legacy = graph.InputProfile{ .sampled_value_count = 0, .claimed_sum_count = plan.logical_count, .relation_challenge_count = 0, .transcript_claimed_sum_count = 43 };
    try std.testing.expectEqual(@as(usize, 12), (try graph.vmInputCount(legacy)) - (try graph.vmInputCount(dense)));
    try std.testing.expectEqual(@as(u32, 35), try plan.physicalRange(35, 7));
    try std.testing.expectEqual(@as(u32, 42), try plan.physicalRange(44, 3));
    try std.testing.expectError(error.InvalidEthereumClaimRouting, plan.physicalRange(41, 2));
    try std.testing.expectError(error.InvalidEthereumClaimRouting, plan.physicalRange(74, 1));
    try std.testing.expectError(error.InvalidEthereumClaimRouting, plan.route(75));
    try std.testing.expectError(error.InvalidEthereumClaimRouting, plan.logicalForPhysical(72));
    try std.testing.expectError(error.InvalidEthereumClaimRouting, plan.sourceForWord(0, 4));
    var changed = plan;
    changed.aliases[0].canonical = 30;
    try std.testing.expectError(error.InvalidEthereumClaimRouting, changed.validate());
    try std.testing.expect(!std.meta.eql(plan.identity(), changed.identity()));
    changed = plan;
    changed.physical_count += 1;
    try std.testing.expectError(error.InvalidEthereumClaimRouting, changed.validate());
    var wrong_counts = counts;
    wrong_counts[1] = 2;
    try std.testing.expectError(error.InvalidEthereumClaimRouting, admission.ClaimRoutingPlan.init(35, wrong_counts));
}
