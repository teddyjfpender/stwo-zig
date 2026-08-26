const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const work_profile = @import("stwo_prover_api").work_profile;
const backend_mod = @import("../commit_backend.zig");
const engine_mod = @import("../prover_engine.zig");
const commit_memory = @import("../runtime/commit_memory.zig");
const ownership_testing = @import("../runtime/ownership_testing.zig");
const precommitted_work = @import("../runtime/precommitted_work.zig");

const M31 = core.fields.m31.M31;
const Hasher = core.vcs_lifted.blake2_merkle.Blake2sPrefixedMerkleHasher;
const MetalBackend = backend_mod.MetalCommitBackend;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const CircleCoefficients = prover.poly.circle.CircleCoefficients;
const TwiddleSource = prover.poly.twiddle_source.TwiddleSource;

const test_logs = [_]u32{ 8, 6, 8, 7, 6 };

const BackedColumns = struct {
    columns: []ColumnEvaluation,
    backings: [][]M31,
    moved: bool = false,

    fn deinit(self: *BackedColumns, allocator: std.mem.Allocator) void {
        if (self.moved) return;
        allocator.free(self.columns);
        for (self.backings) |backing| allocator.free(backing);
        allocator.free(self.backings);
        self.* = undefined;
    }
};

fn makeBackedColumns(allocator: std.mem.Allocator) !BackedColumns {
    const page_words = std.heap.pageSize() / @sizeOf(M31);
    var group_logs = std.ArrayList(u32).empty;
    defer group_logs.deinit(allocator);
    var group_counts = std.ArrayList(usize).empty;
    defer group_counts.deinit(allocator);
    for (test_logs) |log_size| {
        var found: ?usize = null;
        for (group_logs.items, 0..) |group_log, index| {
            if (group_log == log_size) {
                found = index;
                break;
            }
        }
        if (found) |index| {
            group_counts.items[index] += 1;
        } else {
            try group_logs.append(allocator, log_size);
            try group_counts.append(allocator, 1);
        }
    }
    const group_offsets = try allocator.alloc(usize, group_logs.items.len);
    defer allocator.free(group_offsets);
    var cursor: usize = 0;
    for (group_logs.items, group_counts.items, group_offsets) |log_size, count, *offset| {
        cursor = std.mem.alignForward(usize, cursor, page_words);
        offset.* = cursor;
        cursor += count * (@as(usize, 1) << @intCast(log_size));
    }
    const arena_words = std.mem.alignForward(usize, cursor, page_words);
    const arena = try allocator.alloc(M31, arena_words);
    errdefer allocator.free(arena);
    if (@intFromPtr(arena.ptr) % std.heap.pageSize() != 0)
        return error.UnsupportedTestAllocatorAlignment;

    const columns = try allocator.alloc(ColumnEvaluation, test_logs.len);
    errdefer allocator.free(columns);
    const group_cursors = try allocator.dupe(usize, group_offsets);
    defer allocator.free(group_cursors);
    for (test_logs, columns, 0..) |log_size, *column, column_index| {
        var group_index: usize = 0;
        for (group_logs.items, 0..) |group_log, index| {
            if (group_log == log_size) {
                group_index = index;
                break;
            }
        }
        const rows = @as(usize, 1) << @intCast(log_size);
        const offset = group_cursors[group_index];
        const values = arena[offset..][0..rows];
        group_cursors[group_index] += rows;
        for (values, 0..) |*value, row| {
            const raw = column_index * 31337 + row * 7919 + @as(usize, log_size) * 101 + 41;
            value.* = M31.fromCanonical(@intCast(
                raw % @as(usize, core.fields.m31.Modulus),
            ));
        }
        column.* = .{ .log_size = log_size, .values = values };
    }
    const backings = try allocator.alloc([]M31, 1);
    backings[0] = arena;
    return .{ .columns = columns, .backings = backings };
}

const Expected = struct {
    columns: []ColumnEvaluation,
    coefficients: [][]M31,

    fn deinit(self: *Expected, allocator: std.mem.Allocator) void {
        for (self.columns) |column| allocator.free(@constCast(column.values));
        allocator.free(self.columns);
        for (self.coefficients) |coefficient| allocator.free(coefficient);
        allocator.free(self.coefficients);
        self.* = undefined;
    }
};

fn expectedExtension(allocator: std.mem.Allocator, columns: []const ColumnEvaluation) !Expected {
    const expected = try allocator.alloc(ColumnEvaluation, columns.len);
    var initialized_evaluations: usize = 0;
    errdefer {
        for (expected[0..initialized_evaluations]) |column| allocator.free(@constCast(column.values));
        allocator.free(expected);
    }
    const coefficients = try allocator.alloc([]M31, columns.len);
    var initialized_coefficients: usize = 0;
    errdefer {
        for (coefficients[0..initialized_coefficients]) |coefficient| allocator.free(coefficient);
        allocator.free(coefficients);
    }

    for (columns, expected, coefficients) |column, *evaluation, *coefficient| {
        const base_domain = core.poly.circle.canonic.CanonicCoset.new(column.log_size).circleDomain();
        const extended_domain = core.poly.circle.canonic.CanonicCoset.new(column.log_size + 1).circleDomain();
        var base_tree = try prover.poly.twiddles.precomputeM31(allocator, base_domain.half_coset);
        defer prover.poly.twiddles.deinitM31(allocator, &base_tree);
        var extended_tree = try prover.poly.twiddles.precomputeM31(allocator, extended_domain.half_coset);
        defer prover.poly.twiddles.deinitM31(allocator, &extended_tree);
        const base_twiddles = prover.poly.twiddles.TwiddleTree([]const M31).init(
            base_tree.root_coset,
            base_tree.twiddles,
            base_tree.itwiddles,
        );
        const extended_twiddles = prover.poly.twiddles.TwiddleTree([]const M31).init(
            extended_tree.root_coset,
            extended_tree.twiddles,
            extended_tree.itwiddles,
        );

        coefficient.* = try allocator.dupe(M31, column.values);
        initialized_coefficients += 1;
        var coefficient_slices = [_][]M31{coefficient.*};
        try prover.poly.circle.poly.interpolateBuffersWithTwiddles(
            &coefficient_slices,
            base_domain,
            base_twiddles,
        );

        const values = try allocator.alloc(M31, extended_domain.size());
        @memcpy(values[0..coefficient.len], coefficient.*);
        @memset(values[coefficient.len..], M31.zero());
        var evaluation_slices = [_][]M31{values};
        try prover.poly.circle.poly.evaluateBuffersWithTwiddles(
            &evaluation_slices,
            extended_domain,
            extended_twiddles,
        );
        evaluation.* = .{ .log_size = column.log_size + 1, .values = values };
        initialized_evaluations += 1;
    }
    return .{ .columns = expected, .coefficients = coefficients };
}

fn deinitPrepared(allocator: std.mem.Allocator, prepared: anytype) void {
    var owned = prepared;
    owned.commitment.deinit(allocator);
    if (owned.column_backing_buffers) |buffers| {
        allocator.free(owned.columns);
        for (buffers) |buffer| allocator.free(buffer);
        allocator.free(buffers);
    } else {
        for (owned.columns) |column| allocator.free(@constCast(column.values));
        allocator.free(owned.columns);
    }
    for (owned.coefficients) |*coefficient| coefficient.deinit(allocator);
    allocator.free(owned.coefficients);
    if (owned.coefficient_backing_buffers) |buffers| {
        for (buffers) |buffer| allocator.free(buffer);
        allocator.free(buffers);
    }
    if (owned.backing_teardown) |*token| token.deinit();
}

test "metal: backed heterogeneous commit has one submit, one wait, and canonical root" {
    const runtime_was_initialized = MetalBackend.runtimeLifecycleSnapshot().initialized;
    try MetalBackend.initializeRuntime(std.testing.allocator, .source_jit);
    defer if (!runtime_was_initialized) MetalBackend.shutdown() catch unreachable;
    const allocator = std.heap.page_allocator;
    const resources_before = MetalBackend.runtimeLifecycleSnapshot().live_resident_resources;
    const reserved_bytes_before = commit_memory.liveBytes();
    const telemetry_before = try MetalBackend.telemetrySnapshot();
    ownership_testing.setForceHeterogeneousAdmission(true);
    defer ownership_testing.setForceHeterogeneousAdmission(false);

    var input = try makeBackedColumns(allocator);
    defer input.deinit(allocator);
    const source_arena_address = @intFromPtr(input.backings[0].ptr);
    const source_arena_bytes = @as(u64, @intCast(input.backings[0].len)) * @sizeOf(M31);
    var expected = try expectedExtension(std.testing.allocator, input.columns);
    defer expected.deinit(std.testing.allocator);
    var twiddle_source = TwiddleSource.initOwned(allocator);
    defer twiddle_source.deinit(allocator);

    const result = MetalBackend.prepareAndCommitOwned(
        Hasher,
        allocator,
        input.columns,
        1,
        .always,
        &twiddle_source,
        input.backings,
        .materialized,
    ) catch |err| {
        return err;
    };
    var prepared = result orelse return error.HeterogeneousCommitDeclined;
    input.moved = true;
    var prepared_live = true;
    defer if (prepared_live) deinitPrepared(allocator, prepared);

    for (prepared.columns, prepared.coefficients, expected.columns, expected.coefficients) |
        actual,
        actual_coefficient,
        expected_evaluation,
        expected_coefficient,
    | {
        try std.testing.expectEqual(expected_evaluation.log_size, actual.log_size);
        try std.testing.expectEqualSlices(M31, expected_evaluation.values, actual.values);
        try std.testing.expectEqualSlices(M31, expected_coefficient, actual_coefficient.coefficients());
    }
    const expected_refs = try std.testing.allocator.alloc([]const M31, expected.columns.len);
    defer std.testing.allocator.free(expected_refs);
    for (expected.columns, expected_refs) |column, *values| values.* = column.values;
    var expected_tree = try prover.vcs_lifted.prover.MerkleProverLifted(Hasher).commit(
        std.testing.allocator,
        expected_refs,
    );
    defer expected_tree.deinit(std.testing.allocator);
    const expected_root = expected_tree.root();
    const actual_root = prepared.commitment.root();
    try std.testing.expectEqualSlices(u8, &expected_root, &actual_root);

    const actual_refs = try std.testing.allocator.alloc([]const M31, prepared.columns.len);
    defer std.testing.allocator.free(actual_refs);
    for (prepared.columns, actual_refs) |column, *values| values.* = column.values;
    const query_positions = [_]usize{ 0, 1, 3, 17, 255, 511 };
    var expected_decommitment = try expected_tree.decommit(
        std.testing.allocator,
        &query_positions,
        expected_refs,
    );
    defer expected_decommitment.deinit(std.testing.allocator);
    var actual_decommitment = try prepared.commitment.decommit(
        std.testing.allocator,
        &query_positions,
        actual_refs,
    );
    defer actual_decommitment.deinit(std.testing.allocator);
    for (expected_decommitment.queried_values, actual_decommitment.queried_values) |expected_values, actual_values|
        try std.testing.expectEqualSlices(M31, expected_values, actual_values);
    try std.testing.expectEqualSlices(
        Hasher.Hash,
        expected_decommitment.decommitment.decommitment.hash_witness,
        actual_decommitment.decommitment.decommitment.hash_witness,
    );
    try std.testing.expectEqual(
        expected_decommitment.decommitment.aux.all_node_values.len,
        actual_decommitment.decommitment.aux.all_node_values.len,
    );
    for (
        expected_decommitment.decommitment.aux.all_node_values,
        actual_decommitment.decommitment.aux.all_node_values,
    ) |expected_layer, actual_layer| {
        try std.testing.expectEqual(expected_layer.len, actual_layer.len);
        for (expected_layer, actual_layer) |expected_node, actual_node| {
            try std.testing.expectEqual(expected_node.index, actual_node.index);
            try std.testing.expectEqualSlices(u8, &expected_node.hash, &actual_node.hash);
        }
    }

    const queried_value_refs = try std.testing.allocator.alloc(
        []const M31,
        actual_decommitment.queried_values.len,
    );
    defer std.testing.allocator.free(queried_value_refs);
    for (actual_decommitment.queried_values, queried_value_refs) |values, *reference|
        reference.* = values;
    const column_logs = try std.testing.allocator.alloc(u32, prepared.columns.len);
    defer std.testing.allocator.free(column_logs);
    for (prepared.columns, column_logs) |column, *log_size| log_size.* = column.log_size;
    var verifier = try core.vcs_lifted.verifier.MerkleVerifierLifted(Hasher).init(
        std.testing.allocator,
        actual_root,
        column_logs,
    );
    defer verifier.deinit(std.testing.allocator);
    try verifier.verify(
        std.testing.allocator,
        &query_positions,
        queried_value_refs,
        actual_decommitment.decommitment.decommitment,
    );

    const telemetry_after = try MetalBackend.telemetrySnapshot();
    const delta = MetalBackend.TelemetrySnapshot.delta(telemetry_after, telemetry_before).counters;
    try std.testing.expectEqual(@as(u64, 1), delta.metal_heterogeneous_commit_epochs);
    try std.testing.expectEqual(@as(u64, 1), delta.metal_heterogeneous_commit_command_buffers);
    try std.testing.expectEqual(@as(u64, 1), delta.metal_heterogeneous_commit_waits);
    try std.testing.expect(delta.metal_heterogeneous_commit_dispatches > 0);
    const committed_arena_bytes = @as(u64, @intCast(prepared.column_backing_buffers.?[0].len)) *
        @sizeOf(M31);
    try std.testing.expectEqual(
        committed_arena_bytes,
        delta.metal_heterogeneous_commit_arena_bytes,
    );
    try std.testing.expectEqual(@as(u64, 0), delta.metal_commit_source_arena_aliases);
    if (@intFromPtr(prepared.column_backing_buffers.?[0].ptr) == source_arena_address) {
        try std.testing.expectEqual(@as(u64, 0), delta.metal_heterogeneous_commit_resize_moved_bytes);
    } else {
        try std.testing.expectEqual(
            source_arena_bytes,
            delta.metal_heterogeneous_commit_resize_moved_bytes,
        );
    }
    var expected_staging_bytes: u64 = 0;
    for (expected.columns) |column|
        expected_staging_bytes += @as(u64, @intCast(column.values.len)) * @sizeOf(M31);
    try std.testing.expectEqual(
        expected_staging_bytes,
        delta.metal_heterogeneous_commit_staging_bytes_avoided,
    );
    try std.testing.expectEqual(
        reserved_bytes_before + committed_arena_bytes,
        commit_memory.liveBytes(),
    );

    deinitPrepared(allocator, prepared);
    prepared_live = false;
    try std.testing.expectEqual(reserved_bytes_before, commit_memory.liveBytes());
    try std.testing.expectEqual(
        resources_before,
        MetalBackend.runtimeLifecycleSnapshot().live_resident_resources,
    );
}

test "metal: heterogeneous precommit authenticates exact transform and Merkle work" {
    const runtime_was_initialized = MetalBackend.runtimeLifecycleSnapshot().initialized;
    try MetalBackend.initializeRuntime(std.testing.allocator, .source_jit);
    defer if (!runtime_was_initialized) MetalBackend.shutdown() catch unreachable;
    const allocator = std.heap.page_allocator;
    ownership_testing.setForceHeterogeneousAdmission(true);
    defer ownership_testing.setForceHeterogeneousAdmission(false);

    var input = try makeBackedColumns(allocator);
    defer input.deinit(allocator);
    var twiddle_source = TwiddleSource.initOwned(allocator);
    defer twiddle_source.deinit(allocator);
    var recorder: precommitted_work.Recorder = .{};

    const result = try MetalBackend.prepareAndCommitOwnedWithWorkRecorder(
        Hasher,
        allocator,
        input.columns,
        1,
        .always,
        &twiddle_source,
        input.backings,
        .materialized,
        &recorder,
    );
    const prepared = result orelse return error.HeterogeneousCommitDeclined;
    input.moved = true;
    defer deinitPrepared(allocator, prepared);

    var receipt_builder: precommitted_work.HeterogeneousReceipt = .{};
    try receipt_builder.addGroup(8, 2);
    try receipt_builder.addGroup(6, 2);
    try receipt_builder.addGroup(7, 1);
    const expected = try receipt_builder.finish(@as(u64, 1) << 9);
    try std.testing.expect(!recorder.incomplete);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.planned_sites[@intFromEnum(work_profile.Site.column_combined_fft)],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.column_combined_fft)],
    );
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.completed_sites[@intFromEnum(work_profile.Site.commitment_tree_merkle)],
    );
    try std.testing.expectEqual(expected.transform.fft_butterflies, recorder.counters.fft_butterflies);
    try std.testing.expectEqual(expected.merkle_compressions, recorder.counters.merkle_compressions);
}

test "metal: uniform owned and polynomial precommits return device receipts" {
    const runtime_was_initialized = MetalBackend.runtimeLifecycleSnapshot().initialized;
    try MetalBackend.initializeRuntime(std.testing.allocator, .source_jit);
    defer if (!runtime_was_initialized) MetalBackend.shutdown() catch unreachable;
    const allocator = std.heap.page_allocator;
    const log_size: u32 = 16;
    const column_count: usize = 8;
    const row_count = @as(usize, 1) << @intCast(log_size);
    var twiddle_source = TwiddleSource.initOwned(allocator);
    defer twiddle_source.deinit(allocator);

    const owned_columns = try allocator.alloc(ColumnEvaluation, column_count);
    var initialized_columns: usize = 0;
    var columns_consumed = false;
    defer if (!columns_consumed) {
        for (owned_columns[0..initialized_columns]) |column| allocator.free(@constCast(column.values));
        allocator.free(owned_columns);
    };
    for (owned_columns, 0..) |*column, column_index| {
        const values = try allocator.alloc(M31, row_count);
        for (values, 0..) |*value, row|
            value.* = M31.fromCanonical(@intCast((column_index * 313 + row * 17 + 11) % 0x7fffffff));
        column.* = .{ .log_size = log_size, .values = values };
        initialized_columns += 1;
    }
    var owned_recorder: precommitted_work.Recorder = .{};
    const owned_result = try MetalBackend.prepareAndCommitOwnedWithWorkRecorder(
        Hasher,
        allocator,
        owned_columns,
        1,
        .always,
        &twiddle_source,
        null,
        .materialized,
        &owned_recorder,
    );
    const owned_prepared = owned_result orelse return error.UniformCommitDeclined;
    columns_consumed = true;
    defer deinitPrepared(allocator, owned_prepared);
    const expected_owned = try precommitted_work.Receipt.fromUniformOwned(16, 17, 8, .{
        .normalization_batch_count = 1,
        .forward_skipped_layers = 1,
        .merkle_compressions = (@as(u64, 1) << 17) - 1,
    });
    try std.testing.expect(!owned_recorder.incomplete);
    try std.testing.expectEqual(
        expected_owned.transform.fft_butterflies,
        owned_recorder.counters.fft_butterflies,
    );
    try std.testing.expectEqual(
        expected_owned.merkle_compressions,
        owned_recorder.counters.merkle_compressions,
    );

    const polys = try allocator.alloc(CircleCoefficients, column_count);
    var initialized_polys: usize = 0;
    defer {
        for (polys[0..initialized_polys]) |*poly| poly.deinit(allocator);
        allocator.free(polys);
    }
    for (polys, 0..) |*poly, column_index| {
        const coefficients = try allocator.alloc(M31, row_count);
        for (coefficients, 0..) |*value, row|
            value.* = M31.fromCanonical(@intCast((column_index * 659 + row * 19 + 23) % 0x7fffffff));
        poly.* = try CircleCoefficients.initOwned(coefficients);
        initialized_polys += 1;
    }
    var polynomial_recorder: precommitted_work.Recorder = .{};
    const polynomial_result = try MetalBackend.prepareAndCommitPolysWithWorkRecorder(
        Hasher,
        allocator,
        polys,
        1,
        .always,
        &twiddle_source,
        &polynomial_recorder,
    );
    const polynomial_prepared = polynomial_result orelse return error.UniformCommitDeclined;
    defer deinitPrepared(allocator, polynomial_prepared);
    const expected_polynomial = try precommitted_work.Receipt.fromUniformPolynomials(17, 8, .{
        .normalization_batch_count = 0,
        .forward_skipped_layers = 1,
        .merkle_compressions = (@as(u64, 1) << 17) - 1,
    });
    try std.testing.expect(!polynomial_recorder.incomplete);
    try std.testing.expectEqual(
        expected_polynomial.transform.fft_butterflies,
        polynomial_recorder.counters.fft_butterflies,
    );
    try std.testing.expectEqual(
        expected_polynomial.merkle_compressions,
        polynomial_recorder.counters.merkle_compressions,
    );
}

test "metal: profiled heterogeneous post-dispatch failure remains incomplete" {
    const runtime_was_initialized = MetalBackend.runtimeLifecycleSnapshot().initialized;
    try MetalBackend.initializeRuntime(std.testing.allocator, .source_jit);
    defer if (!runtime_was_initialized) MetalBackend.shutdown() catch unreachable;
    const allocator = std.heap.page_allocator;
    ownership_testing.setForceHeterogeneousAdmission(true);
    defer ownership_testing.setForceHeterogeneousAdmission(false);

    var input = try makeBackedColumns(allocator);
    defer input.deinit(allocator);
    var twiddle_source = TwiddleSource.initOwned(allocator);
    defer twiddle_source.deinit(allocator);
    var recorder: precommitted_work.Recorder = .{};
    ownership_testing.armHeterogeneousFailure(.after_wait);
    defer ownership_testing.clearHeterogeneousFailure();

    try std.testing.expectError(
        error.InjectedHeterogeneousCommitFailure,
        MetalBackend.prepareAndCommitOwnedWithWorkRecorder(
            Hasher,
            allocator,
            input.columns,
            1,
            .always,
            &twiddle_source,
            input.backings,
            .materialized,
            &recorder,
        ),
    );
    try std.testing.expect(recorder.incomplete);
    try std.testing.expectEqual(
        @as(u64, 1),
        recorder.planned_sites[@intFromEnum(work_profile.Site.column_combined_fft)],
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        recorder.completed_sites[@intFromEnum(work_profile.Site.column_combined_fft)],
    );
    try std.testing.expectEqual(
        @as(u64, 0),
        recorder.completed_sites[@intFromEnum(work_profile.Site.commitment_tree_merkle)],
    );
}

test "metal: post-transfer failure releases heterogeneous arena and resident tree" {
    const runtime_was_initialized = MetalBackend.runtimeLifecycleSnapshot().initialized;
    try MetalBackend.initializeRuntime(std.testing.allocator, .source_jit);
    defer if (!runtime_was_initialized) MetalBackend.shutdown() catch unreachable;
    const allocator = std.heap.page_allocator;
    const resources_before = MetalBackend.runtimeLifecycleSnapshot().live_resident_resources;
    const reserved_bytes_before = commit_memory.liveBytes();
    const telemetry_before = try MetalBackend.telemetrySnapshot();
    ownership_testing.setForceHeterogeneousAdmission(true);
    defer ownership_testing.setForceHeterogeneousAdmission(false);

    var input = try makeBackedColumns(allocator);
    defer input.deinit(allocator);
    const config = core.pcs.PcsConfig{
        .pow_bits = 0,
        .fri_config = try core.fri.FriConfig.init(0, 1, 3),
    };
    var scheme = try engine_mod.MetalProverEngine.init(allocator, config);
    defer engine_mod.MetalProverEngine.deinit(&scheme, allocator);
    var channel = core.channel.blake2s.Blake2sChannel{};
    MetalBackend.armOwnershipTransferFailureForTesting();
    defer MetalBackend.clearOwnershipTransferFailureForTesting();
    input.moved = true;
    try std.testing.expectError(
        error.InjectedOwnershipTransferFailure,
        engine_mod.MetalProverEngine.commitWithBacking(
            &scheme,
            allocator,
            input.columns,
            input.backings,
            null,
            &channel,
        ),
    );
    const telemetry_after = try MetalBackend.telemetrySnapshot();
    const delta = MetalBackend.TelemetrySnapshot.delta(telemetry_after, telemetry_before).counters;
    try std.testing.expectEqual(@as(u64, 1), delta.metal_heterogeneous_commit_epochs);
    try std.testing.expectEqual(@as(u64, 1), delta.metal_heterogeneous_commit_command_buffers);
    try std.testing.expectEqual(@as(u64, 1), delta.metal_heterogeneous_commit_waits);
    try std.testing.expectEqual(
        resources_before,
        MetalBackend.runtimeLifecycleSnapshot().live_resident_resources,
    );
    try std.testing.expectEqual(reserved_bytes_before, commit_memory.liveBytes());
}

test "metal: heterogeneous failures release resized arena, aliases, tree, and reservation" {
    const runtime_was_initialized = MetalBackend.runtimeLifecycleSnapshot().initialized;
    try MetalBackend.initializeRuntime(std.testing.allocator, .source_jit);
    defer if (!runtime_was_initialized) MetalBackend.shutdown() catch unreachable;
    const allocator = std.heap.page_allocator;
    const resources_before = MetalBackend.runtimeLifecycleSnapshot().live_resident_resources;
    const reserved_bytes_before = commit_memory.liveBytes();
    ownership_testing.setForceHeterogeneousAdmission(true);
    defer ownership_testing.setForceHeterogeneousAdmission(false);

    const failure_points = [_]ownership_testing.HeterogeneousFailurePoint{
        .after_resize,
        .after_alias,
        .after_wait,
        .after_tree_adoption,
        .during_descriptor_initialization,
    };
    for (failure_points) |failure_point| {
        {
            var input = try makeBackedColumns(allocator);
            defer input.deinit(allocator);
            var twiddle_source = TwiddleSource.initOwned(allocator);
            defer twiddle_source.deinit(allocator);
            ownership_testing.armHeterogeneousFailure(failure_point);
            defer ownership_testing.clearHeterogeneousFailure();
            try std.testing.expectError(
                error.InjectedHeterogeneousCommitFailure,
                MetalBackend.prepareAndCommitOwned(
                    Hasher,
                    allocator,
                    input.columns,
                    1,
                    .always,
                    &twiddle_source,
                    input.backings,
                    .materialized,
                ),
            );
        }
        try std.testing.expectEqual(reserved_bytes_before, commit_memory.liveBytes());
        try std.testing.expectEqual(
            resources_before,
            MetalBackend.runtimeLifecycleSnapshot().live_resident_resources,
        );
    }
}
