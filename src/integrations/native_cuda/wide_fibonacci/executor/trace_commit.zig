//! Resident main-trace generation, commitment, and transcript prefix.

const std = @import("std");
const stages = @import("../../../../backends/cuda/runtime/stages/mod.zig");
const runtime_error = @import("../../../../backends/cuda/runtime/error.zig");
const commit_tree = @import("../commit_tree.zig");
const ingress = @import("ingress.zig");
const plan_mod = @import("../plan.zig");
const bindings = @import("../resident_bindings/mod.zig");
const proof_assembly = @import("proof_assembly.zig");

const NativeOps = struct {
    const Trace = stages.trace.Native;
    const Transform = stages.transform.Native;
    const Commitment = stages.commitment.Native;
    const Transcript = stages.transcript.Native;
};

pub fn generate(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
) !void {
    return generateWith(NativeOps, transaction, prepared, views);
}

pub fn commit(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
) !void {
    return commitWith(NativeOps, transaction, prepared, views);
}

fn generateWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
) !void {
    const geometry = prepared.logical.geometry;
    try Ops.Trace.wideFibonacci(
        transaction.proofSession(),
        views.trace.main_coefficients,
        try count(geometry.trace_rows),
        geometry.statement.log_n_rows,
    );
}

fn commitWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
) !void {
    const geometry = prepared.logical.geometry;
    const trace_log = geometry.statement.log_n_rows;
    const commitment_log = geometry.queryLogSize();
    const session = transaction.proofSession();

    try Ops.Transcript.initialize(
        session,
        .trace_commit,
        views.transcript.state,
        null,
        null,
        prepared.transcript.initialChain(),
    );
    try mixStatic(
        Ops.Transcript,
        session,
        prepared,
        views,
        0,
        try ingress.configSource(views),
        true,
    );
    try mixStatic(
        Ops.Transcript,
        session,
        prepared,
        views,
        1,
        try ingress.emptyRootSource(views),
        false,
    );
    try proof_assembly.captureStaticTraceRoot(
        session,
        views,
        0,
        try ingress.emptyRootSource(views),
    );

    try Ops.Transform.inverseCompact(
        session,
        .trace_commit,
        views.trace.main_coefficients,
        views.trace.main_coefficients,
        trace_log,
        views.trace.twiddles_inverse,
    );
    const main_logs = try views.trace.coefficient_log_sizes.sub(
        0,
        geometry.main_columns,
    );
    try Ops.Transform.extend(
        session,
        .trace_commit,
        views.trace.main_coefficients,
        main_logs,
        views.trace.main_evaluations,
        commitment_log,
        views.trace.twiddles_forward,
        false,
    );

    const opening = prepared.decommit.trace_trees[0];
    const layers = retainedLayers(
        prepared,
        opening.retained_layer_offset,
        opening.retained_layer_count,
    );
    const Builder = commit_tree.BuilderFor(Ops.Commitment);
    const main_root = try Builder.baseField(
        session,
        .trace_commit,
        try count(geometry.commitment_rows),
        views.trace.main_evaluations,
        views.trace.main_merkle_hashes,
        layers,
    );
    if (main_root.len != 1) return error.InvalidKernelDescriptor;
    try proof_assembly.captureTraceRoot(session, views, 1, main_root);
    try mixStatic(
        Ops.Transcript,
        session,
        prepared,
        views,
        2,
        try main_root.cast(u32),
        false,
    );
    try mixStatic(
        Ops.Transcript,
        session,
        prepared,
        views,
        3,
        try ingress.statementSource(views),
        false,
    );
}

fn mixStatic(
    comptime Transcript: type,
    session: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
    step: u32,
    source: stages.common.Words,
    validate_m31: bool,
) !void {
    try requirePrefixOperation(prepared, step);
    const scheduled = try prepared.transcript.boundary(step);
    const snapshot = try views.transcript.input_snapshot.sub(0, source.len);
    try Transcript.mixWords(
        session,
        .trace_commit,
        views.transcript.state,
        .{
            .expected_step = scheduled.expected_step,
            .expected_chain = scheduled.expected_chain,
            .next_chain = scheduled.next_chain,
            .snapshot = views.transcript.boundary_snapshot,
        },
        source,
        validate_m31,
        snapshot,
    );
}

fn requirePrefixOperation(
    prepared: *const plan_mod.PreparedPlan,
    step: u32,
) !void {
    const operation = try prepared.transcript.operation(step);
    switch (step) {
        0 => switch (operation) {
            .mix_pcs_config => {},
            else => return error.InvalidKernelDescriptor,
        },
        1 => switch (operation) {
            .mix_preprocessed_root => {},
            else => return error.InvalidKernelDescriptor,
        },
        2 => switch (operation) {
            .mix_main_root => {},
            else => return error.InvalidKernelDescriptor,
        },
        3 => switch (operation) {
            .mix_statement => {},
            else => return error.InvalidKernelDescriptor,
        },
        else => return error.InvalidKernelDescriptor,
    }
}

fn retainedLayers(
    prepared: *const plan_mod.PreparedPlan,
    offset: usize,
    layer_count: usize,
) []const @import("../../../../backends/cuda/abi/field.zig").MerkleLayerDescriptor {
    return prepared.decommit.retained_layers[offset..][0..layer_count];
}

fn count(value: usize) runtime_error.Error!u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

test "trace executor follows raw upstream prefix without host escape" {
    const support = @import("trace/test_support.zig");

    const Calls = struct {
        var trace: usize = 0;
        var inverse: usize = 0;
        var extend: usize = 0;
        var initialize: usize = 0;
        var mix_count: usize = 0;
        var mix_lengths: [4]usize = undefined;
        var mix_validate: [4]bool = undefined;
        var contiguous_leaves: usize = 0;
        var merkle_layers: usize = 0;
        var device_copies: usize = 0;

        fn reset() void {
            trace = 0;
            inverse = 0;
            extend = 0;
            initialize = 0;
            mix_count = 0;
            contiguous_leaves = 0;
            merkle_layers = 0;
            device_copies = 0;
        }
    };
    const FakeOps = struct {
        const Trace = struct {
            pub fn wideFibonacci(
                _: anytype,
                matrix: stages.common.WordMatrix,
                rows: u32,
                log_n_rows: u32,
            ) !void {
                try std.testing.expectEqual(
                    @as(usize, rows),
                    matrix.column_stride_words,
                );
                try std.testing.expectEqual(
                    rows,
                    @as(u32, 1) << @intCast(log_n_rows),
                );
                Calls.trace += 1;
            }
        };
        const Transform = struct {
            pub fn inverseCompact(
                _: anytype,
                stage: anytype,
                input: stages.common.WordMatrix,
                output: stages.common.WordMatrix,
                _: u32,
                _: stages.common.Words,
            ) !void {
                try std.testing.expectEqual(.trace_commit, stage);
                try std.testing.expectEqual(
                    input.storage.address,
                    output.storage.address,
                );
                Calls.inverse += 1;
            }

            pub fn extend(
                _: anytype,
                stage: anytype,
                coefficients: stages.common.WordMatrix,
                logs: stages.common.Words,
                evaluations: stages.common.WordMatrix,
                _: u32,
                _: stages.common.Words,
                before_final_circle: bool,
            ) !void {
                try std.testing.expectEqual(.trace_commit, stage);
                try std.testing.expect(!before_final_circle);
                try std.testing.expectEqual(
                    coefficients.storage.len /
                        coefficients.column_stride_words,
                    logs.len,
                );
                try std.testing.expectEqual(
                    logs.len,
                    evaluations.storage.len /
                        evaluations.column_stride_words,
                );
                Calls.extend += 1;
            }
        };
        const Commitment = struct {
            pub fn contiguousLeaves(
                _: anytype,
                _: anytype,
                _: u32,
                _: anytype,
                _: anytype,
            ) !void {
                Calls.contiguous_leaves += 1;
            }
            pub fn layer(
                _: anytype,
                _: anytype,
                previous: anytype,
                output: anytype,
                four_levels: bool,
            ) !void {
                try std.testing.expect(!four_levels);
                try std.testing.expectEqual(previous.len / 2, output.len);
                Calls.merkle_layers += 1;
            }
        };
        const Transcript = struct {
            pub fn initialize(
                _: anytype,
                stage: anytype,
                _: anytype,
                seed: anytype,
                seed_snapshot: anytype,
                _: u64,
            ) !void {
                try std.testing.expectEqual(.trace_commit, stage);
                try std.testing.expect(seed == null);
                try std.testing.expect(seed_snapshot == null);
                Calls.initialize += 1;
            }
            pub fn mixWords(
                _: anytype,
                stage: anytype,
                _: anytype,
                _: anytype,
                source: stages.common.Words,
                validate_m31: bool,
                snapshot: stages.common.Words,
            ) !void {
                try std.testing.expectEqual(.trace_commit, stage);
                try std.testing.expectEqual(source.len, snapshot.len);
                Calls.mix_lengths[Calls.mix_count] = source.len;
                Calls.mix_validate[Calls.mix_count] = validate_m31;
                Calls.mix_count += 1;
            }
        };
    };
    const FakeContext = struct {
        pub fn copyDeviceSlice(
            _: *@This(),
            comptime F: type,
            destination: anytype,
            source: anytype,
        ) runtime_error.Error!void {
            if (F != u32 or destination.len != source.len)
                return error.InvalidKernelDescriptor;
            Calls.device_copies += 1;
        }
    };
    const FakeTransaction = struct {
        session: struct { context: FakeContext = .{} } = .{},
    };

    const allocator = std.testing.allocator;
    const geometry = try support.geometry(5, 8);
    var prepared = try plan_mod.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);
    const provider = support.Provider{ .prepared = &prepared };
    const views = try bindings.bind(&provider, &prepared);
    var transaction = FakeTransaction{};
    Calls.reset();

    try generateWith(FakeOps, &transaction, &prepared, &views);
    try commitWith(FakeOps, &transaction, &prepared, &views);

    try std.testing.expectEqual(@as(usize, 1), Calls.trace);
    try std.testing.expectEqual(@as(usize, 1), Calls.inverse);
    try std.testing.expectEqual(@as(usize, 1), Calls.extend);
    try std.testing.expectEqual(@as(usize, 1), Calls.initialize);
    try std.testing.expectEqual(@as(usize, 4), Calls.mix_count);
    try std.testing.expectEqualSlices(
        usize,
        &.{ 4, 8, 8, 2 },
        &Calls.mix_lengths,
    );
    try std.testing.expectEqualSlices(
        bool,
        &.{ true, false, false, false },
        &Calls.mix_validate,
    );
    try std.testing.expectEqual(@as(usize, 1), Calls.contiguous_leaves);
    try std.testing.expectEqual(@as(usize, 2), Calls.device_copies);
    try std.testing.expectEqual(
        @as(usize, geometry.queryLogSize()),
        Calls.merkle_layers,
    );
}
