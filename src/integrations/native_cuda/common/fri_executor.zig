//! AIR-neutral resident FRI commitment, folding, and terminal stage.

const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const stages = @import("../../../backends/cuda/runtime/stages/mod.zig");
const runtime_error = @import("../../../backends/cuda/runtime/error.zig");
const commit_tree = @import("commit_tree.zig");
const proof_assembly = @import("proof_assembly.zig");
const transcript_schedule = @import("transcript_schedule.zig");

const NativeOps = struct {
    const Commitment = stages.commitment.Native;
    const Fri = stages.fri.Native;
    const Transcript = stages.transcript.Native;
    const Capture = proof_assembly;
};

pub fn run(
    transaction: anytype,
    prepared: anytype,
    pack: anytype,
    views: anytype,
) !void {
    return runWith(NativeOps, transaction, prepared, pack, views);
}

pub fn runWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: anytype,
    pack: anytype,
    views: anytype,
) !void {
    const topology = prepared.fri.layers;
    if (topology.len == 0 or
        topology.len != views.fri.layer_count or
        topology.len != pack.fri_inverse_twiddle_offsets.len or
        topology[topology.len - 1].evaluation_log_size != 2)
    {
        return error.InvalidKernelDescriptor;
    }
    try proof_assembly.validateLayout(prepared, views);

    const session = transaction.proofSession();
    const Builder = commit_tree.BuilderFor(Ops.Commitment);
    for (topology, 0..) |layer, layer_index| {
        const resident = views.fri.layers[layer_index];
        const first_retained = layer.retained_layer_offset;
        const retained = prepared.fri.retained_layers[first_retained..][0..layer.retained_layer_count];
        const evaluation_size = try pow2Count(
            layer.evaluation_log_size,
        );
        const root = if (layer_index == 0)
            try Builder.fri(
                session,
                evaluation_size,
                layer.log_rows_per_leaf,
                resident.coordinates,
                resident.merkle_hashes,
                retained,
            )
        else
            try Builder.friPrehashed(
                session,
                evaluation_size,
                layer.log_rows_per_leaf,
                resident.merkle_hashes,
                retained,
            );
        try Ops.Capture.captureFriRoot(
            session,
            views,
            layer_index,
            root,
        );
        try mixRoot(
            Ops.Transcript,
            session,
            prepared,
            views,
            layer_index,
            try root.cast(u32),
        );
        try drawAlpha(
            Ops.Transcript,
            session,
            prepared,
            views,
            layer_index,
        );

        const destination = if (layer_index + 1 < topology.len)
            views.fri.layers[layer_index + 1].coordinates
        else
            stages.common.WordMatrix{
                .storage = try views.fri.last_evaluation.cast(u32),
                .column_stride_words = prepared.logical.geometry.last_layer_domain_rows,
            };
        const is_circle = layer_index == 0;
        if (is_circle) {
            if (layer_index + 1 >= topology.len)
                return error.InvalidKernelDescriptor;
            try session.zeroResidentSlice(
                u32,
                .fri_commit,
                destination.storage,
            );
        }
        if (layer_index + 1 < topology.len) {
            const next = topology[layer_index + 1];
            if (next.log_rows_per_leaf != 0)
                return error.InvalidKernelDescriptor;
            const next_evaluation_size = try pow2Count(
                next.evaluation_log_size,
            );
            if (next_evaluation_size != evaluation_size / 2)
                return error.InvalidKernelDescriptor;
            const next_first = next.retained_layer_offset;
            const next_retained = prepared.fri.retained_layers[next_first..][0..next.retained_layer_count];
            const next_leaves = try commit_tree.leafHashes(
                next_evaluation_size,
                views.fri.layers[layer_index + 1].merkle_hashes,
                next_retained,
            );
            try Ops.Fri.foldAndHash(
                session,
                is_circle,
                views.trace.twiddles_inverse,
                pack.fri_inverse_twiddle_offsets[layer_index],
                evaluation_size,
                resident.coordinates,
                views.fri.alpha,
                0,
                destination,
                next_leaves,
            );
        } else {
            try Ops.Fri.fold(
                session,
                is_circle,
                views.trace.twiddles_inverse,
                pack.fri_inverse_twiddle_offsets[layer_index],
                evaluation_size,
                resident.coordinates,
                views.fri.alpha,
                0,
                destination,
            );
        }
    }

    const geometry = prepared.logical.geometry;
    const last_rows = geometry.last_layer_domain_rows;
    const last_log = std.math.log2_int(usize, last_rows);
    try Ops.Fri.lastLayer(
        session,
        try views.fri.last_evaluation.cast(u32),
        try count(last_rows),
        last_log,
        views.trace.twiddles_inverse,
        geometry.lastLayerDegreeBound(),
        try views.fri.last_coefficients.cast(u32),
        views.fri.last_degree_error,
        try views.fri.last_transcript.cast(u32),
    );
    try Ops.Capture.captureLastLayer(session, views);
    try mixLastLayer(
        Ops.Transcript,
        session,
        prepared,
        views,
    );
}

fn mixRoot(
    comptime Transcript: type,
    session: anytype,
    prepared: anytype,
    views: anytype,
    layer_index: usize,
    root: stages.common.Words,
) !void {
    const step = try friStep(layer_index, false);
    switch (try prepared.transcript.operation(step)) {
        .mix_fri_root => |scheduled| {
            if (scheduled != layer_index)
                return error.InvalidKernelDescriptor;
        },
        else => return error.InvalidKernelDescriptor,
    }
    try Transcript.mixWords(
        session,
        .fri_commit,
        views.transcript.state,
        try boundary(prepared, views, step),
        root,
        false,
        try views.transcript.input_snapshot.sub(0, root.len),
    );
}

fn drawAlpha(
    comptime Transcript: type,
    session: anytype,
    prepared: anytype,
    views: anytype,
    layer_index: usize,
) !void {
    const step = try friStep(layer_index, true);
    switch (try prepared.transcript.operation(step)) {
        .draw_fri_alpha => |scheduled| {
            if (scheduled != layer_index)
                return error.InvalidKernelDescriptor;
        },
        else => return error.InvalidKernelDescriptor,
    }
    try Transcript.drawSecure(
        session,
        .fri_commit,
        views.transcript.state,
        try boundary(prepared, views, step),
        1,
        max_rejection_rounds,
        views.fri.alpha,
        try (try views.transcript.output_snapshot.sub(0, 4)).cast(
            field.SecureField,
        ),
    );
}

fn mixLastLayer(
    comptime Transcript: type,
    session: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    const step = try friStep(prepared.fri.layers.len, false);
    switch (try prepared.transcript.operation(step)) {
        .mix_last_layer => {},
        else => return error.InvalidKernelDescriptor,
    }
    const source = try views.fri.last_transcript.cast(u32);
    try Transcript.mixWords(
        session,
        .fri_commit,
        views.transcript.state,
        try boundary(prepared, views, step),
        source,
        true,
        try views.transcript.input_snapshot.sub(0, source.len),
    );
}

fn boundary(
    prepared: anytype,
    views: anytype,
    step: u32,
) !stages.transcript.Boundary {
    const scheduled = try prepared.transcript.boundary(step);
    return .{
        .expected_step = scheduled.expected_step,
        .expected_chain = scheduled.expected_chain,
        .next_chain = scheduled.next_chain,
        .snapshot = views.transcript.boundary_snapshot,
    };
}

pub fn friStep(
    layer_index: usize,
    draw: bool,
) runtime_error.Error!u32 {
    const doubled = std.math.mul(usize, layer_index, 2) catch
        return error.SizeOverflow;
    return std.math.cast(
        u32,
        9 + doubled + @as(usize, @intFromBool(draw)),
    ) orelse error.SizeOverflow;
}

fn pow2Count(log_size: u32) runtime_error.Error!u32 {
    if (log_size >= 31) return error.SizeOverflow;
    return @as(u32, 1) << @intCast(log_size);
}

fn count(value: usize) runtime_error.Error!u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

const max_rejection_rounds: u32 = 64;

test "shared FRI schedule maps one challenge to every folded tree" {
    const schedule = try transcript_schedule.Schedule.init(0x1234, 5);
    for (0..5) |index| {
        try std.testing.expectEqual(
            transcript_schedule.Operation{
                .mix_fri_root = @intCast(index),
            },
            try schedule.operation(try friStep(index, false)),
        );
        try std.testing.expectEqual(
            transcript_schedule.Operation{
                .draw_fri_alpha = @intCast(index),
            },
            try schedule.operation(try friStep(index, true)),
        );
    }
    try std.testing.expectEqual(
        transcript_schedule.Operation.mix_last_layer,
        try schedule.operation(try friStep(5, false)),
    );
}

test "terminal FRI storage remains distinct and exactly size two" {
    const Words = stages.common.Words;
    const evaluation = Words{ .address = 0x1000, .len = 8, .owner = 1 };
    const coefficients = Words{ .address = 0x2000, .len = 8, .owner = 1 };
    try std.testing.expect(evaluation.address != coefficients.address);
    try std.testing.expectEqual(@as(usize, 2), evaluation.len / 4);
    try std.testing.expectEqual(@as(usize, 2), coefficients.len / 4);
}
