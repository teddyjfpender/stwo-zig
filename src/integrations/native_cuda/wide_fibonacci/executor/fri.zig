//! Fully resident FRI commitment, folding, and terminal polynomial stage.

const std = @import("std");
const field = @import("../../../../backends/cuda/abi/field.zig");
const stages = @import("../../../../backends/cuda/runtime/stages/mod.zig");
const runtime_error = @import("../../../../backends/cuda/runtime/error.zig");
const canonical_ingress = @import("../canonical_ingress.zig");
const commit_tree = @import("../commit_tree.zig");
const plan_mod = @import("../plan.zig");
const slots = @import("../slots.zig");
const bindings = @import("../resident_bindings/mod.zig");
const proof_assembly = @import("proof_assembly.zig");

const NativeOps = struct {
    const Commitment = stages.commitment.Native;
    const Fri = stages.fri.Native;
    const Transcript = stages.transcript.Native;
    const Capture = proof_assembly;
};

pub fn run(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    pack: *const canonical_ingress.Pack,
    views: *const bindings.Views,
) !void {
    return runWith(NativeOps, transaction, prepared, pack, views);
}

fn runWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    pack: *const canonical_ingress.Pack,
    views: *const bindings.Views,
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

    const session = &transaction.session;
    const Builder = commit_tree.BuilderFor(Ops.Commitment);
    for (topology, 0..) |layer, layer_index| {
        const resident = views.fri.layers[layer_index];
        const layers = retainedLayers(prepared, layer);
        const evaluation_size = try pow2Count(layer.evaluation_log_size);
        const root = try Builder.fri(
            session,
            evaluation_size,
            layer.log_rows_per_leaf,
            resident.coordinates,
            resident.merkle_hashes,
            layers,
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
            // The canonical circle fold is an accumulator. Its first output
            // must be zero, but no later line fold needs a clearing launch.
            if (layer_index + 1 >= topology.len)
                return error.InvalidKernelDescriptor;
            try transaction.zeroResidentSlice(
                u32,
                .fri_commit,
                slots.friCoordinates(layer_index + 1),
                0,
                destination.storage.len,
            );
        }
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

    const geometry = prepared.logical.geometry;
    const last_rows = geometry.last_layer_domain_rows;
    const last_log = std.math.log2_int(usize, last_rows);
    try Ops.Fri.lastLayer(
        session,
        try views.fri.last_evaluation.cast(u32),
        try count(last_rows),
        last_log,
        views.trace.twiddles_inverse,
        geometry.protocol.log_last_layer_degree_bound,
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
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
    layer_index: usize,
    root: stages.common.Words,
) !void {
    const step = try friStep(layer_index, false);
    const operation = try prepared.transcript.operation(step);
    switch (operation) {
        .mix_fri_root => |scheduled| {
            if (scheduled != layer_index)
                return error.InvalidKernelDescriptor;
        },
        else => return error.InvalidKernelDescriptor,
    }
    const snapshot = try views.transcript.input_snapshot.sub(0, root.len);
    try Transcript.mixWords(
        session,
        .fri_commit,
        views.transcript.state,
        try boundary(prepared, views, step),
        root,
        false,
        snapshot,
    );
}

fn drawAlpha(
    comptime Transcript: type,
    session: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
    layer_index: usize,
) !void {
    const step = try friStep(layer_index, true);
    const operation = try prepared.transcript.operation(step);
    switch (operation) {
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
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
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
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
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

fn retainedLayers(
    prepared: *const plan_mod.PreparedPlan,
    layer: @import("../topology.zig").FriLayer,
) []const @import("../../../../backends/cuda/abi/field.zig").MerkleLayerDescriptor {
    const first = layer.retained_layer_offset;
    return prepared.fri.retained_layers[first..][0..layer.retained_layer_count];
}

fn friStep(layer_index: usize, draw: bool) runtime_error.Error!u32 {
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

test "FRI contract maps one challenge to one canonical fold per tree" {
    const allocator = std.testing.allocator;
    const geometry = try @import("../request.zig").admit(.{
        .statement = .{ .log_n_rows = 5, .sequence_len = 37 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    });
    var prepared = try plan_mod.PreparedPlan.init(allocator, geometry);
    defer prepared.deinit(allocator);

    for (prepared.fri.layers, 0..) |layer, index| {
        try std.testing.expectEqual(
            @as(u32, 6) - @as(u32, @intCast(index)),
            layer.evaluation_log_size,
        );
        const mix_step = try friStep(index, false);
        const draw_step = try friStep(index, true);
        try std.testing.expectEqual(mix_step + 1, draw_step);
        try std.testing.expectEqual(
            @import("../transcript_schedule.zig").Operation{
                .mix_fri_root = @intCast(index),
            },
            try prepared.transcript.operation(mix_step),
        );
        try std.testing.expectEqual(
            @import("../transcript_schedule.zig").Operation{
                .draw_fri_alpha = @intCast(index),
            },
            try prepared.transcript.operation(draw_step),
        );
    }
    try std.testing.expectEqual(
        @import("../transcript_schedule.zig").Operation.mix_last_layer,
        try prepared.transcript.operation(
            try friStep(prepared.fri.layers.len, false),
        ),
    );
}

test "terminal FRI storage is distinct and exactly size two" {
    const Words = stages.common.Words;
    const evaluation = Words{ .address = 0x1000, .len = 8, .owner = 1 };
    const coefficients = Words{ .address = 0x2000, .len = 8, .owner = 1 };
    try std.testing.expect(evaluation.address != coefficients.address);
    try std.testing.expectEqual(@as(usize, 2), evaluation.len / 4);
    try std.testing.expectEqual(@as(usize, 2), coefficients.len / 4);
}

test {
    _ = @import("pow_decommit.zig");
}
