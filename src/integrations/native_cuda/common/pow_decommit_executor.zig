//! AIR-neutral resident PoW and authenticated opening assembly.

const std = @import("std");
const stages = @import("../../../backends/cuda/runtime/stages/mod.zig");
const runtime_error = @import("../../../backends/cuda/runtime/error.zig");
const proof_assembly = @import("proof_assembly.zig");

const NativeOps = struct {
    const Fri = stages.fri.Native;
    const Transcript = stages.transcript.Native;
    const Decommit = stages.decommit.Native;
    const Capture = proof_assembly;
};

/// Covers the complete nonce lattice admitted by the persistent CUDA kernel.
pub const pow_search_end: u64 = @as(u64, 0x7fff_ffff) << 20;

pub fn executePow(
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    return executePowWith(NativeOps, transaction, prepared, views);
}

pub fn executeDecommit(
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    return executeDecommitWith(NativeOps, transaction, prepared, views);
}

pub fn executePowWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    const session = transaction.proofSession();
    try Ops.Fri.grindPow(
        session,
        views.transcript.state,
        prepared.logical.geometry.powBits(),
        pow_search_end,
        views.pow.prefix_digest,
        views.pow.best_nonce,
        views.pow.completed_blocks,
        views.pow.transcript_nonce,
    );
    try Ops.Capture.capturePowNonce(session, views);

    const step = try powStep(prepared.fri.layers.len);
    switch (try prepared.transcript.operation(step)) {
        .absorb_pow => {},
        else => return error.InvalidKernelDescriptor,
    }
    try Ops.Transcript.absorbPow(
        session,
        views.transcript.state,
        try boundary(prepared, views, step),
        views.pow.transcript_nonce,
        prepared.logical.geometry.powBits(),
        try views.transcript.input_snapshot.sub(0, 2),
    );
}

pub fn executeDecommitWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: anytype,
    views: anytype,
) !void {
    const geometry = prepared.logical.geometry;
    const topology = prepared.decommit;
    if (views.decommit.raw_queries.len != topology.query_count or
        topology.trace_trees.len != views.trace.trees.active().len or
        topology.fri_trees.len != views.fri.layer_count or
        views.proof.decommitment.len != topology.assembly_words)
    {
        return error.InvalidKernelDescriptor;
    }

    const session = transaction.proofSession();
    const query_step = try queryStep(prepared.fri.layers.len);
    switch (try prepared.transcript.operation(query_step)) {
        .draw_queries => {},
        else => return error.InvalidKernelDescriptor,
    }
    try Ops.Transcript.drawQueries(
        session,
        views.transcript.state,
        try boundary(prepared, views, query_step),
        topology.query_log_size,
        views.decommit.raw_queries,
        try views.transcript.output_snapshot.sub(0, topology.query_count),
    );
    try Ops.Decommit.normalizeQueries(
        session,
        views.decommit.raw_queries,
        topology.query_log_size,
        try count(geometry.decommit_tree_count),
        views.decommit.unique_queries,
        views.decommit.counts.unique,
        views.proof.decommitment,
    );

    for (topology.trace_trees) |tree| {
        try openTrace(
            Ops.Decommit,
            session,
            prepared,
            views,
            tree,
        );
    }
    for (topology.fri_trees, 0..) |tree, layer_index| {
        try openFri(
            Ops.Decommit,
            session,
            views,
            tree,
            layer_index,
        );
    }
}

fn openTrace(
    comptime Decommit: type,
    session: anytype,
    prepared: anytype,
    views: anytype,
    opening: anytype,
) !void {
    if (opening.unretained_bottom_layers != 0)
        return error.InvalidKernelDescriptor;
    const queries = views.decommit.traceQueries();
    try Decommit.prepareTraceQueries(
        session,
        views.decommit.unique_queries,
        views.decommit.counts.unique,
        opening.source_log_size,
        opening.tree_log_size,
        opening.leaf_log_size,
        opening.unretained_bottom_layers,
        queries,
    );

    const source = try views.trace.trees.require(opening.role);
    try Decommit.packTraceGroup(
        session,
        opening.tree_index,
        opening.column_count,
        0,
        source.evaluations,
        source.column_log_sizes,
        prepared.decommit.query_log_size,
        queries.mapped,
        queries.mapped_count,
        views.proof.decommitment,
    );

    const retained = stages.decommit.RetainedTree{
        .hashes = source.merkle_hashes,
        .layers = source.merkle_layers,
    };
    const empty_words = try views.decommit.sparse_indices.sub(0, 0);
    const empty_hashes = try views.decommit.sparse_hashes.sub(0, 0);
    const first_retained_log =
        opening.leaf_log_size - opening.unretained_bottom_layers;
    try Decommit.assembleTrace(
        session,
        opening.tree_index,
        @intFromEnum(opening.role),
        opening.leaf_log_size,
        first_retained_log,
        opening.column_count,
        try count(prepared.decommit.query_count),
        .{
            .mapped_count = queries.mapped_count,
            .walk_queries = views.decommit.walk_queries,
            .walk_scratch = views.decommit.walk_scratch,
            .walk_count = views.decommit.counts.walk,
            .retained = retained,
            .sparse_indices = empty_words,
            .sparse_hashes = empty_hashes,
            .sparse_level_offsets = empty_words,
            .sparse_level_counts = empty_words,
            .assembly = views.proof.decommitment,
        },
    );
}

fn openFri(
    comptime Decommit: type,
    session: anytype,
    views: anytype,
    opening: anytype,
    layer_index: usize,
) !void {
    const layer = views.fri.layers[layer_index];
    const queries = views.decommit.friQueries();
    try Decommit.prepareFriQueries(
        session,
        views.decommit.unique_queries,
        views.decommit.counts.unique,
        opening.cumulative_fold,
        opening.fold_step,
        opening.log_rows_per_leaf,
        queries,
    );
    try Decommit.assembleFri(
        session,
        opening.tree_index,
        opening.evaluation_log_size - opening.log_rows_per_leaf,
        views.decommit.friAssembly(
            layer,
            views.proof.decommitment,
        ),
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

pub fn powStep(layer_count: usize) runtime_error.Error!u32 {
    return tailStep(layer_count, 1);
}

pub fn queryStep(layer_count: usize) runtime_error.Error!u32 {
    return tailStep(layer_count, 2);
}

fn tailStep(
    layer_count: usize,
    tail_offset: usize,
) runtime_error.Error!u32 {
    const fri_operations = std.math.mul(
        usize,
        layer_count,
        2,
    ) catch return error.SizeOverflow;
    return std.math.cast(
        u32,
        9 + fri_operations + tail_offset,
    ) orelse error.SizeOverflow;
}

fn count(value: usize) runtime_error.Error!u32 {
    return std.math.cast(u32, value) orelse error.SizeOverflow;
}

test "shared tail schedule always places PoW before query derivation" {
    const schedule_mod = @import("transcript_schedule.zig");
    for ([_]usize{ 3, 14, 22 }) |layers| {
        const schedule = try schedule_mod.Schedule.init(0x1234, layers);
        const pow_step = try powStep(layers);
        const query_step = try queryStep(layers);
        try std.testing.expectEqual(pow_step + 1, query_step);
        try std.testing.expectEqual(
            schedule_mod.Operation.absorb_pow,
            try schedule.operation(pow_step),
        );
        try std.testing.expectEqual(
            schedule_mod.Operation.draw_queries,
            try schedule.operation(query_step),
        );
    }
}

test "PoW bound covers the imported monotone SIMD nonce lattice" {
    try std.testing.expectEqual(
        @as(u64, 0x7fff_ffff) << 20,
        pow_search_end,
    );
    try std.testing.expect(pow_search_end > std.math.maxInt(u32));
}
