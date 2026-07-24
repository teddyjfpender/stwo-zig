//! Resident PoW, query derivation, and authenticated opening assembly.
//!
//! All work is enqueued on the proof stream. The only host read is the later
//! transaction finalizer, which decodes and authenticates the complete SWPC
//! bundle after this stage has finished.

const std = @import("std");
const arena = @import("../../../../backends/cuda/runtime/arena.zig");
const column = @import("../../../../backends/cuda/runtime/column.zig");
const stages = @import("../../../../backends/cuda/runtime/stages/mod.zig");
const runtime_error = @import("../../../../backends/cuda/runtime/error.zig");
const plan_mod = @import("../plan.zig");
const topology_mod = @import("../topology.zig");
const bindings = @import("../resident_bindings/mod.zig");
const proof_assembly = @import("proof_assembly.zig");

const NativeOps = struct {
    const Fri = stages.fri.Native;
    const Transcript = stages.transcript.Native;
    const Decommit = stages.decommit.Native;
    const Capture = proof_assembly;
};

/// Covers the complete nonce lattice admitted by the persistent CUDA kernel.
/// The kernel's monotone index mapping plus atomic-min result makes this the
/// lowest valid bounded Stwo nonce, not merely the first racing winner.
pub const pow_search_end: u64 = @as(u64, 0x7fff_ffff) << 20;

pub fn executePow(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
) !void {
    return executePowWith(NativeOps, transaction, prepared, views);
}

pub fn executeDecommit(
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
) !void {
    return executeDecommitWith(NativeOps, transaction, prepared, views);
}

fn executePowWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
) !void {
    const session = &transaction.session;
    try Ops.Fri.grindPow(
        session,
        views.transcript.state,
        prepared.logical.geometry.protocol.pow_bits,
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
        prepared.logical.geometry.protocol.pow_bits,
        try views.transcript.input_snapshot.sub(0, 2),
    );
}

fn executeDecommitWith(
    comptime Ops: type,
    transaction: anytype,
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
) !void {
    const geometry = prepared.logical.geometry;
    const topology = prepared.decommit;
    if (views.decommit.raw_queries.len != topology.query_count or
        topology.trace_trees.len != 2 or
        topology.fri_trees.len != views.fri.layer_count or
        views.proof.decommitment.len != topology.assembly_words)
    {
        return error.InvalidKernelDescriptor;
    }

    const session = &transaction.session;
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
    prepared: *const plan_mod.PreparedPlan,
    views: *const bindings.Views,
    opening: topology_mod.TraceOpening,
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

    const source = traceSource(views, opening.role);
    // Each trace tree owns an independent resident slab. `first_column` is
    // therefore zero for both trees; the global sample offset is unrelated to
    // the local decommitment value layout.
    try Decommit.packTraceGroup(
        session,
        opening.tree_index,
        opening.column_count,
        localFirstColumn(opening.role),
        source.columns,
        source.log_sizes,
        prepared.decommit.query_log_size,
        queries.mapped,
        queries.mapped_count,
        views.proof.decommitment,
    );

    const retained = traceRetained(views, opening.role);
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
            // No bottom layer is omitted in the admitted v1 topology. Passing
            // true empty views prevents a one-word arena sentinel from being
            // misinterpreted as sparse authentication data.
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
    views: *const bindings.Views,
    opening: topology_mod.FriOpening,
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

const TraceSource = struct {
    columns: stages.common.WordMatrix,
    log_sizes: stages.common.Words,
};

fn traceSource(
    views: *const bindings.Views,
    role: @import("../layout.zig").TraceRole,
) TraceSource {
    return switch (role) {
        .main => .{
            .columns = views.trace.main_evaluations,
            .log_sizes = views.decommit.main_column_log_sizes,
        },
        .composition => .{
            .columns = views.trace.composition_evaluations,
            .log_sizes = views.decommit.composition_column_log_sizes,
        },
        .preprocessed => unreachable,
    };
}

fn traceRetained(
    views: *const bindings.Views,
    role: @import("../layout.zig").TraceRole,
) stages.decommit.RetainedTree {
    return switch (role) {
        .main => .{
            .hashes = views.trace.main_merkle_hashes,
            .layers = views.trace.main_merkle_layers,
        },
        .composition => .{
            .hashes = views.trace.composition_merkle_hashes,
            .layers = views.trace.composition_merkle_layers,
        },
        .preprocessed => unreachable,
    };
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

fn powStep(layer_count: usize) runtime_error.Error!u32 {
    return tailStep(layer_count, 1);
}

fn queryStep(layer_count: usize) runtime_error.Error!u32 {
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

test "tail schedule places PoW before query derivation for every depth" {
    const request = @import("../request.zig");
    const allocator = std.testing.allocator;
    for ([_]u32{ 3, 14, 22 }) |log_n_rows| {
        const geometry = try request.admit(.{
            .statement = .{
                .log_n_rows = log_n_rows,
                .sequence_len = 37,
            },
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
        const pow_step = try powStep(prepared.fri.layers.len);
        const query_step = try queryStep(prepared.fri.layers.len);
        try std.testing.expectEqual(pow_step + 1, query_step);
        try std.testing.expectEqual(
            @import("../transcript_schedule.zig").Operation.absorb_pow,
            try prepared.transcript.operation(pow_step),
        );
        try std.testing.expectEqual(
            @import("../transcript_schedule.zig").Operation.draw_queries,
            try prepared.transcript.operation(query_step),
        );
    }
}

test "PoW bound is the full imported monotone SIMD nonce lattice" {
    try std.testing.expectEqual(
        @as(u64, 0x7fff_ffff) << 20,
        pow_search_end,
    );
    try std.testing.expect(pow_search_end > std.math.maxInt(u32));
}

test "composition trace packing is tree-local rather than sample-global" {
    try std.testing.expectEqual(@as(u32, 0), localFirstColumn(.composition));
    try std.testing.expectEqual(@as(u32, 0), localFirstColumn(.main));
}

fn localFirstColumn(
    role: @import("../layout.zig").TraceRole,
) u32 {
    return switch (role) {
        .main, .composition => 0,
        .preprocessed => unreachable,
    };
}

test "fake contract observes PoW then absorb without a host boundary" {
    const allocator = std.testing.allocator;
    var prepared = try testPrepared(allocator);
    defer prepared.deinit(allocator);
    const provider = FakeProvider{ .prepared = &prepared };
    const views = try bindings.bind(&provider, &prepared);
    var transaction = FakeTransaction{};

    const FakeOps = struct {
        var cursor: usize = 0;
        var events: [3]enum { grind, capture, absorb } = undefined;

        const Fri = struct {
            pub fn grindPow(
                _: anytype,
                _: stages.common.Words,
                _: u32,
                search_end: u64,
                _: stages.common.Words,
                _: stages.common.Nonce,
                _: stages.common.Words,
                _: stages.common.Words,
            ) !void {
                try std.testing.expectEqual(pow_search_end, search_end);
                events[cursor] = .grind;
                cursor += 1;
            }
        };
        const Capture = struct {
            pub fn capturePowNonce(
                _: anytype,
                _: *const bindings.Views,
            ) !void {
                events[cursor] = .capture;
                cursor += 1;
            }
        };
        const Transcript = struct {
            pub fn absorbPow(
                _: anytype,
                _: stages.common.Words,
                boundary_value: stages.transcript.Boundary,
                nonce: stages.common.Words,
                _: u32,
                snapshot: stages.common.Words,
            ) !void {
                try std.testing.expectEqual(
                    try powStep(3),
                    boundary_value.expected_step,
                );
                try std.testing.expectEqual(@as(usize, 2), nonce.len);
                try std.testing.expectEqual(@as(usize, 2), snapshot.len);
                events[cursor] = .absorb;
                cursor += 1;
            }
        };
    };
    FakeOps.cursor = 0;
    try executePowWith(
        FakeOps,
        &transaction,
        &prepared,
        &views,
    );
    try std.testing.expectEqual(@as(usize, 3), FakeOps.cursor);
    try std.testing.expectEqual(.grind, FakeOps.events[0]);
    try std.testing.expectEqual(.capture, FakeOps.events[1]);
    try std.testing.expectEqual(.absorb, FakeOps.events[2]);
}

test "fake opening contract covers every tree in canonical order" {
    const allocator = std.testing.allocator;
    var prepared = try testPrepared(allocator);
    defer prepared.deinit(allocator);
    const provider = FakeProvider{ .prepared = &prepared };
    const views = try bindings.bind(&provider, &prepared);
    var transaction = FakeTransaction{};

    const Event = struct {
        kind: enum {
            draw,
            normalize,
            prepare_trace,
            pack_trace,
            assemble_trace,
            prepare_fri,
            assemble_fri,
        },
        tree: u32 = 0,
        first_column: u32 = 0,
        column_count: u32 = 0,
    };
    const FakeOps = struct {
        var cursor: usize = 0;
        var events: [14]Event = undefined;

        fn append(event: Event) void {
            events[cursor] = event;
            cursor += 1;
        }

        const Transcript = struct {
            pub fn drawQueries(
                _: anytype,
                _: stages.common.Words,
                _: stages.transcript.Boundary,
                _: u32,
                output: stages.common.Words,
                snapshot: stages.common.Words,
            ) !void {
                try std.testing.expectEqual(output.len, snapshot.len);
                append(.{ .kind = .draw });
            }
        };
        const Decommit = struct {
            pub fn normalizeQueries(
                _: anytype,
                _: stages.common.Words,
                _: u32,
                tree_count: u32,
                _: stages.common.Words,
                _: stages.common.Words,
                _: stages.common.Words,
            ) !void {
                try std.testing.expectEqual(@as(u32, 5), tree_count);
                append(.{ .kind = .normalize });
            }

            pub fn prepareTraceQueries(
                _: anytype,
                _: stages.common.Words,
                _: stages.common.Words,
                _: u32,
                _: u32,
                _: u32,
                _: u32,
                _: stages.decommit.TraceQueries,
            ) !void {
                append(.{ .kind = .prepare_trace });
            }

            pub fn packTraceGroup(
                _: anytype,
                tree: u32,
                total: u32,
                first: u32,
                _: stages.common.WordMatrix,
                _: stages.common.Words,
                _: u32,
                _: stages.common.Words,
                _: stages.common.Words,
                _: stages.common.Words,
            ) !void {
                append(.{
                    .kind = .pack_trace,
                    .tree = tree,
                    .first_column = first,
                    .column_count = total,
                });
            }

            pub fn assembleTrace(
                _: anytype,
                tree: u32,
                _: u32,
                _: u32,
                _: u32,
                columns: u32,
                _: u32,
                data: stages.decommit.TraceAssembly,
            ) !void {
                try std.testing.expectEqual(@as(usize, 0), data.sparse_indices.len);
                try std.testing.expectEqual(@as(usize, 0), data.sparse_hashes.len);
                append(.{
                    .kind = .assemble_trace,
                    .tree = tree,
                    .column_count = columns,
                });
            }

            pub fn prepareFriQueries(
                _: anytype,
                _: stages.common.Words,
                _: stages.common.Words,
                cumulative_fold: u32,
                _: u32,
                _: u32,
                _: stages.decommit.FriQueries,
            ) !void {
                append(.{ .kind = .prepare_fri, .tree = cumulative_fold });
            }

            pub fn assembleFri(
                _: anytype,
                tree: u32,
                _: u32,
                _: stages.decommit.FriAssembly,
            ) !void {
                append(.{ .kind = .assemble_fri, .tree = tree });
            }
        };
    };
    FakeOps.cursor = 0;
    try executeDecommitWith(
        FakeOps,
        &transaction,
        &prepared,
        &views,
    );

    try std.testing.expectEqual(FakeOps.events.len, FakeOps.cursor);
    try std.testing.expectEqual(.draw, FakeOps.events[0].kind);
    try std.testing.expectEqual(.normalize, FakeOps.events[1].kind);
    try std.testing.expectEqual(.pack_trace, FakeOps.events[3].kind);
    try std.testing.expectEqual(@as(u32, 0), FakeOps.events[3].first_column);
    try std.testing.expectEqual(@as(u32, 3), FakeOps.events[3].column_count);
    try std.testing.expectEqual(.pack_trace, FakeOps.events[6].kind);
    try std.testing.expectEqual(@as(u32, 0), FakeOps.events[6].first_column);
    try std.testing.expectEqual(@as(u32, 8), FakeOps.events[6].column_count);
    try std.testing.expectEqual(.prepare_fri, FakeOps.events[8].kind);
    try std.testing.expectEqual(.assemble_fri, FakeOps.events[13].kind);
    try std.testing.expectEqual(@as(u32, 4), FakeOps.events[13].tree);
}

const FakeTransaction = struct {
    session: u8 = 0,
};

const FakeProvider = struct {
    prepared: *const plan_mod.PreparedPlan,

    pub fn slot(
        self: *const FakeProvider,
        id: arena.SlotId,
    ) runtime_error.Error!column.DeviceSlice(u32) {
        const placement = try self.prepared.arena_plan.placement(id);
        return .{
            .address = 0x1000_0000 +
                placement.offset_words * @sizeOf(u32),
            .len = placement.requirement.words,
            .owner = 17,
            .generation = 23,
        };
    }
};

fn testPrepared(
    allocator: std.mem.Allocator,
) !plan_mod.PreparedPlan {
    return plan_mod.PreparedPlan.init(
        allocator,
        try @import("../request.zig").admit(.{
            .statement = .{ .log_n_rows = 3, .sequence_len = 3 },
            .protocol = .{
                .pow_bits = 10,
                .log_blowup_factor = 1,
                .log_last_layer_degree_bound = 0,
                .n_queries = 3,
                .fold_step = 1,
                .lifting_log_size = null,
            },
        }),
    );
}
