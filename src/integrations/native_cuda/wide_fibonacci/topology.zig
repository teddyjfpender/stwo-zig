//! Host-owned, geometry-sealed descriptors for resident proof stages.

const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const quotient_abi = @import("../../../backends/cuda/abi/stages/quotient.zig");
const layout_mod = @import("layout.zig");
const request = @import("request.zig");

pub const Quotient = struct {
    prepared_terms: []quotient_abi.PreparedTermDescriptor,
    group_offsets: []u32,
    group_term_indices: []u32,
    batch_offsets: []u32,
    batch_terms: []quotient_abi.BatchTermDescriptor,
    group_log_sizes: []u32,
    partial_log_sizes: []u32,
    source_count: u32,
    source_stride_words: usize,
    output_rows: u32,

    pub fn init(
        allocator: std.mem.Allocator,
        logical: layout_mod.Layout,
    ) (std.mem.Allocator.Error || request.Error)!Quotient {
        const count = logical.quotient.term_count;
        const count_u32 = try u32Count(count);
        const log_size = logical.geometry.queryLogSize();
        const rows = try u32Count(logical.quotient.output_rows);
        const prepared = try allocator.alloc(
            quotient_abi.PreparedTermDescriptor,
            count,
        );
        errdefer allocator.free(prepared);
        const group_offsets = try allocator.dupe(u32, &.{ 0, count_u32 });
        errdefer allocator.free(group_offsets);
        const indices = try allocator.alloc(u32, count);
        errdefer allocator.free(indices);
        const batch_offsets = try allocator.dupe(u32, &.{ 0, count_u32 });
        errdefer allocator.free(batch_offsets);
        const batch = try allocator.alloc(quotient_abi.BatchTermDescriptor, count);
        errdefer allocator.free(batch);
        const group_logs = try allocator.dupe(u32, &.{log_size});
        errdefer allocator.free(group_logs);
        const partial_logs = try allocator.dupe(u32, &.{log_size});
        errdefer allocator.free(partial_logs);

        for (0..count) |index| {
            const ordinal = try u32Count(index);
            prepared[index] = .{
                .sample_index = ordinal,
                .exponent = ordinal,
                .periodic = 0,
                .period_x = 0,
                .period_y = 0,
            };
            indices[index] = ordinal;
            batch[index] = .{
                .source_index = ordinal,
                .term_index = ordinal,
                .source_log_size = log_size,
            };
        }
        return .{
            .prepared_terms = prepared,
            .group_offsets = group_offsets,
            .group_term_indices = indices,
            .batch_offsets = batch_offsets,
            .batch_terms = batch,
            .group_log_sizes = group_logs,
            .partial_log_sizes = partial_logs,
            .source_count = count_u32,
            .source_stride_words = logical.quotient.source_stride_words,
            .output_rows = rows,
        };
    }

    pub fn deinit(self: *Quotient, allocator: std.mem.Allocator) void {
        allocator.free(self.prepared_terms);
        allocator.free(self.group_offsets);
        allocator.free(self.group_term_indices);
        allocator.free(self.batch_offsets);
        allocator.free(self.batch_terms);
        allocator.free(self.group_log_sizes);
        allocator.free(self.partial_log_sizes);
        self.* = undefined;
    }
};

pub const FriLayer = struct {
    tree_index: u32,
    evaluation_log_size: u32,
    cumulative_fold: u32,
    fold_step: u32,
    log_rows_per_leaf: u32,
    evaluation_rows: usize,
    coordinate_stride_words: usize,
    coordinate_words: usize,
    merkle_hashes: usize,
    retained_layer_offset: usize,
    retained_layer_count: usize,
};

pub const Fri = struct {
    layers: []FriLayer,
    retained_layers: []field.MerkleLayerDescriptor,

    pub fn init(
        allocator: std.mem.Allocator,
        logical: layout_mod.Layout,
    ) (std.mem.Allocator.Error || request.Error)!Fri {
        const layers = try allocator.alloc(FriLayer, logical.fri_trees.len);
        errdefer allocator.free(layers);
        var layer_descriptor_count: usize = 0;
        for (logical.fri_trees) |tree| {
            layer_descriptor_count = try add(
                layer_descriptor_count,
                @as(usize, tree.evaluation_log_size) + 1,
            );
        }
        const retained = try allocator.alloc(
            field.MerkleLayerDescriptor,
            layer_descriptor_count,
        );
        errdefer allocator.free(retained);

        var descriptor_cursor: usize = 0;
        for (logical.fri_trees, 0..) |tree, index| {
            const rows = try pow2(tree.evaluation_log_size);
            const descriptor_count = @as(usize, tree.evaluation_log_size) + 1;
            try fillMerkleLayers(
                retained[descriptor_cursor..][0..descriptor_count],
                tree.evaluation_log_size,
            );
            layers[index] = .{
                .tree_index = try u32Count(tree.tree_index),
                .evaluation_log_size = tree.evaluation_log_size,
                .cumulative_fold = tree.cumulative_fold,
                .fold_step = tree.fold_step,
                .log_rows_per_leaf = tree.log_rows_per_leaf,
                .evaluation_rows = rows,
                .coordinate_stride_words = rows,
                .coordinate_words = try mul(rows, 4),
                .merkle_hashes = try fullTreeHashes(rows),
                .retained_layer_offset = descriptor_cursor,
                .retained_layer_count = descriptor_count,
            };
            descriptor_cursor = try add(descriptor_cursor, descriptor_count);
        }
        return .{ .layers = layers, .retained_layers = retained };
    }

    pub fn deinit(self: *Fri, allocator: std.mem.Allocator) void {
        allocator.free(self.layers);
        allocator.free(self.retained_layers);
        self.* = undefined;
    }
};

pub const TraceOpening = struct {
    tree_index: u32,
    role: layout_mod.TraceRole,
    first_column: u32,
    column_count: u32,
    source_log_size: u32,
    tree_log_size: u32,
    leaf_log_size: u32,
    unretained_bottom_layers: u32,
    retained_layer_offset: usize,
    retained_layer_count: usize,
};

pub const FriOpening = struct {
    tree_index: u32,
    evaluation_log_size: u32,
    cumulative_fold: u32,
    fold_step: u32,
    log_rows_per_leaf: u32,
    max_expanded_positions: usize,
    retained_layer_offset: usize,
    retained_layer_count: usize,
};

pub const Decommit = struct {
    query_log_size: u32,
    query_count: usize,
    trace_trees: [2]TraceOpening,
    fri_trees: []FriOpening,
    column_log_sizes: []u32,
    retained_layers: []field.MerkleLayerDescriptor,
    unique_query_words: usize,
    mapped_query_words: usize,
    walk_query_words: usize,
    leaf_index_words: usize,
    expanded_position_words: usize,
    sparse_index_words: usize,
    sparse_hash_words: usize,
    count_words: usize,
    assembly_words: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        logical: layout_mod.Layout,
    ) (std.mem.Allocator.Error || request.Error)!Decommit {
        const geometry = logical.geometry;
        const query_count = geometry.protocol.n_queries;
        const log_size = geometry.queryLogSize();
        const trace_layer_count = try mul(@as(usize, log_size) + 1, 2);
        var fri_layer_count: usize = 0;
        for (logical.fri_trees) |tree| {
            fri_layer_count = try add(
                fri_layer_count,
                @as(usize, tree.evaluation_log_size) + 1,
            );
        }
        const retained = try allocator.alloc(
            field.MerkleLayerDescriptor,
            try add(trace_layer_count, fri_layer_count),
        );
        errdefer allocator.free(retained);
        const column_logs = try allocator.alloc(
            u32,
            logical.quotient.source_column_count,
        );
        errdefer allocator.free(column_logs);
        @memset(column_logs, log_size);
        const fri_trees = try allocator.alloc(FriOpening, logical.fri_trees.len);
        errdefer allocator.free(fri_trees);

        const per_trace_layers = @as(usize, log_size) + 1;
        try fillMerkleLayers(retained[0..per_trace_layers], log_size);
        try fillMerkleLayers(
            retained[per_trace_layers..][0..per_trace_layers],
            log_size,
        );
        var descriptor_cursor = trace_layer_count;
        var assembly_words = try decommitPrefixWords(
            geometry.decommit_tree_count,
            query_count,
        );
        assembly_words = try add(
            assembly_words,
            try traceAssemblyWords(query_count, geometry.main_columns, log_size),
        );
        assembly_words = try add(
            assembly_words,
            try traceAssemblyWords(
                query_count,
                request.composition_column_count,
                log_size,
            ),
        );
        var max_expanded = query_count;
        for (logical.fri_trees, 0..) |tree, index| {
            const expanded = try mul(query_count, try pow2(tree.fold_step));
            max_expanded = @max(max_expanded, expanded);
            const count = @as(usize, tree.evaluation_log_size) + 1;
            try fillMerkleLayers(
                retained[descriptor_cursor..][0..count],
                tree.evaluation_log_size,
            );
            fri_trees[index] = .{
                .tree_index = try u32Count(tree.tree_index),
                .evaluation_log_size = tree.evaluation_log_size,
                .cumulative_fold = tree.cumulative_fold,
                .fold_step = tree.fold_step,
                .log_rows_per_leaf = tree.log_rows_per_leaf,
                .max_expanded_positions = expanded,
                .retained_layer_offset = descriptor_cursor,
                .retained_layer_count = count,
            };
            descriptor_cursor = try add(descriptor_cursor, count);
            assembly_words = try add(
                assembly_words,
                try friAssemblyWords(
                    query_count,
                    expanded,
                    tree.evaluation_log_size - tree.log_rows_per_leaf,
                ),
            );
        }
        _ = std.math.cast(u32, assembly_words) orelse
            return error.GeometryOverflow;
        return .{
            .query_log_size = log_size,
            .query_count = query_count,
            .trace_trees = .{
                .{
                    .tree_index = 0,
                    .role = .main,
                    .first_column = 0,
                    .column_count = try u32Count(geometry.main_columns),
                    .source_log_size = log_size,
                    .tree_log_size = log_size,
                    .leaf_log_size = log_size,
                    .unretained_bottom_layers = 0,
                    .retained_layer_offset = 0,
                    .retained_layer_count = per_trace_layers,
                },
                .{
                    .tree_index = 1,
                    .role = .composition,
                    .first_column = try u32Count(geometry.main_columns),
                    .column_count = request.composition_column_count,
                    .source_log_size = log_size,
                    .tree_log_size = log_size,
                    .leaf_log_size = log_size,
                    .unretained_bottom_layers = 0,
                    .retained_layer_offset = per_trace_layers,
                    .retained_layer_count = per_trace_layers,
                },
            },
            .fri_trees = fri_trees,
            .column_log_sizes = column_logs,
            .retained_layers = retained,
            .unique_query_words = query_count,
            .mapped_query_words = query_count,
            .walk_query_words = max_expanded,
            .leaf_index_words = 1,
            .expanded_position_words = max_expanded,
            .sparse_index_words = 1,
            .sparse_hash_words = 8,
            .count_words = 5,
            .assembly_words = assembly_words,
        };
    }

    pub fn deinit(self: *Decommit, allocator: std.mem.Allocator) void {
        allocator.free(self.fri_trees);
        allocator.free(self.column_log_sizes);
        allocator.free(self.retained_layers);
        self.* = undefined;
    }
};

fn fillMerkleLayers(
    output: []field.MerkleLayerDescriptor,
    leaf_log_size: u32,
) request.Error!void {
    if (output.len != @as(usize, leaf_log_size) + 1)
        return error.UnsupportedProtocol;
    var count = try pow2(leaf_log_size);
    var offset: usize = 0;
    for (output) |*descriptor| {
        descriptor.* = .{
            .offset_hashes = std.math.cast(u64, offset) orelse
                return error.GeometryOverflow,
            .hash_count = try u32Count(count),
        };
        offset = try add(offset, count);
        count = @max(count / 2, 1);
    }
}

fn decommitPrefixWords(tree_count: usize, queries: usize) request.Error!usize {
    return add(try add(8, try mul(tree_count, 16)), try mul(queries, 2));
}

fn traceAssemblyWords(
    queries: usize,
    columns: usize,
    leaf_log_size: u32,
) request.Error!usize {
    const path_nodes = try mul(queries, leaf_log_size);
    return add(
        try add(queries, try mul(columns, queries)),
        try mul(path_nodes, 28),
    );
}

fn friAssemblyWords(
    queries: usize,
    expanded: usize,
    leaf_log_size: u32,
) request.Error!usize {
    const paths = try mul(expanded, leaf_log_size);
    return add(
        try add(queries, try mul(expanded, 9)),
        try mul(paths, 28),
    );
}

fn fullTreeHashes(leaves: usize) request.Error!usize {
    return std.math.sub(usize, try mul(leaves, 2), 1) catch
        return error.GeometryOverflow;
}

fn pow2(log_size: u32) request.Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn u32Count(value: anytype) request.Error!u32 {
    return std.math.cast(u32, value) orelse error.GeometryOverflow;
}

fn add(left: anytype, right: anytype) request.Error!usize {
    const lhs = std.math.cast(usize, left) orelse return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.GeometryOverflow;
    return std.math.add(usize, lhs, rhs) catch error.GeometryOverflow;
}

fn mul(left: anytype, right: anytype) request.Error!usize {
    const lhs = std.math.cast(usize, left) orelse return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse return error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.GeometryOverflow;
}

test "sealed topologies cover quotient and every opened tree" {
    const allocator = std.testing.allocator;
    const geometry = try request.admit(testRequest(14));
    var logical = try layout_mod.Layout.init(allocator, geometry);
    defer logical.deinit(allocator);
    var quotient = try Quotient.init(allocator, logical);
    defer quotient.deinit(allocator);
    var fri = try Fri.init(allocator, logical);
    defer fri.deinit(allocator);
    var decommit = try Decommit.init(allocator, logical);
    defer decommit.deinit(allocator);

    try std.testing.expectEqual(@as(usize, 108), quotient.prepared_terms.len);
    try std.testing.expectEqual(@as(usize, 14), fri.layers.len);
    try std.testing.expectEqual(@as(usize, 14), decommit.fri_trees.len);
    try std.testing.expectEqual(@as(usize, 108), decommit.column_log_sizes.len);
    try std.testing.expect(decommit.assembly_words > 8 + 16 * 16);
}

fn testRequest(log_n_rows: u32) request.Request {
    return .{
        .statement = .{ .log_n_rows = log_n_rows, .sequence_len = 100 },
        .protocol = .{
            .pow_bits = 10,
            .log_blowup_factor = 1,
            .log_last_layer_degree_bound = 0,
            .n_queries = 3,
            .fold_step = 1,
            .lifting_log_size = null,
        },
    };
}
