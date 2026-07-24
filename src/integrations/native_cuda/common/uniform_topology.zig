//! Host-sealed topology for uniform-log, single-component STARK proofs.

const std = @import("std");
const field = @import("../../../backends/cuda/abi/field.zig");
const quotient_abi = @import(
    "../../../backends/cuda/abi/stages/quotient.zig",
);
const layout_mod = @import("uniform_layout.zig");

pub const Error = error{
    GeometryOverflow,
    UnsupportedProtocol,
};

pub fn TopologyFor(comptime Layout: type) type {
    return struct {
        pub const Quotient = struct {
            prepared_terms: []quotient_abi.PreparedTermDescriptor,
            group_offsets: []u32,
            group_term_indices: []u32,
            batch_terms: []quotient_abi.BatchTermDescriptor,
            group_log_sizes: []u32,
            partial_log_sizes: []u32,
            source_count: u32,
            source_stride_words: usize,
            output_rows: u32,

            pub fn init(
                allocator: std.mem.Allocator,
                logical: Layout,
            ) (std.mem.Allocator.Error || Error)!Quotient {
                const count = logical.quotient.term_count;
                if (count != logical.quotient.sample_count or
                    logical.quotient.structural_group_count != 1)
                {
                    return error.UnsupportedProtocol;
                }
                const count_u32 = try u32Count(count);
                const log_size = try commitmentLog(logical);
                const rows = try u32Count(logical.quotient.output_rows);
                const prepared = try allocator.alloc(
                    quotient_abi.PreparedTermDescriptor,
                    count,
                );
                errdefer allocator.free(prepared);
                const group_offsets = try allocator.dupe(
                    u32,
                    &.{ 0, count_u32 },
                );
                errdefer allocator.free(group_offsets);
                const indices = try allocator.alloc(u32, count);
                errdefer allocator.free(indices);
                const batch = try allocator.alloc(
                    quotient_abi.BatchTermDescriptor,
                    count,
                );
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
                    .batch_terms = batch,
                    .group_log_sizes = group_logs,
                    .partial_log_sizes = partial_logs,
                    .source_count = count_u32,
                    .source_stride_words = logical.quotient.source_stride_words,
                    .output_rows = rows,
                };
            }

            pub fn deinit(
                self: *Quotient,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.prepared_terms);
                allocator.free(self.group_offsets);
                allocator.free(self.group_term_indices);
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
                logical: Layout,
            ) (std.mem.Allocator.Error || Error)!Fri {
                const layers = try allocator.alloc(
                    FriLayer,
                    logical.fri_trees.len,
                );
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
                    const descriptor_count =
                        @as(usize, tree.evaluation_log_size) + 1;
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
                    descriptor_cursor = try add(
                        descriptor_cursor,
                        descriptor_count,
                    );
                }
                return .{
                    .layers = layers,
                    .retained_layers = retained,
                };
            }

            pub fn deinit(
                self: *Fri,
                allocator: std.mem.Allocator,
            ) void {
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
            trace_trees: []TraceOpening,
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
                logical: Layout,
            ) (std.mem.Allocator.Error || Error)!Decommit {
                const query_count = try queryCount(logical);
                const log_size = try commitmentLog(logical);
                var trace_count: usize = 0;
                var trace_layer_count: usize = 0;
                var source_columns: usize = 0;
                var sampled_columns: usize = 0;
                for (logical.trace_trees) |tree| {
                    if (tree.sampled) {
                        sampled_columns = try add(
                            sampled_columns,
                            tree.column_count,
                        );
                    }
                    if (!tree.decommitted) continue;
                    trace_count += 1;
                    trace_layer_count = try add(
                        trace_layer_count,
                        @as(usize, tree.commitment_log_size) + 1,
                    );
                    source_columns = try add(
                        source_columns,
                        tree.column_count,
                    );
                }
                if (trace_count == 0 or
                    sampled_columns != logical.quotient.source_column_count)
                {
                    return error.UnsupportedProtocol;
                }
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
                    source_columns,
                );
                errdefer allocator.free(column_logs);
                const trace_trees = try allocator.alloc(
                    TraceOpening,
                    trace_count,
                );
                errdefer allocator.free(trace_trees);
                const fri_trees = try allocator.alloc(
                    FriOpening,
                    logical.fri_trees.len,
                );
                errdefer allocator.free(fri_trees);

                var descriptor_cursor: usize = 0;
                var column_cursor: usize = 0;
                var trace_cursor: usize = 0;
                var assembly_words = try decommitPrefixWords(
                    trace_count + logical.fri_trees.len,
                    query_count,
                );
                for (logical.trace_trees) |tree| {
                    if (!tree.decommitted) continue;
                    const layer_count =
                        @as(usize, tree.commitment_log_size) + 1;
                    try fillMerkleLayers(
                        retained[descriptor_cursor..][0..layer_count],
                        tree.commitment_log_size,
                    );
                    @memset(
                        column_logs[column_cursor..][0..tree.column_count],
                        tree.column_log_size,
                    );
                    trace_trees[trace_cursor] = .{
                        .tree_index = try u32Count(trace_cursor),
                        .role = tree.role,
                        .first_column = try u32Count(column_cursor),
                        .column_count = try u32Count(tree.column_count),
                        .source_log_size = tree.commitment_log_size,
                        .tree_log_size = tree.commitment_log_size,
                        .leaf_log_size = tree.commitment_log_size,
                        .unretained_bottom_layers = 0,
                        .retained_layer_offset = descriptor_cursor,
                        .retained_layer_count = layer_count,
                    };
                    assembly_words = try add(
                        assembly_words,
                        try traceAssemblyWords(
                            query_count,
                            tree.column_count,
                            tree.commitment_log_size,
                        ),
                    );
                    descriptor_cursor = try add(
                        descriptor_cursor,
                        layer_count,
                    );
                    column_cursor = try add(
                        column_cursor,
                        tree.column_count,
                    );
                    trace_cursor += 1;
                }

                var max_expanded = query_count;
                for (logical.fri_trees, 0..) |tree, index| {
                    const expanded = try mul(
                        query_count,
                        try pow2(tree.fold_step),
                    );
                    max_expanded = @max(max_expanded, expanded);
                    const count =
                        @as(usize, tree.evaluation_log_size) + 1;
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
                            tree.evaluation_log_size -
                                tree.log_rows_per_leaf,
                        ),
                    );
                }
                _ = std.math.cast(u32, assembly_words) orelse
                    return error.GeometryOverflow;
                return .{
                    .query_log_size = log_size,
                    .query_count = query_count,
                    .trace_trees = trace_trees,
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

            pub fn deinit(
                self: *Decommit,
                allocator: std.mem.Allocator,
            ) void {
                allocator.free(self.trace_trees);
                allocator.free(self.fri_trees);
                allocator.free(self.column_log_sizes);
                allocator.free(self.retained_layers);
                self.* = undefined;
            }
        };
    };
}

fn commitmentLog(logical: anytype) Error!u32 {
    var result: ?u32 = null;
    for (logical.trace_trees) |tree| {
        if (!tree.decommitted) continue;
        if (result) |value| {
            if (value != tree.commitment_log_size)
                return error.UnsupportedProtocol;
        } else {
            result = tree.commitment_log_size;
        }
    }
    return result orelse error.UnsupportedProtocol;
}

fn queryCount(logical: anytype) Error!usize {
    if (!@hasField(@TypeOf(logical.geometry), "protocol"))
        return error.UnsupportedProtocol;
    return logical.geometry.protocol.n_queries;
}

fn fillMerkleLayers(
    output: []field.MerkleLayerDescriptor,
    leaf_log_size: u32,
) Error!void {
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

fn decommitPrefixWords(tree_count: usize, queries: usize) Error!usize {
    return add(try add(8, try mul(tree_count, 16)), try mul(queries, 2));
}

fn traceAssemblyWords(
    queries: usize,
    columns: usize,
    leaf_log_size: u32,
) Error!usize {
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
) Error!usize {
    const paths = try mul(expanded, leaf_log_size);
    return add(
        try add(queries, try mul(expanded, 9)),
        try mul(paths, 28),
    );
}

fn fullTreeHashes(leaves: usize) Error!usize {
    return std.math.sub(usize, try mul(leaves, 2), 1) catch
        return error.GeometryOverflow;
}

fn pow2(log_size: u32) Error!usize {
    if (log_size >= @bitSizeOf(usize)) return error.GeometryOverflow;
    return @as(usize, 1) << @intCast(log_size);
}

fn u32Count(value: anytype) Error!u32 {
    return std.math.cast(u32, value) orelse error.GeometryOverflow;
}

fn add(left: anytype, right: anytype) Error!usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.GeometryOverflow;
    return std.math.add(usize, lhs, rhs) catch error.GeometryOverflow;
}

fn mul(left: anytype, right: anytype) Error!usize {
    const lhs = std.math.cast(usize, left) orelse
        return error.GeometryOverflow;
    const rhs = std.math.cast(usize, right) orelse
        return error.GeometryOverflow;
    return std.math.mul(usize, lhs, rhs) catch error.GeometryOverflow;
}

test "indexed XOR preprocessed columns are sampled and opened" {
    const Geometry = struct {
        log_rows: u32,
        protocol: struct { n_queries: usize },
    };
    const Descriptor = struct {
        pub fn describe(geometry: Geometry) !layout_mod.Description {
            const commitment_log = geometry.log_rows + 1;
            return .{
                // This is the structural CPU XOR shape: two public
                // preprocessed columns, one main column, and eight split
                // composition columns. Component mask expansion includes the
                // indexed preprocessed columns, so all eleven are sampled and
                // opened.
                .trace_trees = .{
                    .{
                        .role = .preprocessed,
                        .column_count = 2,
                        .column_log_size = geometry.log_rows,
                        .commitment_log_size = commitment_log,
                        .sampled = true,
                        .decommitted = true,
                    },
                    .{
                        .role = .main,
                        .column_count = 1,
                        .column_log_size = geometry.log_rows,
                        .commitment_log_size = commitment_log,
                        .sampled = true,
                        .decommitted = true,
                    },
                    .{
                        .role = .composition,
                        .column_count = 8,
                        .column_log_size = geometry.log_rows,
                        .commitment_log_size = commitment_log,
                        .sampled = true,
                        .decommitted = true,
                    },
                },
                .fri_tree_count = geometry.log_rows,
                .first_fri_tree_index = 3,
                .first_fri_evaluation_log = commitment_log,
                .last_fri_evaluation_log = 2,
                .fri_fold_step = 1,
                .fri_log_rows_per_leaf = 0,
                .quotient = .{
                    .sample_count = 11,
                    .term_count = 11,
                    .structural_group_count = 1,
                    .source_column_count = 11,
                    .source_stride_words = @as(usize, 1) <<
                        @intCast(commitment_log),
                    .output_rows = @as(usize, 1) <<
                        @intCast(commitment_log),
                },
            };
        }
    };
    const TestLayout = layout_mod.LayoutFor(Geometry, Descriptor);
    const Set = TopologyFor(TestLayout);
    var logical = try TestLayout.init(
        std.testing.allocator,
        .{
            .log_rows = 3,
            .protocol = .{ .n_queries = 3 },
        },
    );
    defer logical.deinit(std.testing.allocator);
    var quotient = try Set.Quotient.init(std.testing.allocator, logical);
    defer quotient.deinit(std.testing.allocator);
    var decommit = try Set.Decommit.init(std.testing.allocator, logical);
    defer decommit.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 11), quotient.source_count);
    try std.testing.expectEqual(@as(usize, 3), decommit.trace_trees.len);
    try std.testing.expectEqual(@as(usize, 11), decommit.column_log_sizes.len);
    try std.testing.expectEqual(
        layout_mod.TraceRole.preprocessed,
        decommit.trace_trees[0].role,
    );
}
