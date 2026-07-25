//! Logical layout for a uniform-log, single-component three-tree proof.

const std = @import("std");

pub const TraceRole = enum(u32) {
    preprocessed = 0,
    main = 1,
    composition = 2,
    interaction = 3,
};

pub const TraceTree = struct {
    role: TraceRole,
    column_count: usize,
    column_log_size: u32,
    commitment_log_size: u32,
    /// Whether this tree contributes OODS samples and quotient sources.
    sampled: bool,
    /// Whether query openings for this tree are assembled into the proof.
    decommitted: bool,
};

pub const FriTree = struct {
    tree_index: usize,
    evaluation_log_size: u32,
    cumulative_fold: u32,
    fold_step: u32,
    log_rows_per_leaf: u32,
};

pub const Quotient = struct {
    sample_count: usize,
    term_count: usize,
    structural_group_count: usize,
    source_column_count: usize,
    source_stride_words: usize,
    output_rows: usize,
};

pub fn DescriptionFor(comptime trace_tree_count: usize) type {
    return struct {
        trace_trees: [trace_tree_count]TraceTree,
        fri_tree_count: usize,
        first_fri_tree_index: usize,
        first_fri_evaluation_log: u32,
        last_fri_evaluation_log: u32,
        fri_fold_step: u32,
        fri_log_rows_per_leaf: u32,
        quotient: Quotient,
    };
}

pub const Description = DescriptionFor(3);

/// `Descriptor.describe(geometry)` is the only workload-owned policy. It
/// provides counts and protocol geometry, never an AIR or benchmark identity.
pub fn LayoutFor(comptime Geometry: type, comptime Descriptor: type) type {
    return LayoutForTreeCount(Geometry, Descriptor, 3);
}

pub fn LayoutForTreeCount(
    comptime Geometry: type,
    comptime Descriptor: type,
    comptime trace_tree_count: usize,
) type {
    comptime {
        if (!@hasDecl(Descriptor, "describe"))
            @compileError("uniform layout descriptor requires describe");
        if (trace_tree_count < 3 or trace_tree_count > 4)
            @compileError("uniform layout supports three or four trace trees");
    }
    return struct {
        const Self = @This();

        geometry: Geometry,
        trace_trees: [trace_tree_count]TraceTree,
        fri_trees: []FriTree,
        quotient: Quotient,

        pub fn init(
            allocator: std.mem.Allocator,
            geometry: Geometry,
        ) !Self {
            const description = try Descriptor.describe(geometry);
            try validateDescription(description);
            const fri_trees = try allocator.alloc(
                FriTree,
                description.fri_tree_count,
            );
            errdefer allocator.free(fri_trees);
            for (fri_trees, 0..) |*tree, index| {
                const fold = std.math.cast(u32, index) orelse
                    return error.GeometryOverflow;
                const folded = std.math.mul(
                    u32,
                    fold,
                    description.fri_fold_step,
                ) catch return error.GeometryOverflow;
                tree.* = .{
                    .tree_index = std.math.add(
                        usize,
                        description.first_fri_tree_index,
                        index,
                    ) catch return error.GeometryOverflow,
                    .evaluation_log_size = std.math.sub(
                        u32,
                        description.first_fri_evaluation_log,
                        folded,
                    ) catch return error.UnsupportedProtocol,
                    .cumulative_fold = folded,
                    .fold_step = description.fri_fold_step,
                    .log_rows_per_leaf = description.fri_log_rows_per_leaf,
                };
            }
            return .{
                .geometry = geometry,
                .trace_trees = description.trace_trees,
                .fri_trees = fri_trees,
                .quotient = description.quotient,
            };
        }

        pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
            allocator.free(self.fri_trees);
            self.* = undefined;
        }

        pub fn validate(self: Self) !void {
            const description = try Descriptor.describe(self.geometry);
            try validateDescription(description);
            if (!std.meta.eql(self.trace_trees, description.trace_trees) or
                self.fri_trees.len != description.fri_tree_count or
                !std.meta.eql(self.quotient, description.quotient))
            {
                return error.UnsupportedProtocol;
            }
            for (self.fri_trees, 0..) |tree, index| {
                const fold = std.math.cast(u32, index) orelse
                    return error.GeometryOverflow;
                const cumulative = std.math.mul(
                    u32,
                    fold,
                    description.fri_fold_step,
                ) catch return error.GeometryOverflow;
                if (tree.tree_index !=
                    description.first_fri_tree_index + index or
                    tree.cumulative_fold != cumulative or
                    tree.fold_step != description.fri_fold_step or
                    tree.log_rows_per_leaf !=
                        description.fri_log_rows_per_leaf or
                    tree.evaluation_log_size !=
                        description.first_fri_evaluation_log - cumulative)
                {
                    return error.UnsupportedProtocol;
                }
            }
            if (self.fri_trees[self.fri_trees.len - 1]
                .evaluation_log_size !=
                description.last_fri_evaluation_log)
            {
                return error.UnsupportedProtocol;
            }
        }

        /// Returns the exact coefficient log for one logical column. Uniform
        /// layouts inherit the tree maximum; mixed-height frontends provide
        /// `Descriptor.columnLogSize`.
        pub fn columnLogSize(
            self: Self,
            tree_index: usize,
            column_index: usize,
        ) !u32 {
            if (tree_index >= self.trace_trees.len or
                column_index >= self.trace_trees[tree_index].column_count)
            {
                return error.UnsupportedProtocol;
            }
            const tree = self.trace_trees[tree_index];
            const value = if (@hasDecl(Descriptor, "columnLogSize"))
                try Descriptor.columnLogSize(
                    self.geometry,
                    tree.role,
                    column_index,
                )
            else
                tree.column_log_size;
            if (value > tree.column_log_size)
                return error.UnsupportedProtocol;
            return value;
        }

        pub fn columnCommitmentLogSize(
            self: Self,
            tree_index: usize,
            column_index: usize,
        ) !u32 {
            const tree = self.trace_trees[tree_index];
            const blowup = std.math.sub(
                u32,
                tree.commitment_log_size,
                tree.column_log_size,
            ) catch return error.UnsupportedProtocol;
            return std.math.add(
                u32,
                try self.columnLogSize(tree_index, column_index),
                blowup,
            ) catch return error.GeometryOverflow;
        }
    };
}

fn validateDescription(description: anytype) !void {
    if (description.trace_trees[0].role != .preprocessed or
        description.trace_trees[1].role != .main or
        (description.trace_trees.len == 4 and
            description.trace_trees[2].role != .interaction) or
        description.trace_trees[description.trace_trees.len - 1].role !=
            .composition or
        description.trace_trees[1].column_count == 0 or
        description.trace_trees[
            description.trace_trees.len - 1
        ].column_count == 0 or
        description.fri_tree_count == 0 or
        description.fri_fold_step == 0 or
        description.quotient.sample_count == 0 or
        description.quotient.term_count == 0 or
        description.quotient.source_column_count == 0 or
        description.quotient.output_rows == 0)
    {
        return error.UnsupportedProtocol;
    }
    var sampled_columns: usize = 0;
    var decommitted_trees: usize = 0;
    var column_log: ?u32 = null;
    var commitment_log: ?u32 = null;
    for (description.trace_trees) |tree| {
        if (tree.column_count == 0) {
            if (tree.sampled or tree.decommitted)
                return error.UnsupportedProtocol;
            continue;
        }
        if (column_log) |expected| {
            if (tree.column_log_size != expected)
                return error.UnsupportedProtocol;
        } else {
            column_log = tree.column_log_size;
        }
        if (commitment_log) |expected| {
            if (tree.commitment_log_size != expected)
                return error.UnsupportedProtocol;
        } else {
            commitment_log = tree.commitment_log_size;
        }
        if (tree.sampled) {
            sampled_columns = std.math.add(
                usize,
                sampled_columns,
                tree.column_count,
            ) catch return error.GeometryOverflow;
        }
        decommitted_trees += @intFromBool(tree.decommitted);
    }
    if (decommitted_trees == 0 or
        description.quotient.sample_count !=
            description.quotient.term_count or
        description.quotient.source_column_count != sampled_columns)
    {
        return error.UnsupportedProtocol;
    }
    const total_fold = std.math.mul(
        usize,
        description.fri_tree_count - 1,
        description.fri_fold_step,
    ) catch return error.GeometryOverflow;
    const expected_last = std.math.sub(
        u32,
        description.first_fri_evaluation_log,
        std.math.cast(u32, total_fold) orelse
            return error.GeometryOverflow,
    ) catch return error.UnsupportedProtocol;
    if (expected_last != description.last_fri_evaluation_log)
        return error.UnsupportedProtocol;
}

test "layout accepts a nonempty preprocessed tree without workload branches" {
    const Geometry = struct { log_rows: u32 };
    const Descriptor = struct {
        pub fn describe(geometry: Geometry) !Description {
            return .{
                .trace_trees = .{
                    .{
                        .role = .preprocessed,
                        .column_count = 2,
                        .column_log_size = geometry.log_rows,
                        .commitment_log_size = geometry.log_rows + 1,
                        .sampled = true,
                        .decommitted = true,
                    },
                    .{
                        .role = .main,
                        .column_count = 1,
                        .column_log_size = geometry.log_rows,
                        .commitment_log_size = geometry.log_rows + 1,
                        .sampled = true,
                        .decommitted = true,
                    },
                    .{
                        .role = .composition,
                        .column_count = 8,
                        .column_log_size = geometry.log_rows,
                        .commitment_log_size = geometry.log_rows + 1,
                        .sampled = true,
                        .decommitted = true,
                    },
                },
                .fri_tree_count = geometry.log_rows,
                .first_fri_tree_index = 3,
                .first_fri_evaluation_log = geometry.log_rows + 1,
                .last_fri_evaluation_log = 2,
                .fri_fold_step = 1,
                .fri_log_rows_per_leaf = 0,
                .quotient = .{
                    .sample_count = 11,
                    .term_count = 11,
                    .structural_group_count = 1,
                    .source_column_count = 11,
                    .source_stride_words = @as(usize, 1) <<
                        @intCast(geometry.log_rows + 1),
                    .output_rows = @as(usize, 1) <<
                        @intCast(geometry.log_rows + 1),
                },
            };
        }
    };
    const Layout = LayoutFor(Geometry, Descriptor);
    var layout = try Layout.init(
        std.testing.allocator,
        .{ .log_rows = 3 },
    );
    defer layout.deinit(std.testing.allocator);
    try layout.validate();
    try std.testing.expectEqual(@as(usize, 2), layout.trace_trees[0].column_count);
    try std.testing.expectEqual(@as(usize, 3), layout.fri_trees[0].tree_index);
    var opened_columns: usize = 0;
    var sampled_columns: usize = 0;
    for (layout.trace_trees) |tree| {
        if (tree.decommitted) opened_columns += tree.column_count;
        if (tree.sampled) sampled_columns += tree.column_count;
    }
    try std.testing.expectEqual(@as(usize, 11), opened_columns);
    try std.testing.expectEqual(@as(usize, 11), sampled_columns);
    try std.testing.expectEqual(
        sampled_columns,
        layout.quotient.source_column_count,
    );
}
