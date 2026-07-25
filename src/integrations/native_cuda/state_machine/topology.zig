//! Exact mixed-height OODS, quotient, FRI, and opening topology for State v2.

const std = @import("std");
const quotient_abi = @import(
    "../../../backends/cuda/abi/stages/quotient.zig",
);
const geometry_mod = @import("geometry.zig");
const layout = @import("layout.zig");
const oods_batches = @import("../common/oods_batches.zig");
const shared = @import("../common/uniform_topology.zig");

const Set = shared.TopologyFor(layout.Layout);

pub const FriLayer = Set.FriLayer;
pub const Fri = Set.Fri;
pub const TraceOpening = Set.TraceOpening;
pub const FriOpening = Set.FriOpening;
pub const Decommit = Set.Decommit;
pub const SampleBatch = oods_batches.Descriptor;

/// Execution batches are grouped by coefficient height and mask point. The
/// order is deliberately different from canonical proof order to keep every
/// resident source view contiguous.
pub const sample_batches = [_]SampleBatch{
    .{ .role = .main, .first_column = 0, .column_count = 2, .first_execution_sample = 0 },
    .{ .role = .main, .first_column = 2, .column_count = 2, .first_execution_sample = 2 },
    .{ .role = .interaction, .first_column = 0, .column_count = 4, .first_execution_sample = 4 },
    .{ .role = .interaction, .first_column = 0, .column_count = 4, .first_execution_sample = 8 },
    .{ .role = .interaction, .first_column = 4, .column_count = 4, .first_execution_sample = 12 },
    .{ .role = .interaction, .first_column = 4, .column_count = 4, .first_execution_sample = 16 },
    .{ .role = .composition, .first_column = 0, .column_count = 8, .first_execution_sample = 20 },
};

/// Canonical proof sample -> resident coefficient source.
pub const sample_source_indices = [_]u32{
    0,  1,  2,  3,
    4,  4,  5,  5,
    6,  6,  7,  7,
    8,  8,  9,  9,
    10, 10, 11, 11,
    12, 13, 14, 15,
    16, 17, 18, 19,
};

/// OODS execution sample -> canonical proof sample.
pub const sample_output_indices = [_]u32{
    0,  1,  2,  3,
    4,  6,  8,  10,
    5,  7,  9,  11,
    12, 14, 16, 18,
    13, 15, 17, 19,
    20, 21, 22, 23,
    24, 25, 26, 27,
};

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
        logical: layout.Layout,
    ) !Quotient {
        const sample_count = logical.quotient.sample_count;
        if (sample_count != sample_source_indices.len or
            logical.quotient.source_column_count !=
                geometry_mod.source_columns)
        {
            return error.UnsupportedProtocol;
        }
        const samples = try u32Count(sample_count);
        const source_count = try u32Count(
            logical.quotient.source_column_count,
        );
        const commitment_log =
            logical.trace_trees[1].commitment_log_size;
        const prepared = try allocator.alloc(
            quotient_abi.PreparedTermDescriptor,
            sample_count,
        );
        errdefer allocator.free(prepared);
        const group_offsets = try allocator.dupe(
            u32,
            &.{ 0, samples },
        );
        errdefer allocator.free(group_offsets);
        const indices = try allocator.alloc(u32, sample_count);
        errdefer allocator.free(indices);
        const batch = try allocator.alloc(
            quotient_abi.BatchTermDescriptor,
            sample_count,
        );
        errdefer allocator.free(batch);
        const group_logs = try allocator.dupe(
            u32,
            &.{commitment_log},
        );
        errdefer allocator.free(group_logs);
        const partial_logs = try allocator.dupe(
            u32,
            &.{commitment_log},
        );
        errdefer allocator.free(partial_logs);

        for (0..sample_count) |index| {
            const ordinal = try u32Count(index);
            const source_index = sample_source_indices[index];
            prepared[index] = .{
                .sample_index = ordinal,
                .exponent = ordinal,
                .periodic = 0,
                .period_x = 0,
                .period_y = 0,
            };
            indices[index] = ordinal;
            batch[index] = .{
                .source_index = source_index,
                .term_index = ordinal,
                .source_log_size = try sourceCommitmentLog(
                    logical,
                    source_index,
                ),
            };
        }
        return .{
            .prepared_terms = prepared,
            .group_offsets = group_offsets,
            .group_term_indices = indices,
            .batch_terms = batch,
            .group_log_sizes = group_logs,
            .partial_log_sizes = partial_logs,
            .source_count = source_count,
            .source_stride_words = logical.quotient.source_stride_words,
            .output_rows = try u32Count(logical.quotient.output_rows),
        };
    }

    pub fn deinit(self: *Quotient, allocator: std.mem.Allocator) void {
        allocator.free(self.prepared_terms);
        allocator.free(self.group_offsets);
        allocator.free(self.group_term_indices);
        allocator.free(self.batch_terms);
        allocator.free(self.group_log_sizes);
        allocator.free(self.partial_log_sizes);
        self.* = undefined;
    }
};

fn sourceCommitmentLog(
    logical: layout.Layout,
    source_index: u32,
) !u32 {
    var first: usize = 0;
    for (logical.trace_trees, 0..) |tree, tree_index| {
        if (!tree.sampled) continue;
        const index: usize = @intCast(source_index);
        if (index < first + tree.column_count) {
            return logical.columnCommitmentLogSize(
                tree_index,
                index - first,
            );
        }
        first += tree.column_count;
    }
    return error.UnsupportedProtocol;
}

fn u32Count(value: usize) !u32 {
    return std.math.cast(u32, value) orelse
        error.GeometryOverflow;
}

test "State v2 topology preserves mixed source logs and four trees" {
    const geometry = try geometry_mod.admit(
        .{
            .log_n_rows = 16,
            .initial_state = .{
                @import("stwo_core").fields.m31.M31.fromU64(9),
                @import("stwo_core").fields.m31.M31.fromU64(3),
            },
        },
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    var logical = try layout.Layout.init(std.testing.allocator, geometry);
    defer logical.deinit(std.testing.allocator);
    var quotient = try Quotient.init(std.testing.allocator, logical);
    defer quotient.deinit(std.testing.allocator);
    var decommit = try Decommit.init(std.testing.allocator, logical);
    defer decommit.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 20), quotient.source_count);
    try std.testing.expectEqual(@as(usize, 28), quotient.batch_terms.len);
    try std.testing.expectEqual(@as(u32, 17), quotient.batch_terms[0].source_log_size);
    try std.testing.expectEqual(@as(u32, 16), quotient.batch_terms[2].source_log_size);
    try std.testing.expectEqual(@as(u32, 17), quotient.batch_terms[4].source_log_size);
    try std.testing.expectEqual(@as(u32, 16), quotient.batch_terms[12].source_log_size);
    try std.testing.expectEqual(@as(usize, 3), decommit.trace_trees.len);
    try std.testing.expectEqual(@as(usize, 20), decommit.column_log_sizes.len);
    try std.testing.expectEqualSlices(
        u32,
        &.{ 17, 17, 16, 16 },
        decommit.column_log_sizes[0..4],
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 17, 17, 17, 17, 16, 16, 16, 16 },
        decommit.column_log_sizes[4..12],
    );
    try std.testing.expectEqual(@as(usize, 7), sample_batches.len);
}
