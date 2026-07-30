//! Exact OODS and quotient topology for Native Poseidon.

const std = @import("std");
const quotient_abi = @import("stwo_cuda_backend").abi.stages.quotient;
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

const main_end: u32 = 1264;
const interaction_single_end: u32 = main_end + 28;
const interaction_sample_end: u32 = interaction_single_end + 8;

pub const sample_batches = [_]SampleBatch{
    .{
        .role = .main,
        .first_column = 0,
        .column_count = 1264,
        .first_execution_sample = 0,
    },
    .{
        .role = .interaction,
        .first_column = 0,
        .column_count = 28,
        .first_execution_sample = main_end,
    },
    .{
        .role = .interaction,
        .first_column = 28,
        .column_count = 4,
        .first_execution_sample = interaction_single_end,
    },
    .{
        .role = .interaction,
        .first_column = 28,
        .column_count = 4,
        .first_execution_sample = interaction_single_end + 4,
    },
    .{
        .role = .composition,
        .first_column = 0,
        .column_count = 16,
        .first_execution_sample = interaction_sample_end,
    },
};

/// Canonical proof sample -> resident source column.
pub const sample_source_indices = sampleSources();

/// Execution sample -> canonical proof sample. The previous-point samples for
/// the final secure column are evaluated as one copy-free four-column batch.
pub const sample_output_indices = sampleOutputs();

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
        const log_size = logical.trace_trees[1].commitment_log_size;
        const prepared = try allocator.alloc(
            quotient_abi.PreparedTermDescriptor,
            sample_count,
        );
        errdefer allocator.free(prepared);
        const group_offsets = try allocator.dupe(u32, &.{ 0, samples });
        errdefer allocator.free(group_offsets);
        const indices = try allocator.alloc(u32, sample_count);
        errdefer allocator.free(indices);
        const batch = try allocator.alloc(
            quotient_abi.BatchTermDescriptor,
            sample_count,
        );
        errdefer allocator.free(batch);
        const group_logs = try allocator.dupe(u32, &.{log_size});
        errdefer allocator.free(group_logs);
        const partial_logs = try allocator.dupe(u32, &.{log_size});
        errdefer allocator.free(partial_logs);
        for (0..sample_count) |index| {
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
                .source_index = sample_source_indices[index],
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

fn sampleSources() [geometry_mod.sampled_mask_points]u32 {
    @setEvalBranchQuota(10_000);
    var result: [geometry_mod.sampled_mask_points]u32 = undefined;
    for (0..interaction_single_end) |index| {
        result[index] = @intCast(index);
    }
    for (0..4) |coordinate| {
        const sample = interaction_single_end + coordinate * 2;
        const source = interaction_single_end + coordinate;
        result[sample] = source;
        result[sample + 1] = source;
    }
    for (interaction_sample_end..geometry_mod.sampled_mask_points) |index| {
        result[index] = index - 4;
    }
    return result;
}

fn sampleOutputs() [geometry_mod.sampled_mask_points]u32 {
    @setEvalBranchQuota(10_000);
    var result: [geometry_mod.sampled_mask_points]u32 = undefined;
    for (0..interaction_single_end) |index| {
        result[index] = @intCast(index);
    }
    for (0..4) |coordinate| {
        result[interaction_single_end + coordinate] =
            interaction_single_end + @as(u32, @intCast(coordinate * 2));
        result[interaction_single_end + 4 + coordinate] =
            interaction_single_end + @as(u32, @intCast(coordinate * 2 + 1));
    }
    for (interaction_sample_end..geometry_mod.sampled_mask_points) |index| {
        result[index] = @intCast(index);
    }
    return result;
}

fn u32Count(value: usize) !u32 {
    return std.math.cast(u32, value) orelse error.GeometryOverflow;
}

test "exact topology repeats only final interaction coordinate sources" {
    const geometry = try geometry_mod.admit(
        .{ .log_n_instances = 13 },
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    var logical = try layout.Layout.init(std.testing.allocator, geometry);
    defer logical.deinit(std.testing.allocator);
    var quotient = try Quotient.init(std.testing.allocator, logical);
    defer quotient.deinit(std.testing.allocator);
    var decommit = try Decommit.init(std.testing.allocator, logical);
    defer decommit.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(u32, 1312), quotient.source_count);
    try std.testing.expectEqual(@as(usize, 1316), quotient.batch_terms.len);
    try std.testing.expectEqual(
        quotient.batch_terms[1292].source_index,
        quotient.batch_terms[1293].source_index,
    );
    try std.testing.expectEqual(@as(usize, 3), decommit.trace_trees.len);
    try std.testing.expectEqual(@as(usize, 1312), decommit.column_log_sizes.len);
    try std.testing.expectEqual(@as(usize, 5), sample_batches.len);
}
