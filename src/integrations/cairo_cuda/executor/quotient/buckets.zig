//! Deterministic native-height lowering for quotient numerator terms.
//!
//! Each source is evaluated once per row in its own domain. The later gather
//! reproduces the canonical bit-reversed lift into the group's output domain.

const std = @import("std");
const abi = @import("stwo_cuda_backend").abi.stages.quotient;
const types = @import("types.zig");

pub const Geometry = struct {
    bucket_count: usize,
    maximum_scratch_rows: usize,
};

pub const BucketDescriptor = @import("stwo_cuda_backend").runtime.stages.quotient.addressed.NativeBucket;

pub const Plan = struct {
    allocator: std.mem.Allocator,
    terms: []abi.BatchTermDescriptor,
    descriptors: []BucketDescriptor,
    group_bucket_offsets: []u32,
    maximum_scratch_rows: usize,

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.group_bucket_offsets);
        self.allocator.free(self.descriptors);
        self.allocator.free(self.terms);
        self.* = undefined;
    }
};

pub fn geometry(topology: types.Topology) !Geometry {
    if (topology.group_log_sizes.len == 0 or
        topology.group_offsets.len != topology.group_log_sizes.len + 1 or
        topology.group_offsets[0] != 0 or
        topology.group_offsets[topology.group_log_sizes.len] != topology.batch_terms.len)
    {
        return error.InvalidBucketTopology;
    }
    var buckets: usize = 0;
    var maximum: usize = 0;
    for (topology.group_log_sizes, 0..) |group_log, group| {
        if (group_log == 0 or group_log > 30) return error.InvalidBucketTopology;
        const begin = topology.group_offsets[group];
        const end = topology.group_offsets[group + 1];
        if (begin >= end or end > topology.batch_terms.len) return error.InvalidBucketTopology;
        var seen = [_]bool{false} ** 31;
        var scratch: usize = 0;
        for (topology.batch_terms[begin..end]) |term| {
            const log = term.source_log_size;
            if (log == 0 or log > group_log) return error.InvalidBucketTopology;
            if (seen[log]) continue;
            seen[log] = true;
            buckets = try std.math.add(usize, buckets, 1);
            scratch = @max(scratch, @as(usize, 1) << @intCast(log));
        }
        maximum = @max(maximum, scratch);
    }
    if (buckets > std.math.maxInt(u32) or maximum > std.math.maxInt(u32))
        return error.InvalidBucketTopology;
    return .{ .bucket_count = buckets, .maximum_scratch_rows = maximum };
}

pub fn build(allocator: std.mem.Allocator, topology: types.Topology) !Plan {
    const shape = try geometry(topology);
    const terms = try allocator.alloc(abi.BatchTermDescriptor, topology.batch_terms.len);
    errdefer allocator.free(terms);
    const descriptors = try allocator.alloc(BucketDescriptor, shape.bucket_count);
    errdefer allocator.free(descriptors);
    const offsets = try allocator.alloc(u32, topology.group_log_sizes.len + 1);
    errdefer allocator.free(offsets);
    var term_cursor: usize = 0;
    var bucket_cursor: usize = 0;
    offsets[0] = 0;
    for (topology.group_log_sizes, 0..) |group_log, group| {
        const begin = topology.group_offsets[group];
        const end = topology.group_offsets[group + 1];
        var scratch: usize = 0;
        for (1..@as(usize, group_log) + 1) |log| {
            const bucket_begin = term_cursor;
            for (topology.batch_terms[begin..end]) |term| {
                if (term.source_log_size != log) continue;
                terms[term_cursor] = term;
                term_cursor += 1;
            }
            if (term_cursor == bucket_begin) continue;
            descriptors[bucket_cursor] = .{
                .term_begin = @intCast(bucket_begin),
                .term_end = @intCast(term_cursor),
                .source_log_size = @intCast(log),
            };
            bucket_cursor += 1;
            scratch = @max(scratch, @as(usize, 1) << @intCast(log));
        }
        if (term_cursor != end or scratch > shape.maximum_scratch_rows)
            return error.InvalidBucketTopology;
        offsets[group + 1] = @intCast(bucket_cursor);
    }
    if (term_cursor != terms.len or bucket_cursor != descriptors.len)
        return error.InvalidBucketTopology;
    return .{
        .allocator = allocator,
        .terms = terms,
        .descriptors = descriptors,
        .group_bucket_offsets = offsets,
        .maximum_scratch_rows = shape.maximum_scratch_rows,
    };
}

test "native-height buckets retain every term and bound scratch by the next domain" {
    const allocator = std.testing.allocator;
    const source_terms = [_]abi.BatchTermDescriptor{
        .{ .source_index = 0, .term_index = 0, .source_log_size = 5 },
        .{ .source_index = 1, .term_index = 1, .source_log_size = 2 },
        .{ .source_index = 2, .term_index = 2, .source_log_size = 5 },
        .{ .source_index = 3, .term_index = 3, .source_log_size = 3 },
    };
    const offsets = [_]u32{ 0, 3, 4 };
    const logs = [_]u32{ 5, 3 };
    const topology = types.Topology{
        .allocator = allocator,
        .prepared_terms = undefined,
        .group_offsets = @constCast(&offsets),
        .group_term_indices = undefined,
        .batch_terms = @constCast(&source_terms),
        .sources = undefined,
        .source_trees = undefined,
        .group_log_sizes = @constCast(&logs),
        .partial_log_sizes = undefined,
        .partial_offsets = undefined,
        .sampled_value_count = 0,
        .source_evaluation_word_count = 0,
        .maximum_partial_rows = 32,
        .identity = [_]u8{0} ** 32,
    };
    const shape = try geometry(topology);
    try std.testing.expectEqual(@as(usize, 3), shape.bucket_count);
    try std.testing.expectEqual(@as(usize, 32), shape.maximum_scratch_rows);
    var plan = try build(allocator, topology);
    defer plan.deinit();
    try std.testing.expectEqualSlices(u32, &.{ 0, 2, 3 }, plan.group_bucket_offsets);
    try std.testing.expectEqual(@as(u32, 1), plan.terms[0].term_index);
    try std.testing.expectEqual(@as(u32, 0), plan.terms[1].term_index);
    try std.testing.expectEqual(@as(u32, 2), plan.terms[2].term_index);
    try std.testing.expectEqual(@as(u32, 3), plan.terms[3].term_index);
}
