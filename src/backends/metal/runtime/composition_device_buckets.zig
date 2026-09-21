//! Distinct output ownership for sequential resident composition commands.

const std = @import("std");
const metal_runtime = @import("../runtime.zig");
const prover = @import("stwo_prover_engine");

const SecureColumn = prover.secure_column.SecureColumnByCoords;

/// One device command owns one zero-initialized output set. The Objective-C
/// batch ABI copies a completed command back to these host destinations; two
/// commands must therefore never alias one set before their explicit merge.
pub const DeviceBucketSet = struct {
    allocator: std.mem.Allocator,
    output_index_by_log: []?u32,
    buckets: []?SecureColumn,
    outputs: []metal_runtime.BasePolynomialOutput,

    pub fn init(
        allocator: std.mem.Allocator,
        max_log_size: u32,
        jobs: anytype,
    ) !DeviceBucketSet {
        if (max_log_size >= @bitSizeOf(usize))
            return error.InvalidBasePolynomialProgram;
        const slot_count = @as(usize, max_log_size) + 1;
        const output_index_by_log = try allocator.alloc(?u32, slot_count);
        errdefer allocator.free(output_index_by_log);
        @memset(output_index_by_log, null);

        var output_count: usize = 0;
        for (jobs) |job| {
            if (job.eval_log_size > max_log_size)
                return error.InvalidBasePolynomialProgram;
            if (output_index_by_log[job.eval_log_size] == null) {
                output_index_by_log[job.eval_log_size] = @intCast(output_count);
                output_count += 1;
            }
        }

        const buckets = try allocator.alloc(?SecureColumn, slot_count);
        errdefer allocator.free(buckets);
        @memset(buckets, null);
        errdefer for (buckets) |*bucket| if (bucket.*) |*owned|
            owned.deinit(allocator);

        const outputs = try allocator.alloc(
            metal_runtime.BasePolynomialOutput,
            output_count,
        );
        errdefer allocator.free(outputs);
        for (output_index_by_log, 0..) |maybe_output, log_size| {
            const output_index = maybe_output orelse continue;
            const row_count = @as(usize, 1) << @intCast(log_size);
            buckets[log_size] = try SecureColumn.zeros(allocator, row_count);
            const bucket = &buckets[log_size].?;
            var columns: [4][*]u32 = undefined;
            inline for (0..4) |coordinate|
                columns[coordinate] = @ptrCast(bucket.columns[coordinate].ptr);
            outputs[output_index] = .{
                .columns = columns,
                .row_count = @intCast(row_count),
            };
        }
        return .{
            .allocator = allocator,
            .output_index_by_log = output_index_by_log,
            .buckets = buckets,
            .outputs = outputs,
        };
    }

    pub fn deinit(self: *DeviceBucketSet) void {
        for (self.buckets) |*bucket| if (bucket.*) |*owned|
            owned.deinit(self.allocator);
        self.allocator.free(self.outputs);
        self.allocator.free(self.buckets);
        self.allocator.free(self.output_index_by_log);
        self.* = undefined;
    }

    pub fn outputIndex(self: *const DeviceBucketSet, log_size: u32) u32 {
        return self.output_index_by_log[log_size].?;
    }
};

/// Canonically adds two completed device results. Shape is checked first, so
/// failure leaves both owners untouched. Unique source buckets move without an
/// allocation; overlapping buckets remain independently owned until cleanup.
pub fn mergeCompleted(
    destination: *DeviceBucketSet,
    source: *DeviceBucketSet,
) !void {
    if (destination.buckets.len != source.buckets.len)
        return error.InvalidBasePolynomialOutputShape;
    for (destination.buckets, source.buckets) |maybe_destination, maybe_source| {
        const source_bucket = maybe_source orelse continue;
        if (maybe_destination) |destination_bucket| {
            if (destination_bucket.len() != source_bucket.len())
                return error.InvalidBasePolynomialOutputShape;
        }
    }
    for (destination.buckets, source.buckets) |*maybe_destination, *maybe_source| {
        const source_bucket = maybe_source.* orelse continue;
        if (maybe_destination.*) |*destination_bucket| {
            inline for (0..4) |coordinate| {
                for (
                    destination_bucket.columns[coordinate],
                    source_bucket.columns[coordinate],
                ) |*lhs, rhs| lhs.* = lhs.add(rhs);
            }
        } else {
            maybe_destination.* = source_bucket;
            maybe_source.* = null;
        }
    }
}

const FixtureJob = struct { eval_log_size: u32 };

fn fill(set: *DeviceBucketSet, seed: u32) void {
    for (set.buckets, 0..) |*maybe_bucket, log_size| {
        if (maybe_bucket.*) |*bucket| {
            inline for (0..4) |coordinate| {
                for (bucket.columns[coordinate], 0..) |*value, row| {
                    value.* = @import("stwo_core").fields.m31.M31.fromCanonical(
                        @intCast(
                            @as(usize, seed) + log_size * 100 +
                                coordinate * 10 + row,
                        ),
                    );
                }
            }
        }
    }
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    const jobs = [_]FixtureJob{ .{ .eval_log_size = 2 }, .{ .eval_log_size = 4 } };
    var buckets = try DeviceBucketSet.init(allocator, 4, &jobs);
    defer buckets.deinit();
}

test "Metal composition keeps retained semantic and lookup roster outputs disjoint then merges" {
    var semantic_jobs: [78]FixtureJob = undefined;
    for (&semantic_jobs, 0..) |*job, index|
        job.* = .{ .eval_log_size = @intCast(2 + index % 2) };
    var lookup_jobs: [75]FixtureJob = undefined;
    for (&lookup_jobs, 0..) |*job, index|
        job.* = .{ .eval_log_size = @intCast(2 + 2 * (index % 2)) };

    var semantic = try DeviceBucketSet.init(
        std.testing.allocator,
        4,
        &semantic_jobs,
    );
    defer semantic.deinit();
    var lookup = try DeviceBucketSet.init(
        std.testing.allocator,
        4,
        &lookup_jobs,
    );
    defer lookup.deinit();
    fill(&semantic, 1);
    fill(&lookup, 10_000);

    const semantic_before = semantic.buckets[2].?.at(3);
    const lookup_before = lookup.buckets[2].?.at(3);
    try mergeCompleted(&semantic, &lookup);
    try std.testing.expect(
        semantic.buckets[2].?.at(3).eql(semantic_before.add(lookup_before)),
    );
    try std.testing.expect(lookup.buckets[2].?.at(3).eql(lookup_before));
    try std.testing.expect(semantic.buckets[4] != null);
    try std.testing.expect(lookup.buckets[4] == null);
}

test "Metal composition device bucket ownership cleans every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
