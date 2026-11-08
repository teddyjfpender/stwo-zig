//! Checked logical-work arithmetic and backend-independent schedule formulas.

const std = @import("std");
const Error = @import("work_profile_core.zig").Error;
const Counters = @import("work_profile_core.zig").Counters;
const FieldOperations = @import("work_profile_core.zig").FieldOperations;

pub fn addCounter(lhs: u64, rhs: u64) Error!u64 {
    return std.math.add(u64, lhs, rhs) catch error.CounterOverflow;
}

pub fn multiplyCounter(lhs: u64, rhs: u64) Error!u64 {
    return std.math.mul(u64, lhs, rhs) catch error.CounterOverflow;
}

pub fn logicalFftButterflies(log_size: u32, skipped_layers: u32) Error!u64 {
    if (skipped_layers > log_size or log_size >= @bitSizeOf(u64))
        return error.CounterOverflow;
    const element_count = @as(u64, 1) << @intCast(log_size);
    const pair_count = element_count >> 1;
    return std.math.mul(
        u64,
        pair_count,
        @as(u64, log_size - skipped_layers),
    ) catch error.CounterOverflow;
}

/// Scalar M31 work executed by a forward radix-2 FFT boundary. Each logical
/// butterfly performs one multiplication and two additions/subtractions;
/// negation and data movement are free under the v1 counter semantics.
pub fn logicalM31ForwardFftFieldOperations(
    butterflies: u64,
) Error!FieldOperations {
    return .{
        .additions = std.math.mul(u64, butterflies, 2) catch
            return error.CounterOverflow,
        .multiplications = butterflies,
        .inversions = 0,
    };
}

/// Exact logical work of one batched M31 circle interpolation. A batch shares
/// its domain normalization inverse; the FFT kernels may fuse or vectorize
/// stages, but report the equivalent scalar-lane butterfly and normalization
/// work under the stable V2 counter semantics.
pub fn logicalM31InterpolationWork(
    log_size: u32,
    batch_column_count: u64,
) Error!Counters {
    return logicalM31InterpolationExecutionWork(
        log_size,
        batch_column_count,
        1,
    );
}

pub fn logicalM31InterpolationExecutionWork(
    log_size: u32,
    column_count: u64,
    batch_count: u64,
) Error!Counters {
    if (column_count == 0 or batch_count == 0 or batch_count > column_count or
        log_size == 0 or log_size >= @bitSizeOf(u64))
        return error.InvalidCounterGroup;

    const element_count = @as(u64, 1) << @intCast(log_size);
    const butterflies = try multiplyCounter(
        try logicalFftButterflies(log_size, 0),
        column_count,
    );
    const additions = try multiplyCounter(butterflies, 2);
    const multiplications = switch (log_size) {
        1 => try addCounter(
            try multiplyCounter(column_count, 3),
            try multiplyCounter(batch_count, 3),
        ),
        2 => try addCounter(
            try multiplyCounter(column_count, 8),
            try multiplyCounter(batch_count, 8),
        ),
        else => try addCounter(
            butterflies,
            try multiplyCounter(column_count, element_count),
        ),
    };
    return .{
        .field_additions = additions,
        .field_multiplications = multiplications,
        .field_inversions = batch_count,
        .fft_butterflies = butterflies,
    };
}

/// Exact scalar M31 work for constructing one cold canonical twiddle tree.
/// `circle_log - 1` is the root-coset log. Small trees invert every twiddle
/// directly; large power-of-two trees execute 4096-element striped batches.
pub fn logicalM31ColdTwiddleWork(circle_log: u32) Error!Counters {
    if (circle_log == 0 or circle_log - 1 >= @bitSizeOf(u64))
        return error.InvalidCounterGroup;

    const root_log = circle_log - 1;
    const tree_size = @as(u64, 1) << @intCast(root_log);
    const non_identity_points = tree_size - 1;
    const additions = try addCounter(
        try multiplyCounter(non_identity_points, 2),
        try multiplyCounter(root_log, 4),
    );
    var multiplications = try addCounter(
        try multiplyCounter(non_identity_points, 4),
        try multiplyCounter(root_log, 8),
    );
    const chunk_size: u64 = 1 << 12;
    const inversions: u64 = if (tree_size < chunk_size)
        tree_size
    else blk: {
        const chunk_count = tree_size / chunk_size;
        multiplications = try addCounter(
            multiplications,
            try multiplyCounter(
                chunk_count,
                try addCounter(try multiplyCounter(chunk_size, 3), 5),
            ),
        );
        break :blk chunk_count;
    };
    return .{
        .field_additions = additions,
        .field_multiplications = multiplications,
        .field_inversions = inversions,
    };
}

/// Internal parent compressions completed by one full binary Merkle tree.
/// Constant-reuse implementations hash one representative parent per layer;
/// ordinary implementations materialize every internal node.
pub fn logicalMerkleCompressions(
    leaf_count: u64,
    reuses_constant_parents: bool,
) Error!u64 {
    if (leaf_count == 0 or !std.math.isPowerOfTwo(leaf_count))
        return error.InvalidCounterGroup;
    return if (reuses_constant_parents)
        @intCast(std.math.log2_int(u64, leaf_count))
    else
        leaf_count - 1;
}
