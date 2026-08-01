//! One-submit circle LDE and resident Merkle commitment for large uniform trees.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const prover = @import("stwo_prover_engine");
const metal_merkle = @import("../merkle_tree.zig");
const shared_runtime = @import("../shared_runtime.zig");
const telemetry = @import("../telemetry.zig");

const M31 = m31.M31;
const ColumnEvaluation = prover.pcs.ColumnEvaluation;
const CircleCoefficients = prover.poly.circle.CircleCoefficients;
const ColumnSource = prover.pcs.ColumnSource;
const min_base_log_size: u32 = 16;
const min_deferred_base_log_size: u32 = 18;
const min_columns: usize = 64;
const composition_column_count: usize = 8;
const max_columns: usize = 256;

/// Reuses the established uniform-commit crossover as the minimum useful work
/// for a mixed-log epoch: eight log-16 columns' worth of base values, no shape
/// larger than the already-supported uniform maximum, and at least one log-16
/// column. This avoids paying a submit and terminal wait for tiny trees.
pub fn admitsMeasuredHeterogeneousShape(
    column_count: usize,
    maximum_base_log_size: u32,
    total_base_words: u64,
) bool {
    const minimum_base_words = @as(u64, composition_column_count) << min_base_log_size;
    return column_count >= 2 and column_count <= max_columns and
        maximum_base_log_size >= min_base_log_size and
        total_base_words >= minimum_base_words;
}

pub fn admitsDeferredQuadraticRecurrenceTrace(row_count: usize, column_count: usize) bool {
    return std.math.isPowerOfTwo(row_count) and
        row_count >= (1 << min_deferred_base_log_size) and
        column_count >= min_columns and column_count <= max_columns;
}

pub fn PreparedCommitment(comptime H: type) type {
    return struct {
        columns: []ColumnEvaluation,
        coefficients: []CircleCoefficients,
        column_backing_buffers: ?[][]M31,
        coefficient_backing_buffers: ?[][]M31,
        backing_teardown: ?prover.pcs.BackingTeardownToken = null,
        commitment: metal_merkle.MetalMerkleTree(H),
    };
}

/// Takes ownership only when the combined Metal epoch succeeds. Returning
/// `null` leaves every input column untouched for the generic fallback.
pub fn prepareAndCommitOwned(
    comptime H: type,
    allocator: std.mem.Allocator,
    owned_columns: []ColumnEvaluation,
    log_blowup_factor: u32,
    retention_policy: anytype,
    twiddle_source: anytype,
    source_backing_buffers: ?[][]M31,
    source: ColumnSource,
) !?PreparedCommitment(H) {
    const supported_column_count = owned_columns.len == composition_column_count or
        (owned_columns.len >= min_columns and owned_columns.len <= max_columns);
    if (retention_policy != .always or log_blowup_factor != 1 or
        !supported_column_count)
        return null;

    const base_log_size = owned_columns[0].log_size;
    if (base_log_size < min_base_log_size or base_log_size >= @bitSizeOf(usize) - 1) return null;
    const base_len = @as(usize, 1) << @intCast(base_log_size);
    for (owned_columns) |column| {
        column.validate() catch return null;
        if (column.log_size != base_log_size or column.values.len != base_len) return null;
    }
    const deferred_recipe: ?[7]u32 = switch (source) {
        .materialized => null,
        .quadratic_recurrence => |deferred| blk: {
            if (deferred.log_n_rows != base_log_size) return null;
            for (deferred.recipe) |value| if (value >= 0x7fffffff) return null;
            break :blk deferred.recipe;
        },
    };

    const extended_log_size = base_log_size + 1;
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);
    const page_words = std.heap.pageSize() / @sizeOf(M31);
    const page_rotate = owned_columns.len >= 64 and extended_len >= (1 << 18);
    const extended_stride = try std.math.add(
        usize,
        extended_len,
        if (page_rotate) page_words + 16 else 16,
    );
    const extended_span = try std.math.add(
        usize,
        try std.math.mul(usize, owned_columns.len - 1, extended_stride),
        extended_len,
    );
    const backing_words = std.mem.alignBackward(
        usize,
        try std.math.add(usize, extended_span, page_words - 1),
        page_words,
    );

    const base_words = try std.math.mul(usize, owned_columns.len, base_len);
    const reuse_source = source_backing_buffers != null and
        source_backing_buffers.?.len == 1 and
        source_backing_buffers.?[0].len == base_words and
        columnsCoverContiguousBacking(owned_columns, source_backing_buffers.?[0], base_len);
    if (deferred_recipe != null and !reuse_source) return null;
    const base_buffer = if (reuse_source)
        source_backing_buffers.?[0]
    else
        try allocator.alloc(M31, base_words);
    var keep_base = false;
    defer if (!reuse_source and !keep_base) allocator.free(base_buffer);
    const transform_buffer = try allocator.alloc(M31, backing_words);
    var keep_transform = false;
    defer if (!keep_transform) allocator.free(transform_buffer);

    const source_values = try allocator.alloc([]const M31, owned_columns.len);
    defer allocator.free(source_values);
    const base_values = try allocator.alloc([]M31, owned_columns.len);
    defer allocator.free(base_values);
    const extended_values = try allocator.alloc([]M31, owned_columns.len);
    defer allocator.free(extended_values);
    for (owned_columns, 0..) |column, index| {
        source_values[index] = column.values;
        base_values[index] = base_buffer[index * base_len ..][0..base_len];
        extended_values[index] = transform_buffer[index * extended_stride ..][0..extended_len];
    }

    const base_twiddles = try twiddle_source.get(allocator, base_log_size);
    const extended_twiddles = try twiddle_source.get(allocator, extended_log_size);
    var lease = shared_runtime.acquireExisting() catch return null;
    defer lease.deinit();
    const result = lease.runtime.transformCircleLdeAndCommitPrepared(
        allocator,
        source_values,
        base_values,
        extended_values,
        transform_buffer,
        0,
        extended_stride,
        base_twiddles.itwiddles,
        extended_twiddles.twiddles,
        base_log_size,
        extended_log_size,
        H.leafSeed(),
        H.nodeSeed(),
        H.domainPrefixBytes(),
        deferred_recipe,
        false,
    ) catch |err| if (reuse_source) return err else return null;
    const commitment = metal_merkle.MetalMerkleTree(H).fromSharedRuntime(result.tree) catch |err|
        if (reuse_source) return err else return null;
    errdefer {
        var owned_commitment = commitment;
        owned_commitment.deinit(allocator);
    }

    const columns = try allocator.alloc(ColumnEvaluation, owned_columns.len);
    errdefer allocator.free(columns);
    const coefficients = try allocator.alloc(CircleCoefficients, owned_columns.len);
    errdefer allocator.free(coefficients);
    for (columns, coefficients, base_values, extended_values) |*column, *coefficient, base, extended| {
        column.* = .{ .log_size = extended_log_size, .values = extended };
        coefficient.* = try CircleCoefficients.initBorrowed(base);
    }

    const column_backings = try allocator.alloc([]M31, 1);
    errdefer allocator.free(column_backings);
    column_backings[0] = transform_buffer;
    const coefficient_backings = if (reuse_source)
        source_backing_buffers.?
    else blk: {
        const buffers = try allocator.alloc([]M31, 1);
        buffers[0] = base_buffer;
        break :blk buffers;
    };
    errdefer if (!reuse_source) allocator.free(coefficient_backings);

    // The GPU has completed before the source trace is released. Returned
    // coefficient/evaluation slices borrow only the two retained backings.
    if (reuse_source) {
        allocator.free(owned_columns);
    } else if (source_backing_buffers) |buffers| {
        allocator.free(owned_columns);
        for (buffers) |buffer| allocator.free(buffer);
        allocator.free(buffers);
    } else {
        for (owned_columns) |column| allocator.free(column.values);
        allocator.free(owned_columns);
    }
    keep_base = true;
    keep_transform = true;
    telemetry.record(.metal_circle_lde_dispatch);
    if (deferred_recipe != null) telemetry.record(.metal_trace_generation_dispatch);
    telemetry.record(.resident_merkle_commit);
    std.log.debug("Metal circle LDE + Merkle epoch: {d:.3}ms", .{result.gpu_ms});
    return .{
        .columns = columns,
        .coefficients = coefficients,
        .column_backing_buffers = column_backings,
        .coefficient_backing_buffers = coefficient_backings,
        .commitment = commitment,
    };
}

/// Evaluates an already-interpolated secure composition split and builds its
/// Merkle tree in the same command buffer. The input polynomials remain
/// borrowed; the returned commitment owns contiguous coefficient and
/// evaluation arenas used by later PCS opening stages.
pub fn prepareAndCommitPolys(
    comptime H: type,
    allocator: std.mem.Allocator,
    polys: []const CircleCoefficients,
    log_blowup_factor: u32,
    retention_policy: anytype,
    twiddle_source: anytype,
) !?PreparedCommitment(H) {
    if (retention_policy != .always or log_blowup_factor != 1 or
        polys.len != composition_column_count)
        return null;

    const base_log_size = polys[0].logSize();
    if (base_log_size < min_base_log_size or base_log_size >= @bitSizeOf(usize) - 1)
        return null;
    const base_len = @as(usize, 1) << @intCast(base_log_size);
    for (polys) |poly| {
        if (poly.logSize() != base_log_size or poly.coefficients().len != base_len)
            return null;
    }

    const extended_log_size = base_log_size + 1;
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);
    const page_words = std.heap.pageSize() / @sizeOf(M31);
    const extended_stride = try std.math.add(usize, extended_len, 16);
    const extended_span = try std.math.add(
        usize,
        try std.math.mul(usize, polys.len - 1, extended_stride),
        extended_len,
    );
    const backing_words = std.mem.alignBackward(
        usize,
        try std.math.add(usize, extended_span, page_words - 1),
        page_words,
    );
    const base_words = try std.math.mul(usize, polys.len, base_len);

    const base_buffer = try allocator.alloc(M31, base_words);
    var keep_base = false;
    defer if (!keep_base) allocator.free(base_buffer);

    const transform_buffer = try allocator.alloc(M31, backing_words);
    var keep_transform = false;
    defer if (!keep_transform) allocator.free(transform_buffer);

    const source_values = try allocator.alloc([]const M31, polys.len);
    defer allocator.free(source_values);
    const base_values = try allocator.alloc([]M31, polys.len);
    defer allocator.free(base_values);
    const extended_values = try allocator.alloc([]M31, polys.len);
    defer allocator.free(extended_values);
    for (polys, 0..) |poly, index| {
        base_values[index] = base_buffer[index * base_len ..][0..base_len];
        source_values[index] = poly.coefficients();
        extended_values[index] = transform_buffer[index * extended_stride ..][0..extended_len];
    }

    const base_twiddles = try twiddle_source.get(allocator, base_log_size);
    const extended_twiddles = try twiddle_source.get(allocator, extended_log_size);
    var lease = shared_runtime.acquireExisting() catch return null;
    defer lease.deinit();
    const result = lease.runtime.transformCircleLdeAndCommitPrepared(
        allocator,
        source_values,
        base_values,
        extended_values,
        transform_buffer,
        0,
        extended_stride,
        base_twiddles.itwiddles,
        extended_twiddles.twiddles,
        base_log_size,
        extended_log_size,
        H.leafSeed(),
        H.nodeSeed(),
        H.domainPrefixBytes(),
        null,
        true,
    ) catch |err| {
        if (err == error.OutOfMemory) return err;
        return null;
    };
    const commitment = metal_merkle.MetalMerkleTree(H).fromSharedRuntime(result.tree) catch |err| {
        if (err == error.OutOfMemory) return err;
        return null;
    };
    errdefer {
        var owned_commitment = commitment;
        owned_commitment.deinit(allocator);
    }

    const columns = try allocator.alloc(ColumnEvaluation, polys.len);
    errdefer allocator.free(columns);
    const coefficients = try allocator.alloc(CircleCoefficients, polys.len);
    errdefer allocator.free(coefficients);
    for (columns, coefficients, base_values, extended_values) |*column, *coefficient, base, extended| {
        column.* = .{ .log_size = extended_log_size, .values = extended };
        coefficient.* = try CircleCoefficients.initBorrowed(base);
    }

    const column_backings = try allocator.alloc([]M31, 1);
    errdefer allocator.free(column_backings);
    column_backings[0] = transform_buffer;
    const coefficient_backings = try allocator.alloc([]M31, 1);
    errdefer allocator.free(coefficient_backings);
    coefficient_backings[0] = base_buffer;

    keep_base = true;
    keep_transform = true;
    telemetry.record(.metal_circle_lde_dispatch);
    telemetry.record(.resident_merkle_commit);
    std.log.debug("Metal coefficient LDE + Merkle epoch: {d:.3}ms", .{result.gpu_ms});
    return .{
        .columns = columns,
        .coefficients = coefficients,
        .column_backing_buffers = column_backings,
        .coefficient_backing_buffers = coefficient_backings,
        .commitment = commitment,
    };
}

fn columnsCoverContiguousBacking(
    columns: []const ColumnEvaluation,
    backing: []M31,
    column_len: usize,
) bool {
    const required_words = std.math.mul(usize, columns.len, column_len) catch return false;
    if (columns.len == 0 or backing.len != required_words) return false;
    for (columns, 0..) |column, index| {
        if (column.values.len != column_len or
            column.values.ptr != backing.ptr + index * column_len) return false;
    }
    return true;
}

test "combined commit admission constants remain large-shape only" {
    try std.testing.expect(min_base_log_size >= 16);
    try std.testing.expect(min_columns >= 64);
    try std.testing.expect(max_columns <= 256);
}
