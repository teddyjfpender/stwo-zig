//! Runtime binding for the single-submit circle-LDE/Merkle epoch.

const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");

const M31 = @import("stwo_core").fields.m31.M31;
const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;
const LdeCommitResult = runtime.LdeCommitResult;

pub fn transformCircleLdeAndCommit(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source_columns: []const []const M31,
    base_columns: []const []M31,
    extended_columns: []const []M31,
    transform_buffer: []M31,
    extended_start: usize,
    extended_stride: usize,
    inverse_twiddles: []const M31,
    forward_twiddles: []const M31,
    base_log_size: u32,
    extended_log_size: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
) (MetalError || std.mem.Allocator.Error)!LdeCommitResult {
    return transformCircleLdeAndCommitPreparedForHash(
        self,
        allocator,
        source_columns,
        base_columns,
        extended_columns,
        transform_buffer,
        extended_start,
        extended_stride,
        inverse_twiddles,
        forward_twiddles,
        base_log_size,
        extended_log_size,
        leaf_seed,
        node_seed,
        domain_prefix_bytes,
        1,
        null,
        false,
    );
}

pub fn transformCircleLdeAndCommitPrepared(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source_columns: []const []const M31,
    base_columns: []const []M31,
    extended_columns: []const []M31,
    transform_buffer: []M31,
    extended_start: usize,
    extended_stride: usize,
    inverse_twiddles: []const M31,
    forward_twiddles: []const M31,
    base_log_size: u32,
    extended_log_size: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    deferred_recipe: ?[7]u32,
    coefficients_ready: bool,
) (MetalError || std.mem.Allocator.Error)!LdeCommitResult {
    return transformCircleLdeAndCommitPreparedForHash(
        self,
        allocator,
        source_columns,
        base_columns,
        extended_columns,
        transform_buffer,
        extended_start,
        extended_stride,
        inverse_twiddles,
        forward_twiddles,
        base_log_size,
        extended_log_size,
        leaf_seed,
        node_seed,
        domain_prefix_bytes,
        1,
        deferred_recipe,
        coefficients_ready,
    );
}

pub fn transformCircleLdeAndCommitPreparedForHash(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source_columns: []const []const M31,
    base_columns: []const []M31,
    extended_columns: []const []M31,
    transform_buffer: []M31,
    extended_start: usize,
    extended_stride: usize,
    inverse_twiddles: []const M31,
    forward_twiddles: []const M31,
    base_log_size: u32,
    extended_log_size: u32,
    leaf_seed: [8]u32,
    node_seed: [8]u32,
    domain_prefix_bytes: u32,
    hash_family: u32,
    deferred_recipe: ?[7]u32,
    coefficients_ready: bool,
) (MetalError || std.mem.Allocator.Error)!LdeCommitResult {
    const supported_column_count = source_columns.len == 8 or
        (source_columns.len >= 64 and source_columns.len <= 256);
    if (!supported_column_count or source_columns.len != base_columns.len or
        base_columns.len != extended_columns.len or base_log_size < 16 or
        extended_log_size != base_log_size + 1 or extended_log_size >= 31 or
        extended_start > std.math.maxInt(u32) or extended_stride > std.math.maxInt(u32) or
        source_columns.len > std.math.maxInt(u32) or
        (hash_family != 1 and hash_family != 2))
        return MetalError.CircleTransformFailed;
    const base_len = @as(usize, 1) << @intCast(base_log_size);
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);
    if (inverse_twiddles.len != base_len / 2 or forward_twiddles.len != extended_len / 2)
        return MetalError.CircleTransformFailed;
    const column_span = std.math.mul(
        usize,
        extended_columns.len - 1,
        extended_stride,
    ) catch return MetalError.CircleTransformFailed;
    const required_prefix = std.math.add(
        usize,
        extended_start,
        column_span,
    ) catch return MetalError.CircleTransformFailed;
    const required_words = std.math.add(
        usize,
        required_prefix,
        extended_len,
    ) catch return MetalError.CircleTransformFailed;
    if (extended_stride < extended_len or required_words > transform_buffer.len)
        return MetalError.CircleTransformFailed;

    const source_ptrs = try allocator.alloc([*]const u32, source_columns.len);
    defer allocator.free(source_ptrs);
    const base_ptrs = try allocator.alloc([*]u32, base_columns.len);
    defer allocator.free(base_ptrs);
    for (source_columns, base_columns, extended_columns, 0..) |source, base, extended, index| {
        if (source.len != base_len or base.len != base_len or extended.len != extended_len or
            extended.ptr != transform_buffer.ptr + extended_start + index * extended_stride)
            return MetalError.CircleTransformFailed;
        source_ptrs[index] = @ptrCast(source.ptr);
        base_ptrs[index] = @ptrCast(base.ptr);
    }

    const scale_factor = if (coefficients_ready)
        M31.one().v
    else
        (M31.fromCanonical(@intCast(base_len)).inv() catch
            return MetalError.CircleTransformFailed).v;
    const transform_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(transform_buffer));
    const inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_twiddles));
    const forward_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(forward_twiddles));
    var normalization_batch_count: u32 = 0;
    var forward_skipped_layers: u32 = 0;
    var merkle_compressions: u64 = 0;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    var recipe_storage: [7]u32 = undefined;
    const recipe_ptr: ?*const [7]u32 = if (deferred_recipe) |recipe| blk: {
        for (recipe) |value| if (value >= 0x7fffffff)
            return MetalError.CircleTransformFailed;
        recipe_storage = recipe;
        break :blk &recipe_storage;
    } else null;
    const tree_handle = ffi.stwo_zig_metal_circle_lde_merkle_commit(
        self.handle,
        source_ptrs.ptr,
        base_ptrs.ptr,
        transform_words.ptr,
        transform_words.len,
        @intCast(extended_start),
        @intCast(extended_stride),
        @intCast(source_columns.len),
        base_log_size,
        extended_log_size,
        inverse_words.ptr,
        forward_words.ptr,
        scale_factor,
        @intFromBool(coefficients_ready),
        recipe_ptr,
        &leaf_seed,
        &node_seed,
        domain_prefix_bytes,
        hash_family,
        &normalization_batch_count,
        &forward_skipped_layers,
        &merkle_compressions,
        &gpu_ms,
        &message,
        message.len,
    ) orelse {
        std.log.debug("Metal combined LDE/Merkle declined: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CommitmentFailed;
    };
    return .{
        .gpu_ms = gpu_ms,
        .tree = .{
            .handle = tree_handle,
            .runtime_handle = self.handle,
            .log_size = extended_log_size,
        },
        .work = .{
            .normalization_batch_count = normalization_batch_count,
            .forward_skipped_layers = forward_skipped_layers,
            .merkle_compressions = merkle_compressions,
        },
    };
}
