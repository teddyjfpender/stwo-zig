//! Circle transforms, LDE dispatch, and recurrence composition.

const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const telemetry = @import("../telemetry.zig");
const work_profile = @import("stwo_prover_api").work_profile;

const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;
pub const CircleLdeExecutionResult = struct {
    gpu_milliseconds: f64,
    execution: work_profile.M31CircleLdeExecution,
};

fn circleLdeExecutionFromDeviceReceipt(
    base_log_size: u32,
    extended_log_size: u32,
    column_count: usize,
    normalization_batch_count: u32,
    forward_skipped_layers: u32,
) MetalError!work_profile.M31CircleLdeExecution {
    const execution = work_profile.M31CircleLdeExecution{
        .interpolation = .{
            .log_size = base_log_size,
            .column_count = @intCast(column_count),
            .batch_count = normalization_batch_count,
        },
        .forward = .{
            .log_size = extended_log_size,
            .column_count = @intCast(column_count),
            .skipped_layers = forward_skipped_layers,
        },
    };
    execution.validate() catch return MetalError.CircleTransformFailed;
    return execution;
}

test "Metal circle LDE receipt rejects missing device execution counts" {
    const receipt = try circleLdeExecutionFromDeviceReceipt(12, 13, 65, 1, 1);
    try std.testing.expectEqual(@as(u64, 1), receipt.interpolation.batch_count);
    try std.testing.expectEqual(@as(u32, 1), receipt.forward.skipped_layers);
    try std.testing.expectError(
        MetalError.CircleTransformFailed,
        circleLdeExecutionFromDeviceReceipt(12, 13, 65, 0, 1),
    );
    try std.testing.expectError(
        MetalError.CircleTransformFailed,
        circleLdeExecutionFromDeviceReceipt(12, 13, 65, 1, 14),
    );
}

pub fn transformCircle(
    self: *Runtime,
    allocator: std.mem.Allocator,
    columns: []const []@import("stwo_core").fields.m31.M31,
    twiddles: []const @import("stwo_core").fields.m31.M31,
    log_size: u32,
    inverse: bool,
) (MetalError || std.mem.Allocator.Error)!f64 {
    if (columns.len == 0 or log_size < 3) return MetalError.CircleTransformFailed;
    const expected_len = @as(usize, 1) << @intCast(log_size);
    if (twiddles.len != expected_len / 2) return MetalError.CircleTransformFailed;
    const pointers = try allocator.alloc([*]u32, columns.len);
    defer allocator.free(pointers);
    for (columns, 0..) |column, index| {
        if (column.len != expected_len) return MetalError.CircleTransformFailed;
        pointers[index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)).ptr;
    }
    const scale_factor = if (inverse)
        (@import("stwo_core").fields.m31.M31.fromCanonical(@intCast(expected_len)).inv() catch
            return MetalError.CircleTransformFailed).v
    else
        1;
    const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(twiddles));
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_circle_transform(
        self.handle,
        pointers.ptr,
        @intCast(columns.len),
        log_size,
        words.ptr,
        inverse,
        scale_factor,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal circle transform failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

/// Allocation-free single-column transform for arena recomputation. The
/// column pointer already aliases resident shared storage.
pub fn transformCircleResident(
    self: *Runtime,
    column: []@import("stwo_core").fields.m31.M31,
    twiddles: []const @import("stwo_core").fields.m31.M31,
    log_size: u32,
    inverse: bool,
) MetalError!f64 {
    if (log_size < 3) return MetalError.CircleTransformFailed;
    const expected_len = @as(usize, 1) << @intCast(log_size);
    if (column.len != expected_len or twiddles.len != expected_len / 2) return MetalError.CircleTransformFailed;
    var pointers = [_][*]u32{std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)).ptr};
    const scale_factor = if (inverse)
        (@import("stwo_core").fields.m31.M31.fromCanonical(@intCast(expected_len)).inv() catch
            return MetalError.CircleTransformFailed).v
    else
        1;
    const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(twiddles));
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_circle_transform(
        self.handle,
        &pointers,
        1,
        log_size,
        words.ptr,
        inverse,
        scale_factor,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal resident circle recomputation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

pub fn transformCircleLdeInto(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source_columns: []const []const @import("stwo_core").fields.m31.M31,
    base_columns: []const []@import("stwo_core").fields.m31.M31,
    extended_columns: []const []@import("stwo_core").fields.m31.M31,
    transform_buffer: []@import("stwo_core").fields.m31.M31,
    extended_start: usize,
    extended_stride: usize,
    inverse_twiddles: []const @import("stwo_core").fields.m31.M31,
    forward_twiddles: []const @import("stwo_core").fields.m31.M31,
    base_log_size: u32,
    extended_log_size: u32,
) (MetalError || std.mem.Allocator.Error)!CircleLdeExecutionResult {
    if (base_columns.len == 0 or source_columns.len != base_columns.len or base_columns.len != extended_columns.len or base_log_size < 3 or extended_log_size <= base_log_size) {
        return MetalError.CircleTransformFailed;
    }
    const base_len = @as(usize, 1) << @intCast(base_log_size);
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);
    if (inverse_twiddles.len != base_len / 2 or forward_twiddles.len != extended_len / 2) return MetalError.CircleTransformFailed;
    const base_ptrs = try allocator.alloc([*]u32, base_columns.len);
    defer allocator.free(base_ptrs);
    const source_ptrs = try allocator.alloc([*]const u32, source_columns.len);
    defer allocator.free(source_ptrs);
    for (source_columns, base_columns, extended_columns, 0..) |source, base, extended, index| {
        if (source.len != base_len or base.len != base_len or extended.len != extended_len) return MetalError.CircleTransformFailed;
        if (extended.ptr != transform_buffer.ptr + extended_start + index * extended_stride) {
            return MetalError.CircleTransformFailed;
        }
        source_ptrs[index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(source)).ptr;
        base_ptrs[index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(base)).ptr;
    }
    const required_words = extended_start + (extended_columns.len - 1) * extended_stride + extended_len;
    if (extended_stride < extended_len or required_words > transform_buffer.len) return MetalError.CircleTransformFailed;
    const transform_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(transform_buffer));
    const inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_twiddles));
    const forward_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(forward_twiddles));
    const scale_factor = (@import("stwo_core").fields.m31.M31.fromCanonical(@intCast(base_len)).inv() catch
        return MetalError.CircleTransformFailed).v;
    var gpu_ms: f64 = 0;
    var source_binding: u32 = 0;
    var normalization_batch_count: u32 = 0;
    var forward_skipped_layers: u32 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_circle_lde(
        self.handle,
        source_ptrs.ptr,
        base_ptrs.ptr,
        transform_words.ptr,
        transform_words.len,
        @intCast(extended_start),
        @intCast(extended_stride),
        @intCast(base_columns.len),
        base_log_size,
        extended_log_size,
        inverse_words.ptr,
        forward_words.ptr,
        scale_factor,
        &source_binding,
        &normalization_batch_count,
        &forward_skipped_layers,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal circle LDE failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    telemetry.recordCommitSourceBinding(source_binding);
    const execution = try circleLdeExecutionFromDeviceReceipt(
        base_log_size,
        extended_log_size,
        base_columns.len,
        normalization_batch_count,
        forward_skipped_layers,
    );
    return .{
        .gpu_milliseconds = gpu_ms,
        .execution = execution,
    };
}

pub fn evaluateRecurrenceComposition(
    self: *Runtime,
    resident_tree: ?*anyopaque,
    trace_first: [*]const @import("stwo_core").fields.m31.M31,
    row_count: usize,
    column_count: usize,
    column_stride: usize,
    power_words: []const u32,
    denominator_inverses: [2]u32,
    output: []@import("stwo_core").fields.m31.M31,
    inverse_twiddles: []const @import("stwo_core").fields.m31.M31,
) MetalError!f64 {
    if (row_count == 0 or column_count < 3 or column_stride < row_count or
        power_words.len != (column_count - 2) * 4 or output.len != row_count * 4 or
        inverse_twiddles.len != row_count / 2 or
        row_count > std.math.maxInt(u32) or column_count > std.math.maxInt(u32) or
        column_stride > std.math.maxInt(u32) or power_words.len > std.math.maxInt(u32))
    {
        return MetalError.CompositionEvaluationFailed;
    }
    const trace_words: [*]const u32 = @ptrCast(trace_first);
    const output_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(output));
    const inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_twiddles));
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_recurrence_composition(
        self.handle,
        resident_tree,
        trace_words,
        @intCast(row_count),
        @intCast(column_count),
        @intCast(column_stride),
        power_words.ptr,
        @intCast(power_words.len),
        &denominator_inverses,
        output_words.ptr,
        output_words.len,
        inverse_words.ptr,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal composition evaluation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CompositionEvaluationFailed;
    }
    return gpu_ms;
}

pub fn transformCircleLde(
    self: *Runtime,
    allocator: std.mem.Allocator,
    source_columns: []const []const @import("stwo_core").fields.m31.M31,
    base_columns: []const []@import("stwo_core").fields.m31.M31,
    extended_columns: []const []@import("stwo_core").fields.m31.M31,
    inverse_twiddles: []const @import("stwo_core").fields.m31.M31,
    forward_twiddles: []const @import("stwo_core").fields.m31.M31,
    base_log_size: u32,
    extended_log_size: u32,
) (MetalError || std.mem.Allocator.Error)!f64 {
    if (extended_columns.len == 0 or extended_log_size >= @bitSizeOf(usize)) {
        return MetalError.CircleTransformFailed;
    }
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);
    const transform_len = std.math.mul(usize, extended_columns.len, extended_len) catch
        return MetalError.CircleTransformFailed;
    const transform_buffer = try allocator.alloc(@import("stwo_core").fields.m31.M31, transform_len);
    defer allocator.free(transform_buffer);
    const transform_columns = try allocator.alloc([]@import("stwo_core").fields.m31.M31, extended_columns.len);
    defer allocator.free(transform_columns);
    for (transform_columns, 0..) |*column, index| {
        column.* = transform_buffer[index * extended_len .. (index + 1) * extended_len];
    }
    const result = try self.transformCircleLdeInto(
        allocator,
        source_columns,
        base_columns,
        transform_columns,
        transform_buffer,
        0,
        extended_len,
        inverse_twiddles,
        forward_twiddles,
        base_log_size,
        extended_log_size,
    );
    for (extended_columns, transform_columns) |destination, source| @memcpy(destination, source);
    return result.gpu_milliseconds;
}
