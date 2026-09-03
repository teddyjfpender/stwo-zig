//! Circle transforms, LDE dispatch, and recurrence composition.

const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const telemetry = @import("../telemetry.zig");
const work_profile = @import("stwo_prover_api").work_profile;

const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;
const ResidentBuffer = runtime.ResidentBuffer;
const CircleLdeBatch = runtime.CircleLdeBatch;
const CircleLdeBatchStats = runtime.CircleLdeBatchStats;
pub const CircleLdeExecutionResult = struct {
    gpu_milliseconds: f64,
    execution: work_profile.M31CircleLdeExecution,
};

/// The legacy circle kernels address each output column with a `u32` word
/// offset.  A proof-owned arena may be larger than that because columns are
/// independent: dispatch page-aligned column runs against rebased arena
/// slices, while retaining the original logical order and one host-computed
/// normalization factor.
const CircleLdeArenaDispatchPlan = struct {
    extended_start: usize,
    extended_stride: usize,
    extended_len: usize,
    column_count: usize,
    max_columns_per_dispatch: usize,

    const Dispatch = struct {
        first_column: usize,
        column_count: usize,
        first_word: usize,
        word_count: usize,
    };

    fn init(
        transform_word_count: usize,
        extended_start: usize,
        extended_stride: usize,
        extended_len: usize,
        column_count: usize,
    ) MetalError!CircleLdeArenaDispatchPlan {
        const abi_max_words: usize = std.math.maxInt(u32);
        if (column_count == 0 or extended_len == 0 or
            extended_stride < extended_len or
            extended_len > abi_max_words or extended_stride > abi_max_words)
        {
            return MetalError.CircleTransformFailed;
        }
        const last_offset = std.math.mul(
            usize,
            column_count - 1,
            extended_stride,
        ) catch return MetalError.CircleTransformFailed;
        const required_words = std.math.add(
            usize,
            std.math.add(
                usize,
                extended_start,
                last_offset,
            ) catch return MetalError.CircleTransformFailed,
            extended_len,
        ) catch return MetalError.CircleTransformFailed;
        if (required_words > transform_word_count)
            return MetalError.CircleTransformFailed;

        // `(n - 1) * stride + len <= UINT32_MAX`, matching the checked
        // Objective-C ABI exactly.  Rebasing makes the first local offset 0.
        const max_columns_per_dispatch =
            (abi_max_words - extended_len) / extended_stride + 1;
        if (max_columns_per_dispatch == 0)
            return MetalError.CircleTransformFailed;
        return .{
            .extended_start = extended_start,
            .extended_stride = extended_stride,
            .extended_len = extended_len,
            .column_count = column_count,
            .max_columns_per_dispatch = max_columns_per_dispatch,
        };
    }

    fn dispatchCount(self: CircleLdeArenaDispatchPlan) usize {
        return (self.column_count - 1) / self.max_columns_per_dispatch + 1;
    }

    fn dispatch(
        self: CircleLdeArenaDispatchPlan,
        dispatch_index: usize,
    ) MetalError!Dispatch {
        if (dispatch_index >= self.dispatchCount())
            return MetalError.CircleTransformFailed;
        const first_column = std.math.mul(
            usize,
            dispatch_index,
            self.max_columns_per_dispatch,
        ) catch return MetalError.CircleTransformFailed;
        const column_count = @min(
            self.max_columns_per_dispatch,
            self.column_count - first_column,
        );
        const column_word_offset = std.math.mul(
            usize,
            first_column,
            self.extended_stride,
        ) catch return MetalError.CircleTransformFailed;
        const first_word = std.math.add(
            usize,
            self.extended_start,
            column_word_offset,
        ) catch return MetalError.CircleTransformFailed;
        const word_count = std.math.add(
            usize,
            std.math.mul(
                usize,
                column_count - 1,
                self.extended_stride,
            ) catch return MetalError.CircleTransformFailed,
            self.extended_len,
        ) catch return MetalError.CircleTransformFailed;
        if (word_count > std.math.maxInt(u32))
            return MetalError.CircleTransformFailed;
        return .{
            .first_column = first_column,
            .column_count = column_count,
            .first_word = first_word,
            .word_count = word_count,
        };
    }
};

test "Metal circle LDE splits the retained Stage101 log-23 main arena at the u32 boundary" {
    // The retained CPU statement has 455 main columns at base log 23.  With
    // blowup one, its unchanged logical arena is 455 * 2^24 words.  The Metal
    // ABI can address 255 such columns per locally rebased dispatch, not 256.
    const extended_len: usize = @as(usize, 1) << 24;
    const column_count: usize = 455;
    const transform_words = try std.math.mul(
        usize,
        column_count,
        extended_len,
    );
    const plan = try CircleLdeArenaDispatchPlan.init(
        transform_words,
        0,
        extended_len,
        extended_len,
        column_count,
    );
    try std.testing.expectEqual(@as(usize, 255), plan.max_columns_per_dispatch);
    try std.testing.expectEqual(@as(usize, 2), plan.dispatchCount());

    const first = try plan.dispatch(0);
    try std.testing.expectEqual(@as(usize, 0), first.first_column);
    try std.testing.expectEqual(@as(usize, 255), first.column_count);
    try std.testing.expectEqual(@as(usize, 0), first.first_word);
    try std.testing.expectEqual(@as(usize, 4_278_190_080), first.word_count);

    const second = try plan.dispatch(1);
    try std.testing.expectEqual(@as(usize, 255), second.first_column);
    try std.testing.expectEqual(@as(usize, 200), second.column_count);
    try std.testing.expectEqual(
        @as(usize, 4_278_190_080),
        second.first_word,
    );
    try std.testing.expectEqual(@as(usize, 3_355_443_200), second.word_count);
    try std.testing.expectEqual(
        transform_words,
        second.first_word + second.word_count,
    );
}

test "Metal circle LDE arena planner rejects hostile bounds without truncation" {
    const extended_len: usize = @as(usize, 1) << 24;
    const exact_limit_words = 255 * extended_len;
    const exact = try CircleLdeArenaDispatchPlan.init(
        exact_limit_words,
        0,
        extended_len,
        extended_len,
        255,
    );
    try std.testing.expectEqual(@as(usize, 1), exact.dispatchCount());
    try std.testing.expectEqual(exact_limit_words, (try exact.dispatch(0)).word_count);

    try std.testing.expectError(
        MetalError.CircleTransformFailed,
        CircleLdeArenaDispatchPlan.init(
            exact_limit_words - 1,
            0,
            extended_len,
            extended_len,
            255,
        ),
    );
    try std.testing.expectError(
        MetalError.CircleTransformFailed,
        CircleLdeArenaDispatchPlan.init(
            std.math.maxInt(usize),
            std.math.maxInt(usize) - 7,
            8,
            8,
            2,
        ),
    );
    try std.testing.expectError(
        MetalError.CircleTransformFailed,
        CircleLdeArenaDispatchPlan.init(
            std.math.maxInt(usize),
            0,
            @as(usize, std.math.maxInt(u32)) + 1,
            8,
            2,
        ),
    );
}

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
    return (try transformCircleWithBinding(
        self,
        allocator,
        columns,
        twiddles,
        log_size,
        inverse,
    )).gpu_milliseconds;
}

pub const CircleTransformBindingV1 = struct {
    gpu_milliseconds: f64,
    direct_host_alias: bool,
    exact_resident_source: bool,
};

/// Executes the ordinary circle transform while returning the exact source
/// binding selected by the Objective-C runtime.  Proof-local owners use this
/// to require the no-copy alias path before later dispatches resolve the same
/// host pointer through their original resident buffer.
pub fn transformCircleWithBinding(
    self: *Runtime,
    allocator: std.mem.Allocator,
    columns: []const []@import("stwo_core").fields.m31.M31,
    twiddles: []const @import("stwo_core").fields.m31.M31,
    log_size: u32,
    inverse: bool,
) (MetalError || std.mem.Allocator.Error)!CircleTransformBindingV1 {
    return transformCircleConfigured(
        self,
        allocator,
        null,
        columns,
        twiddles,
        log_size,
        inverse,
    );
}

/// Batch transform whose source/destination is one exact runtime-owned Metal
/// buffer.  Unlike the compatibility no-copy alias, this passes the original
/// handle to the encoder and rejects any pointer/length mismatch.
pub fn transformCircleResidentBatch(
    self: *Runtime,
    allocator: std.mem.Allocator,
    resident: *const ResidentBuffer,
    columns: []const []@import("stwo_core").fields.m31.M31,
    twiddles: []const @import("stwo_core").fields.m31.M31,
    log_size: u32,
    inverse: bool,
) (MetalError || std.mem.Allocator.Error)!CircleTransformBindingV1 {
    return transformCircleConfigured(
        self,
        allocator,
        resident,
        columns,
        twiddles,
        log_size,
        inverse,
    );
}

fn transformCircleConfigured(
    self: *Runtime,
    allocator: std.mem.Allocator,
    resident: ?*const ResidentBuffer,
    columns: []const []@import("stwo_core").fields.m31.M31,
    twiddles: []const @import("stwo_core").fields.m31.M31,
    log_size: u32,
    inverse: bool,
) (MetalError || std.mem.Allocator.Error)!CircleTransformBindingV1 {
    if (columns.len == 0 or log_size < 3) return MetalError.CircleTransformFailed;
    const expected_len = @as(usize, 1) << @intCast(log_size);
    if (twiddles.len != expected_len / 2) return MetalError.CircleTransformFailed;
    const expected_bytes = std.math.mul(
        usize,
        std.math.mul(usize, columns.len, expected_len) catch
            return MetalError.CircleTransformFailed,
        @sizeOf(u32),
    ) catch return MetalError.CircleTransformFailed;
    const pointers = try allocator.alloc([*]u32, columns.len);
    defer allocator.free(pointers);
    for (columns, 0..) |column, index| {
        if (column.len != expected_len) return MetalError.CircleTransformFailed;
        pointers[index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(column)).ptr;
        if (index != 0 and
            pointers[index] != pointers[0] + index * expected_len)
        {
            if (resident != null) return MetalError.CircleTransformFailed;
        }
    }
    if (resident) |source| {
        if (source.byte_length != expected_bytes or
            @intFromPtr(source.contents) != @intFromPtr(pointers[0]))
        {
            return MetalError.CircleTransformFailed;
        }
    }
    const scale_factor = if (inverse)
        (@import("stwo_core").fields.m31.M31.fromCanonical(@intCast(expected_len)).inv() catch
            return MetalError.CircleTransformFailed).v
    else
        1;
    const words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(twiddles));
    var source_binding: u32 = 0;
    var gpu_ms: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_circle_transform(
        self.handle,
        if (resident) |source| source.handle else null,
        pointers.ptr,
        @intCast(columns.len),
        log_size,
        words.ptr,
        inverse,
        scale_factor,
        &source_binding,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal circle transform failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    if (source_binding > 2 or
        (resident != null and source_binding != 2))
    {
        return MetalError.CircleTransformFailed;
    }
    return .{
        .gpu_milliseconds = gpu_ms,
        .direct_host_alias = source_binding != 0,
        .exact_resident_source = source_binding == 2,
    };
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
        null,
        &pointers,
        1,
        log_size,
        words.ptr,
        inverse,
        scale_factor,
        null,
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err("Metal resident circle recomputation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return gpu_ms;
}

pub fn beginCircleLdeBatch(self: *Runtime) MetalError!CircleLdeBatch {
    var message: [1024]u8 = [_]u8{0} ** 1024;
    const handle = ffi.stwo_zig_metal_circle_lde_batch_create(
        self.handle,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal circle LDE batch creation failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    };
    return .{ .handle = handle };
}

pub fn destroyCircleLdeBatch(_: *Runtime, batch: *CircleLdeBatch) void {
    ffi.stwo_zig_metal_circle_lde_batch_destroy(batch.handle);
    batch.* = undefined;
}

pub fn finishCircleLdeBatch(
    _: *Runtime,
    batch: *CircleLdeBatch,
) MetalError!CircleLdeBatchStats {
    var encoded_operations: u64 = 0;
    var gpu_milliseconds: f64 = 0;
    var message: [1024]u8 = [_]u8{0} ** 1024;
    if (!ffi.stwo_zig_metal_circle_lde_batch_finish(
        batch.handle,
        &encoded_operations,
        &gpu_milliseconds,
        &message,
        message.len,
    )) {
        std.log.err("Metal circle LDE batch completion failed: {s}", .{std.mem.sliceTo(&message, 0)});
        return MetalError.CircleTransformFailed;
    }
    return .{
        .encoded_operations = encoded_operations,
        .gpu_milliseconds = gpu_milliseconds,
    };
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
    return transformCircleLdeIntoConfigured(
        self,
        null,
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
    );
}

pub fn transformCircleLdeIntoBatch(
    self: *Runtime,
    batch: *CircleLdeBatch,
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
    return transformCircleLdeIntoConfigured(
        self,
        batch,
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
    );
}

fn transformCircleLdeIntoConfigured(
    self: *Runtime,
    batch: ?*CircleLdeBatch,
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
    if (extended_log_size >= 31) return MetalError.CircleTransformFailed;
    const base_len = @as(usize, 1) << @intCast(base_log_size);
    const extended_len = @as(usize, 1) << @intCast(extended_log_size);
    if (inverse_twiddles.len != base_len / 2 or forward_twiddles.len != extended_len / 2) return MetalError.CircleTransformFailed;
    const arena_plan = try CircleLdeArenaDispatchPlan.init(
        transform_buffer.len,
        extended_start,
        extended_stride,
        extended_len,
        extended_columns.len,
    );
    const base_ptrs = try allocator.alloc([*]u32, base_columns.len);
    defer allocator.free(base_ptrs);
    const source_ptrs = try allocator.alloc([*]const u32, source_columns.len);
    defer allocator.free(source_ptrs);
    for (source_columns, base_columns, extended_columns, 0..) |source, base, extended, index| {
        if (source.len != base_len or base.len != base_len or extended.len != extended_len) return MetalError.CircleTransformFailed;
        const column_offset = std.math.add(
            usize,
            extended_start,
            std.math.mul(
                usize,
                index,
                extended_stride,
            ) catch return MetalError.CircleTransformFailed,
        ) catch return MetalError.CircleTransformFailed;
        if (extended.ptr != transform_buffer.ptr + column_offset) {
            return MetalError.CircleTransformFailed;
        }
        source_ptrs[index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(source)).ptr;
        base_ptrs[index] = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(base)).ptr;
    }
    const transform_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(transform_buffer));
    const inverse_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(inverse_twiddles));
    const forward_words = std.mem.bytesAsSlice(u32, std.mem.sliceAsBytes(forward_twiddles));
    const scale_factor = (@import("stwo_core").fields.m31.M31.fromCanonical(@intCast(base_len)).inv() catch
        return MetalError.CircleTransformFailed).v;
    var gpu_ms: f64 = 0;
    var logical_forward_skipped_layers: ?u32 = null;
    var dispatch_index: usize = 0;
    while (dispatch_index < arena_plan.dispatchCount()) : (dispatch_index += 1) {
        const dispatch = try arena_plan.dispatch(dispatch_index);
        const transform_chunk = transform_words[dispatch.first_word..][0..dispatch.word_count];
        var source_binding: u32 = 0;
        var normalization_batch_count: u32 = 0;
        var forward_skipped_layers: u32 = 0;
        var dispatch_gpu_ms: f64 = 0;
        var message: [1024]u8 = [_]u8{0} ** 1024;
        const succeeded = if (batch) |active|
            ffi.stwo_zig_metal_circle_lde_batch_enqueue(
                self.handle,
                active.handle,
                source_ptrs[dispatch.first_column..].ptr,
                base_ptrs[dispatch.first_column..].ptr,
                transform_chunk.ptr,
                transform_chunk.len,
                0,
                @intCast(extended_stride),
                @intCast(dispatch.column_count),
                base_log_size,
                extended_log_size,
                inverse_words.ptr,
                forward_words.ptr,
                scale_factor,
                &source_binding,
                &normalization_batch_count,
                &forward_skipped_layers,
                &dispatch_gpu_ms,
                &message,
                message.len,
            )
        else
            ffi.stwo_zig_metal_circle_lde(
                self.handle,
                source_ptrs[dispatch.first_column..].ptr,
                base_ptrs[dispatch.first_column..].ptr,
                transform_chunk.ptr,
                transform_chunk.len,
                0,
                @intCast(extended_stride),
                @intCast(dispatch.column_count),
                base_log_size,
                extended_log_size,
                inverse_words.ptr,
                forward_words.ptr,
                scale_factor,
                &source_binding,
                &normalization_batch_count,
                &forward_skipped_layers,
                &dispatch_gpu_ms,
                &message,
                message.len,
            );
        if (!succeeded) {
            std.log.err(
                "Metal circle LDE failed for columns {}..{} of {} " ++
                    "(base log {}, extended log {}, local words {}): {s}",
                .{
                    dispatch.first_column,
                    dispatch.first_column + dispatch.column_count,
                    base_columns.len,
                    base_log_size,
                    extended_log_size,
                    dispatch.word_count,
                    std.mem.sliceTo(&message, 0),
                },
            );
            return MetalError.CircleTransformFailed;
        }
        telemetry.recordCommitSourceBinding(source_binding);
        // Every device dispatch executed the same logical transform branch.
        // The work receipt retains one normalization batch because `scale_factor`
        // was derived once above and then borrowed by every addressability chunk.
        if (normalization_batch_count != 1 or
            (logical_forward_skipped_layers != null and
                logical_forward_skipped_layers.? != forward_skipped_layers))
        {
            return MetalError.CircleTransformFailed;
        }
        logical_forward_skipped_layers = forward_skipped_layers;
        gpu_ms += dispatch_gpu_ms;
    }
    const execution = try circleLdeExecutionFromDeviceReceipt(
        base_log_size,
        extended_log_size,
        base_columns.len,
        1,
        logical_forward_skipped_layers orelse
            return MetalError.CircleTransformFailed,
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
