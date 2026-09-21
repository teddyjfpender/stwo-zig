//! AOT-only resident framework dispatch. The composition job owns semantic
//! admission and derives metadata from the shared authenticated program.
const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");
const MetalError = runtime.MetalError;

pub fn prepareFrameworkPolynomialAot(
    self: *runtime.Runtime,
    name: []const u8,
    column_trees: []const u32,
    profile_word_count: u32,
    relation_word_count: u32,
    power_word_count: u32,
) MetalError!runtime.FrameworkPolynomialPlan {
    if (!std.mem.startsWith(u8, name, "stwo_zig_framework_poly_v1_") or
        column_trees.len == 0 or column_trees.len > std.math.maxInt(u32) or
        relation_word_count < 4 or relation_word_count % 4 != 0 or
        power_word_count == 0 or power_word_count % 4 != 0)
        return error.InvalidFrameworkPolynomialDispatch;
    for (column_trees) |tree| if (tree > 2 and tree != std.math.maxInt(u32))
        return error.InvalidFrameworkPolynomialDispatch;
    var message: [4096]u8 = @splat(0);
    const handle = ffi.stwo_zig_metal_framework_polynomial_prepare_aot(
        self.handle,
        name.ptr,
        name.len,
        column_trees.ptr,
        @intCast(column_trees.len),
        profile_word_count,
        relation_word_count,
        power_word_count,
        &message,
        message.len,
    ) orelse {
        std.log.err("Metal admitted framework pipeline unavailable: {s}", .{std.mem.sliceTo(&message, 0)});
        return error.FrameworkPolynomialUnavailable;
    };
    return .{ .handle = handle };
}

pub fn evaluateFrameworkPolynomialBatch(
    self: *runtime.Runtime,
    trees: []const ?*anyopaque,
    composition_domain: ?*const runtime.ResidentBuffer,
    columns: []const ?[*]const u32,
    dispatches: []const runtime.FrameworkPolynomialDispatch,
    profile_words: []const u32,
    relation_words: []const u32,
    power_words: []const u32,
    outputs: []const runtime.BasePolynomialOutput,
) MetalError!f64 {
    if (trees.len != 3 or columns.len == 0 or dispatches.len == 0 or
        relation_words.len == 0 or power_words.len == 0 or outputs.len == 0)
        return error.InvalidFrameworkPolynomialDispatch;
    for ([_]usize{ columns.len, dispatches.len, profile_words.len, relation_words.len, power_words.len, outputs.len }) |length|
        if (length > std.math.maxInt(u32)) return error.InvalidFrameworkPolynomialDispatch;
    if (composition_domain) |scratch| {
        if (scratch.byte_length == 0 or scratch.byte_length % @sizeOf(u32) != 0 or
            @intFromPtr(scratch.contents) % @alignOf(u32) != 0)
            return error.InvalidFrameworkPolynomialDispatch;
    }
    var gpu_ms: f64 = 0;
    var message: [4096]u8 = @splat(0);
    const status = ffi.stwo_zig_metal_framework_polynomial_batch(
        self.handle,
        trees.ptr,
        @intCast(trees.len),
        if (composition_domain) |scratch| scratch.handle else null,
        if (composition_domain) |scratch| @ptrCast(@alignCast(scratch.contents)) else null,
        if (composition_domain) |scratch| scratch.byte_length / @sizeOf(u32) else 0,
        columns.ptr,
        @intCast(columns.len),
        dispatches.ptr,
        @intCast(dispatches.len),
        profile_words.ptr,
        @intCast(profile_words.len),
        relation_words.ptr,
        @intCast(relation_words.len),
        power_words.ptr,
        @intCast(power_words.len),
        outputs.ptr,
        @intCast(outputs.len),
        &gpu_ms,
        &message,
        message.len,
    );
    if (status != 0) {
        std.log.err("Metal framework dispatch rejected: {s}", .{std.mem.sliceTo(&message, 0)});
        return switch (status) {
            1 => error.InvalidFrameworkPolynomialDispatch,
            2 => error.FrameworkPolynomialUnsupported,
            else => error.CompositionEvaluationFailed,
        };
    }
    return gpu_ms;
}
