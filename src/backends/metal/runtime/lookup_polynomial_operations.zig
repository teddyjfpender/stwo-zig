const std = @import("std");
const runtime = @import("../runtime.zig");
const ffi = @import("bindings.zig");

const MetalError = runtime.MetalError;
const Runtime = runtime.Runtime;
const EvalLibrary = runtime.EvalLibrary;
const LookupPolynomialPlan = runtime.LookupPolynomialPlan;
const LookupPolynomialDispatch = runtime.LookupPolynomialDispatch;
const BasePolynomialOutput = runtime.BasePolynomialOutput;

pub fn prepareLookupPolynomialAot(
    self: *Runtime,
    name: []const u8,
) MetalError!LookupPolynomialPlan {
    if (name.len == 0) return MetalError.CompositionEvaluationFailed;
    var message: [4096]u8 = [_]u8{0} ** 4096;
    const handle = ffi.stwo_zig_metal_lookup_polynomial_prepare_aot(
        self.handle,
        name.ptr,
        name.len,
        &message,
        message.len,
    ) orelse {
        std.log.err(
            "Metal AOT lookup-polynomial pipeline resolution failed: {s}",
            .{std.mem.sliceTo(&message, 0)},
        );
        return MetalError.CompositionEvaluationFailed;
    };
    return .{ .handle = handle };
}

pub fn prepareLookupPolynomialFromLibrary(
    self: *Runtime,
    library: EvalLibrary,
    name: []const u8,
) MetalError!LookupPolynomialPlan {
    if (name.len == 0) return MetalError.CompositionEvaluationFailed;
    var message: [4096]u8 = [_]u8{0} ** 4096;
    const handle = ffi.stwo_zig_metal_lookup_polynomial_prepare_library(
        self.handle,
        library.handle,
        name.ptr,
        name.len,
        &message,
        message.len,
    ) orelse {
        std.log.err(
            "Metal lookup-polynomial pipeline resolution failed: {s}",
            .{std.mem.sliceTo(&message, 0)},
        );
        return MetalError.CompositionEvaluationFailed;
    };
    return .{ .handle = handle };
}

pub fn evaluateLookupPolynomialBatch(
    self: *Runtime,
    trees: []const ?*anyopaque,
    main_columns: []const [*]const u32,
    interaction_columns: []const [*]const u32,
    dispatches: []const LookupPolynomialDispatch,
    power_words: []const u32,
    parameter_words: []const u32,
    outputs: []const BasePolynomialOutput,
) MetalError!f64 {
    if (trees.len == 0 or main_columns.len == 0 or interaction_columns.len == 0 or
        dispatches.len == 0 or power_words.len == 0 or parameter_words.len == 0 or
        outputs.len == 0 or trees.len > std.math.maxInt(u32) or
        main_columns.len > std.math.maxInt(u32) or
        interaction_columns.len > std.math.maxInt(u32) or
        dispatches.len > std.math.maxInt(u32) or
        power_words.len > std.math.maxInt(u32) or
        parameter_words.len > std.math.maxInt(u32) or
        outputs.len > std.math.maxInt(u32))
        return MetalError.CompositionEvaluationFailed;
    var gpu_ms: f64 = 0;
    var message: [4096]u8 = [_]u8{0} ** 4096;
    if (!ffi.stwo_zig_metal_lookup_polynomial_batch(
        self.handle,
        trees.ptr,
        @intCast(trees.len),
        main_columns.ptr,
        @intCast(main_columns.len),
        interaction_columns.ptr,
        @intCast(interaction_columns.len),
        dispatches.ptr,
        @intCast(dispatches.len),
        power_words.ptr,
        @intCast(power_words.len),
        parameter_words.ptr,
        @intCast(parameter_words.len),
        outputs.ptr,
        @intCast(outputs.len),
        &gpu_ms,
        &message,
        message.len,
    )) {
        std.log.err(
            "Metal lookup-polynomial execution failed: {s}",
            .{std.mem.sliceTo(&message, 0)},
        );
        return MetalError.CompositionEvaluationFailed;
    }
    return gpu_ms;
}
