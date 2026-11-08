//! Concrete host binding for the generated hybrid OM31 polynomial kernels.
//! Registry misses fall back to the independently checked SIMD interpreter.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const N = @import("stwo_cairo_frontend").proving.air.native_evaluator;
const Registry = @import("outer_gkr_cpu_aot");
const H = @import("hybrid_air.zig");
const Inputs = @import("cpu_inputs.zig");
const Polynomial = @import("cpu_polynomial.zig");
const O = core.fields.om31.OM31;
const DA = engine.air.accumulation.ForField(O);
const Captured = @import("stwo_cairo_frontend").witness.composition_bundle.Component;
pub fn enabled() bool {
    return @import("builtin").cpu.arch == .aarch64 and std.process.hasEnvVarConstant("STWO_RV64_OUTER_GKR_NATIVE") and !std.process.hasEnvVarConstant("STWO_RV64_OUTER_GKR_INTERPRETER");
}
pub const Prepared = struct {
    a: std.mem.Allocator,
    sites: []N.Column,
    coefficients: []O,
    range: N.Om31.Range,
    kernel: N.Om31.Kernel,
    pub fn init(a: std.mem.Allocator, artifact: *const H.Artifact, source: *const Captured, inputs: []const Polynomial.Input, parameters: []const O, column: DA.ColumnAccumulator) !?Prepared {
        try artifact.program.validate();
        const kernel = Registry.executor().resolve(artifact.program.identity) orelse return null;
        const log = source.trace_log_size;
        if (log < 4 or log > @import("profile.zig").MAX_VARIABLES or source.evaluation_log_size != log + 1 or inputs.len != artifact.program.inputs.len or parameters.len != artifact.program.parameters.len or column.random_coeff_powers.len != artifact.program.roots.len or source.denominator_inverses.len != 2) return error.InvalidHybridNativeGeometry;
        const rows = @as(usize, 1) << @intCast(log + 1);
        if (column.col.len() != rows) return error.InvalidHybridNativeGeometry;
        for (column.col.columns) |values| if (values.len != rows) return error.InvalidHybridNativeGeometry;
        var count: usize = 0;
        for (inputs, artifact.program.inputs) |input, original| {
            const actual: Inputs.Kind = switch (input) {
                .zero => .zero,
                .base => .base,
                .secure => .secure,
            };
            if (actual != Inputs.expected(artifact.component, original)) return error.InvalidHybridNativeInput;
            switch (input) {
                .zero => {},
                .base => |poly| if (poly.offset != original.offset) return error.InvalidHybridNativeInput,
                .secure => |poly| if (poly.offset != original.offset) return error.InvalidHybridNativeInput,
            }
            count += switch (input) {
                .zero => 0,
                .base => 1,
                .secure => 8,
            };
        }
        const sites = try a.alloc(N.Column, count);
        errdefer a.free(sites);
        var cursor: usize = 0;
        for (inputs) |input| switch (input) {
            .zero => {},
            .base => |poly| {
                if (poly.log == 0 or poly.log > log + 1 or poly.values.len != @as(usize, 1) << @intCast(poly.log)) return error.InvalidHybridNativeInput;
                sites[cursor] = .{ .values = @ptrCast(poly.values.ptr), .shift = log + 2 - poly.log };
                cursor += 1;
            },
            .secure => |poly| for (poly.values) |values| {
                if (values.len != rows) return error.InvalidHybridNativeInput;
                sites[cursor] = .{ .values = @ptrCast(values.ptr), .shift = 1 };
                cursor += 1;
            },
        };
        const coefficients = try a.alloc(O, column.random_coeff_powers.len);
        errdefer a.free(coefficients);
        for (coefficients, 0..) |*coefficient, i| coefficient.* = column.random_coeff_powers[coefficients.len - 1 - i];
        var out = Prepared{ .a = a, .sites = sites, .coefficients = coefficients, .kernel = kernel, .range = .{ .sites = sites.ptr, .parameters = @ptrCast(parameters.ptr), .coefficients = @ptrCast(coefficients.ptr), .denominators = source.denominator_inverses.ptr, .output = undefined, .first = 0, .end = rows, .evaluation_log = log + 1, .trace_log = log, .constraint_base = 0, .additive = 1 } };
        for (column.col.columns, &out.range.output) |values, *destination| destination.* = @ptrCast(values.ptr);
        return out;
    }
    pub fn deinit(self: *Prepared) void {
        self.a.free(self.sites);
        self.a.free(self.coefficients);
        self.* = undefined;
    }
    pub fn evaluateRange(self: *const Prepared, first: usize, end: usize) !void {
        if (first > end or first % 4 != 0 or end % 4 != 0 or end > self.range.end) return error.InvalidHybridNativeGeometry;
        var range = self.range;
        range.first = first;
        range.end = end;
        self.kernel(&range);
    }
};
comptime {
    if (@sizeOf(O) != 32 or @sizeOf(core.fields.m31.M31) != 4) @compileError("hybrid field ABI changed");
}
