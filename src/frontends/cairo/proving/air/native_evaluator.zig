//! Authenticated ahead-of-time CPU AIR kernels. Unregistered programs use SIMD IR.
const std = @import("std");
const eval = @import("../../witness/eval_program.zig");
const simd = @import("simd_evaluator.zig");
const read_plan = @import("read_plan.zig");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub const Column = extern struct { values: [*]const u32, shift: u32, reserved: u32 = 0 };
pub const Range = extern struct {
    sites: [*]const Column,
    parameters: [*]const u32,
    coefficients: [*]const u32,
    denominators: [*]const u32,
    output: [4][*]u32,
    first: usize,
    end: usize,
    evaluation_log: u32,
    trace_log: u32,
    constraint_base: u32,
    additive: u32,
};
pub const Kernel = *const fn (*const Range) callconv(.c) void;
pub const Executor = struct {
    resolve: *const fn ([32]u8) ?Kernel,
};

pub const identity = @import("../../witness/eval_program_identity.zig").identity;

/// Validates and resolves one immutable program for a joined component phase.
/// Worker tiles borrow the same sites and inputs without rehashing the program
/// or allocating a mask-read plan for every range.
pub const Prepared = struct {
    kernel: Kernel,
    sites: []Column,
    range: Range,

    pub fn init(
        allocator: std.mem.Allocator,
        kernel: Kernel,
        program: eval.Program,
        input: simd.Input,
        columns: [4][]M31,
    ) !Prepared {
        if (input.evaluation_log_size >= @bitSizeOf(usize)) return error.InvalidEvaluationInput;
        const row_count = @as(usize, 1) << @intCast(input.evaluation_log_size);
        try simd.validateRange(program, input, 0, row_count);
        for (columns) |column| if (column.len < row_count) return error.InvalidEvaluationInput;
        var plan = try read_plan.build(simd.ResolvedColumn, allocator, program, input.trace.context, input.trace.resolve);
        defer plan.deinit(allocator);
        const sites = try allocator.alloc(Column, plan.sites.len);
        errdefer allocator.free(sites);
        for (plan.sites, sites) |source, *destination| {
            const maximum = (((row_count - 1) >> source.column.shift_amt) << 1) + 1;
            if (maximum >= source.column.values.len) return error.InvalidTraceShape;
            destination.* = .{ .values = @ptrCast(source.column.values.ptr), .shift = source.column.shift_amt };
        }
        var range = Range{
            .sites = sites.ptr,
            .parameters = @ptrCast(input.extension_parameters.ptr),
            .coefficients = @ptrCast(input.random_coefficients.ptr),
            .denominators = input.denominator_inverses.ptr,
            .output = undefined,
            .first = 0,
            .end = row_count,
            .evaluation_log = input.evaluation_log_size,
            .trace_log = input.trace_log_size,
            .constraint_base = input.constraint_base,
            .additive = 0,
        };
        for (columns, &range.output) |column, *pointer| pointer.* = @ptrCast(column.ptr);
        return .{ .kernel = kernel, .sites = sites, .range = range };
    }

    pub fn deinit(self: *Prepared, allocator: std.mem.Allocator) void {
        allocator.free(self.sites);
        self.* = undefined;
    }

    pub fn evaluateRange(self: *const Prepared, first: usize, end: usize, additive: bool) !void {
        if (first > end or end > self.range.end or first % simd.lane_count != 0 or end % simd.lane_count != 0)
            return error.InvalidEvaluationInput;
        var range = self.range;
        range.first = first;
        range.end = end;
        range.additive = @intFromBool(additive);
        self.kernel(&range);
    }
};

pub fn evaluateRange(
    allocator: std.mem.Allocator,
    kernel: Kernel,
    program: eval.Program,
    input: simd.Input,
    columns: [4][]M31,
    first: usize,
    end: usize,
    additive: bool,
) !void {
    var prepared = try Prepared.init(allocator, kernel, program, input, columns);
    defer prepared.deinit(allocator);
    try prepared.evaluateRange(first, end, additive);
}

comptime {
    if (@sizeOf(M31) != 4 or @sizeOf(QM31) != 16 or @sizeOf(Column) != @sizeOf(usize) + 8)
        @compileError("CPU AIR native field ABI mismatch");
    if (@offsetOf(Range, "first") != 8 * @sizeOf(usize) or
        @offsetOf(Range, "evaluation_log") != 10 * @sizeOf(usize))
        @compileError("CPU AIR native range ABI mismatch");
}
