//! Exactness of bounded AIR closures against the existing SIMD interpreter.
const std = @import("std");
const cairo = @import("stwo_cairo_frontend");
const core = @import("stwo_core");
const eval = cairo.witness.eval_program;
const simd = cairo.proving.air.simd_evaluator;
const slices = @import("eval_slices.zig");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

const Reader = struct {
    columns: [8][32]M31,
    fn resolve(context: *const anyopaque, interaction: u8, column: u32) !simd.ResolvedColumn {
        const self: *const Reader = @ptrCast(@alignCast(context));
        return .{ .values = &self.columns[(column + interaction) % self.columns.len], .shift_amt = 1 };
    }
};
const Output = struct {
    values: [32]QM31 = @splat(QM31.zero()),
    pub fn accumulate(self: *Output, row: usize, value: QM31) void {
        self.values[row] = self.values[row].add(value);
    }
};

fn compare(program: eval.Program, dynamic: []const bool) !void {
    const a = std.testing.allocator;
    var reader: Reader = undefined;
    for (&reader.columns, 0..) |*column, ci| for (column, 0..) |*value, row| {
        value.* = M31.fromU32Unchecked(@intCast(1 + ci * 193 + row * 41));
    };
    const parameters = try a.alloc(QM31, program.header.n_ext_params);
    defer a.free(parameters);
    for (parameters, 0..) |*value, i| value.* = QM31.fromU32Unchecked(@intCast(i + 2), 7, 11, 19);
    const coefficients = try a.alloc(QM31, program.constraint_roots.len + 3);
    defer a.free(coefficients);
    for (coefficients, 0..) |*value, i| value.* = QM31.fromU32Unchecked(@intCast(i * 7 + 1), 13, 17, 23);
    var input = simd.Input{
        .evaluation_log_size = 5,
        .trace_log_size = 4,
        .trace = .{ .context = &reader, .resolve = Reader.resolve },
        .extension_parameters = parameters,
        .random_coefficients = coefficients,
        .constraint_base = 3,
        .denominator_inverses = &.{ 31, 37 },
    };
    var original = try program.clone(a);
    defer original.deinit();
    original.header.domain_log_size = 4;
    original.header.semantic_hash = original.semanticHash();
    var expected: Output = .{};
    try simd.evaluatePart(a, original, input, &expected);
    for ([_]usize{ 1, 31, 32, 33, 64, 128 }) |width| {
        var actual: Output = .{};
        var first: usize = 0;
        while (first < original.constraint_roots.len) : (first += width) {
            var slice = try slices.Slice.init(a, original, first, @min(first + width, original.constraint_roots.len), dynamic);
            defer slice.deinit();
            input.constraint_base = @intCast(3 + first);
            try simd.evaluatePart(a, slice.program, input, &actual);
            // Dynamic constants retain the original runtime table ordinal.
            var ordinal: u32 = 0;
            var kept: usize = 0;
            for (original.base_insts) |inst| if (inst.op == .constant) {
                if (kept < slice.constant_offsets.len and slice.constant_offsets[kept] == ordinal) {
                    try std.testing.expectEqual(dynamic[ordinal], slice.dynamic_constants[kept]);
                    kept += 1;
                }
                ordinal += 1;
            };
            try std.testing.expectEqual(slice.constant_offsets.len, kept);
        }
        try std.testing.expectEqualDeep(expected.values, actual.values);
    }
}

test "bounded AIR slices preserve imperative writes, repeated roots and original constant ordinals" {
    var base = [_]eval.BaseInst{
        .{ .op = .constant, .interaction = 0, .dst = 0, .a = 7, .b = 0, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 1, .a = 11, .b = 0, .imm = 0 },
        .{ .op = .add, .interaction = 0, .dst = 0, .a = 0, .b = 1, .imm = 0 },
        .{ .op = .constant, .interaction = 0, .dst = 2, .a = 13, .b = 0, .imm = 0 },
        .{ .op = .mul, .interaction = 0, .dst = 0, .a = 0, .b = 2, .imm = 0 },
    };
    var extended = [_]eval.ExtInst{
        .{ .op = .secure_col, .dst = 0, .a = 0, .b = 1, .c = 2, .d = 0 },
        .{ .op = .param, .dst = 1, .a = 0, .b = 0, .c = 0, .d = 0 },
        .{ .op = .add, .dst = 0, .a = 0, .b = 1, .c = 0, .d = 0 },
        .{ .op = .mul, .dst = 0, .a = 0, .b = 1, .c = 0, .d = 0 },
        .{ .op = .neg, .dst = 2, .a = 0, .b = 0, .c = 0, .d = 0 },
    };
    var roots = [_]u32{ 2, 0, 1, 0, 2 };
    var program = eval.Program{
        .allocator = std.testing.allocator,
        .header = .{ .flags = 0, .semantic_hash = 0, .capability_bits = eval.Capability.ext_mul, .n_interactions = 1, .n_base_params = 0, .n_ext_params = 1, .n_constraints = 5, .max_base_regs = 3, .max_ext_regs = 3, .domain_log_size = 4 },
        .base_consts = &.{},
        .ext_consts = &.{},
        .base_insts = &base,
        .ext_insts = &extended,
        .constraint_roots = &roots,
    };
    program.header.semantic_hash = program.semanticHash();
    try compare(program, &.{ false, true, false });
    try std.testing.expectError(error.InvalidConstraintSlice, slices.Slice.init(std.testing.allocator, program, 0, 0, &.{ false, true, false }));
    try std.testing.expectError(error.AirConstantExtentMismatch, slices.Slice.init(std.testing.allocator, program, 0, 1, &.{}));
}

test "bounded AIR slices match full SIMD evaluation across authenticated Cairo templates" {
    const a = std.testing.allocator;
    var library = try @import("canonical_eval_aot.zig").loadLibrary(a, "vectors/cairo/official/air_template_library_v1.json");
    defer library.deinit();
    var count: usize = 0;
    for (library.sources) |source| for (source.bundle.components) |component| for (component.parts) |part| {
        const dynamic = try a.alloc(bool, try @import("parametric_eval.zig").constantWordCount(part.program));
        defer a.free(dynamic);
        for (dynamic, 0..) |*value, i| value.* = i % 2 == 0;
        try compare(part.program, dynamic);
        count += 1;
    };
    try std.testing.expect(count >= 142);
}
