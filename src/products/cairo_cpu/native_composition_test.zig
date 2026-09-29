//! All authenticated native AIR kernels against the independent SIMD evaluator.
const std = @import("std");
const package = @import("stwo_cairo_cpu");
const frontend = package.frontends.cairo;
const aot = @import("cairo_composition_cpu_aot");
const simd = frontend.proving.air.simd_evaluator;
const native = frontend.proving.air.native_evaluator;
const M31 = package.core.fields.m31.M31;
const QM31 = package.core.fields.qm31.QM31;
const Column = package.prover.secure_column.SecureColumnByCoords;
const Reader = struct {
    values: [17][64]M31,
    shift: std.math.Log2Int(usize) = 1,
    fn resolve(raw: *const anyopaque, interaction: u8, column: u32) anyerror!simd.ResolvedColumn {
        const self: *const Reader = @ptrCast(@alignCast(raw));
        return .{ .values = &self.values[(column + @as(u32, interaction) * 7) % 17], .shift_amt = self.shift };
    }
};
const Output = struct {
    column: *Column,
    additive: bool,
    pub fn accumulate(self: @This(), row: usize, value: QM31) void {
        self.column.set(row, if (self.additive) self.column.at(row).add(value) else value);
    }
};
test "Cairo native CPU AIR all authenticated kernels match SIMD across masks lifting and accumulation" {
    const allocator = std.testing.allocator;
    var library = try frontend.air.template_library.Library.readFile(allocator, "vectors/cairo/official/air_template_library_v1.json");
    defer library.deinit();
    var seen = std.AutoHashMap([32]u8, void).init(allocator);
    defer seen.deinit();
    var random = std.Random.DefaultPrng.init(0x12d8498b);
    const rng = random.random();
    var reader: Reader = undefined;
    for (&reader.values) |*values| for (values, 0..) |*value, index| {
        value.* = M31.fromU32Unchecked(switch (index % 7) {
            0 => 0,
            1 => 0x7ffffffe,
            else => rng.uintLessThan(u32, 0x7fffffff),
        });
    };
    for (library.sources) |source| for (source.bundle.components) |component| for (component.parts) |part| {
        const digest = native.identity(part.program);
        const entry = try seen.getOrPut(digest);
        if (entry.found_existing) continue;
        const kernel = aot.executor().resolve(digest) orelse return error.MissingNativeKernel;
        var program = try part.program.clone(allocator);
        defer program.deinit();
        const parameters = try allocator.alloc(QM31, program.header.n_ext_params);
        defer allocator.free(parameters);
        const coefficients = try allocator.alloc(QM31, program.header.n_constraints + 3);
        defer allocator.free(coefficients);
        for (parameters) |*value| value.* = QM31.fromU32Unchecked(rng.uintLessThan(u32, 0x7fffffff), rng.uintLessThan(u32, 0x7fffffff), rng.uintLessThan(u32, 0x7fffffff), rng.uintLessThan(u32, 0x7fffffff));
        for (coefficients) |*value| value.* = QM31.fromU32Unchecked(rng.uintLessThan(u32, 0x7fffffff), rng.uintLessThan(u32, 0x7fffffff), rng.uintLessThan(u32, 0x7fffffff), rng.uintLessThan(u32, 0x7fffffff));
        for (0..4) |scenario| {
            const eval_log: u32 = if (scenario == 2) 7 else 6;
            const trace_log: u32 = if (scenario == 1) 6 else 5;
            const rows = @as(usize, 1) << @intCast(eval_log);
            try program.setDomainLogSize(trace_log);
            reader.shift = @intCast(eval_log - 6 + 1);
            var denominator: [4]u32 = .{ 11, 13, 17, 19 };
            const input = simd.Input{ .evaluation_log_size = eval_log, .trace_log_size = trace_log, .trace = .{ .context = &reader, .resolve = Reader.resolve }, .extension_parameters = parameters, .random_coefficients = coefficients, .constraint_base = 3, .denominator_inverses = denominator[0 .. @as(usize, 1) << @intCast(eval_log - trace_log)] };
            var expected = try Column.zeros(allocator, rows);
            defer expected.deinit(allocator);
            var actual = try Column.zeros(allocator, rows);
            defer actual.deinit(allocator);
            for (expected.columns, actual.columns) |a, b| {
                for (a, b) |*x, *y| {
                    x.* = M31.fromU32Unchecked(23);
                    y.* = x.*;
                }
            }
            const first: usize = if (scenario == 3) 4 else 0;
            const end = if (scenario == 3) rows - 4 else rows;
            const additive = scenario == 3;
            try simd.evaluatePartRange(allocator, program, input, Output{ .column = &expected, .additive = additive }, first, end);
            var prepared = try native.Prepared.init(allocator, kernel, program, input, actual.columns);
            defer prepared.deinit(allocator);
            try std.testing.expectError(error.InvalidEvaluationInput, prepared.evaluateRange(1, end, additive));
            try std.testing.expectError(error.InvalidEvaluationInput, prepared.evaluateRange(end, first, additive));
            try std.testing.expectError(error.InvalidEvaluationInput, prepared.evaluateRange(first, rows + 4, additive));
            // Reuse one immutable read plan across disjoint worker-sized tiles.
            var tile = first;
            while (tile < end) : (tile += 12)
                try prepared.evaluateRange(tile, @min(tile + 12, end), additive);
            for (expected.columns, actual.columns) |a, b| try std.testing.expectEqualSlices(M31, a, b);
        }
        // Payload mutation cannot accidentally select the original native kernel.
        program.base_insts[0].imm +%= 1;
        try std.testing.expect(aot.executor().resolve(native.identity(program)) == null);
    };
    try std.testing.expectEqual(@as(usize, aot.generated_program_count), seen.count());
}
