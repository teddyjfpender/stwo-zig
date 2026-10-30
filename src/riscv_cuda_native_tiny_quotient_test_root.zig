const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Adapter = @import("integrations/riscv_cuda/resident_native_quotient_v1.zig");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const Point = core.circle.CirclePointQM31;
const Poly = engine.poly.circle.poly;
const Column = engine.pcs.ColumnEvaluation;
const Tree = core.pcs.utils.TreeVec;
const Case = struct { log: u32, index: u32, input: [4]u32, expected: [4]u32 };
fn record(cases: *std.ArrayList(Case), a: std.mem.Allocator, log: u32, domain: core.poly.circle.domain.CircleDomain, input: []const M, expected: []const M) !void {
    if (log > 2) return;
    var c: Case = .{ .log = log, .index = @intCast(domain.half_coset.initial_index.v), .input = @splat(0), .expected = @splat(0) };
    try std.testing.expectEqual(c.index, try Adapter.initialIndex(log));
    for (input, 0..) |x, i| c.input[i] = x.v;
    for (expected, 0..) |x, i| c.expected[i] = x.v;
    try cases.append(a, c);
}
test "native tiny DEEP original interpolation and mixed height periodic quotient oracle" {
    const a = std.testing.allocator;
    var cases: std.ArrayList(Case) = .empty;
    defer cases.deinit(a);
    var rng = std.Random.DefaultPrng.init(0x71bdbbf4);
    for (1..4) |log_usize| {
        const log: u32 = @intCast(log_usize);
        const n = @as(usize, 1) << @intCast(log);
        const full = core.poly.circle.canonic.CanonicCoset.new(log + 1).circleDomain();
        var split = try full.split(a, 1);
        defer split.deinit(a);
        const values = try a.alloc(M, n);
        defer a.free(values);
        for (0..34) |trial| {
            for (values) |*value| value.* = if (trial == 0) M.zero() else if (trial == 1) M.fromCanonical(core.fields.m31.Modulus - 1) else M.fromCanonical(rng.random().uintLessThan(u32, core.fields.m31.Modulus));
            var poly = try Poly.interpolateFromEvaluation(a, .{ .domain = split.subdomain, .values = values });
            defer poly.deinit(a);
            const restored = try poly.evaluate(a, split.subdomain);
            defer a.free(restored.values);
            try std.testing.expectEqualSlices(M, values, restored.values);
            try record(&cases, a, log, split.subdomain, values, poly.coeffs);
        }
        for (0..3) |scenario| {
            const coefficients = try a.alloc(M, n);
            defer a.free(coefficients);
            for (coefficients, 0..) |*value, i| value.* = M.fromCanonical(@intCast(17 + 7 * i));
            const poly = try Poly.CircleCoefficients.initBorrowed(coefficients);
            const short_coeff = [_]M{ M.fromCanonical(31), M.fromCanonical(9) };
            const short = try Poly.CircleCoefficients.initBorrowed(&short_coeff);
            const large_eval = try poly.evaluate(a, full);
            defer a.free(large_eval.values);
            const short_log: u32 = if (log == 1) 2 else log;
            const short_eval = try short.evaluate(a, core.poly.circle.canonic.CanonicCoset.new(short_log).circleDomain());
            defer a.free(short_eval.values);
            var columns = [_]Column{ .{ .log_size = log + 1, .values = large_eval.values }, .{ .log_size = short_log, .values = short_eval.values } };
            var points = [_]Point{ core.circle.SECURE_FIELD_CIRCLE_GEN.mul(7), core.circle.SECURE_FIELD_CIRCLE_GEN.mul(13) };
            var main_samples = [_]Q{ poly.evalAtPoint(points[0]), poly.evalAtPoint(points[1]) };
            // Pair-aligned lifting evaluates the short polynomial at the
            // doubled point; using its unlifted sample would not be a valid oracle.
            var short_samples = [_]Q{ short.evalAtPoint(points[0].repeatedDouble(log + 1 - short_log)), short.evalAtPoint(points[1].repeatedDouble(log + 1 - short_log)) };
            const samples: usize = if (scenario == 2) 2 else 1;
            var point_columns = [_][]Point{ points[0..samples], points[0..samples] };
            var value_columns = [_][]Q{ main_samples[0..samples], short_samples[0..samples] };
            const used: usize = if (scenario == 0) 1 else 2;
            var trees = [_][]const Column{columns[0..used]};
            var pt = [_][][]Point{point_columns[0..used]};
            var vt = [_][][]Q{value_columns[0..used]};
            var quotient = try engine.pcs.quotient_ops.computeFriQuotients(a, Tree([]const Column).initOwned(&trees), Tree([][]Point).initOwned(&pt), Tree([][]Q).initOwned(&vt), Q.fromU32Unchecked(2, 3, 5, 7), log + 1, 1);
            defer quotient.deinit(a);
            for (quotient.columns) |coordinate| {
                var interpolated = try Poly.interpolateFromEvaluation(a, .{ .domain = split.subdomain, .values = coordinate[0..n] });
                defer interpolated.deinit(a);
                const extended = try interpolated.evaluate(a, full);
                defer a.free(extended.values);
                try std.testing.expectEqualSlices(M, coordinate, extended.values);
                try record(&cases, a, log, split.subdomain, coordinate[0..n], interpolated.coeffs);
            }
        }
    }
    try std.testing.expectError(error.InvalidKernelDescriptor, Adapter.initialIndex(0));
    try std.testing.expectError(error.InvalidKernelDescriptor, Adapter.initialIndex(3));
    const output = std.process.getEnvVarOwned(a, "STWO_NATIVE_TINY_ORACLE") catch |err| switch (err) {
        error.EnvironmentVariableNotFound => return,
        else => return err,
    };
    defer a.free(output);
    var file = try std.fs.cwd().createFile(output, .{});
    defer file.close();
    for (cases.items) |case| {
        const words = [_]u32{ case.log, case.index } ++ case.input ++ case.expected;
        for (words) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            try file.writeAll(&bytes);
        }
    }
    std.debug.print("NATIVE_TINY_ORACLE cases={d} logs=1,2,3 mixed_height=true multiple_samples=true\n", .{cases.items.len});
}

const Common = @import("stwo_cuda_backend").runtime.stages.common;
const Controller = @import("stwo_cairo_cuda_integration").executor.quotient.controller;
const Fake = struct {
    context: Context = .{},
    const Context = struct {
        ingress: bool = true,
        uploads: usize = 0,
        expected_log: u32 = 1,
        pub fn requireStage(self: *Context, stage: @import("stwo_cuda_backend").runtime.telemetry.Stage) !void {
            if (!self.ingress or stage != .ingress) return error.StageOrderViolation;
        }
        pub fn uploadSlice(self: *Context, comptime T: type, dest: Common.Words, source: []const T) !void {
            try std.testing.expectEqual(@as(usize, 4), dest.len);
            try std.testing.expectEqualSlices(u32, &.{ self.expected_log, self.expected_log, self.expected_log, self.expected_log }, source);
            self.uploads += 1;
        }
        pub fn copyDeviceSlice(_: *Context, comptime T: type, dest: anytype, source: anytype) !void {
            _ = T;
            _ = dest;
            _ = source;
            return error.UnexpectedTinyTwiddleCopy;
        }
    };
};
test "native tiny DEEP explicit policy keeps original fast guard and rejects mismatched domain" {
    const words = Common.Words{ .address = 4096, .len = 8, .owner = 1, .generation = 1 };
    for (1..3) |index| {
        const log: u32 = @intCast(index);
        var prepared: Controller.Prepared = undefined;
        prepared.combine.domain_log_size = log;
        prepared.circle.half_coset_initial_index = try Adapter.initialIndex(log);
        prepared.views.coefficient_logs = .{ .address = 8192, .len = 4, .owner = 1, .generation = 1 };
        prepared.views.subdomain_inverse_twiddles = .{ .address = 16384, .len = @as(usize, 1) << @intCast(log - 1), .owner = 1, .generation = 1 };
        var session = Fake{};
        session.context.expected_log = log;
        try std.testing.expectError(error.InvalidKernelDescriptor, prepared.initializeTransform(&session, words));
        try Adapter.initialize(&prepared, &session, words);
        try std.testing.expectEqual(@as(usize, 1), session.context.uploads);
        prepared.circle.half_coset_initial_index ^= 1;
        try std.testing.expectError(error.InvalidKernelDescriptor, Adapter.initialize(&prepared, &session, words));
        prepared.circle.half_coset_initial_index ^= 1;
        prepared.views.coefficient_logs.len = 3;
        try std.testing.expectError(error.InvalidKernelDescriptor, Adapter.initialize(&prepared, &session, words));
        prepared.views.coefficient_logs.len = 4;
        session.context.ingress = false;
        try std.testing.expectError(error.StageOrderViolation, Adapter.initialize(&prepared, &session, words));
        try std.testing.expectEqual(@as(usize, 1), session.context.uploads);
    }
}
