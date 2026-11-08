const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_circuit_cpu_integration");
const H = @import("hybrid_air.zig");
const Fixture = @import("cpu_polynomial_test.zig");
const N = @import("cpu_native.zig");
const Polynomial = @import("cpu_polynomial.zig");
const O = core.fields.om31.OM31;
const DA = engine.air.accumulation.ForField(O);
const Captured = @import("stwo_cairo_frontend").witness.composition_bundle.Component;
const a = std.testing.allocator;
const rows = 64;
fn allocationCase(allocator: std.mem.Allocator, artifact: *const H.Artifact, source: *const Captured, inputs: []const Polynomial.Input, parameters: []const O, column: DA.ColumnAccumulator) !void {
    var bound = (try N.Prepared.init(allocator, artifact, source, inputs, parameters, column)) orelse return error.MissingHybridNativeKernel;
    defer bound.deinit();
    try bound.evaluateRange(0, rows);
}
test "outer GKR compiled coordinate kernels match scalar roots carries lifts offsets and additive tiles" {
    const bytes = try std.fs.cwd().readFileAlloc(a, CPU.air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var bundle = try CPU.air.parse(a, bytes);
    defer bundle.deinit();
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    for (bundle.components, 0..) |original, kind| {
        var source = original;
        source.trace_log_size = 5;
        source.evaluation_log_size = 6;
        var denominators = [_]u32{ 17, 19 };
        source.denominator_inverses = &denominators;
        var artifact = try H.record(a, &source, @enumFromInt(kind));
        defer artifact.deinit();
        const parameters = try a.alloc(O, artifact.program.parameters.len);
        defer a.free(parameters);
        const scalar_inputs = try a.alloc(O, artifact.program.inputs.len);
        defer a.free(scalar_inputs);
        for ([_]u32{ 6, 5, 4 }) |lift| for (0..2) |_| {
            var inputs = try Fixture.Inputs.init(&artifact);
            defer inputs.deinit();
            for (inputs.values, 0..) |*input, slot| switch (input.*) {
                .base => |*value| {
                    // The fixture owns its full allocation; only the borrowed
                    // view changes, so every lift tests the same scalar data.
                    if (value.values.len < rows) value.values = try inputs.plane(rows, 771 + slot);
                    value.log = lift;
                    value.values = value.values[0 .. @as(usize, 1) << @intCast(lift)];
                },
                else => {},
            };
            for (parameters) |*p| p.* = channel.drawSecureFelt();
            var accumulator = try DA.DomainEvaluationAccumulator.init(a, channel.drawSecureFelt(), 6, artifact.program.roots.len);
            defer accumulator.deinit();
            const columns = try accumulator.columns(a, &.{.{ .log_size = 6, .n_cols = artifact.program.roots.len }});
            defer a.free(columns);
            var compiled = (try N.Prepared.init(a, &artifact, &source, inputs.values, parameters, columns[0])) orelse return error.MissingHybridNativeKernel;
            defer compiled.deinit();
            try compiled.evaluateRange(0, rows / 2);
            try compiled.evaluateRange(rows / 2, rows);
            var expected: [rows]O = undefined;
            for (&expected, 0..) |*value, row| {
                for (scalar_inputs, 0..) |*input, i| input.* = try inputs.scalar(i, row);
                const roots = try artifact.evaluateFor(O, a, scalar_inputs, parameters);
                defer a.free(roots);
                var sum = O.zero();
                for (roots, 0..) |root, i| sum = sum.add(root.mul(columns[0].random_coeff_powers[roots.len - 1 - i]));
                value.* = sum.mulM31(core.fields.m31.M31.fromCanonical(source.denominator_inverses[row >> 5]));
                try std.testing.expect(value.eql(columns[0].col.at(row)));
            }
            try compiled.evaluateRange(0, rows);
            for (expected, 0..) |value, row| try std.testing.expect(value.add(value).eql(columns[0].col.at(row)));
            try std.testing.expectError(error.InvalidHybridNativeGeometry, compiled.evaluateRange(1, rows));
            try std.testing.expectError(error.InvalidHybridNativeGeometry, compiled.evaluateRange(0, rows + 4));
            if (kind == 2 and lift == 6) {
                for (inputs.values) |*input| if (input.* == .secure) {
                    const last = input.secure.values[7];
                    input.secure.values[7] = last[1..];
                    try std.testing.expectError(error.InvalidHybridNativeInput, N.Prepared.init(a, &artifact, &source, inputs.values, parameters, columns[0]));
                    input.secure.values[7] = last;
                    const saved = input.*;
                    input.* = .zero;
                    try std.testing.expectError(error.InvalidHybridNativeInput, N.Prepared.init(a, &artifact, &source, inputs.values, parameters, columns[0]));
                    input.* = saved;
                    break;
                };
            }
            if (kind == 0 and lift == 6) {
                try std.testing.checkAllAllocationFailures(a, allocationCase, .{ &artifact, &source, inputs.values, parameters, columns[0] });
                const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 8 << 20);
                defer budget.destroy();
                try allocationCase(budget.allocator(), &artifact, &source, inputs.values, parameters, columns[0]);
                try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
                try std.testing.expectError(error.InvalidHybridNativeGeometry, N.Prepared.init(budget.allocator(), &artifact, &source, inputs.values, parameters[1..], columns[0]));
                const output = columns[0].col.columns[7];
                columns[0].col.columns[7] = output[1..];
                try std.testing.expectError(error.InvalidHybridNativeGeometry, N.Prepared.init(budget.allocator(), &artifact, &source, inputs.values, parameters, columns[0]));
                columns[0].col.columns[7] = output;
                const input = inputs.values[0].base;
                inputs.values[0].base.offset += 1;
                try std.testing.expectError(error.InvalidHybridNativeInput, N.Prepared.init(budget.allocator(), &artifact, &source, inputs.values, parameters, columns[0]));
                inputs.values[0].base = input;
                inputs.values[0].base.values = input.values[1..];
                try std.testing.expectError(error.InvalidHybridNativeInput, N.Prepared.init(budget.allocator(), &artifact, &source, inputs.values, parameters, columns[0]));
                inputs.values[0].base = input;
                try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
                const authority = artifact.program.authority;
                const identity = artifact.program.identity;
                artifact.program.authority[0] ^= 1;
                artifact.program.identity = artifact.program.identityDigest();
                try std.testing.expect((try N.Prepared.init(a, &artifact, &source, inputs.values, parameters, columns[0])) == null);
                artifact.program.authority = authority;
                artifact.program.identity = identity;
            }
        };
    }
    std.debug.print("HYBRID_CPU_NATIVE all_components=11 coordinates=8 lifts=3 fresh_parameters=2 offsets=true additive_tiles=true scalar_exact=true\n", .{});
}
