const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const CPU = @import("stwo_circuit_cpu_integration");
const H = @import("hybrid_air.zig");
const P = @import("profile.zig");
const L = @import("cpu_lowering.zig");
const IR = engine.air.secure_polynomial_program_v2;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn kindsFor(artifact: *const H.Artifact) ![]L.InputKind {
    const out = try a.alloc(L.InputKind, artifact.program.inputs.len);
    for (out, artifact.program.inputs) |*kind, input| kind.* = if (P.gkrBound(artifact.component) and input.tree == 2 and input.column >= 18) (if (input.column == 18) .secure else .zero) else .base;
    return out;
}
fn lifecycle(allocator: std.mem.Allocator, source: *const IR.ProgramFor(O), kinds: []const L.InputKind) !void {
    var plan = try L.Plan.init(allocator, source, kinds);
    defer plan.deinit();
}
test "outer GKR coordinate lowering preserves all source roots and fresh parameters" {
    const bytes = try std.fs.cwd().readFileAlloc(a, CPU.air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var source = try CPU.air.parse(a, bytes);
    defer source.deinit();
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    for (source.components, 0..) |*component, i| {
        var artifact = try H.record(a, component, @enumFromInt(i));
        defer artifact.deinit();
        const kinds = try kindsFor(&artifact);
        defer a.free(kinds);
        var plan = try L.Plan.init(a, &artifact.program, kinds);
        defer plan.deinit();
        const inputs = try a.alloc(O, kinds.len);
        defer a.free(inputs);
        const parameters = try a.alloc(O, artifact.program.parameters.len);
        defer a.free(parameters);
        for (0..16) |_| {
            for (inputs, kinds) |*v, kind| v.* = switch (kind) {
                .zero => O.zero(),
                .base => O.fromBase(channel.drawSecureFelt().toM31Array()[0]),
                .secure => channel.drawSecureFelt(),
            };
            for (parameters) |*v| v.* = channel.drawSecureFelt();
            const expected = try artifact.evaluateFor(O, a, inputs, parameters);
            defer a.free(expected);
            const actual = try plan.evaluate(a, inputs, parameters);
            defer a.free(actual);
            try std.testing.expectEqualSlices(u8, std.mem.sliceAsBytes(expected), std.mem.sliceAsBytes(actual));
        }
        if (i == 0) {
            try std.testing.checkAllAllocationFailures(a, lifecycle, .{ &artifact.program, kinds });
            const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 8 << 20);
            defer budget.destroy();
            try lifecycle(budget.allocator(), &artifact.program, kinds);
            try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
            try std.testing.expectError(error.InvalidCpuLoweringInputs, L.Plan.init(budget.allocator(), &artifact.program, kinds[1..]));
        }
        var dynamic: usize = 0;
        var products: usize = 0;
        for (plan.nodes, plan.invariant) |node, fixed| if (!fixed) {
            dynamic += 1;
            products += @intFromBool(node.op == .mul);
        };
        std.debug.print("HYBRID_CPU_LOWERING component={s} secure_nodes={} base_nodes={} dynamic={} dynamic_products={} roots={}\n", .{ @tagName(artifact.component), artifact.program.nodes.len, plan.nodes.len, dynamic, products, plan.roots.len });
    }
}
test "outer GKR coordinate multiplication covers every basis pair and signed residues" {
    var b = IR.BuilderFor(O).init(a);
    defer b.deinit();
    const x = b.input(.{ .tree = 1, .column = 0, .offset = 0 });
    const y = b.input(.{ .tree = 1, .column = 1, .offset = 0 });
    const root = b.mul(x, y);
    var program = try b.finish(@splat(17), &.{root});
    defer program.deinit();
    var plan = try L.Plan.init(a, &program, &.{ .secure, .secure });
    defer plan.deinit();
    for (0..8) |i| for (0..8) |j| {
        var left: [8]M = @splat(M.zero());
        var right: [8]M = @splat(M.zero());
        left[i] = M.one();
        right[j] = M.one();
        const values = [2]O{ O.fromM31Array(left), O.fromM31Array(right) };
        const actual = try plan.evaluate(a, &values, &.{});
        defer a.free(actual);
        try std.testing.expect(values[0].mul(values[1]).eql(actual[0]));
    };
    var channel = core.channel.raw_mod_m31.Om31Channel.init();
    for (0..64) |_| {
        const inputs = [2]O{ channel.drawSecureFelt(), channel.drawSecureFelt() };
        const actual = try plan.evaluate(a, &inputs, &.{});
        defer a.free(actual);
        try std.testing.expect(inputs[0].mul(inputs[1]).eql(actual[0]));
    }
    const minus = O.fromM31Array(@splat(M.fromCanonical(core.fields.m31.Modulus - 1)));
    const actual = try plan.evaluate(a, &.{ minus, minus }, &.{});
    defer a.free(actual);
    try std.testing.expect(minus.mul(minus).eql(actual[0]));
}
