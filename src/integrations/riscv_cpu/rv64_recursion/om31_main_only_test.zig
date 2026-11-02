const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const Main = A.main_only.authority;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn public(role: Main.Role) Main.PublicFor(O) {
    return switch (role) {
        .cpu => .{ .cpu = .{ .steps = 17, .initial_pc = .{ 4, 0, 0, 0 }, .final_pc = .{ 8, 0, 0, 0 }, .epoch = 1 } },
        .alu => .{ .alu = {} },
        .binary => .{ .binary = {} },
        .shift => .{ .shift = {} },
        .jalr => .{ .jalr = {} },
        .ls => .{ .ls = .{ .count = 17 } },
        .mul => .{ .mul = .{ .count = 17 } },
        .div => .{ .div = .{ .count = 17 } },
    };
}
fn value(seed: usize) O {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = M.fromCanonical(@intCast((seed * 719 + i * 79 + 3) % 65521));
    return O.fromM31Array(c);
}
test "OM31 MAIN-only exact role counts and degree-three finite differences" {
    var fixed: [3]O = undefined;
    var main: [128]O = undefined;
    var previous: [128]O = undefined;
    var samples: [5][512]O = undefined;
    for (std.enums.values(Main.Role)) |role| {
        const shape = Main.shape(role);
        var count: usize = 0;
        for (0..5) |t| {
            const x = O.fromBase(M.fromCanonical(@intCast(t)));
            for (&fixed, 0..) |*v, i| v.* = value(i + 1).add(value(i + 101).mul(x));
            for (&main, &previous, 0..) |*v, *p, i| {
                v.* = value(i + 11).add(value(i + 211).mul(x));
                p.* = value(i + 31).add(value(i + 311).mul(x));
            }
            var sink = E.SinkFor(O){ .values = &samples[t] };
            try Main.emitFor(O, public(role), fixed[0..shape.fixed], main[0..shape.main], previous[0..shape.main], &sink);
            count = sink.count;
        }
        std.debug.print("MAIN_ONLY role={s} constraints={d} main={d}\n", .{ @tagName(role), count, shape.main });
        try std.testing.expectEqual(shape.constraints, count);
        for (0..shape.max_degree) |order| for (0..4 - order) |t| for (0..count) |i| {
            samples[t][i] = samples[t + 1][i].sub(samples[t][i]);
        };
        var highest_nonzero = false;
        for (samples[0][0..count]) |residual| highest_nonzero = highest_nonzero or !residual.isZero();
        try std.testing.expect(highest_nonzero); // Stated maximum is exercised.
        for (0..count) |i| try std.testing.expect(samples[1][i].sub(samples[0][i]).isZero());
    }
}

fn componentMasks(allocator: std.mem.Allocator, component: *const A.main_only.component.Component) !core.air.components.ForField(O).MaskValues {
    const shape = Main.shape(component.role());
    const trees = try allocator.alloc([][]O, 3);
    errdefer allocator.free(trees);
    var initialized: usize = 0;
    errdefer for (trees[0..initialized]) |tree| {
        for (tree) |column| allocator.free(column);
        allocator.free(tree);
    };
    for (trees, [_]usize{ shape.fixed, shape.main, 0 }, 0..) |*tree, width, t| {
        tree.* = try allocator.alloc([]O, width);
        var assigned: usize = 0;
        errdefer {
            for (tree.*[0..assigned]) |column| allocator.free(column);
            allocator.free(tree.*);
        }
        for (tree.*, 0..) |*column, c| {
            const prior = t == 1 and Main.previousMain(component.role(), c);
            column.* = try allocator.alloc(O, if (prior) 2 else 1);
            column.*[0] = value(c + 17 + 1000 * t);
            if (prior) column.*[1] = value(c + 101);
            assigned += 1;
        }
        initialized += 1;
    }
    return .{ .items = trees };
}
test "OM31 MAIN-only actual verifier vtables use exact masks and scaled accumulator with no INTER columns" {
    const Air = core.air.components.ForField(O);
    const Acc = core.air.accumulation.ForField(O).PointEvaluationAccumulator;
    const point = core.circle.CirclePoint(O){ .x = value(711), .y = value(911) };
    for (std.enums.values(Main.Role)) |role| {
        const component = A.main_only.component.Component{ .log_size = 5, .public = public(role), .offsets = .{ 0, 0 } };
        const verifier = component.asVerifierComponent();
        const shape = Main.shape(role);
        try std.testing.expectEqual(shape.constraints, verifier.nConstraints());
        try std.testing.expectEqual(@as(u32, 1), verifier.compositionLogSplit());
        var bounds = try verifier.traceLogDegreeBounds(a);
        defer bounds.deinitDeep(a);
        try std.testing.expectEqual(@as(usize, 0), bounds.items[2].len);
        var points = try verifier.maskPoints(a, point, 7);
        defer points.deinitDeep(a);
        try std.testing.expectEqual(@as(usize, 0), points.items[2].len);
        for (points.items[1], 0..) |column, c| try std.testing.expectEqual(@as(usize, if (Main.previousMain(role, c)) 2 else 1), column.len);
        var masks: Air.MaskValues = try componentMasks(a, &component);
        defer masks.deinitDeep(a);
        var fixed: [3]O = undefined;
        var main: [128]O = undefined;
        var previous: [128]O = @splat(O.zero());
        for (fixed[0..shape.fixed], 0..) |*v, c| v.* = masks.items[0][c][0];
        for (main[0..shape.main], 0..) |*v, c| {
            v.* = masks.items[1][c][0];
            if (Main.previousMain(role, c)) previous[c] = masks.items[1][c][1];
        }
        var results: [512]O = undefined;
        var sink = E.SinkFor(O){ .values = &results };
        try Main.emitFor(O, public(role), fixed[0..shape.fixed], main[0..shape.main], previous[0..shape.main], &sink);
        var expected = Acc.init(value(199));
        var actual = Acc.init(value(199));
        const inverse = try A.geometry.denominatorInverseFor(O, point, 7, 5);
        for (results[0..sink.count]) |r| expected.accumulate(r.mul(inverse));
        try verifier.evaluateConstraintQuotientsAtPoint(point, &masks, &actual, 7);
        try std.testing.expectEqualDeep(expected.finalize(), actual.finalize());
        // Remove the previous sample of a genuinely linked MAIN column.
        for (masks.items[1], 0..) |column, c| if (Main.previousMain(role, c)) {
            const old = masks.items[1][c];
            masks.items[1][c] = column[0..1];
            defer masks.items[1][c] = old;
            var rejected = Acc.init(value(199));
            try std.testing.expectError(error.InvalidRv64MaskShape, verifier.evaluateConstraintQuotientsAtPoint(point, &masks, &rejected, 7));
            break;
        };
    }
}
fn allocationMetadata(allocator: std.mem.Allocator) !void {
    const component = A.main_only.component.Component{ .log_size = 5, .public = public(.cpu), .offsets = .{ 0, 0 } };
    const v = component.asVerifierComponent();
    var logs = try v.traceLogDegreeBounds(allocator);
    defer logs.deinitDeep(allocator);
    var masks = try v.maskPoints(allocator, .{ .x = value(17), .y = value(53) }, 7);
    defer masks.deinitDeep(allocator);
    const fixed = try v.preprocessedColumnIndices(allocator);
    defer allocator.free(fixed);
}
test "OM31 MAIN-only metadata allocation failure cleanup is atomic" {
    try std.testing.checkAllAllocationFailures(a, allocationMetadata, .{});
}
