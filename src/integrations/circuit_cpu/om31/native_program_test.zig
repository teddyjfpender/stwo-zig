const std = @import("std");
const core = @import("stwo_core");
const cairo = @import("stwo_cairo_frontend");
const E = @import("program.zig");
const N = @import("native_program.zig");
const P = @import("protocol.zig");
const Air = @import("../air.zig");
const a = std.testing.allocator;
const Col = cairo.proving.air.native_evaluator.Column;
const n = 64;
const prover = @import("stwo_prover_engine");
const Domain = prover.air.accumulation.ForField(P.O);
const Source = struct {
    row: usize,
    log: u32,
    fn value(tree: u8, column: u32, row: usize) P.M {
        const seed = 13 + @as(u64, tree) * 1777 + @as(u64, column) * 191 + row * 271;
        return P.M.fromU64(if (seed & 1 == 0) seed else 2 * @as(u64, core.fields.m31.Modulus) - seed);
    }
    fn get(raw: *const anyopaque, tree: u8, column: u32, offset: i32) !P.O {
        const self: *const Source = @ptrCast(@alignCast(raw));
        const mapped = core.utils.offsetBitReversedCircleDomainIndex(self.row, 5, 6, offset);
        const index = ((mapped >> @intCast(6 - self.log + 1)) << 1) + (mapped & 1);
        return P.O.fromBase(value(tree, column, index));
    }
};
fn secure(seed: usize) P.O {
    var coordinates: [8]P.M = undefined;
    for (&coordinates, 0..) |*v, i| v.* = Source.value(2, @intCast(seed), i);
    return P.O.fromM31Array(coordinates);
}

test "OM31 AOT matches scalar pinned AIR for both halves offsets lifting and additive tiles" {
    const bytes = try std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var bundle = try Air.parse(a, bytes);
    defer bundle.deinit();
    var tested: usize = 0;
    for (bundle.components) |component| for (component.parts) |part| {
        try E.validateLens(a, part.program);
        const function = N.kernel(part.program) orelse return error.MissingPinnedOm31Kernel;
        const inputs = try N.reads(a, part.program);
        defer a.free(inputs);
        const parameters = try a.alloc(P.O, part.program.header.n_ext_params);
        defer a.free(parameters);
        for (parameters, 0..) |*v, j| v.* = secure(19 + j);
        const coefficients = try a.alloc(P.O, part.program.constraint_roots.len);
        defer a.free(coefficients);
        for (coefficients, 0..) |*v, j| v.* = secure(177 + j);
        for ([_]u32{ 6, 5, 4 }) |source_log| {
            const sites = try a.alloc(Col, inputs.len);
            defer a.free(sites);
            var made: usize = 0;
            defer for (sites[0..made]) |site| a.free(site.values[0 .. @as(usize, 1) << @intCast(source_log)]);
            for (sites, inputs) |*site, input| {
                const values = try a.alloc(u32, @as(usize, 1) << @intCast(source_log));
                site.* = .{ .values = values.ptr, .shift = 6 - source_log + 1 };
                made += 1;
                for (values, 0..) |*v, j| v.* = Source.value(input.tree, input.column, j).v;
            }
            var output: [8][n]u32 = @splat(@splat(0));
            const denominators = [_]u32{ 17, 19 };
            var range = N.ABI.Range{
                .sites = sites.ptr,
                .parameters = @ptrCast(parameters.ptr),
                .coefficients = @ptrCast(coefficients.ptr),
                .denominators = &denominators,
                .output = undefined,
                .first = 0,
                .end = n / 2,
                .evaluation_log = 6,
                .trace_log = 5,
                .constraint_base = 0,
                .additive = 1,
            };
            for (&output, &range.output) |*values, *pointer| pointer.* = values;
            function(&range);
            range.first = n / 2;
            range.end = n;
            function(&range);
            var expected: [n]P.O = undefined;
            for (&expected, 0..) |*want, row| {
                const source = Source{ .row = row, .log = source_log };
                const roots = try E.evaluate(a, part.program, .{ .context = &source, .get = Source.get }, parameters);
                defer a.free(roots);
                var sum = P.O.zero();
                for (roots, coefficients) |root, coefficient| sum = sum.add(root.mul(coefficient));
                want.* = sum.mulM31(P.M.fromCanonical(denominators[row >> 5]));
                for (want.toM31Array(), 0..) |coordinate, j| try std.testing.expectEqual(coordinate.v, output[j][row]);
            }
            range.first = 0;
            function(&range);
            for (expected, 0..) |want, row| for (want.add(want).toM31Array(), 0..) |coordinate, j| try std.testing.expectEqual(coordinate.v, output[j][row]);
        }
        tested += 1;
    };
    try std.testing.expect(tested >= 11);
    std.debug.print("OM31_AOT pinned_parts={} coordinates=8 offsets=true lifts=3 additive_tiles=true exact_scalar=true\n", .{tested});
}

const FixedSource = struct {
    values: [n]P.M = @splat(P.M.one()),
    invalid: bool = false,
    fn get(raw: *const anyopaque, _: u8, _: u32) !N.Poly {
        const self: *const FixedSource = @ptrCast(@alignCast(raw));
        return .{ .log_size = 6, .values = self.values[0..if (self.invalid) n - 1 else n] };
    }
};
fn allocationCase(allocator: std.mem.Allocator, component: *const cairo.witness.composition_bundle.Component, parameters: []const P.O, column: Domain.ColumnAccumulator) !void {
    const source = FixedSource{};
    var prepared = (try N.Prepared.init(allocator, component, parameters, column, .{ .context = &source, .get = FixedSource.get })) orelse return error.MissingPinnedOm31Kernel;
    defer prepared.deinit();
}

test "OM31 AOT admission bounds geometry and releases partial bindings on every allocation failure" {
    const bytes = try std.fs.cwd().readFileAlloc(a, Air.bundle_path, 64 << 20);
    defer a.free(bytes);
    var bundle = try Air.parse(a, bytes);
    defer bundle.deinit();
    var component = bundle.components[0];
    var denominators = [_]u32{ 17, 19 };
    component.trace_log_size = 5;
    component.evaluation_log_size = 6;
    component.denominator_inverses = &denominators;
    const parameters = try a.alloc(P.O, component.ext_sources.len);
    defer a.free(parameters);
    for (parameters, 0..) |*v, j| v.* = secure(j + 1);
    var accumulator = try Domain.DomainEvaluationAccumulator.init(a, secure(37), 6, component.n_constraints);
    defer accumulator.deinit();
    const columns = try accumulator.columns(a, &.{.{ .log_size = 6, .n_cols = component.n_constraints }});
    defer a.free(columns);
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{ &component, parameters, columns[0] });
    const budget = try prover.host_budget_allocator.SharedHostBudget.create(a, 32 << 20);
    defer budget.destroy();
    try allocationCase(budget.allocator(), &component, parameters, columns[0]);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    const bad = FixedSource{ .invalid = true };
    try std.testing.expectError(error.InvalidColumnLength, N.Prepared.init(budget.allocator(), &component, parameters, columns[0], .{ .context = &bad, .get = FixedSource.get }));
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    const good = FixedSource{};
    component.evaluation_log_size = 7;
    try std.testing.expectError(error.InvalidOm31NativeGeometry, N.Prepared.init(budget.allocator(), &component, parameters, columns[0], .{ .context = &good, .get = FixedSource.get }));
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    var changed = try component.parts[0].program.clone(a);
    defer changed.deinit();
    for (changed.base_insts) |*i| {
        if (i.op == .trace_col) {
            i.imm += 1;
            break;
        }
    }
    try std.testing.expect(N.kernel(changed) == null);
}
