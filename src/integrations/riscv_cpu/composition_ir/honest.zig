//! Honest-trace parity: a test-only observer on the prover's composition
//! entry captures the real committed trace and every live component handle of
//! an actual proof, recognises each handle's component type by its static
//! vtable, records that very instance into the IR, and checks the IR against
//! the component's native domain evaluator on the component's real columns.
const std = @import("std");
const builtin = @import("builtin");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const R = @import("record.zig");
const K = @import("case.zig");
const cp = R.cp;
const M = R.M;
const Q = R.Q;
const accumulation = engine.air.accumulation;

pub const Tally = struct {
    pub const MAX = 128;
    names: [MAX][]const u8 = undefined,
    counts: [MAX]usize = @splat(0),
    rows: [MAX]usize = @splat(0),
    len: usize = 0,
    unrecognised: usize = 0,
    observed: usize = 0,
    fn add(self: *Tally, name: []const u8, rows: usize) void {
        for (self.names[0..self.len], 0..) |n, i| if (std.mem.eql(u8, n, name)) {
            self.counts[i] += 1;
            self.rows[i] += rows;
            return;
        };
        if (self.len == MAX) return;
        self.names[self.len] = name;
        self.counts[self.len] = 1;
        self.rows[self.len] = rows;
        self.len += 1;
    }
    pub fn print(self: *const Tally) void {
        std.debug.print("honest composition IR parity: {d} handles observed, {d} unrecognised\n", .{ self.observed, self.unrecognised });
        for (self.names[0..self.len], self.counts[0..self.len], self.rows[0..self.len]) |n, c, r| std.debug.print("  {s}: {d} handle(s), {d} rows bit-exact\n", .{ n, c, r });
    }
};

/// Component offsets live in one of three field shapes.
fn offsetsOf(comptime T: type, c: *const T) [3]usize {
    if (@hasField(T, "offsets")) {
        const O = @TypeOf(c.offsets);
        if (O == [3]usize) return c.offsets;
        if (@hasField(O, "fixed")) return .{ c.offsets.fixed, c.offsets.main, c.offsets.interaction };
    }
    if (@hasField(T, "fixed_offset")) return .{ c.fixed_offset, c.main_offset, c.interaction_offset };
    @compileError("unknown offset layout for " ++ @typeName(T));
}
fn zeroOffsets(comptime T: type, c: *T) void {
    if (@hasField(T, "offsets")) {
        const O = @TypeOf(c.offsets);
        if (O == [3]usize) {
            c.offsets = .{ 0, 0, 0 };
            return;
        }
        if (@hasField(O, "fixed")) {
            c.offsets.fixed = 0;
            c.offsets.main = 0;
            c.offsets.interaction = 0;
            return;
        }
    }
    if (@hasField(T, "fixed_offset")) {
        c.fixed_offset = 0;
        c.main_offset = 0;
        c.interaction_offset = 0;
        return;
    }
    @compileError("unknown offset layout for " ++ @typeName(T));
}

/// Evaluation-domain values of one committed column (LDE values when the
/// committed height equals the evaluation height, else from coefficients).
fn domainValues(a: std.mem.Allocator, poly: cp.Poly, eval_log: u32) ![]M {
    if (poly.log_size == eval_log and poly.values.len != 0) return a.dupe(M, poly.values);
    const coefficients = poly.coefficients orelse return error.CompositionIrHonestMissingCoefficients;
    const domain = core.poly.circle.canonic.CanonicCoset.new(eval_log).circleDomain();
    const evaluation = try coefficients.evaluate(a, domain);
    return @constCast(evaluation.values);
}

pub fn checkCase(a: std.mem.Allocator, case: *const K.Case, offsets: [3]usize, trace: *const cp.Trace, alpha: Q) !usize {
    const shape = case.exported.shape;
    var sliced: [3][]const cp.Poly = undefined;
    for (0..3) |t| {
        if (shape.widths[t] == 0) {
            sliced[t] = &.{};
            continue;
        }
        if (trace.polys.items.len <= t or trace.polys.items[t].len < offsets[t] + shape.widths[t]) return error.CompositionIrHonestShape;
        sliced[t] = trace.polys.items[t][offsets[t]..][0..shape.widths[t]];
    }
    const view = cp.Trace{ .polys = core.pcs.TreeVec([]const cp.Poly).initOwned(&sliced) };
    var acc = try accumulation.DomainEvaluationAccumulator.init(a, alpha, shape.eval_log, shape.constraints);
    defer acc.deinit();
    const powers = try a.dupe(Q, acc.random_coeff_powers);
    defer a.free(powers);
    try case.prover.vtable.evaluateConstraintQuotientsOnDomain(case.prover.ctx, &view, &acc);
    var native = try acc.finalize();
    defer native.deinit(a);
    var owned: [3][][]M = undefined;
    var views: [3][]const []const M = undefined;
    var done: [3]usize = @splat(0);
    defer for (owned, done) |tree, n| {
        for (tree[0..n]) |column| a.free(column);
        a.free(tree);
    };
    for (0..3) |t| {
        owned[t] = try a.alloc([]M, shape.widths[t]);
        for (owned[t], 0..) |*column, c| {
            column.* = try domainValues(a, sliced[t][c], shape.eval_log);
            done[t] += 1;
        }
        views[t] = @ptrCast(owned[t]);
    }
    const n = @as(usize, 1) << @intCast(shape.eval_log);
    const got = try a.alloc(Q, n);
    defer a.free(got);
    try R.evaluateDomain(a, &case.exported.program, shape, views, powers, got);
    for (got, 0..) |g, row| if (!native.at(row).eql(g)) {
        std.debug.print("honest composition IR mismatch for {s} at row {d}/{d}\n", .{ case.name, row, n });
        return error.CompositionIrHonestMismatch;
    };
    return n;
}

pub fn Observer(comptime handler_tables: anytype) type {
    return struct {
        pub var tally: Tally = .{};
        pub var failure: ?anyerror = null;
        var prng = std.Random.DefaultPrng.init(0x484f4e45);
        pub fn install() void {
            tally = .{};
            failure = null;
            engine.air.component_prover.ForField(Q).test_composition_observer = observe;
        }
        pub fn uninstall() void {
            engine.air.component_prover.ForField(Q).test_composition_observer = null;
        }
        fn observe(components: []const cp.ComponentProver, trace: *const cp.Trace) anyerror!void {
            const a = std.heap.page_allocator;
            for (components) |handle| {
                tally.observed += 1;
                const recognised = check(a, handle, trace) catch |err| {
                    if (failure == null) failure = err;
                    return err;
                };
                if (!recognised) tally.unrecognised += 1;
            }
        }
        fn check(a: std.mem.Allocator, handle: cp.ComponentProver, trace: *const cp.Trace) !bool {
            inline for (handler_tables) |table| inline for (table) |entry| {
                const T = entry[0];
                const dummy: T = undefined;
                if (handle.vtable == dummy.asProverComponent().vtable) {
                    const instance: *const T = @ptrCast(@alignCast(handle.ctx));
                    var copy = instance.*;
                    const offsets = offsetsOf(T, instance);
                    zeroOffsets(T, &copy);
                    var case = try entry[1](a, copy);
                    defer case.deinit(a);
                    const rows = try checkCase(a, &case, offsets, trace, R.randomQ(prng.random()));
                    tally.add(case.name, rows);
                    return true;
                }
            };
            return false;
        }
    };
}
