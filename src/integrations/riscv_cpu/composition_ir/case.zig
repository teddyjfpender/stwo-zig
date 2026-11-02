//! Shared export case type and adapters for components whose `emitFor`
//! takes (fixed, main, previous_main, interaction, previous_interaction).
const std = @import("std");
const core = @import("stwo_core");
const R = @import("record.zig");
const Lane = R.Lane;
const Sink = R.Sink;

/// One component instance under export.
pub const Case = struct {
    name: []const u8,
    /// Coverage group (the role in the v3 roster).
    group: []const u8,
    exported: R.Exported,
    prover: R.cp.ComponentProver,
    /// Owns the component instance the prover handle borrows.
    storage: *anyopaque,
    free: *const fn (std.mem.Allocator, *anyopaque) void,
    /// Optional per-column fill for parity traces (e.g. canonical range values).
    fill: ?*const fn (tree: usize, column: usize, row: usize, rng: std.Random) core.fields.m31.M31 = null,
    pub fn deinit(self: *Case, a: std.mem.Allocator) void {
        self.exported.deinit();
        self.free(a, self.storage);
    }
};

pub fn Boxed(comptime T: type) type {
    return struct {
        pub fn create(a: std.mem.Allocator, value: T) !*T {
            const out = try a.create(T);
            out.* = value;
            return out;
        }
        pub fn free(a: std.mem.Allocator, ptr: *anyopaque) void {
            a.destroy(@as(*T, @ptrCast(@alignCast(ptr))));
        }
    };
}

/// Components exposing `widths()`, `needsPrevious(tree, column)` and
/// `emitFor(F, fixed, main, previous_main, interaction, previous_interaction, sink)`.
pub fn StandardEmit(comptime T: type) type {
    return struct {
        pub const Ctx = struct { a: std.mem.Allocator, c: *const T };
        fn needs1(ctx: Ctx, column: usize) bool {
            return ctx.c.needsPrevious(1, column);
        }
        fn needs2(ctx: Ctx, column: usize) bool {
            return ctx.c.needsPrevious(2, column);
        }
        pub fn emit(ctx: Ctx, sink: *Sink) anyerror!void {
            const w = ctx.c.widths();
            const f = try R.Masks.init(ctx.a, 0, w[0], {}, R.never);
            defer f.deinit(ctx.a);
            const m = try R.Masks.init(ctx.a, 1, w[1], ctx, needs1);
            defer m.deinit(ctx.a);
            const i = try R.Masks.init(ctx.a, 2, w[2], ctx, needs2);
            defer i.deinit(ctx.a);
            ctx.c.emitFor(Lane, f.current, m.current, m.previous, i.current, i.previous, sink);
        }
    };
}

/// Generic case: `emit(allocator, component, sink)` reads masks through
/// `Lane.input(tree, column, offset)` in the component's local column space
/// and calls the component's own `emitFor(Lane, ...)`.
pub fn caseWith(a: std.mem.Allocator, comptime T: type, name: []const u8, group: []const u8, value: T, widths: [3]usize, comptime emit: fn (std.mem.Allocator, *const T, *Sink) anyerror!void) !Case {
    const box = try Boxed(T).create(a, value);
    errdefer Boxed(T).free(a, box);
    const Ctx = struct {
        a: std.mem.Allocator,
        c: *const T,
        fn run(ctx: @This(), sink: *Sink) anyerror!void {
            return emit(ctx.a, ctx.c, sink);
        }
    };
    const shape = R.Shape{ .log_size = if (@hasField(T, "log_size")) box.log_size else box.maxConstraintLogDegreeBound() - 1, .eval_log = box.maxConstraintLogDegreeBound(), .widths = widths, .offsets = .{ 0, 0, 0 }, .constraints = box.nConstraints(), .declared_degree = if (@hasDecl(T, "constraintDegreeBound")) try box.constraintDegreeBound(0) else null };
    const exported = try R.record(a, name, shape, Ctx{ .a = a, .c = box }, Ctx.run);
    return .{ .name = name, .group = group, .exported = exported, .prover = box.asProverComponent(), .storage = box, .free = Boxed(T).free };
}

pub fn standardCase(a: std.mem.Allocator, comptime T: type, name: []const u8, group: []const u8, value: T) !Case {
    const Emit = struct {
        fn run(alloc: std.mem.Allocator, c: *const T, sink: *Sink) anyerror!void {
            return StandardEmit(T).emit(.{ .a = alloc, .c = c }, sink);
        }
    };
    return caseWith(a, T, name, group, value, value.widths(), Emit.run);
}

/// Random-trace parity for one case (two independent traces and alphas).
pub fn expectParity(a: std.mem.Allocator, case: *const Case, rng: std.Random) !void {
    for (0..2) |_| {
        var trace = try R.RandomTrace.init(a, rng, case.exported.shape, case.fill);
        defer trace.deinit(a);
        const result = R.checkDomain(a, &case.exported, case.prover, &trace, R.randomQ(rng)) catch |err| {
            std.debug.print("composition IR parity failed for {s}: {s}\n", .{ case.name, @errorName(err) });
            return err;
        };
        if (result.nonzero_rows == 0) {
            std.debug.print("composition IR parity for {s} is vacuous (all rows zero)\n", .{case.name});
            return error.CompositionIrVacuousParity;
        }
    }
}

const Point = core.circle.CirclePointQM31;
/// Sample offsets of every opened column, derived from the component's own
/// `maskPoints` at a random point on its own domain (global log = local log):
/// sample j of column c sits at `point + offset_j * step`.
pub const MaskOffsets = struct {
    offsets: [3][][]i8,
    pub fn init(a: std.mem.Allocator, component: anytype, log: u32) !MaskOffsets {
        const point = core.circle.secureFieldPointFromRandomSeed(R.Q.fromU32Unchecked(91, 7, 13, 1009));
        var points = try component.maskPoints(a, point, log);
        defer points.deinitDeep(a);
        if (points.items.len != 3) return error.CompositionIrMaskTrees;
        const s = core.poly.circle.canonic.CanonicCoset.new(log).coset().step;
        const step = Point{ .x = R.Q.fromBase(s.x), .y = R.Q.fromBase(s.y) };
        var self: MaskOffsets = .{ .offsets = undefined };
        var done: usize = 0;
        errdefer for (self.offsets[0..done]) |tree| {
            for (tree) |c| a.free(c);
            a.free(tree);
        };
        for (points.items, &self.offsets) |tree, *out| {
            out.* = try a.alloc([]i8, tree.len);
            for (tree, out.*) |samples, *column| {
                column.* = try a.alloc(i8, samples.len);
                for (samples, column.*) |sample, *offset| offset.* = try find(point, step, sample);
            }
            done += 1;
        }
        return self;
    }
    fn find(point: Point, step: Point, sample: Point) !i8 {
        if (sample.eql(point)) return 0;
        var up = point;
        var down = point;
        var k: i8 = 1;
        while (k <= 8) : (k += 1) {
            up = up.add(step);
            down = down.sub(step);
            if (sample.eql(up)) return k;
            if (sample.eql(down)) return -k;
        }
        return error.CompositionIrUnsupportedMaskOffset;
    }
    pub fn deinit(self: *MaskOffsets, a: std.mem.Allocator) void {
        for (self.offsets) |tree| {
            for (tree) |c| a.free(c);
            a.free(tree);
        }
    }
    pub fn widths(self: *const MaskOffsets) [3]usize {
        return .{ self.offsets[0].len, self.offsets[1].len, self.offsets[2].len };
    }
    /// Lane mask accessor (`count`/`at`) for generic point evaluators.
    pub fn count(self: *const MaskOffsets, tree: usize, column: usize) !usize {
        if (tree >= 3 or column >= self.offsets[tree].len) return error.InvalidRv64MaskShape;
        return self.offsets[tree][column].len;
    }
    pub fn at(self: *const MaskOffsets, tree: usize, column: usize, sample: usize) !Lane {
        const n = try self.count(tree, column);
        if (sample >= n) return error.InvalidRv64MaskShape;
        return Lane.input(@intCast(tree), column, self.offsets[tree][column][sample]);
    }
};

/// Components with a generic point authority
/// `evaluateQuotientsAtPointFor(F, point, global_log, masks, sink)`: the very
/// mask routing the verifier uses is replayed with symbolic inputs.
pub fn pointCase(a: std.mem.Allocator, comptime T: type, name: []const u8, group: []const u8, value: T) !Case {
    const box = try Boxed(T).create(a, value);
    errdefer Boxed(T).free(a, box);
    const log: u32 = box.log_size;
    var masks = try MaskOffsets.init(a, box, log);
    defer masks.deinit(a);
    const Ctx = struct {
        c: *const T,
        masks: *const MaskOffsets,
        log: u32,
        fn run(ctx: @This(), sink: *Sink) anyerror!void {
            const point = A_geometry.PointFor(Lane){ .x = Lane.zero(), .y = Lane.zero() };
            try ctx.c.evaluateQuotientsAtPointFor(Lane, point, ctx.log, ctx.masks, sink);
        }
    };
    const shape = R.Shape{ .log_size = log, .eval_log = box.maxConstraintLogDegreeBound(), .widths = masks.widths(), .offsets = .{ 0, 0, 0 }, .constraints = box.nConstraints(), .declared_degree = if (@hasDecl(T, "constraintDegreeBound")) try box.constraintDegreeBound(0) else null };
    const exported = try R.record(a, name, shape, Ctx{ .c = box, .masks = &masks, .log = log }, Ctx.run);
    return .{ .name = name, .group = group, .exported = exported, .prover = box.asProverComponent(), .storage = box, .free = Boxed(T).free };
}
const A_geometry = @import("stwo_riscv_frontend").rv64_air.geometry;
