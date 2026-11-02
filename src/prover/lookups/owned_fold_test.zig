const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const ML = @import("mle.zig");
const G = @import("gkr_prover.zig");
const Pools = @import("../work_pool.zig");
const a = std.testing.allocator;
fn dense(comptime S: type, i: usize) S {
    var coordinates: [S.zero().toM31Array().len]M = undefined;
    for (&coordinates, 0..) |*v, j| v.* = M.fromCanonical(@intCast((i * 7919 + j * 977 + 3) % 1048573));
    return S.fromM31Array(coordinates);
}
const NoResize = struct {
    child: std.mem.Allocator,
    fn allocator(self: *@This()) std.mem.Allocator {
        return .{ .ptr = self, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ra: usize) ?[*]u8 {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        return self.child.rawAlloc(len, alignment, ra);
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ra: usize) void {
        const self: *@This() = @ptrCast(@alignCast(ctx));
        self.child.rawFree(bytes, alignment, ra);
    }
};
fn check(comptime S: type) !void {
    const n = 65536;
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const bytes = try a.alignedAlloc(u8, .of(S), n * @sizeOf(S));
    defer a.free(bytes);
    var fba = std.heap.FixedBufferAllocator.init(bytes);
    const allocator = fba.allocator();
    var owned = try ML.MleFor(S, S).initOwned(try allocator.alloc(S, n));
    defer owned.deinit(allocator);
    for (owned.evals, 0..) |*v, i| v.* = dense(S, i);
    const original = owned.evals.ptr;
    const r = dense(S, 97);
    try owned.foldOwnedSecure(allocator, r);
    try std.testing.expectEqual(original, owned.evals.ptr);
    try std.testing.expectEqual(@as(usize, n / 2), owned.evals.len);
    for (owned.evals, 0..) |value, i| try std.testing.expectEqualDeep(dense(S, i).add(r.mul(dense(S, i + n / 2).sub(dense(S, i)))), value);

    var no_resize = NoResize{ .child = a };
    const fallback = no_resize.allocator();
    var copied = try ML.MleFor(S, S).initOwned(try fallback.alloc(S, 32));
    defer copied.deinit(fallback);
    for (copied.evals, 0..) |*v, i| v.* = dense(S, i);
    const old_ptr = copied.evals.ptr;
    try copied.foldOwnedSecure(fallback, r);
    try std.testing.expect(copied.evals.ptr != old_ptr);
    for (copied.evals, 0..) |value, i| try std.testing.expectEqualDeep(dense(S, i).add(r.mul(dense(S, i + 16).sub(dense(S, i)))), value);

    const caller = try a.alloc(S, 32);
    defer a.free(caller);
    for (caller, 0..) |*v, i| v.* = dense(S, i);
    var borrowed = try ML.MleFor(S, S).initBorrowed(caller);
    defer borrowed.deinit(a);
    try borrowed.foldOwnedSecure(a, r);
    try std.testing.expect(borrowed.owns_evals);
    for (caller, 0..) |value, i| try std.testing.expectEqualDeep(dense(S, i), value);
}
test "owned Q folding preserves pooled halfsplit alias law and both allocator paths" {
    try check(core.fields.qm31.QM31);
}
test "owned OM folding preserves pooled halfsplit alias law and both allocator paths" {
    try check(core.fields.om31.OM31);
}
test "nonresizable fallback OOM leaves a valid original allocation for deinit" {
    const O = core.fields.om31.OM31;
    var owned = try ML.MleFor(O, O).initOwned(try a.alloc(O, 32));
    defer owned.deinit(a);
    for (owned.evals, 0..) |*v, i| v.* = dense(O, i);
    const original = owned.evals.ptr;
    var failing = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    var wrapper = NoResize{ .child = failing.allocator() };
    try std.testing.expectError(error.OutOfMemory, owned.foldOwnedSecure(wrapper.allocator(), dense(O, 97)));
    try std.testing.expectEqual(original, owned.evals.ptr);
    try std.testing.expectEqual(@as(usize, 32), owned.evals.len);
    // Prefix mutation is allowed on this destructive failure path; the
    // immutable suffix and owner remain intact for abort cleanup.
    for (owned.evals[16..], 16..) |value, i| try std.testing.expectEqualDeep(dense(O, i), value);
}
fn lifecycle(allocator: std.mem.Allocator) !void {
    const O = core.fields.om31.OM31;
    const GP = G.ForField(O);
    var wrapper = NoResize{ .child = allocator };
    const child = wrapper.allocator();
    const n = try child.alloc(M, 32);
    defer child.free(n);
    const d = try child.alloc(O, 32);
    defer child.free(d);
    for (n, d, 0..) |*nv, *dv, i| {
        nv.* = M.fromCanonical(@intCast(i % 3));
        dv.* = dense(O, i);
    }
    const layer = GP.Layer{ .LogUpMultiplicities = .{ .numerators = try ML.MleFor(O, M).initBorrowed(n), .denominators = try ML.MleFor(O, O).initBorrowed(d) } };
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    var result = GP.proveBatch(child, &ch, &.{layer}) catch |err| {
        for (n, d, 0..) |nv, dv, i| {
            try std.testing.expectEqualDeep(M.fromCanonical(@intCast(i % 3)), nv);
            try std.testing.expectEqualDeep(dense(O, i), dv);
        }
        return err;
    };
    defer result.deinit(child);
    for (n, d, 0..) |nv, dv, i| {
        try std.testing.expectEqualDeep(M.fromCanonical(@intCast(i % 3)), nv);
        try std.testing.expectEqualDeep(dense(O, i), dv);
    }
}
test "destructive internal GKR fold cleans every allocation failure without changing caller matrices" {
    try std.testing.checkAllAllocationFailures(a, lifecycle, .{});
}

test "optional destructive oracle propagates its own error and consumes owner once" {
    const O = core.fields.om31.OM31;
    const Inner = ML.MleFor(O, O);
    const Oracle = struct {
        inner: Inner,
        released: *usize,
        pub fn deinit(self: *@This(), allocator: std.mem.Allocator) void {
            self.released.* += 1;
            self.inner.deinit(allocator);
            self.* = undefined;
        }
        pub fn nVariables(self: @This()) usize {
            return self.inner.nVariables();
        }
        pub fn cloneOwned(self: @This(), allocator: std.mem.Allocator) !@This() {
            return .{ .inner = try self.inner.cloneOwned(allocator), .released = self.released };
        }
        pub fn sumAsPolyInFirstVariable(self: @This(), allocator: std.mem.Allocator, claim: O) !@import("utils.zig").UnivariatePoly(O) {
            return self.inner.sumAsPolyInFirstVariable(allocator, claim);
        }
        pub fn fixFirstVariable(self: @This(), allocator: std.mem.Allocator, r: O) !@This() {
            return .{ .inner = try self.inner.fixFirstVariable(allocator, r), .released = self.released };
        }
        pub fn fixFirstVariableInPlace(_: *@This(), _: std.mem.Allocator, _: O) error{InjectedInPlaceFailure}!void {
            return error.InjectedInPlaceFailure;
        }
    };
    const values = try a.dupe(O, &.{ O.one(), O.fromBase(M.fromCanonical(2)) });
    const oracles = a.alloc(Oracle, 1) catch |err| {
        a.free(values);
        return err;
    };
    var released: usize = 0;
    oracles[0] = .{ .inner = try Inner.initOwned(values), .released = &released };
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    try std.testing.expectError(error.InjectedInPlaceFailure, @import("sumcheck.zig").ForField(O).proveBatchOwned(Oracle, a, &.{O.fromBase(M.fromCanonical(3))}, oracles, O.one(), &ch));
    try std.testing.expectEqual(@as(usize, 1), released);
}

fn checkPair(comptime S: type) !void {
    var pool: Pools.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 3, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try Pools.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    const r = dense(S, 97);
    for ([_]usize{ 1, 2, 4, 12, 16 }) |log| {
        const n = @as(usize, 1) << @intCast(log);
        for ([_]bool{ false, true }) |held| {
            var lease = if (held) try pool.acquire(try Pools.WorkerBudget.init(3)) else null;
            defer if (lease) |*l| l.deinit();
            var wrapper = NoResize{ .child = a };
            const child = wrapper.allocator();
            var first = try ML.MleFor(S, S).initOwned(try child.alloc(S, n));
            defer first.deinit(child);
            var second = try ML.MleFor(S, S).initOwned(try child.alloc(S, n));
            defer second.deinit(child);
            for (first.evals, second.evals, 0..) |*x, *y, i| {
                x.* = dense(S, i);
                y.* = dense(S, i + 211);
            }
            try first.foldOwnedSecurePair(&second, child, r);
            for (first.evals, second.evals, 0..) |x, y, i| {
                try std.testing.expectEqualDeep(dense(S, i).add(r.mul(dense(S, i + n / 2).sub(dense(S, i)))), x);
                try std.testing.expectEqualDeep(dense(S, i + 211).add(r.mul(dense(S, i + 211 + n / 2).sub(dense(S, i + 211)))), y);
            }
        }
    }
}
test "owned Q and OM paired folds preserve scalar authority pooled and held-lease paths" {
    try checkPair(core.fields.qm31.QM31);
    try checkPair(core.fields.om31.OM31);
}
test "paired folds reject unequal or aliased owners before any mutation" {
    const S = core.fields.om31.OM31;
    const T = ML.MleFor(S, S);
    const caller = try a.alloc(S, 64);
    defer a.free(caller);
    for (caller, 0..) |*v, i| v.* = dense(S, i);
    var left = try T.initBorrowed(caller[0..32]);
    var right = try T.initBorrowed(caller[32..48]);
    try std.testing.expectError(error.PairShapeMismatch, left.foldOwnedSecurePair(&right, a, S.one()));
    right = try T.initBorrowed(caller[16..48]);
    left.owns_evals = true; // Validation only: caller remains the real owner.
    defer left.owns_evals = false;
    try std.testing.expectError(error.AliasedMleOwners, left.foldOwnedSecurePair(&right, a, S.one()));
    try std.testing.expectError(error.AliasedMleOwners, left.foldOwnedSecurePair(&left, a, S.one()));
    for (caller, 0..) |v, i| try std.testing.expectEqualDeep(dense(S, i), v);
}
test "paired borrowed aliases are immutable and become separate owned outputs" {
    const S = core.fields.om31.OM31;
    const T = ML.MleFor(S, S);
    const caller = try a.alloc(S, 32);
    defer a.free(caller);
    for (caller, 0..) |*v, i| v.* = dense(S, i);
    var left = try T.initBorrowed(caller);
    defer left.deinit(a);
    var right = try T.initBorrowed(caller);
    defer right.deinit(a);
    try left.foldOwnedSecurePair(&right, a, dense(S, 97));
    try std.testing.expect(left.owns_evals and right.owns_evals and left.evals.ptr != right.evals.ptr);
    try std.testing.expectEqualDeep(left.evals, right.evals);
    for (caller, 0..) |v, i| try std.testing.expectEqualDeep(dense(S, i), v);
}
fn pairLifecycle(allocator: std.mem.Allocator) !void {
    const S = core.fields.om31.OM31;
    var wrapper = NoResize{ .child = allocator };
    const child = wrapper.allocator();
    var left = try ML.MleFor(S, S).initOwned(try child.alloc(S, 32));
    defer left.deinit(child);
    var right = try ML.MleFor(S, S).initOwned(try child.alloc(S, 32));
    defer right.deinit(child);
    for (left.evals, right.evals, 0..) |*x, *y, i| {
        x.* = dense(S, i);
        y.* = dense(S, i + 211);
    }
    try left.foldOwnedSecurePair(&right, child, dense(S, 97));
}
test "paired owned nonresizable folds deinitialize both owners at every OOM boundary" {
    try std.testing.checkAllAllocationFailures(a, pairLifecycle, .{});
}

fn multiplicityOwnedLifecycle(comptime S: type, allocator: std.mem.Allocator, borrowed_num: bool) !void {
    const Layer = G.ForField(S).Layer;
    var wrapper = NoResize{ .child = allocator };
    const child = wrapper.allocator();
    const n = try child.alloc(M, 32);
    var owns_base = true;
    defer if (owns_base) child.free(n);
    const d = try child.alloc(S, 32);
    var layer = Layer{ .LogUpMultiplicities = .{
        .numerators = if (borrowed_num) try ML.MleFor(S, M).initBorrowed(n) else try ML.MleFor(S, M).initOwned(n),
        .denominators = try ML.MleFor(S, S).initOwned(d),
    } };
    if (!borrowed_num) owns_base = false;
    defer layer.deinit(child);
    for (n, d, 0..) |*x, *y, i| {
        x.* = if (i % 3 == 0) M.zero() else if (i % 3 == 1) M.one().neg() else M.fromCanonical(@intCast(i));
        y.* = dense(S, i + 211);
    }
    const r = dense(S, 97);
    try layer.fixFirstVariableInPlace(child, r);
    try std.testing.expectEqual(std.meta.Tag(Layer).LogUpGeneric, std.meta.activeTag(layer));
    const inner = layer.LogUpGeneric;
    for (inner.numerators.evals, inner.denominators.evals, 0..) |x, y, i| {
        const lo = if (i % 3 == 0) M.zero() else if (i % 3 == 1) M.one().neg() else M.fromCanonical(@intCast(i));
        const j = i + 16;
        const hi = if (j % 3 == 0) M.zero() else if (j % 3 == 1) M.one().neg() else M.fromCanonical(@intCast(j));
        try std.testing.expectEqualDeep(S.fromBase(lo).add(r.mulM31(hi.sub(lo))), x);
        try std.testing.expectEqualDeep(dense(S, i + 211).add(r.mul(dense(S, i + 227).sub(dense(S, i + 211)))), y);
    }
    if (borrowed_num) for (n, 0..) |x, i| {
        const expected = if (i % 3 == 0) M.zero() else if (i % 3 == 1) M.one().neg() else M.fromCanonical(@intCast(i));
        try std.testing.expectEqualDeep(expected, x);
    };
}
fn ownedNumLifecycle(allocator: std.mem.Allocator) !void {
    try multiplicityOwnedLifecycle(core.fields.om31.OM31, allocator, false);
}
fn borrowedNumLifecycle(allocator: std.mem.Allocator) !void {
    try multiplicityOwnedLifecycle(core.fields.om31.OM31, allocator, true);
}
test "multiplicity owned denominator lift preserves Q OM scalar fractions and caller base inputs" {
    try multiplicityOwnedLifecycle(core.fields.qm31.QM31, a, false);
    try multiplicityOwnedLifecycle(core.fields.om31.OM31, a, false);
    try multiplicityOwnedLifecycle(core.fields.om31.OM31, a, true);
}
test "multiplicity owned denominator lift cleans every allocation failure with both base ownerships" {
    try std.testing.checkAllAllocationFailures(a, ownedNumLifecycle, .{});
    try std.testing.checkAllAllocationFailures(a, borrowedNumLifecycle, .{});
}
test "multiplicity fold rejects unequal and overlapping owned planes before mutation" {
    const S = core.fields.om31.OM31;
    const Layer = G.ForField(S).Layer;
    const n = try a.alloc(M, 32);
    defer a.free(n);
    const d = try a.alloc(S, 32);
    defer a.free(d);
    for (d, 0..) |*v, i| v.* = dense(S, i);
    var wrong = Layer{ .LogUpMultiplicities = .{ .numerators = try ML.MleFor(S, M).initBorrowed(n[0..16]), .denominators = try ML.MleFor(S, S).initOwned(d) } };
    // Validation only; outer scope retains the real owners.
    try std.testing.expectError(error.PairShapeMismatch, wrong.fixFirstVariableInPlace(a, S.one()));
    const overlapping: [*]M = @ptrCast(d.ptr);
    wrong.LogUpMultiplicities.numerators = try ML.MleFor(S, M).initBorrowed(overlapping[0..32]);
    try std.testing.expectError(error.AliasedMleOwners, wrong.fixFirstVariableInPlace(a, S.one()));
    for (d, 0..) |v, i| try std.testing.expectEqualDeep(dense(S, i), v);
}
