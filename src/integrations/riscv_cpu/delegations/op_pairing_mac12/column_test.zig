//! Same-source numerical/failure gates for bounded physical column generation.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const A = @import("stwo_riscv_frontend").rv64_air;
const G = A.crypto.bn254_pairing_mac12;
const T = @import("trace.zig");
const Fixture = struct {
    original: G.original_witness.Witness,
    plan: G.lowering.Program,
    normalized: G.witness.Witness,
    pub fn init(a: std.mem.Allocator) !@This() {
        const r = G.residue_vectors.POSITIVE;
        var original = try G.original_witness.Witness.init(a, G.vectors.INPUT, .{ .seed = r.seed, .scale = r.c[0..6].*, .inverse2 = r.inverse2 });
        errdefer original.deinit();
        var plan = try G.lowering.Program.init(a);
        errdefer plan.deinit();
        var normalized = try G.witness.Witness.init(a, &plan, &original);
        errdefer normalized.deinit();
        return .{ .original = original, .plan = plan, .normalized = normalized };
    }
    pub fn deinit(f: *@This()) void {
        f.normalized.deinit();
        f.plan.deinit();
        f.original.deinit();
    }
    pub fn model(f: *const @This()) !G.fixture.Model {
        const expected = try G.source.initialValues(G.vectors.INPUT);
        return G.fixture.Model.init(&f.plan, &f.normalized, &expected);
    }
};
const Poison = struct {
    backing: std.mem.Allocator,
    fn allocator(p: *@This()) std.mem.Allocator {
        return .{ .ptr = p, .vtable = &.{ .alloc = alloc, .resize = resize, .remap = remap, .free = free } };
    }
    fn alloc(ctx: *anyopaque, len: usize, alignment: std.mem.Alignment, ret: usize) ?[*]u8 {
        const p: *@This() = @ptrCast(@alignCast(ctx));
        const bytes = p.backing.rawAlloc(len, alignment, ret) orelse return null;
        @memset(bytes[0..len], 0xa5);
        return bytes;
    }
    fn resize(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) bool {
        return false;
    }
    fn remap(_: *anyopaque, _: []u8, _: std.mem.Alignment, _: usize, _: usize) ?[*]u8 {
        return null;
    }
    fn free(ctx: *anyopaque, bytes: []u8, alignment: std.mem.Alignment, ret: usize) void {
        const p: *@This() = @ptrCast(@alignCast(ctx));
        p.backing.rawFree(bytes, alignment, ret);
    }
};
test "MAC12 complete physical tiles initialize every matrix field and match scalar reference" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 16 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var parallel = try fixture.model();
    var reference = try fixture.model();
    var pp: [4]T.Part = undefined;
    var rr: [4]T.Part = undefined;
    var count: usize = 0;
    defer for (pp[0..count], rr[0..count]) |*p, *r| {
        p.deinit();
        r.deinit();
    };
    var poison = Poison{ .backing = a };
    inline for (T.ORDER, 0..) |role, i| {
        pp[i] = try T.Part.init(role, poison.allocator(), &parallel);
        rr[i] = T.Part.initScalarReferenceForTesting(role, a, &reference) catch |err| {
            pp[i].deinit();
            return err;
        };
        count += 1;
        try std.testing.expectEqualSlices(@TypeOf(pp[i].fixed[0]), rr[i].fixed, pp[i].fixed);
        try std.testing.expectEqualSlices(@TypeOf(pp[i].main[0]), rr[i].main, pp[i].main);
        try std.testing.expectEqualSlices(@TypeOf(pp[i].inter[0]), rr[i].inter, pp[i].inter);
    }
    try parallel.requireColumns();
    try reference.requireColumns();
}
fn allocationGate(a: std.mem.Allocator, fixture: *const Fixture) !void {
    var model = try fixture.model();
    var part = try T.Part.init(.arithmetic, a, &model);
    var owns = true;
    defer if (owns) part.deinit();
    try std.testing.expect(model.columns[@intFromEnum(G.fixture.Role.arithmetic)] != null);
    part.deinit();
    owns = false;
    try std.testing.expect(model.columns[@intFromEnum(G.fixture.Role.arithmetic)] == null);
}
test "MAC12 complete joined row errors and OOM leave no installed borrowed columns" {
    const a = std.testing.allocator;
    var fixture = try Fixture.init(a);
    defer fixture.deinit();
    var pool: engine.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 16 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    try std.testing.checkAllAllocationFailures(a, allocationGate, .{&fixture});
    const budget = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(a, 2 << 30);
    defer budget.destroy();
    const expected = try G.source.initialValues(G.vectors.INPUT);
    var authority = try G.fixture.Model.initAuthority(&fixture.plan, &expected);
    try std.testing.expectError(error.PairingFixtureMissingWitness, T.Part.init(.arithmetic, budget.allocator(), &authority));
    try std.testing.expect(authority.columns[@intFromEnum(G.fixture.Role.arithmetic)] == null);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    var model = try fixture.model();
    const id = fixture.plan.stages[1024].writer;
    const original = fixture.normalized.values[id];
    fixture.normalized.values[id] += G.source.B.BN254_P;
    defer fixture.normalized.values[id] = original;
    const result = T.Part.init(.arithmetic, budget.allocator(), &model);
    if (result) |value| {
        var unexpected = value;
        unexpected.deinit();
        return error.ExpectedNoncanonicalColumnFailure;
    } else |_| {}
    try std.testing.expect(model.columns[@intFromEnum(G.fixture.Role.arithmetic)] == null);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectError(error.PairingFixtureMissingColumns, T.Part.init(.table, budget.allocator(), &model));
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
}
