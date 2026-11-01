const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Base = @import("coordinator_fixture.zig");
const F = @import("../fixture.zig");
const C = @import("coordinator.zig");
const KR = @import("../../keccak/shared/roster.zig");
const SR = @import("../../secp/roster.zig");
const a = std.testing.allocator;
fn keys() !Base.Keys {
    var out = try Base.Keys.init(a);
    errdefer out.deinit();
    var k = try KR.TruthSetup.init(a, 11);
    out.keccak.deinit();
    out.keccak.* = k;
    k = undefined;
    var add = try SR.TruthSetup.init(a, .add, .{ @max(11, out.add.logs[0]), @max(11, out.add.logs[1]) });
    out.add.deinit();
    out.add.* = add;
    add = undefined;
    var double = try SR.TruthSetup.init(a, .double, .{ @max(11, out.double.logs[0]), @max(11, out.double.logs[1]) });
    out.double.deinit();
    out.double.* = double;
    double = undefined;
    return out;
}
fn produce(k: *const Base.Keys, workers: u8) !C.Bundle {
    var captured = try F.Captured.init(a);
    defer captured.deinit();
    return C.produce(a, &k.pointers(), &k.truths(), &.{ &captured.native[0], &captured.native[1] }, &captured.advice, F.expectedFor(captured.program.identity), try Base.config(), .{ .gkr_budget = 2 << 30, .max_retained_frontend_bytes = 2 << 30, .global_budget = 1 << 30, .schedule = .{ .lanes = 1, .workers_per_lane = workers } });
}
fn digest(bundle: *const C.Bundle) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(bundle.stage_one_bytes);
    for (bundle.cpus) |p| {
        h.update(p.bytes);
        for (p.claims) |v| h.update(&v.toBytesLe());
    }
    for (bundle.truths) |p| {
        h.update(p.bytes);
        for (p.claims) |v| h.update(&v.toBytesLe());
    }
    return h.finalResult();
}
test "truth packed domain whole service proof parity across bounded1MiB pool and serial" {
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .stack_size = 1024 * 1024 });
    defer pool.deinit();
    var binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var k = try keys();
    defer k.deinit();
    var serial = try produce(&k, 1);
    defer serial.deinit(a);
    var parallel = try produce(&k, 4);
    defer parallel.deinit(a);
    try std.testing.expectEqualSlices(u8, serial.stage_one_bytes, parallel.stage_one_bytes);
    for (serial.cpus, parallel.cpus) |left, right| {
        try std.testing.expectEqualSlices(u8, left.bytes, right.bytes);
        try std.testing.expectEqualDeep(left.claims, right.claims);
    }
    for (serial.truths, parallel.truths) |left, right| {
        try std.testing.expectEqualSlices(u8, left.bytes, right.bytes);
        try std.testing.expectEqualDeep(left.claims, right.claims);
    }
    var fresh = try keys();
    defer fresh.deinit();
    const accepted = try parallel.verify(a, &fresh.pointers(), &fresh.truths(), F.expectedFor(fresh.cpus[0].materials.program.identity), try Base.config());
    try std.testing.expect(accepted.completed);
    var pinned: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pinned, "eaa04370373513f54f8c7435f1453983681413dfd978f56026f363ed8fa9f386");
    try std.testing.expectEqualSlices(u8, &pinned, &digest(&parallel));
    std.debug.print("TRUTH_DOMAIN_CAPTURE bundle_sha256={x} proofs={d} fresh_global_closed=true\n", .{ digest(&parallel), accepted.physical_proofs });
}

const A = @import("stwo_riscv_frontend").rv64_air;
const E = A.evaluation;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Role = @import("truth_role.zig");
const Domain = @import("truth_role_domain.zig");
const PF = E.PackedFields.BaseForField(O);
const PS = E.SecureFor(PF);
const ScalarSamples = struct {
    lane: usize,
    pub fn get(self: @This(), tree: usize, col: usize, shift: i32) !O {
        return O.fromBase(value(self.lane, tree, col, shift));
    }
    pub fn last(self: @This()) !O {
        return O.fromBase(value(self.lane, 3, 0, 0));
    }
};
fn value(lane: usize, tree: usize, col: usize, shift: i32) M {
    return M.fromCanonical(@intCast((lane * 7919 + tree * 100003 + col * 11 + @as(usize, @intCast(shift + 2))) % 1000003));
}
const PackedSamples = struct {
    pub fn get(_: @This(), tree: usize, col: usize, shift: i32) !PF {
        var lanes: [E.LANES]M = undefined;
        for (&lanes, 0..) |*v, i| v.* = value(i, tree, col, shift);
        return PF.fromLanes(lanes);
    }
    pub fn last(self: @This()) !PF {
        return self.get(3, 0, 0);
    }
};
test "truth shared workspace matches original wrapper and scalar constraints for every family" {
    var ch = core.channel.raw_mod_m31.Om31Channel.init();
    const local = @import("truth_fractions.zig").ChallengesFor(O).draw(&ch);
    var shared: @import("manifest.zig").Shared = undefined;
    shared.ram.offset = ch.drawSecureFelt();
    for (&shared.ram.coefficients) |*v| v.* = ch.drawSecureFelt();
    shared.kio = A.crypto.keccak.equations.IoFor(O).draw(&ch);
    shared.wire = A.crypto.secp256k1.equations.WireFor(O).draw(&ch);
    const workspace = try a.create(Domain.RowWorkspace);
    defer a.destroy(workspace);
    for (std.enums.values(Role.Kind)) |kind| {
        const role = Role.Component{ .kind = kind, .log_size = 5, .program = if (kind == .product or kind == .linear) A.crypto.secp256k1.program.get(.add) else null, .byte_policy = .canonical_inputs, .local = local, .shared = shared, .claim = ch.drawSecureFelt(), .global_claim = ch.drawSecureFelt(), .split = if (kind == .keccak) 2 else 1 };
        const count = role.nConstraints();
        const wrapped = try a.alloc(PS, count);
        defer a.free(wrapped);
        const explicit = try a.alloc(PS, count);
        defer a.free(explicit);
        var old = E.SinkFor(PF){ .values = wrapped };
        var heap = E.SinkFor(PF){ .values = explicit };
        try role.emitFor(PF, PackedSamples{}, &old);
        try role.emitForWithWorkspace(PF, PackedSamples{}, &heap, workspace);
        try std.testing.expectEqual(count, heap.count);
        try std.testing.expectEqualDeep(wrapped, explicit);
        const scalar = try a.alloc(O, count);
        defer a.free(scalar);
        for ([_]usize{ 0, E.LANES - 1 }) |lane| {
            var sink = E.SinkFor(O){ .values = scalar };
            try role.emitFor(O, ScalarSamples{ .lane = lane }, &sink);
            for (scalar, explicit) |expected, pack_value| try std.testing.expectEqualDeep(expected, pack_value.lane(lane));
        }
    }
}
fn workspaceAllocation(allocator: std.mem.Allocator) !void {
    const plan = try Domain.WorkspacePlan.init(2048, 4);
    const work = try plan.allocate(allocator);
    defer allocator.free(work);
    try std.testing.expectEqual(@as(usize, 2), work.len);
}
test "truth row scratch is explicitly capped and failure atomic" {
    try std.testing.expectError(error.InvalidWideTruthTrace, Domain.WorkspacePlan.init(0, 4));
    try std.testing.expectError(error.InvalidWideTruthTrace, Domain.WorkspacePlan.init(17, 4));
    const maximal = try Domain.WorkspacePlan.init(1 << 22, std.math.maxInt(usize));
    try std.testing.expectEqual(@as(usize, 16), maximal.jobs);
    try std.testing.expect(maximal.bytes <= Domain.MAX_ROW_WORKSPACE_BYTES);
    try std.testing.expect(@sizeOf(Domain.RowWorkspace) > 1024 * 1024);
    try std.testing.expectError(error.WideTruthRowScratchBudgetExceeded, (Domain.WorkspacePlan{ .jobs = 17, .bytes = 0 }).allocate(a));
    try std.testing.checkAllAllocationFailures(a, workspaceAllocation, .{});
}
