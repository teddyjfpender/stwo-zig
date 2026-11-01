const std = @import("std");
const core = @import("stwo_core");
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;
const Manifest = @import("manifest.zig");
const Child = @import("child.zig");
const Frame = @import("frame.zig");
const a = std.testing.allocator;
const instances = [_]Frame.Instance{
    .{ .origin = .{ .core = .alu }, .row_log = 5, .terms = 1, .fixed_offset = 0, .main_offset = 0 },
    .{ .origin = .{ .core = .range16 }, .row_log = 5, .terms = 1, .fixed_offset = 2, .main_offset = 47 },
};
const Balanced = struct {
    pub fn emit(_: @This(), instance: Frame.Instance, logical: usize, sink: *@import("inputs.zig").RowSink) !void {
        sink.emitBase(.range16, [1]M{M.fromCanonical(@intCast(logical))}, if (instance.origin.core == .alu) M.one() else M.one().neg());
    }
};
const Fixture = struct {
    children: [2]*Child.Unbound,
    expected: [3]Manifest.ExpectedWorker,
    stages: [3]Manifest.StageOne,
    fn init() !Fixture {
        var children: [2]*Child.Unbound = undefined;
        var initialized: usize = 0;
        errdefer for (children[0..initialized]) |child| child.deinit();
        var expected: [3]Manifest.ExpectedWorker = undefined;
        var stages: [3]Manifest.StageOne = undefined;
        for (0..2) |i| {
            const scope = @import("receipt.zig").Scope{ .statement = @splat(@intCast(11 + i)), .fixed = @splat(@intCast(21 + i)), .main = @splat(@intCast(31 + i)), .ordinal = @intCast(i) };
            children[i] = try Child.Unbound.prove(a, 1 << 20, scope, &instances, Balanced{});
            initialized += 1;
            expected[i] = .{ .kind = .cpu, .global_relations = .{ .ram = true, .kio = true, .wire = true }, .ordinal = @intCast(i), .statement = scope.statement, .fixed = scope.fixed, .local_instances = &instances };
            stages[i] = .{ .main = scope.main, .local = .{ .proof = &children[i].result.proof, .receipt_digest = children[i].digest } };
        }
        expected[2] = .{ .kind = .keccak, .global_relations = .{ .ram = false, .kio = true, .wire = false }, .ordinal = 2, .statement = @splat(41), .fixed = @splat(42), .local_instances = null };
        stages[2] = .{ .main = @splat(43), .local = null };
        return .{ .children = children, .expected = expected, .stages = stages };
    }
    fn deinit(self: *Fixture) void {
        for (self.children) |child| child.deinit();
    }
    fn verify(self: *const Fixture) !Manifest.PendingManifest {
        return Manifest.verifyAndSeal(a, @splat(1), &self.expected, &self.stages);
    }
};
fn refused(result: anyerror!Manifest.PendingManifest) !void {
    if (result) |value| {
        var unexpected = value;
        unexpected.deinit(a);
        return error.InvalidManifestAccepted;
    } else |_| {}
}

test "OM manifest verifies actual local children before deriving shared eight-coordinate globals" {
    var f = try Fixture.init();
    defer f.deinit();
    var first = try f.verify();
    defer first.deinit(a);
    var fresh = try f.verify();
    defer fresh.deinit(a);
    try std.testing.expectEqualDeep(first.digest, fresh.digest);
    try std.testing.expectEqualDeep(first.shared, fresh.shared);
    try std.testing.expect(first.entries[0].local != null and first.entries[1].local != null and first.entries[2].local == null);
    try std.testing.expect(!first.shared.ram.offset.c1.isZero());
    try std.testing.expect(!first.shared.kio.offset.c1.isZero());
    try std.testing.expect(!first.shared.wire.offset.c1.isZero());
    for (f.expected, f.stages, 0..) |expected, stage, i| try first.checkPhysicalRoots(i, expected.fixed, stage.main);
}

test "OM manifest rejects missing reordered and relabeled worker authority before allocation" {
    var f = try Fixture.init();
    defer f.deinit();
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    try std.testing.expectError(error.GlobalGkrManifestRoster, Manifest.verifyAndSeal(fail.allocator(), @splat(1), &f.expected, f.stages[0..2]));
    try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
    std.mem.swap(Manifest.ExpectedWorker, &f.expected[0], &f.expected[1]);
    try std.testing.expectError(error.GlobalGkrManifestOrdinal, f.verify());
    std.mem.swap(Manifest.ExpectedWorker, &f.expected[0], &f.expected[1]);
    f.stages[0].local = null;
    try std.testing.expectError(error.MissingGlobalGkrLocalChild, f.verify());
    f.stages[0].local = .{ .proof = &f.children[0].result.proof, .receipt_digest = f.children[0].digest };
    f.stages[2].local = f.stages[0].local;
    try std.testing.expectError(error.UnexpectedGlobalGkrLocalChild, f.verify());
}

test "OM manifest rejects substituted local statement root roster or receipt" {
    var f = try Fixture.init();
    defer f.deinit();
    f.expected[0].statement[0] ^= 1;
    try refused(f.verify());
    f.expected[0].statement[0] ^= 1;
    f.stages[0].main[0] ^= 1;
    try refused(f.verify());
    f.stages[0].main[0] ^= 1;
    f.expected[0].fixed[0] ^= 1;
    try refused(f.verify());
    f.expected[0].fixed[0] ^= 1;
    f.stages[0].local.?.receipt_digest[0] ^= 1;
    try std.testing.expectError(error.LocalGkrReceiptMismatch, f.verify());
    f.stages[0].local.?.receipt_digest[0] ^= 1;
    var changed = instances;
    changed[0].terms = 2;
    f.expected[0].local_instances = &changed;
    try refused(f.verify());
}

test "OM manifest commits classic truth roots and execution scope before global draws" {
    var f = try Fixture.init();
    defer f.deinit();
    var old = try f.verify();
    defer old.deinit(a);
    f.stages[2].main[0] ^= 1;
    var changed = try f.verify();
    defer changed.deinit(a);
    try std.testing.expect(!std.mem.eql(u8, &old.digest, &changed.digest));
    try std.testing.expect(!old.shared.ram.offset.eql(changed.shared.ram.offset));
    try std.testing.expect(!old.shared.kio.offset.eql(changed.shared.kio.offset));
    try std.testing.expect(!old.shared.wire.offset.eql(changed.shared.wire.offset));
    try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, old.checkPhysicalRoots(2, f.expected[2].fixed, f.stages[2].main));
    try std.testing.expectError(error.GlobalGkrManifestOrdinal, old.checkPhysicalRoots(3, @splat(0), @splat(0)));
    var execution = try Manifest.verifyAndSeal(a, @splat(2), &f.expected, &f.stages);
    defer execution.deinit(a);
    try std.testing.expect(!std.mem.eql(u8, &changed.digest, &execution.digest));
}

test "OM manifest closes RAM KIO and Wire separately across every worker" {
    var f = try Fixture.init();
    defer f.deinit();
    var manifest = try f.verify();
    defer manifest.deinit(a);
    var claims = [_]Manifest.Claims{.{ .ram = O.zero(), .kio = O.zero(), .wire = O.zero() }} ** 3;
    claims[0].ram = O.basis();
    claims[1].ram = O.basis().neg();
    try manifest.checkGlobalClosure(&claims);
    try std.testing.expectError(error.GlobalGkrManifestRoster, manifest.checkGlobalClosure(claims[0..2]));
    claims[0].kio = O.one();
    claims[0].wire = O.one().neg();
    try std.testing.expectError(error.UnclosedGlobalGkrKio, manifest.checkGlobalClosure(&claims));
    claims[1].kio = O.one().neg();
    try std.testing.expectError(error.UnclosedGlobalGkrWire, manifest.checkGlobalClosure(&claims));
    claims[1].wire = O.one();
    try manifest.checkGlobalClosure(&claims);
    claims[1].ram = O.zero();
    try std.testing.expectError(error.UnclosedGlobalGkrRam, manifest.checkGlobalClosure(&claims));
}
fn allocationProbe(allocator: std.mem.Allocator, expected: []const Manifest.ExpectedWorker, stages: []const Manifest.StageOne) !void {
    var manifest = try Manifest.verifyAndSeal(allocator, @splat(1), expected, stages);
    defer manifest.deinit(allocator);
}
test "OM manifest unwinds every partial child verification allocation failure" {
    var f = try Fixture.init();
    defer f.deinit();
    try std.testing.checkAllAllocationFailures(a, allocationProbe, .{ &f.expected, &f.stages });
}

test "OM manifest rejects absent relation debt even if another worker cancels it" {
    var f = try Fixture.init();
    defer f.deinit();
    var manifest = try f.verify();
    defer manifest.deinit(a);
    var claims = [_]Manifest.Claims{.{ .ram = O.zero(), .kio = O.zero(), .wire = O.zero() }} ** 3;
    claims[0].ram = O.one();
    claims[2].ram = O.one().neg();
    try std.testing.expectError(error.NonzeroAbsentGlobalGkrClaim, manifest.checkGlobalClosure(&claims));
    f.expected[2].global_relations.ram = true;
    try std.testing.expectError(error.GlobalGkrRelationRoster, f.verify());
}
