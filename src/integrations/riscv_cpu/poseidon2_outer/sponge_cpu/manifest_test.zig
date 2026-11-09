//! Pending-phase tests, not complete execution acceptance.
const std = @import("std");
const core = @import("stwo_core");
const M = @import("manifest.zig");
const Base = @import("../pure_p2_native.zig");
const N = @import("native.zig");
const Frame = @import("frame.zig");
const O = core.fields.om31.OM31;
const Proof = @import("stwo_prover_engine").lookups.gkr_verifier.ForField(O).GkrBatchProof;
fn expected(scope: N.Scope, instances: []const Frame.Instance) [3]M.Expected {
    const authority = M.Authority{ .kind = .sponge_cpu, .ordinal = 0, .profile = .op_target_b4_q72_p0_fold4_v1, .fixed_identity = @splat(1), .fixed = scope.fixed, .statement = scope.statement, .global_relations = .{ .ram = true, .kio = false, .wire = true }, .mass = .{ .ram = 100, .kio = 0, .wire = scope.calls } };
    var out: [3]M.Expected = @splat(.{ .authority = authority });
    out[0].cpu = .{ .epoch = scope.epoch, .calls = scope.calls, .instances = instances };
    out[1].authority.kind = .detached;
    out[1].authority.ordinal = 1;
    out[1].authority.global_relations = .{ .ram = true, .kio = true, .wire = true };
    out[1].authority.mass.kio = 100;
    out[2].authority.kind = .keccak;
    out[2].authority.ordinal = 2;
    out[2].authority.global_relations = .{ .ram = false, .kio = true, .wire = false };
    out[2].authority.mass = .{ .ram = 0, .kio = 100, .wire = 0 };
    return out;
}
const INSTANCES = [_]Frame.Instance{
    .{ .legacy = .{ .origin = .{ .core = .cpu }, .row_log = 5, .terms = 15, .fixed_offset = 0, .main_offset = 0 } },
    .{ .frontier = .{ .row_log = 5, .fixed_offset = 1, .main_offset = 1 } },
};
fn testScope() N.Scope {
    return .{ .statement = @splat(8), .fixed = Base.hashWords(&.{ 1, 2 }), .main = Base.hashWords(&.{ 3, 4 }), .ordinal = 0, .epoch = 1, .calls = 1 };
}
test "detached manifest source kind order masks mass epoch and geometry refuse before allocation" {
    var roster = expected(testScope(), &INSTANCES);
    try M.validateExpected(&roster);
    const control = roster;
    roster[0].cpu.?.epoch = 2;
    try std.testing.expectError(error.SpongeCpuGeometry, M.validateExpected(&roster));
    roster = control;
    roster[1].authority.kind = .sponge_cpu;
    try std.testing.expectError(error.MissingGlobalGkrLocalChild, M.validateExpected(&roster));
    roster = control;
    roster[2].authority.mass.wire = 1;
    try std.testing.expectError(error.GlobalGkrRelationMass, M.validateExpected(&roster));
    roster = control;
    roster[1].authority.mass.ram = core.fields.m31.Modulus - 1;
    try std.testing.expectError(error.GlobalGkrCharacteristicBound, M.validateExpected(&roster));
    roster = control;
    roster[1].authority.ordinal = 2;
    try std.testing.expectError(error.GlobalGkrManifestOrdinal, M.validateExpected(&roster));
    roster = control;
    roster[2].authority.profile = .reference_b2_q24_p0;
    try std.testing.expectError(error.InvalidOpNativeProfile, M.validateExpected(&roster));
    const stages = [_]M.StageOne{.{ .main = testScope().main }} ** 3;
    // No child pointer is touched for a missing local child.
    try std.testing.expectError(error.GlobalGkrManifestRoster, M.verifyAndSeal(std.testing.failing_allocator, @splat(4), &control, &stages));
}
/// Called from the existing real two-shard source qualification. No additional
/// guest replay, witness expansion or STARK proof is needed for this phase gate.
pub fn exerciseCheckedCpu(a: std.mem.Allocator, source: N.Scope, instances: []const Frame.Instance, proof: *const Proof, receipt: [36]u8) !void {
    const roster = expected(source, instances);
    var stages = [_]M.StageOne{.{ .main = source.main }} ** 3;
    stages[0].local = .{ .proof = proof, .receipt = receipt };
    var pending = try M.verifyAndSeal(a, @splat(4), &roster, &stages);
    defer pending.deinit(a);
    try std.testing.expectEqualDeep(try @import("../pure_p2_manifest.zig").drawShared(pending.digest), pending.shared);
    try pending.checkPhysicalRoots(0, source.fixed, source.main);
    try std.testing.expectError(error.GlobalGkrPhysicalRootMismatch, pending.checkPhysicalRoots(0, source.fixed, Base.hashWords(&.{9})));
    var claims = [_]@import("../../word16_global_execution/services/gkr_local/manifest.zig").Claims{.{ .ram = O.zero(), .kio = O.zero(), .wire = O.zero() }} ** 3;
    try pending.checkGlobalClosure(&claims);
    claims[0].wire = O.one().neg();
    claims[2].wire = O.one();
    try std.testing.expectError(error.NonzeroAbsentGlobalGkrClaim, pending.checkGlobalClosure(&claims));
    claims[2].wire = O.zero();
    try std.testing.expectError(error.UnclosedGlobalGkrWire, pending.checkGlobalClosure(&claims));
    stages[0].local.?.receipt = Base.hashWords(&.{10});
    try std.testing.expectError(error.LocalGkrReceiptMismatch, M.verifyAndSeal(a, @splat(4), &roster, &stages));
}

test {
    _ = @import("mass.zig");
}
