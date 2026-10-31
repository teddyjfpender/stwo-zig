const std = @import("std");
const F = @import("fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const a = std.testing.allocator;
test "Actual two CPU shards Keccak IO and global RAM join through one first INIT and final TERM" {
    var c = try F.Case.init(a);
    defer c.deinit();
    const keys = c.keys();
    try E.verify(a, &keys, c.expected(), &c.bundle);
    var s0 = try R.Setup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[0].base.materials.geometry, c.setups[0].geo);
    defer s0.deinit();
    var s1 = try R.Setup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[1].base.materials.geometry, c.setups[1].geo);
    defer s1.deinit();
    try E.verify(a, &.{ &s0, &s1 }, c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(usize, 25), c.bundle.proofs[0].request.base.memory.initial.len);
    try std.testing.expectEqual(@as(usize, 0), c.bundle.proofs[0].request.base.memory.terminal.len);
    try std.testing.expectEqual(@as(usize, 0), c.bundle.proofs[1].request.base.memory.initial.len);
    try std.testing.expectEqual(@as(usize, 25), c.bundle.proofs[1].request.base.memory.terminal.len);
}

test "Actual physically proved K output forgery and cross shard predecessor reset reject" {
    var bad = try F.Case.initMutation(a, .wrong_output);
    defer bad.deinit();
    const keys = bad.keys();
    try std.testing.expectError(error.UnclosedLocalKeccakRelations, E.verify(a, &keys, bad.expected(), &bad.bundle));
    var reset = try F.Case.initMutation(a, .false_reset);
    defer reset.deinit();
    const rr = reset.keys();
    // Both local CPU/K/bridge proofs verify, including strict chronology and
    // all local debt. Only aggregate RAM detects the invented genesis read.
    try std.testing.expectError(error.UnclosedGlobalKeccakExecution, E.verify(a, &rr, reset.expected(), &reset.bundle));
}

test "Service inventory fixed roots claims and pristine genesis remain receiver bound" {
    var c = try F.Case.init(a);
    defer c.deinit();
    const keys = c.keys();
    const saved = c.bundle.proofs[0].claims.keccak.bridge.io;
    c.bundle.proofs[0].claims.keccak.bridge.io = saved.add(@import("stwo_core").fields.qm31.QM31.one());
    c.bundle.proofs[0].claims.keccak.bridge.owner = c.bundle.proofs[0].claims.keccak.bridge.owner.sub(@import("stwo_core").fields.qm31.QM31.one());
    if (E.verify(a, &keys, c.expected(), &c.bundle)) |_| return error.AcceptedForgedPhysicalClaim else |_| {}
    c.bundle.proofs[0].claims.keccak.bridge.io = saved;
    c.bundle.proofs[0].claims.keccak.bridge.owner = c.bundle.proofs[0].claims.keccak.bridge.owner.add(@import("stwo_core").fields.qm31.QM31.one());
    c.bundle.proofs[0].request.calls += 1;
    try std.testing.expectError(error.InvalidWord16KeccakGeometry, E.verify(a, &keys, c.expected(), &c.bundle));
    c.bundle.proofs[0].request.calls -= 1;
    @constCast(c.bundle.proofs[0].request.base.memory.initial)[0].state.value = 1;
    try std.testing.expectError(error.UntrustedGlobalMemoryInitialization, E.verify(a, &keys, c.expected(), &c.bundle));
}
