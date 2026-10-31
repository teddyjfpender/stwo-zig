const std = @import("std");
const E = @import("execution.zig");
const F = @import("fixture.zig");
const Setup = @import("../word16_execution/setup.zig").Setup;
const a = std.testing.allocator;
test "Actual two CPU shards share RAM across store load with one trusted INIT and final TEARDOWN" {
    var case = try F.Case.init(a);
    defer case.deinit();
    const keys = case.keys();
    try E.verify(a, &keys, case.expected(), &case.bundle);
    try std.testing.expect(case.bundle.proofs[0].request.memory.initial.len > 0);
    try std.testing.expectEqual(@as(usize, 0), case.bundle.proofs[0].request.memory.terminal.len);
    try std.testing.expectEqual(@as(usize, 0), case.bundle.proofs[1].request.memory.initial.len);
    try std.testing.expect(case.bundle.proofs[1].request.memory.terminal.len > 0);
    try std.testing.expect(!case.bundle.proofs[0].claims.ls.ram.add(case.bundle.proofs[0].claims.initial.ram).isZero());
    var fresh0 = try Setup.initWithAuthority(a, &case.fixture.image.authority, case.setups[0].materials.geometry);
    defer fresh0.deinit();
    var fresh1 = try Setup.initWithAuthority(a, &case.fixture.image.authority, case.setups[1].materials.geometry);
    defer fresh1.deinit();
    try E.verify(a, &.{ &fresh0, &fresh1 }, case.expected(), &case.bundle);
}

test "Independent INIT TERM domains physically prove cross shard RAM and default geometry keys stay exact" {
    var case = try F.Case.initWithIndependentBoundaries(a);
    defer case.deinit();
    try std.testing.expectEqual(@as(u32, 6), case.setups[0].materials.geometry.initialLog());
    try std.testing.expectEqual(@as(u32, 5), case.setups[0].materials.geometry.terminalLog());
    try std.testing.expectEqual(@as(u32, 5), case.setups[1].materials.geometry.initialLog());
    try std.testing.expectEqual(@as(u32, 6), case.setups[1].materials.geometry.terminalLog());
    var fresh0 = try Setup.initWithAuthority(a, &case.fixture.image.authority, case.setups[0].materials.geometry);
    defer fresh0.deinit();
    var fresh1 = try Setup.initWithAuthority(a, &case.fixture.image.authority, case.setups[1].materials.geometry);
    defer fresh1.deinit();
    try E.verify(a, &.{ &fresh0, &fresh1 }, case.expected(), &case.bundle);
    const G = @import("../word16_execution/geometry.zig");
    const legacy = G.Geometry{ .cpu_log = 5, .boundary_log = 6 };
    var explicit = legacy;
    explicit.initial_log = 6;
    explicit.terminal_log = 6;
    try std.testing.expectEqual(try legacy.range16Mass(), try explicit.range16Mass());
    var old_key = try Setup.initWithAuthority(a, &case.fixture.image.authority, legacy);
    defer old_key.deinit();
    var same_key = try Setup.initWithAuthority(a, &case.fixture.image.authority, explicit);
    defer same_key.deinit();
    try std.testing.expectEqualSlices(u8, &old_key.fixed_root.value, &same_key.fixed_root.value);
    explicit.terminal_log = 5;
    try std.testing.expectEqual(@as(u64, 4 * 32), (try legacy.range16Mass()) - (try explicit.range16Mass()));
    try std.testing.expectEqual(@as(u64, 0), (try legacy.range8Mass()) - (try explicit.range8Mass()));
    explicit.initial_log = 4;
    try std.testing.expectError(error.InvalidExecutionGeometry, explicit.validate());
}
