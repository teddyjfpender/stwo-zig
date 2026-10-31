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
