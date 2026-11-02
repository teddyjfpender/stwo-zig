const std = @import("std");
const H = @import("honest.zig");
const Core = @import("catalog.zig");
const Services = @import("catalog_services.zig");
const V3 = @import("../word16_global_execution/services/v3_fixture.zig");
const a = std.testing.allocator;

const Truths = @import("catalog_truths.zig");
const Obs = H.Observer(.{ Core.handlers, Services.handlers, Truths.handlers });

fn proveV3(options: V3.Case.Options) !void {
    Obs.install();
    defer Obs.uninstall();
    var c = try V3.Case.initWith(a, .none, options);
    defer c.deinit();
    if (Obs.failure) |err| return err;
    Obs.tally.print();
    try std.testing.expect(Obs.tally.observed > 0);
    try std.testing.expectEqual(@as(usize, 0), Obs.tally.unrecognised);
}

test "honest v3 services proofs (classic CPU): every composition handle matches the IR bit for bit" {
    try proveV3(.{});
}
test "honest v3 services proofs (fused-tail CPU)" {
    try proveV3(.{ .cpu_fused_tail = true });
}
test "honest v3 services proofs (byte-pair CPU)" {
    try proveV3(.{ .cpu_fused_tail = true, .cpu_u8_pairs = true });
}
