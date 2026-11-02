const std = @import("std");
const H = @import("honest.zig");
const Core = @import("catalog.zig");
const Services = @import("catalog_services.zig");
const V3 = @import("../word16_global_execution/services/v3_fixture.zig");
const a = std.testing.allocator;

const Truths = @import("catalog_truths.zig");
const Obs = H.Observer(.{ Core.handlers, Services.handlers, Truths.handlers });

fn finish() !void {
    if (Obs.failure) |err| return err;
    Obs.tally.print();
    try std.testing.expect(Obs.tally.observed > 0);
    try std.testing.expectEqual(@as(usize, 0), Obs.tally.unrecognised);
}
fn proveV3(options: V3.Case.Options) !void {
    Obs.install();
    defer Obs.uninstall();
    var c = try V3.Case.initWith(a, .none, options);
    defer c.deinit();
    try finish();
}
const Dword = @import("../word16_global_execution/services/ls_dword_fixture.zig");
const Jumpdest = @import("../word16_global_execution/services/jumpdest_fixture.zig");
const Curves = @import("../word16_global_execution/services/curves_fixture.zig");
const Sponge = @import("../word16_global_execution/services/sponge_fixture.zig");
const BulkExt = @import("../word16_global_execution/services/bulk_ext_fixture.zig");
const Types = @import("../word16_global_execution/services/types.zig");

test "honest LS-D64 proofs (plain and all-fused layouts)" {
    const both = [2]Types.Logs{ .{ .ls_dword = 5 }, .{ .ls_dword = 5, .ls_dword_tail = 5 } };
    for ([_]bool{ false, true }) |fused| {
        Obs.install();
        defer Obs.uninstall();
        var c = try Dword.Case.initLayout(a, both, .none, fused);
        defer c.deinit();
        try finish();
    }
}
test "honest JUMPDEST and unaligned-copy/compare bulk proofs" {
    {
        Obs.install();
        defer Obs.uninstall();
        var c = try Jumpdest.Case.init(a);
        defer c.deinit();
        try finish();
    }
    Obs.install();
    defer Obs.uninstall();
    var c = try BulkExt.Case.init(a);
    defer c.deinit();
    try finish();
}
test "honest curve/field proofs: every op on the fused-pair + LS-D64 CPU layout" {
    for (@import("stwo_riscv_frontend").rv64.ethereum_services.curves.ALL) |op| {
        Obs.install();
        defer Obs.uninstall();
        var c = try Curves.Case.initWith(a, op, .none, false, .{ .cpu_fused_tail = true, .cpu_u8_pairs = true, .ls_dword = true });
        defer c.deinit();
        try finish();
    }
}
test "honest Keccak sponge proofs with triple_v2 and throughput Keccak-f truths" {
    {
        Obs.install();
        defer Obs.uninstall();
        var c = try Sponge.Case.init(a, .none, false);
        defer c.deinit();
        try finish();
    }
    Obs.install();
    defer Obs.uninstall();
    var c = try Sponge.Case.initPolicy(a, .none, false, .throughput_v1);
    defer c.deinit();
    try finish();
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
test "honest v3 services proofs (compact-decode CPU)" {
    try proveV3(.{ .cpu_fused_tail = true, .cpu_u8_pairs = true, .cpu_compact_decode = true });
}
