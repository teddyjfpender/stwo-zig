//! v3 curve/field services-lane qualification for every op: real CPU, bridge
//! and truth proofs, fresh receiver keys over the durable wire, split spans
//! and adversarial global closure.
const std = @import("std");
const F = @import("curves_fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const W = @import("wire.zig");
const T = @import("types.zig");
const CR = @import("../curves/roster.zig");
const G = @import("../protocol.zig");
const a = std.testing.allocator;

fn freshVerify(op: F.Op) !void {
    var c = try F.Case.init(a, op, .none, false);
    defer c.deinit();
    const keys = c.keys();
    var buffer: [2]R.Truth = undefined;
    try E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(usize, 3), c.bundle.manifest.roots.len);
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    try W.write(a, temp.dir, &keys, c.truths(&buffer), &c.bundle);
    var loaded = try W.read(a, temp.dir, .{ .max_cpus = 2, .max_truths = 1, .max_total_steps = 5 });
    defer loaded.deinit(a);
    const family = T.curveFamily(op);
    const k = @intFromEnum(family);
    try std.testing.expectEqual(@as(?u32, 5), loaded.cpu_declarations[0].bridges.at(family));
    try std.testing.expectEqual(@as(?u32, null), loaded.cpu_declarations[0].bridges.sha256);
    try std.testing.expectEqual(@as(u32, 2), loaded.bundle.cpus[0].request.calls[k]);
    try std.testing.expectEqual(@as(u32, 1), loaded.bundle.cpus[1].request.calls[k]);
    try std.testing.expectEqual(family, loaded.truth_declarations[0].family);
    // Fresh, independently constructed receiver keys.
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = F.words(op) }, loaded.cpu_declarations[0].geometry, F.bridges(op));
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = F.words(op) }, loaded.cpu_declarations[1].geometry, F.bridges(op));
    defer s1.deinit();
    var t = try CR.TruthSetup.init(a, op, F.LOG);
    defer t.deinit();
    const fresh = [_]R.Truth{.{ .curve = .{ .setup = &t, .first_id = 1, .calls = 3 } }};
    const expected = F.expectedFor(op, s0.materials.program.identity);
    try E.verify(a, &.{ &s0, &s1 }, &fresh, expected, &loaded.bundle);
    // A receiver expecting no curve bridge, or another op's bridge, rejects.
    var bare = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = F.words(op) }, loaded.cpu_declarations[0].geometry, .{});
    defer bare.deinit();
    try std.testing.expectError(error.InvalidCombinedBridgePresence, E.verify(a, &.{ &bare, &s1 }, &fresh, expected, &loaded.bundle));
    const other_op: F.Op = if (op == .bn254_g1_add) .bn254_fp2_mul else .bn254_g1_add;
    var other = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = F.words(op) }, loaded.cpu_declarations[0].geometry, F.bridges(other_op));
    defer other.deinit();
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &other, &s1 }, &fresh, expected, &loaded.bundle)));
    // Another op's truth key, or a truth key of another size, is a different statement.
    var wrong_op = try CR.TruthSetup.init(a, other_op, F.LOG);
    defer wrong_op.deinit();
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &.{.{ .curve = .{ .setup = &wrong_op, .first_id = 1, .calls = 3 } }}, expected, &loaded.bundle)));
    var big = try CR.TruthSetup.init(a, op, F.LOG + 1);
    defer big.deinit();
    try std.testing.expect(std.meta.isError(E.verify(a, &.{ &s0, &s1 }, &.{.{ .curve = .{ .setup = &big, .first_id = 1, .calls = 3 } }}, expected, &loaded.bundle)));
    // Claim slots unused by the single curve component are pinned to zero.
    loaded.bundle.truths[0].claims[1] = G.Q.one();
    try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &.{ &s0, &s1 }, &fresh, expected, &loaded.bundle));
}

test "v3 curve/field calls: CPU bridges, global RAM and one truth verify with fresh keys and wire (every op)" {
    for (@import("stwo_riscv_frontend").rv64.ethereum_services.curves.ALL) |op| try freshVerify(op);
}

test "v3 curve spans split across two truth proofs close the same Wire35 bus" {
    for ([_]F.Op{ .bn254_g1_double, .bls12_381_fp2_mul }) |op| {
        var c = try F.Case.init(a, op, .none, true);
        defer c.deinit();
        const keys = c.keys();
        var buffer: [2]R.Truth = undefined;
        try E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle);
        try std.testing.expectEqual(@as(usize, 4), c.bundle.manifest.roots.len);
        const swapped = [_]R.Truth{ c.truths(&buffer)[1], c.truths(&buffer)[0] };
        try std.testing.expect(std.meta.isError(E.verify(a, &keys, &swapped, c.expected(), &c.bundle)));
    }
}

test "v3 curve adversarial: false output, forged input word and wrong pointer are rejected" {
    for ([_]F.Op{ .bn254_g1_add, .arith384_mont, .bls12_381_g1_double }) |op| {
        for ([_]F.Case.Mutation{ .wrong_output, .forged_input, .wrong_pointer }) |mutation| {
            var c = try F.Case.init(a, op, mutation, false);
            defer c.deinit();
            const keys = c.keys();
            var buffer: [2]R.Truth = undefined;
            const expected = switch (mutation) {
                .wrong_output => error.UnclosedCombinedSecpWire,
                .forged_input => error.UnclosedCombinedRam,
                .wrong_pointer => error.UnclosedCombinedCpuRelations,
                .none => unreachable,
            };
            try std.testing.expectError(expected, E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle));
        }
    }
}
