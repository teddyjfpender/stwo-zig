const std = @import("std");
const F = @import("sha256_fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const W = @import("wire.zig");
const HR = @import("../sha256/roster.zig");
const G = @import("../protocol.zig");
const a = std.testing.allocator;

test "v3 SHA-256 calls: CPU bridges, global RAM and one truth verify with fresh keys and wire" {
    var c = try F.Case.init(a, .none, false);
    defer c.deinit();
    const keys = c.keys();
    var buffer: [2]R.Truth = undefined;
    try E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(usize, 3), c.bundle.manifest.roots.len);
    // Fresh, independently constructed receiver keys over the durable wire.
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    try W.write(a, temp.dir, &keys, c.truths(&buffer), &c.bundle);
    var loaded = try W.read(a, temp.dir, .{ .max_cpus = 2, .max_truths = 1, .max_total_steps = 5 });
    defer loaded.deinit(a);
    try std.testing.expectEqual(@as(?u32, 5), loaded.cpu_declarations[0].bridges.sha256);
    try std.testing.expectEqual(@as(u32, 2), loaded.bundle.cpus[0].request.calls[3]);
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, .{ .sha256 = 5 });
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[1].geometry, .{ .sha256 = 5 });
    defer s1.deinit();
    var ht = try HR.TruthSetup.init(a, 5);
    defer ht.deinit();
    const fresh = [_]R.Truth{.{ .sha256 = .{ .setup = &ht, .first_id = 1, .calls = 3 } }};
    try E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity), &loaded.bundle);
    // A receiver that expects no SHA-256 bridge cannot reuse these proofs.
    var bare = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, loaded.cpu_declarations[0].geometry, .{});
    defer bare.deinit();
    try std.testing.expectError(error.InvalidCombinedBridgePresence, E.verify(a, &.{ &bare, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity), &loaded.bundle));
    // Claim slots unused by the single SHA-256 component are pinned to zero.
    loaded.bundle.truths[0].claims[1] = G.Q.one();
    try std.testing.expectError(error.NonzeroAbsentServiceClaim, E.verify(a, &.{ &s0, &s1 }, &fresh, F.expectedFor(s0.materials.program.identity), &loaded.bundle));
}

test "v3 SHA-256 spans split across two truth proofs close the same Wire35 bus" {
    var c = try F.Case.init(a, .none, true);
    defer c.deinit();
    const keys = c.keys();
    var buffer: [2]R.Truth = undefined;
    try E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(usize, 4), c.bundle.manifest.roots.len);
    // Swapping the truth spans breaks the manifest/span authority.
    var swapped = [_]R.Truth{ c.truths(&buffer)[1], c.truths(&buffer)[0] };
    _ = &swapped;
    try std.testing.expect(std.meta.isError(E.verify(a, &keys, &swapped, c.expected(), &c.bundle)));
}

test "v3 SHA-256 adversarial: false output, forged block word and wrong pointer are rejected" {
    for ([_]F.Case.Mutation{ .wrong_output, .forged_message, .wrong_pointer }) |mutation| {
        var c = try F.Case.init(a, mutation, false);
        defer c.deinit();
        const keys = c.keys();
        var buffer: [2]R.Truth = undefined;
        const expected = switch (mutation) {
            .wrong_output => error.UnclosedCombinedSecpWire,
            .forged_message => error.UnclosedCombinedRam,
            .wrong_pointer => error.UnclosedCombinedCpuRelations,
            .none => unreachable,
        };
        try std.testing.expectError(expected, E.verify(a, &keys, c.truths(&buffer), c.expected(), &c.bundle));
    }
}
