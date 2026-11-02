const std = @import("std");
const F = @import("fixture.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const E = @import("execution.zig");
const G = @import("../../protocol.zig");
const Base = @import("../fixture.zig");
const a = std.testing.allocator;

test "Bounded K truth roster joins four actual proofs with fresh independent keys" {
    var c = try F.BoundedCase.init(a, .none);
    defer c.deinit();
    const keys = c.keys();
    const truths = c.roster();
    try E.verifyBounded(a, &keys, &truths, c.expected(), &c.bundle);
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Base.WORDS }, c.setups[0].materials.geometry, 5);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Base.WORDS }, c.setups[1].materials.geometry, 5);
    defer s1.deinit();
    var t0 = try R.TruthSetup.init(a, 5);
    defer t0.deinit();
    var t1 = try R.TruthSetup.init(a, 5);
    defer t1.deinit();
    const expected_truths = [_]P.Truth{ .{ .setup = &t0, .first_id = 1, .calls = 1 }, .{ .setup = &t1, .first_id = 2, .calls = 1 } };
    try E.verifyBounded(a, &.{ &s0, &s1 }, &expected_truths, c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(usize, 4), c.bundle.manifest.roots.len);
    try std.testing.expectEqualSlices(u8, &t0.key.root, &t1.key.root);
    try std.testing.expect(!std.mem.eql(u8, &c.bundle.manifest.roots[2].main.bytes, &c.bundle.manifest.roots[3].main.bytes));
}

test "Bounded truth admission rejects duplicate overlapping missing and gapped spans before proofs" {
    // Admission needs no witness/tree allocation; only native geometry matters.
    var t: R.TruthSetup = undefined;
    t.log = 5;
    const good = [_]P.Truth{ .{ .setup = &t, .first_id = 1, .calls = 1 }, .{ .setup = &t, .first_id = 2, .calls = 1 } };
    try P.validateSpans(&good, 2);
    for ([_]u32{ 1, 3 }) |bad| {
        var mutant = good;
        mutant[1].first_id = bad;
        try std.testing.expectError(error.InvalidSharedTruthSpan, P.validateSpans(&mutant, 2));
    }
    try std.testing.expectError(error.InvalidSharedTruthSpan, P.validateSpans(good[0..1], 2));
    try std.testing.expectError(error.InvalidSharedTruthInventory, P.validateSpans(&.{}, 2));
    var overlap = good;
    overlap[0].calls = 2;
    try std.testing.expectError(error.InvalidSharedTruthSpan, P.validateSpans(&overlap, 2));
    var empty = good;
    empty[1].calls = 0;
    try std.testing.expectError(error.InvalidSharedTruthSpan, P.validateSpans(&empty, 1));
    // Local chi/xor draws intentionally permit two independently bounded masses
    // whose SUM exceeds p. Common IO remains separately bounded at admission.
    t.log = 21;
    try P.validateSpans(&.{ .{ .setup = &t, .first_id = 1, .calls = 100000 }, .{ .setup = &t, .first_id = 100001, .calls = 100000 } }, 200000);
    try std.testing.expectError(error.KeccakLookupMassExceeded, P.validateSpans(&.{.{ .setup = &t, .first_id = 1, .calls = 111849 }}, 111849));
}

test "Bounded truth receiver rejects missing duplicated swapped roots spans and physical claims" {
    var c = try F.BoundedCase.init(a, .none);
    defer c.deinit();
    const keys = c.keys();
    const truths = c.roster();
    var candidate = c.bundle;
    candidate.truths = c.bundle.truths[0..1];
    try std.testing.expectError(error.IncompleteGlobalExecutionManifest, E.verifyBounded(a, &keys, &truths, c.expected(), &candidate));
    const receipts = try a.dupe(G.Receipt, c.bundle.manifest.roots);
    defer a.free(receipts);
    receipts[3] = receipts[2];
    var duplicate = try G.Manifest.init(a, c.bundle.manifest.specs, receipts);
    defer duplicate.deinit();
    candidate = c.bundle;
    candidate.manifest = duplicate;
    if (E.verifyBounded(a, &keys, &truths, c.expected(), &candidate)) |_| return error.AcceptedDuplicateTruthRoot else |_| {}
    // Swapping actual proof ownership cannot satisfy the ordinal-bound roots.
    var encoded = [_]E.TruthEncoded{ c.bundle.truths[1], c.bundle.truths[0] };
    candidate = c.bundle;
    candidate.truths = &encoded;
    try std.testing.expectError(error.SharedTruthStage1Mismatch, E.verifyBounded(a, &keys, &truths, c.expected(), &candidate));
    const specs = try a.dupe([32]u8, c.bundle.manifest.specs);
    defer a.free(specs);
    var ch = G.T.P.Channel{};
    var wrong_span = truths[1];
    wrong_span.first_id = 1;
    P.beginTruthFor(.bounded_v3, &ch, wrong_span, c.expected(), 1, 2);
    specs[3] = ch.digestBytes();
    var wrong = try G.Manifest.init(a, specs, c.bundle.manifest.roots);
    defer wrong.deinit();
    candidate = c.bundle;
    candidate.manifest = wrong;
    try std.testing.expectError(error.GlobalExecutionInventoryMismatch, E.verifyBounded(a, &keys, &truths, c.expected(), &candidate));
    c.bundle.truths[0].claims[0] = c.bundle.truths[0].claims[0].add(G.Q.one());
    c.bundle.truths[1].claims[0] = c.bundle.truths[1].claims[0].sub(G.Q.one());
    if (E.verifyBounded(a, &keys, &truths, c.expected(), &c.bundle)) |_| return error.AcceptedBalancedFalseClaims else |_| {}
}

test "Four physical proofs reject valid false K output and reset predecessor across bounded truths" {
    var output = try F.BoundedCase.init(a, .wrong_output);
    defer output.deinit();
    const keys = output.keys();
    const truths = output.roster();
    try std.testing.expectError(error.UnclosedSharedTruthIo, E.verifyBounded(a, &keys, &truths, output.expected(), &output.bundle));
    var reset = try F.BoundedCase.init(a, .false_reset);
    defer reset.deinit();
    const rk = reset.keys();
    const rt = reset.roster();
    try std.testing.expectError(error.UnclosedSharedTruthRam, E.verifyBounded(a, &rk, &rt, reset.expected(), &reset.bundle));
}
