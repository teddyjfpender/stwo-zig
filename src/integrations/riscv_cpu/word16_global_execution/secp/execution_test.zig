const std = @import("std");
const F = @import("fixture.zig");
const E = @import("execution.zig");
const R = @import("roster.zig");
const a = std.testing.allocator;
test "Actual CPU SD ADD ADDI DOUBLE join independently sized RCB truth and global RAM proofs" {
    var c = try F.Case.init(a, .none);
    defer c.deinit();
    const keys = c.keys();
    try E.verify(a, &keys, c.truthKeys(), c.expected(), &c.bundle);
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[0].materials.geometry, .{ 5, 5 });
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &F.WORDS }, c.setups[1].materials.geometry, .{ 5, 5 });
    defer s1.deinit();
    var ta = try R.TruthSetup.init(a, .add, c.truths[0].logs);
    defer ta.deinit();
    var td = try R.TruthSetup.init(a, .double, c.truths[1].logs);
    defer td.deinit();
    try E.verify(a, &.{ &s0, &s1 }, .{ &ta, &td }, c.expected(), &c.bundle);
}
test "Actual valid local secp proofs reject false output and fabricated cross epoch predecessor" {
    var output = try F.Case.init(a, .wrong_output);
    defer output.deinit();
    const keys = output.keys();
    try std.testing.expectError(error.UnclosedSecpWire, E.verify(a, &keys, output.truthKeys(), output.expected(), &output.bundle));
    var reset = try F.Case.init(a, .false_reset);
    defer reset.deinit();
    const rr = reset.keys();
    try std.testing.expectError(error.UnclosedSecpRam, E.verify(a, &rr, reset.truthKeys(), reset.expected(), &reset.bundle));
}

test "Actual CPU owner debt rejects substituted pointer and substituted service kind" {
    for ([_]F.Case.Mutation{ .wrong_pointer, .wrong_kind }) |mutation| {
        var c = try F.Case.init(a, mutation);
        defer c.deinit();
        const keys = c.keys();
        try std.testing.expectError(error.UnclosedSecpCpuRelations, E.verify(a, &keys, c.truthKeys(), c.expected(), &c.bundle));
    }
}
test "Secp receiver binds complete expected roots typed roles and every physical claim" {
    const G = @import("../protocol.zig");
    var c = try F.Case.init(a, .none);
    defer c.deinit();
    const keys = c.keys();
    const receipts = try a.dupe(G.Receipt, c.bundle.manifest.roots);
    defer a.free(receipts);
    receipts[3].main.bytes[0] ^= 1;
    var wrong = try G.Manifest.init(a, c.bundle.manifest.specs, receipts);
    defer wrong.deinit();
    var candidate = c.bundle;
    candidate.manifest = wrong;
    if (E.verify(a, &keys, c.truthKeys(), c.expected(), &candidate)) |_| return error.AcceptedWrongTruthRoot else |_| {}
    var missing = try G.Manifest.init(a, c.bundle.manifest.specs[0..3], c.bundle.manifest.roots[0..3]);
    defer missing.deinit();
    candidate = c.bundle;
    candidate.manifest = missing;
    try std.testing.expectError(error.IncompleteGlobalExecutionManifest, E.verify(a, &keys, c.truthKeys(), c.expected(), &candidate));
    const swapped = [2]*const R.TruthSetup{ c.truths[1], c.truths[0] };
    try std.testing.expectError(error.InvalidSecpTruthKind, E.verify(a, &keys, swapped, c.expected(), &c.bundle));
    c.bundle.truths[0].claims[0] = c.bundle.truths[0].claims[0].add(G.Q.one());
    c.bundle.truths[1].claims[0] = c.bundle.truths[1].claims[0].sub(G.Q.one());
    if (E.verify(a, &keys, c.truthKeys(), c.expected(), &c.bundle)) |_| return error.AcceptedBalancedSecpClaims else |_| {}
}
