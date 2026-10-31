const std = @import("std");
const core = @import("stwo_core");
const F = @import("fixture.zig");
const R = @import("roster.zig");
const P = @import("protocol.zig");
const E = @import("execution.zig");
const Base = @import("../fixture.zig");
const a = std.testing.allocator;
test "Two actual CPU RAM shards join one independent execution wide K truth proof" {
    var c = try F.Case.init(a, .none);
    defer c.deinit();
    const keys = c.keys();
    try E.verify(a, &keys, c.truth, c.expected(), &c.bundle);
    var s0 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Base.WORDS }, c.setups[0].materials.geometry, 5);
    defer s0.deinit();
    var s1 = try R.CpuSetup.initProgram(a, .{ .base = 4096, .words = &Base.WORDS }, c.setups[1].materials.geometry, 5);
    defer s1.deinit();
    var truth = try R.TruthSetup.init(a, 5);
    defer truth.deinit();
    try E.verify(a, &.{ &s0, &s1 }, &truth, c.expected(), &c.bundle);
    try std.testing.expectEqual(@as(usize, 3), c.bundle.manifest.roots.len);
    try std.testing.expectEqual(@as(u32, 2), try P.firstCall(&.{ c.bundle.cpus[0].request, c.bundle.cpus[1].request }, 1));
}
test "Physically valid false K output and false cross shard genesis reject shared truth closure" {
    var wrong = try F.Case.init(a, .wrong_output);
    defer wrong.deinit();
    const keys = wrong.keys();
    try std.testing.expectError(error.UnclosedSharedTruthIo, E.verify(a, &keys, wrong.truth, wrong.expected(), &wrong.bundle));
    var reset = try F.Case.init(a, .false_reset);
    defer reset.deinit();
    const kk = reset.keys();
    try std.testing.expectError(error.UnclosedSharedTruthRam, E.verify(a, &kk, reset.truth, reset.expected(), &reset.bundle));
}
test "Shared truth requires every physical root role call span and claim binding" {
    var c = try F.Case.init(a, .none);
    defer c.deinit();
    const keys = c.keys();
    const G = @import("../../protocol.zig");
    var receipts = try a.dupe(G.Receipt, c.bundle.manifest.roots);
    defer a.free(receipts);
    std.mem.swap(G.Root, &receipts[0].main, &receipts[2].main);
    var forged = try G.Manifest.init(a, c.bundle.manifest.specs, receipts);
    defer forged.deinit();
    var candidate = c.bundle;
    candidate.manifest = forged;
    try std.testing.expectError(error.SharedTruthStage1Mismatch, E.verify(a, &keys, c.truth, c.expected(), &candidate));
    var missing = try G.Manifest.init(a, c.bundle.manifest.specs[0..2], c.bundle.manifest.roots[0..2]);
    defer missing.deinit();
    candidate.manifest = missing;
    try std.testing.expectError(error.IncompleteGlobalExecutionManifest, E.verify(a, &keys, c.truth, c.expected(), &candidate));
    const specs = try a.dupe([32]u8, c.bundle.manifest.specs);
    defer a.free(specs);
    var wrong_span_channel = G.T.P.Channel{};
    // Shard1 must start at global call ID2; a coherently resealed span1 receipt
    // cannot replace the independently reconstructed complete inventory.
    try P.beginCpu(&wrong_span_channel, c.setups[1], c.bundle.cpus[1].request, c.expected(), 1, c.bundle.cpus[0].request.base.cpu.steps, 1);
    specs[1] = wrong_span_channel.digestBytes();
    var wrong_span = try G.Manifest.init(a, specs, c.bundle.manifest.roots);
    defer wrong_span.deinit();
    candidate.manifest = wrong_span;
    try std.testing.expectError(error.GlobalExecutionInventoryMismatch, E.verify(a, &keys, c.truth, c.expected(), &candidate));
    c.bundle.truth.claims[0] = c.bundle.truth.claims[0].add(core.fields.qm31.QM31.one());
    c.bundle.truth.claims[1] = c.bundle.truth.claims[1].sub(core.fields.qm31.QM31.one());
    if (E.verify(a, &keys, c.truth, c.expected(), &c.bundle)) |_| return error.AcceptedFalseTruthClaim else |_| {}
}
