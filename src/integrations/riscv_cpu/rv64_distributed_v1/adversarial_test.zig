const std = @import("std");
const M = @import("manifest.zig");
const T = M.T;
const W = @import("wire.zig");
const RW = @import("receipt_wire.zig");
const F = @import("manifest_test.zig");
const a = std.testing.allocator;
fn allocated(allocator: std.mem.Allocator, file: std.fs.File, expected: M.Expected) !void {
    try file.seekTo(0);
    var manifest = try W.read(allocator, file, expected);
    defer manifest.deinit();
    _ = try manifest.derive();
}
test "distributed wire failures and every decode OOM preserve owners and refuse extra or truncated roots" {
    var fixture = try F.Fixture.init();
    defer fixture.deinit();
    var manifest = try M.Manifest.init(a, fixture.expected(), &fixture.receipts);
    defer manifest.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("manifest", .{ .read = true });
    defer file.close();
    try W.write(file, &manifest);
    try std.testing.checkAllAllocationFailures(a, allocated, .{ file, fixture.expected() });
    const bytes = try temp.dir.readFileAlloc(a, "manifest", 1 << 20);
    defer a.free(bytes);
    var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
    const changed = try a.dupe(u8, bytes);
    defer a.free(changed);
    std.mem.writeInt(u32, changed[12..16], 0xffff_ffff, .little);
    try replace(file, changed);
    try std.testing.expectError(error.InvalidDistributedManifestWire, W.read(fail.allocator(), file, fixture.expected()));
    try std.testing.expect(!fail.has_induced_failure);
    for ([_]usize{ 0, W.HEADER_BYTES - 1, bytes.len - 1 }) |len| {
        try replace(file, bytes[0..len]);
        try std.testing.expectError(error.TruncatedWorkPacket, W.read(a, file, fixture.expected()));
    }
    try replace(file, bytes);
    try file.seekFromEnd(0);
    try file.writeAll("EXTRA");
    try file.seekTo(0);
    try std.testing.expectError(error.TrailingDistributedManifestWire, W.read(a, file, fixture.expected()));
    try replace(file, bytes);
    try file.seekTo(0);
    var wrong = fixture.expected();
    wrong.context.request_id ^= @as(u64, 1) << 63;
    try std.testing.expectError(error.InvalidDistributedManifestWire, W.read(fail.allocator(), file, wrong));
    try std.testing.expect(!fail.has_induced_failure);
}
test "distributed proof-observed root binding cannot be mistaken for actual proof verification" {
    var fixture = try F.Fixture.init();
    defer fixture.deinit();
    var manifest = try M.Manifest.init(a, fixture.expected(), &fixture.receipts);
    defer manifest.deinit();
    // Deliberately INVALID proof shell: no samples, openings, FRI or PoW.
    // Root matching must not be marketed as verifying this object.
    var proof = std.mem.zeroes(T.P.Proof);
    proof.commitment_scheme_proof.config = T.P.config();
    var roots = [_]T.P.Hasher.Hash{ fixture.receipts[0].fixed.value, fixture.receipts[0].shared.value };
    proof.commitment_scheme_proof.commitments.items = &roots;
    try manifest.checkObservedRoots(0, &proof);
    try std.testing.expectEqual(@as(usize, 0), proof.commitment_scheme_proof.sampled_values.items.len);
    var local = try M.stage1Channel(F.context(), fixture.specs[0], fixture.receipts[0]);
    const original = try manifest.resumeReceiver(0, &proof, &local);
    roots[1][0] ^= 1;
    try std.testing.expectError(error.Stage1ProofRootMismatch, manifest.checkObservedRoots(0, &proof));
    roots[1][0] ^= 1;
    var other_receipts = fixture.receipts;
    other_receipts[1].shared.value[0] ^= 1;
    var other = try M.Manifest.init(a, fixture.expected(), &other_receipts);
    defer other.deinit();
    // The own root is unchanged, but a peer-root substitution MUST alter both
    // the global alpha and local stage2 transcript. A REAL proof verifier must
    // use those new values and reject replay; this shell cannot qualify it.
    var peer_local = try M.stage1Channel(F.context(), fixture.specs[0], fixture.receipts[0]);
    const peer = try other.resumeReceiver(0, &proof, &peer_local);
    try std.testing.expect(!std.meta.eql(original, peer));
    try std.testing.expect(!std.mem.eql(u8, &local.digestBytes(), &peer_local.digestBytes()));
}
test "distributed stage1 refuses unrelated proof phases and root-only message wrong request" {
    var fixture = try F.Fixture.init();
    defer fixture.deinit();
    var temp = std.testing.tmpDir(.{});
    defer temp.cleanup();
    const file = try temp.dir.createFile("root", .{ .read = true });
    defer file.close();
    try RW.write(file, F.context(), fixture.specs[0], fixture.receipts[0]);
    try file.seekTo(0);
    var wrong = F.context();
    wrong.request_id += 1;
    try std.testing.expectError(error.DistributedInventoryMismatch, RW.read(file, wrong, fixture.specs[0]));
    var values: [32]@import("stwo_core").fields.m31.M31 = @splat(@import("stwo_core").fields.m31.M31.zero());
    try fixture.cpu.scheme.commitBorrowedStreaming(a, &.{.{ .log_size = 5, .values = &values }}, 8, &fixture.cpu.channel);
    try std.testing.expectError(error.InvalidStage1Phase, T.fromCommitted(a, &fixture.cpu.scheme, fixture.specs[0]));
}
fn replace(file: std.fs.File, bytes: []const u8) !void {
    try file.setEndPos(0);
    try file.seekTo(0);
    try file.writeAll(bytes);
    try file.seekTo(0);
}
