const std = @import("std");
const core = @import("stwo_core");
const Wire = @import("manifest_wire.zig");
const Manifest = @import("manifest.zig");
const Fixture = @import("manifest_test.zig").Fixture;
const a = std.testing.allocator;

test "stage1 file exact roundtrip freshly checks both real local children and ordered truth slot" {
    var f = try Fixture.init();
    defer f.deinit();
    var baseline = try f.verify();
    defer baseline.deinit(a);
    const bytes = try Wire.encode(a, @splat(1), &f.expected, &f.stages);
    defer a.free(bytes);
    var decoded = try Wire.decode(a, @splat(1), &f.expected, bytes);
    var owns = true;
    defer if (owns) decoded.deinit();
    const again = try Wire.encode(a, @splat(1), &f.expected, decoded.stages);
    defer a.free(again);
    try std.testing.expectEqualSlices(u8, bytes, again);
    var fresh = try decoded.verifyAndSeal(a, @splat(1), &f.expected);
    defer fresh.deinit(a);
    // Pending verifier artifacts own their data independently of decoded wire.
    decoded.deinit();
    owns = false;
    try std.testing.expectEqualDeep(baseline.digest, fresh.digest);
    try std.testing.expectEqualDeep(baseline.shared, fresh.shared);
    try std.testing.expectEqualDeep(baseline.entries[0].local.?.artifact.claims_to_verify_by_instance, fresh.entries[0].local.?.artifact.claims_to_verify_by_instance);
}

test "stage1 file every truncation trailing byte and framing substitution reject before allocations" {
    var f = try Fixture.init();
    defer f.deinit();
    const bytes = try Wire.encode(a, @splat(1), &f.expected, &f.stages);
    defer a.free(bytes);
    for (0..bytes.len) |length| {
        var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        try std.testing.expectError(error.TruncatedGlobalGkrManifest, Wire.decode(fail.allocator(), @splat(1), &f.expected, bytes[0..length]));
        try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
    }
    const trailing = try a.alloc(u8, bytes.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try std.testing.expectError(error.TrailingGlobalGkrManifest, Wire.decode(a, @splat(1), &f.expected, trailing));
    const bad = try a.dupe(u8, bytes);
    defer a.free(bad);
    bad[0] ^= 1;
    try std.testing.expectError(error.GlobalGkrManifestProfile, Wire.decode(a, @splat(1), &f.expected, bad));
    bad[0] ^= 1;
    bad[8] ^= 1;
    try std.testing.expectError(error.GlobalGkrManifestExecution, Wire.decode(a, @splat(1), &f.expected, bad));
    bad[8] ^= 1;
    const Mutation = enum { count, ordinal, local_flag, child_length };
    for (std.enums.values(Mutation)) |mutation| {
        @memcpy(bad, bytes);
        const offset: usize = switch (mutation) {
            .count => 40,
            .ordinal => 44,
            .local_flag => 80,
            .child_length => 116,
        };
        std.mem.writeInt(u32, bad[offset..][0..4], std.math.maxInt(u32), .little);
        var fail = std.testing.FailingAllocator.init(a, .{ .fail_index = 0 });
        if (Wire.decode(fail.allocator(), @splat(1), &f.expected, bad)) |value| {
            var unexpected = value;
            unexpected.deinit();
            return error.MalformedStageOneAccepted;
        } else |err| try std.testing.expect(err != error.OutOfMemory);
        try std.testing.expectEqual(@as(usize, 0), fail.alloc_index);
    }
}

test "stage1 file rejects nested noncanonical fields and checked child root substitution" {
    var f = try Fixture.init();
    defer f.deinit();
    const bytes = try Wire.encode(a, @splat(1), &f.expected, &f.stages);
    defer a.free(bytes);
    const bad = try a.dupe(u8, bytes);
    defer a.free(bad);
    // Header44 + worker40 + receipt32 + length4 + child header/maskcount20.
    const coordinate = 140;
    try std.testing.expect(std.mem.readInt(u32, bad[coordinate..][0..4], .little) < core.fields.m31.Modulus);
    std.mem.writeInt(u32, bad[coordinate..][0..4], core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NoncanonicalLocalGkrCoordinate, Wire.decode(a, @splat(1), &f.expected, bad));
    @memcpy(bad, bytes);
    bad[48] ^= 1; // worker0 MAIN, not an identity declaration.
    var decoded = try Wire.decode(a, @splat(1), &f.expected, bad);
    defer decoded.deinit();
    if (decoded.verifyAndSeal(a, @splat(1), &f.expected)) |value| {
        var unexpected = value;
        unexpected.deinit(a);
        return error.SubstitutedStageOneAccepted;
    } else |_| {}
}
fn probe(allocator: std.mem.Allocator, expected: []const Manifest.ExpectedWorker, bytes: []const u8) !void {
    var decoded = try Wire.decode(allocator, @splat(1), expected, bytes);
    defer decoded.deinit();
    const encoded = try Wire.encode(allocator, @splat(1), expected, decoded.stages);
    defer allocator.free(encoded);
    try std.testing.expectEqualSlices(u8, bytes, encoded);
    var pending = try decoded.verifyAndSeal(allocator, @splat(1), expected);
    defer pending.deinit(allocator);
}
test "stage1 file unwinds partial decoders nested arenas and manifest allocation failures" {
    var f = try Fixture.init();
    defer f.deinit();
    const bytes = try Wire.encode(a, @splat(1), &f.expected, &f.stages);
    defer a.free(bytes);
    try std.testing.checkAllAllocationFailures(a, probe, .{ &f.expected, bytes });
}

test "nested child wire preserves declared polynomial length including trailing zero coordinates" {
    var f = try Fixture.init();
    defer f.deinit();
    // Codec-only mutation: this altered proof is deliberately not accepted as
    // a cryptographic child. Its declared transcript vector must still survive.
    var changed = false;
    for (f.children[0].result.proof.sumcheck_proofs) |*sumcheck| {
        if (sumcheck.round_polys.len == 0) continue;
        const polynomial = &sumcheck.round_polys[0];
        if (polynomial.len == 0) continue;
        polynomial.coeffs[polynomial.len - 1] = core.fields.om31.OM31.zero();
        changed = true;
        break;
    }
    try std.testing.expect(changed);
    const bytes = try Wire.encode(a, @splat(1), &f.expected, &f.stages);
    defer a.free(bytes);
    var decoded = try Wire.decode(a, @splat(1), &f.expected, bytes);
    defer decoded.deinit();
    const encoded = try Wire.encode(a, @splat(1), &f.expected, decoded.stages);
    defer a.free(encoded);
    try std.testing.expectEqualSlices(u8, bytes, encoded);
    for (f.children[0].result.proof.sumcheck_proofs, decoded.stages[0].local.?.proof.sumcheck_proofs) |expected, actual| {
        for (expected.round_polys, actual.round_polys) |e, v| try std.testing.expectEqualSlices(core.fields.om31.OM31, e.coeffsSlice(), v.coeffsSlice());
    }
}
