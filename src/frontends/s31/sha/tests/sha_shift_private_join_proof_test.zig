//! Native end-to-end one-header direct SHA256d proof qualification.
//! It closes the private SHA word bus; the Gate claim remains open for a
//! sparse-wide circuit component in the final circuit-to-chip proof.
const std = @import("std");
const core = @import("stwo_core");
const plan = @import("../config/sha_chip_plan.zig");
const profile = @import("../config/sha_shift_private_join_profile.zig");
const prover = @import("../proving/sha_shift_private_join_prover.zig");
const native = @import("../verification/sha_shift_private_join_native_verifier.zig");

fn header() [80]u8 {
    var value: [80]u8 = undefined;
    for (&value, 0..) |*byte, i| byte.* = @truncate(29 + 47 * i);
    return value;
}

fn statement(bytes: [80]u8) profile.PublicStatement {
    var addresses: [56]u32 = undefined;
    for (&addresses, 0..) |*value, i| value.* = @intCast(3 + i);
    return .{ .digest = plan.prepare(bytes).digest, .config = .{ .gate_addresses = addresses, .first_call_id = 41 } };
}

test "private direct SHA256d proves one header with ten closed word claims and an open Gate claim" {
    const allocator = std.testing.allocator;
    const bytes = header();
    const s = statement(bytes);
    var first: [32]u8 = undefined;
    var second: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(&bytes, &first, .{});
    std.crypto.hash.sha2.Sha256.hash(&first, &second, .{});
    try std.testing.expectEqualSlices(u8, &second, &s.digest);
    const fri = try core.pcs.config_v2.FriConfigV2.init(0, 0, 1, 12, 1);
    const pcs = core.pcs.config_v2.PcsConfigV2.fromFriAndTraceSize(fri, 7);
    var timer = try std.time.Timer.start();
    var artifact = try prover.proveOne(allocator, bytes, s, pcs);
    const prove_ns = timer.read();
    defer artifact.deinit();
    timer.reset();
    const verified = try native.verifyBytes(allocator, s, pcs, artifact.envelope);
    const verify_ns = timer.read();
    try std.testing.expect(verified.gate_claim.eql(artifact.gate_claim));
    try std.testing.expectEqualDeep(verified.fixed_root, artifact.fixed_root);
    try std.testing.expect(!verified.gate_claim.isZero());
    const claims = try native.decodeClaims(artifact.envelope);
    try std.testing.expect(claims.wordClosure().isZero());
    const layout = profile.Layout.init(.{});
    std.debug.print("S31_SHA_SHIFT_PRIVATE verified=true calls=3 fixed={d} main={d} interaction={d} prove_ms={d} verify_ms={d} proof_bytes={d} fri_pow_bits=0 queries=12 gate_open=true\n", .{
        layout.total_fixed,            layout.total_main,              layout.total_interaction,
        prove_ns / std.time.ns_per_ms, verify_ns / std.time.ns_per_ms, artifact.envelope.len,
    });

    var changed_statement = s;
    changed_statement.digest[0] ^= 1;
    try std.testing.expectError(error.WrongShaPrivateJoinStatementTag, native.verifyBytes(allocator, changed_statement, pcs, artifact.envelope));
    changed_statement = s;
    changed_statement.config.first_call_id += 1;
    try std.testing.expectError(error.WrongShaPrivateJoinStatementTag, native.verifyBytes(allocator, changed_statement, pcs, artifact.envelope));
    changed_statement = s;
    changed_statement.config.gate_addresses[0] += 100;
    try std.testing.expectError(error.WrongShaPrivateJoinStatementTag, native.verifyBytes(allocator, changed_statement, pcs, artifact.envelope));
    const changed_envelope = try allocator.dupe(u8, artifact.envelope);
    defer allocator.free(changed_envelope);
    changed_envelope[native.magic.len + 1] ^= 1;
    if (native.verifyBytes(allocator, s, pcs, changed_envelope)) |_| return error.ChangedWordClaimAccepted else |_| {}
    try std.testing.expectError(error.ShaPrivateJoinProofTooLarge, native.verifyBytes(allocator, s, pcs, artifact.envelope[0..8]));
    var changed_header = bytes;
    changed_header[0] ^= 1;
    try std.testing.expectError(error.WrongPrivateShaDigest, prover.proveOne(allocator, changed_header, s, pcs));
}
