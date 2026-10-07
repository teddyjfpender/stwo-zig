const std = @import("std");
const verifier = @import("bitcoin_fused_chain_verifier.zig");
const chain = @import("bitcoin_chain_verifier.zig");

const block_one_hash = "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048";
const block_one_time: u32 = 1231469665;

test "sealed fused Bitcoin key is pinned to the genesis checkpoint and value-free topology" {
    const allocator = std.heap.page_allocator;
    try std.testing.expectError(error.FusedFoldRequiresGenesisCheckpoint, verifier.generateKeyJson(allocator, block_one_hash));
    const key_bytes = try verifier.generateKeyJson(allocator, chain.genesis_display_hash);
    defer allocator.free(key_bytes);
    const digest = chain.sha256(key_bytes);
    const key = try verifier.validateKey(allocator, key_bytes, digest);
    try std.testing.expectEqualDeep(digest, key.key_sha256);
    try std.testing.expectEqualDeep(try chain.blockHashRoot(chain.genesis_display_hash), key.material.checkpoint_root);
    try std.testing.expectEqual(@as(u32, 1), key.material.fused_key.pcs.fri_config.fold_step);
    try std.testing.expectEqual(@as(u32, 26), key.material.fused_key.pcs.fri_config.pow_bits);

    var wrong_digest = digest;
    wrong_digest[0] ^= 1;
    try std.testing.expectError(error.WrongVerificationKeyDigest, verifier.validateKey(allocator, key_bytes, wrong_digest));

    var parsed = try std.json.parseFromSlice(verifier.Key, allocator, key_bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    parsed.value.step = 1;
    const wrong_step = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(wrong_step);
    try std.testing.expectError(error.InvalidFusedBitcoinKeyProfile, verifier.validateKey(allocator, wrong_step, chain.sha256(wrong_step)));
    parsed.value.step = 0;
    parsed.value.sha_gate_addresses[0] ^= 1;
    const wrong_gate = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(wrong_gate);
    try std.testing.expectError(error.FusedBitcoinKeyTopologyMismatch, verifier.validateKey(allocator, wrong_gate, chain.sha256(wrong_gate)));
    parsed.value.sha_gate_addresses[0] ^= 1;
    parsed.value.fused_fixed_root = "0000000000000000000000000000000000000000000000000000000000000000";
    const wrong_root = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(wrong_root);
    try std.testing.expectError(error.FusedBitcoinKeyTopologyMismatch, verifier.validateKey(allocator, wrong_root, chain.sha256(wrong_root)));
}

test "sealed fused Bitcoin statement binds named block hash and genesis-to-block-one timestamps" {
    const allocator = std.heap.page_allocator;
    const key_bytes = try verifier.generateKeyJson(allocator, chain.genesis_display_hash);
    defer allocator.free(key_bytes);
    const key = try verifier.validateKey(allocator, key_bytes, chain.sha256(key_bytes));
    const statement_bytes = try verifier.generateStatementJson(allocator, key, block_one_hash, block_one_time);
    defer allocator.free(statement_bytes);
    const outputs = try verifier.validateStatement(allocator, key, statement_bytes);
    try std.testing.expectEqual(@as(usize, 8), outputs.len);
    try std.testing.expectError(error.InvalidFusedFoldProofEnvelope, verifier.verifyProof(allocator, key, statement_bytes, ""));
    var wrong_digest = chain.sha256(key_bytes);
    wrong_digest[0] ^= 1;
    try std.testing.expectError(error.WrongVerificationKeyDigest, verifier.verifyPinned(allocator, key_bytes, wrong_digest, statement_bytes, ""));

    var parsed = try std.json.parseFromSlice(verifier.Statement, allocator, statement_bytes, .{ .ignore_unknown_fields = false });
    defer parsed.deinit();
    parsed.value.public_words[0] ^= 1;
    const wrong_words = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(wrong_words);
    try std.testing.expectError(error.InvalidFusedBitcoinStatement, verifier.validateStatement(allocator, key, wrong_words));
    parsed.value.public_words[0] ^= 1;
    parsed.value.last_timestamps[1] ^= 1;
    const wrong_history = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(wrong_history);
    try std.testing.expectError(error.InvalidFusedBitcoinTimestamps, verifier.validateStatement(allocator, key, wrong_history));
    parsed.value.last_timestamps[1] ^= 1;
    parsed.value.current_block_timestamp += 1;
    const wrong_time = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(wrong_time);
    try std.testing.expectError(error.InvalidFusedBitcoinTimestamps, verifier.validateStatement(allocator, key, wrong_time));
    parsed.value.current_block_timestamp -= 1;
    parsed.value.step = 1;
    const wrong_step = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(wrong_step);
    try std.testing.expectError(error.FusedFoldSupportsOnlyStepZero, verifier.validateStatement(allocator, key, wrong_step));
    parsed.value.step = 0;
    parsed.value.current_block_hash = chain.genesis_display_hash;
    const wrong_hash = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(wrong_hash);
    try std.testing.expectError(error.InvalidFusedBitcoinStatement, verifier.validateStatement(allocator, key, wrong_hash));
    parsed.value.current_block_hash = block_one_hash;
    parsed.value.verification_key_sha256 = "0000000000000000000000000000000000000000000000000000000000000000";
    const wrong_key = try std.json.Stringify.valueAlloc(allocator, parsed.value, .{});
    defer allocator.free(wrong_key);
    try std.testing.expectError(error.InvalidFusedBitcoinStatement, verifier.validateStatement(allocator, key, wrong_key));
}
