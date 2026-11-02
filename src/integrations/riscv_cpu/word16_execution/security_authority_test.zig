//! Source authority checks: prevent a policy label from silently drifting from
//! the actual suite or mistaking a Fiat-Shamir channel for its Merkle hasher.
const std = @import("std");
const core = @import("stwo_core");
const Suite = @import("pcs_suite.zig").Suite;
const Policy = @import("security_policy.zig");

test "security authority current benchmark matches actual receiver-owned native suite" {
    const p = Policy.benchmarkControl();
    const native = Suite.production().config();
    try std.testing.expectEqual(p.queries, native.fri_config.n_queries);
    try std.testing.expectEqual(p.query_pow_bits, native.pow_bits);
    try std.testing.expectEqual(@as(u32, 1), native.fri_config.log_blowup_factor);
    try std.testing.expectEqual(p.secure_extension_degree, core.fields.qm31.SECURE_EXTENSION_DEGREE);
    try std.testing.expectEqual(@as(u32, 96), native.securityBits());
}
test "security authority reduced recursive channel keeps raw256 Merkle commitment authority" {
    const profiles = core.vcs_lifted.channel_profile.proving_5a7c5ed;
    const inner = profiles.Blake2sM31MerkleChannel;
    const root = profiles.Blake2sMerkleChannel;
    try std.testing.expect(inner.MerkleHasher == root.MerkleHasher);
    try std.testing.expect(inner.Hasher == core.vcs.blake2_hash.Blake2sHasher);
    try std.testing.expect(inner.Channel == core.channel.blake2s.Blake2sM31Channel);
    try std.testing.expect(root.Channel == core.channel.blake2s.Blake2sChannel);
    const p = Policy.benchmarkControl();
    try std.testing.expectEqual(Policy.Hash.blake2s_256, p.recursive_inner_merkle);
    try std.testing.expectEqual(Policy.Hash.blake2s_eight_m31_words, p.recursive_inner_transcript);
}
