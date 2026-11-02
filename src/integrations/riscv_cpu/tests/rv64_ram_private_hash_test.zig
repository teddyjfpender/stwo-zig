const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const private = @import("../rv64_ram_private_hash.zig");
const values = frontend.rv64_air.memory.values;

test "private value-only hash STARK closes canonical words byte table and full permutation IO" {
    const a = std.testing.allocator;
    var words: [128]u64 = undefined;
    for (&words, 0..) |*word, i| word.* = (@as(u64, i) *% 0xfeedface98765431) ^ 0xfedcba9876543210;
    var digests: [2]values.Digest = undefined;
    for (&digests, 0..) |*digest, i| digest.* = try values.hashValues(.chunk512, words[64 * i ..][0..64], null);
    const public = private.Statement{ .geometry = .chunk512, .digests = &digests };
    const proof = try private.prove(a, public, &words);
    defer a.free(proof);
    try private.verify(a, public, proof);
    var changed = digests;
    changed[1][8] ^= 1;
    try std.testing.expectError(error.UnbalancedPrivateRamPackets, private.verify(a, .{ .geometry = .chunk512, .digests = &changed }, proof));
    try std.testing.expectError(error.InvalidPrivateRamHashShape, private.verifyReceipt(a, public, proof));
    try std.testing.expectError(error.UnbalancedPrivateRamBytes, private.proveAttack(a, public, &words, .byte_carry_alias));
    try std.testing.expectError(error.UnbalancedPrivateRamPoseidon, private.proveAttack(a, public, &words, .unused_capacity_output));
    words[63] ^= 1;
    try std.testing.expectError(error.PrivateRamHashMismatch, private.prove(a, public, &words));
}
