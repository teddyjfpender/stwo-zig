//! Focused tests of the RV64 recursion leaf: transcript walkers and the
//! statement-side helpers that need no circuit prover.
const std = @import("std");
const walk = @import("rv64_recursion/transcript_walk.zig");

test "rv64 recursion: transcript walkers compile and the digest is Blake2s of the words" {
    std.testing.refAllDecls(walk);
    const digest = walk.statementDigest(&.{ 1, 2, 3 });
    var expected_input: [12]u8 = undefined;
    for ([_]u32{ 1, 2, 3 }, 0..) |word, i| std.mem.writeInt(u32, expected_input[4 * i ..][0..4], word, .little);
    var out: [32]u8 = undefined;
    std.crypto.hash.blake2.Blake2s256.hash(&expected_input, &out, .{});
    for (digest, 0..) |word, i| try std.testing.expectEqual(std.mem.readInt(u32, out[4 * i ..][0..4], .little), word);
}
