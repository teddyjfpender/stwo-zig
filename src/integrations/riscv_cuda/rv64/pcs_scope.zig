//! The worker statement already binds program, geometry, source layout and
//! protocol. Keep that authority in the lease namespace rather than deriving a
//! second independently extensible layout identity from producer metadata.
const std = @import("std");
pub fn identity(scope: anytype) [8]u32 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo/rv64/cuda/physical-worker-scope/v1\x00");
    hash.update(&scope.statement);
    hash.update(&scope.fixed);
    hash.update(&scope.main);
    var ordinal: [4]u8 = undefined;
    std.mem.writeInt(u32, &ordinal, scope.ordinal, .little);
    hash.update(&ordinal);
    const digest = hash.finalResult();
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, digest[i * 4 ..][0..4], .little);
    return words;
}
