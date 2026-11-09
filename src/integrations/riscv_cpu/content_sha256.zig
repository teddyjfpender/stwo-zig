//! Raw content digest shared by neutral and product adapters.

const std = @import("std");

pub fn sha(raw: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &result, .{});
    return result;
}
