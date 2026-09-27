//! Suite-aware transcript fields shared by software prove and benchmark reports.
const std = @import("std");
pub const Wire = struct { suite: []const u8, version: u16, digest: []const u8 };
pub fn decode(legacy: ?[]const u8, receipt: ?Wire, blake3: bool) ![32]u8 {
    const encoded = if (blake3) blk: {
        if (legacy != null) return error.InvalidTranscriptSuite;
        const value = receipt orelse return error.InvalidTranscriptSuite;
        if (!std.mem.eql(u8, value.suite, "blake3") or value.version != 2)
            return error.InvalidTranscriptSuite;
        break :blk value.digest;
    } else blk: {
        if (receipt != null) return error.InvalidTranscriptSuite;
        break :blk legacy orelse return error.InvalidTranscriptSuite;
    };
    if (encoded.len != 64) return error.InvalidTranscriptStateDigest;
    for (encoded) |byte| if (!(byte >= '0' and byte <= '9') and !(byte >= 'a' and byte <= 'f'))
        return error.InvalidTranscriptStateDigest;
    var digest: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&digest, encoded);
    return digest;
}
pub fn fieldJson(allocator: std.mem.Allocator, receipt: anytype) ![]u8 {
    const hex = std.fmt.bytesToHex(receipt.digest, .lower);
    const suite = @tagName(receipt.suite);
    if (std.mem.eql(u8, suite, "blake2s") and receipt.version == 1)
        return std.fmt.allocPrint(allocator, "\"transcript_state_blake2s\":\"{s}\",", .{hex});
    if (!std.mem.eql(u8, suite, "blake3") or receipt.version != 2) return error.InvalidTranscriptSuite;
    return std.fmt.allocPrint(allocator, "\"transcript_receipt\":{{\"suite\":\"blake3\",\"version\":2,\"digest\":\"{s}\"}},", .{hex});
}
test "report transcript admits one canonical suite and rejects ambiguous fields" {
    const modern = Wire{ .suite = "blake3", .version = 2, .digest = "ab" ** 32 };
    try std.testing.expectEqual([_]u8{0xab} ** 32, try decode(null, modern, true));
    try std.testing.expectEqual([_]u8{0xab} ** 32, try decode("ab" ** 32, null, false));
    try std.testing.expectError(error.InvalidTranscriptSuite, decode("ab" ** 32, modern, true));
    try std.testing.expectError(error.InvalidTranscriptSuite, decode(null, modern, false));
    try std.testing.expectError(error.InvalidTranscriptSuite, decode("ab" ** 32, null, true));
    var wrong = modern; wrong.version = 1;
    try std.testing.expectError(error.InvalidTranscriptSuite, decode(null, wrong, true));
    wrong = modern; wrong.digest = "AB" ** 32;
    try std.testing.expectError(error.InvalidTranscriptStateDigest, decode(null, wrong, true));
}
