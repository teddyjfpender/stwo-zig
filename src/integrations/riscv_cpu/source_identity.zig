//! Exact file-content pins shared by native qualifications and product requests.
//! Historical rejection names remain unchanged. No request admission lives here.
const std = @import("std");
pub fn pin(raw: []const u8, expected_hex: []const u8) !void {
    var expected: [32]u8 = undefined;
    if (expected_hex.len != 64) return error.InvalidExpectedInputIdentity;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    if (!std.mem.eql(u8, &expected, &sha(raw))) return error.EthereumInputIdentityMismatch;
}
pub fn sha(raw: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &result, .{});
    return result;
}

test "native source pins preserve exact identity and rejection precedence" {
    const hex = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";
    try pin("abc", hex);
    try std.testing.expectError(error.InvalidExpectedInputIdentity, pin("abc", hex[0..63]));
    try std.testing.expectError(error.InvalidCharacter, pin("abc", "z" ** 64));
    try std.testing.expectError(error.EthereumInputIdentityMismatch, pin("abd", hex));
}
