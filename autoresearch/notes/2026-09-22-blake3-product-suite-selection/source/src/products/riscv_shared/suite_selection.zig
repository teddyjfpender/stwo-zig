//! Global proof-suite selection is explicit and precedes the command.
const std = @import("std");
pub const Suite = enum { blake2s, blake3 };
pub const Selection = struct { suite: Suite, args: []const []const u8 };
pub fn parse(args: []const []const u8) !Selection {
    if (args.len == 0 or !std.mem.eql(u8, args[0], "--proof-suite"))
        return .{ .suite = .blake2s, .args = args };
    if (args.len < 3) return error.MissingProofSuiteCommand;
    const suite = std.meta.stringToEnum(Suite, args[1]) orelse return error.UnsupportedProofSuite;
    for (args[2..]) |arg| if (std.mem.eql(u8, arg, "--proof-suite")) return error.DuplicateProofSuite;
    return .{ .suite = suite, .args = args[2..] };
}
test "proof suite prefix is explicit and rejects unknown or duplicate selection" {
    try std.testing.expectEqual(Suite.blake2s, (try parse(&.{"bench"})).suite);
    const selected = try parse(&.{"--proof-suite", "blake3", "verify", "--artifact", "p.json"});
    try std.testing.expectEqual(Suite.blake3, selected.suite);
    try std.testing.expectEqualStrings("verify", selected.args[0]);
    try std.testing.expectError(error.UnsupportedProofSuite, parse(&.{"--proof-suite", "unknown", "bench"}));
    try std.testing.expectError(error.MissingProofSuiteCommand, parse(&.{"--proof-suite", "blake3"}));
    try std.testing.expectError(error.DuplicateProofSuite, parse(&.{"--proof-suite", "blake3", "bench", "--proof-suite", "blake2s"}));
}
