//! Canonical family source selection under one explicit new wire version.
//! Incoming metadata is NEVER authority to select a receiver construction.
const std = @import("std");
pub const WIRE_SCHEMA: u32 = 3;
pub const WIRE_MAGIC = "OPP2B003";
pub const WORDS = 5;
pub const BYTES = 4 * WORDS;
pub const Flavor = enum(u32) { classic = 0, local_gkr = 1 };
pub const Suite = struct {
    version: u32 = 1,
    cpu: u32 = 1,
    truth: Flavor = .classic,
    miller: Flavor = .classic,
    sponge: u32 = 0,
    pub fn validate(self: Suite) !void {
        if (self.version != 1 or self.cpu != 1 or self.sponge != 0) return error.UnsupportedOpSourceSuite;
    }
    pub fn millerGkr() Suite {
        return .{ .truth = .local_gkr, .miller = .local_gkr };
    }
    pub fn encode(self: Suite) ![BYTES]u8 {
        try self.validate();
        var out: [BYTES]u8 = undefined;
        const words = [WORDS]u32{ self.version, self.cpu, @intFromEnum(self.truth), @intFromEnum(self.miller), self.sponge };
        for (words, 0..) |word, i| std.mem.writeInt(u32, out[4 * i ..][0..4], word, .little);
        return out;
    }
    pub fn decode(bytes: [BYTES]u8) !Suite {
        var words: [WORDS]u32 = undefined;
        for (&words, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
        if (words[2] > 1 or words[3] > 1) return error.UnsupportedOpSourceSuite;
        const out = Suite{ .version = words[0], .cpu = words[1], .truth = @enumFromInt(words[2]), .miller = @enumFromInt(words[3]), .sponge = words[4] };
        try out.validate();
        return out;
    }
    pub fn identity(self: Suite) ![32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("opstack-source-suite/v1\x00");
        hash.update(&try self.encode());
        return hash.finalResult();
    }
    /// Must run before source keys or proof-dependent allocation. The expected
    /// suite comes from independently selected receiver policy, not the bundle.
    pub fn requireExpected(self: Suite, expected: ?Suite) !void {
        try self.validate();
        const authority = expected orelse return error.OpSourceSuiteRequiresExplicitReceiver;
        try authority.validate();
        if (!std.meta.eql(self, authority)) return error.OpSourceSuitePolicyMismatch;
    }
};
test "OP source suite canonical wire and independently selected policy" {
    const suite = Suite.millerGkr();
    const encoded = try suite.encode();
    try std.testing.expectEqualDeep(suite, try Suite.decode(encoded));
    try std.testing.expectError(error.OpSourceSuiteRequiresExplicitReceiver, suite.requireExpected(null));
    try std.testing.expectError(error.OpSourceSuitePolicyMismatch, suite.requireExpected(Suite{}));
    try suite.requireExpected(suite);
    try std.testing.expect(!std.mem.eql(u8, &try suite.identity(), &try (Suite{}).identity()));
    var malformed = encoded;
    std.mem.writeInt(u32, malformed[8..12], 2, .little);
    try std.testing.expectError(error.UnsupportedOpSourceSuite, Suite.decode(malformed));
    var unsupported = suite;
    unsupported.sponge = 1;
    try std.testing.expectError(error.UnsupportedOpSourceSuite, unsupported.encode());
}
