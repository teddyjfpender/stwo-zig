//! Hash the shared walker's CONSTANT framing, excluding all free values.
//! This identifies which public layout is associated with a trusted topology.
const std = @import("std");
const A = @import("../rv64_authenticated_execution.zig");
const walk = @import("transcript_walk.zig");
const Hash = std.crypto.hash.sha2.Sha256;
pub fn digest(public: A.Public) ![32]u8 {
    // walkPublic computes logSize; reject malformed untrusted counts BEFORE it.
    if (public.cpu.statement.steps == 0 or public.cpu.statement.steps >= 1 << 22) return error.InvalidRecursionLeafSteps;
    var sink = Sink{ .hash = Hash.init(.{}) };
    sink.hash.update("rv64-recursion-layout-transcript-v1\x00");
    // Program identity is free transcript data, not part of the layout. Its
    // authority is checked by the full statement walk using the expected ELF.
    try walk.walkPublicWithProgramIdentity(&sink, @splat(0), public);
    return sink.hash.finalResult();
}
const Sink = struct {
    hash: Hash,
    fn word(self: *Sink, value: u32) void {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value, .little);
        self.hash.update(&bytes);
    }
    pub fn words(self: *Sink, kinds: []const walk.Kind, values: []const u32) !void {
        self.word(0);
        self.word(@intCast(kinds.len));
        for (kinds, values) |kind, value| {
            self.word(@intFromEnum(kind));
            if (kind == .layout) self.word(value);
        }
    }
    pub fn u64Free(self: *Sink, _: u64) !void {
        self.word(1);
    }
    pub fn digestFree(self: *Sink, _: [9]u32) !void {
        self.word(2);
    }
    pub fn clockFree(self: *Sink, _: u32) !void {
        self.word(3);
    }
    pub fn configFelt(self: *Sink) !void {
        self.word(4);
        var channel = A.P.Channel{};
        A.P.config().mixInto(&channel);
        self.hash.update(&channel.digestBytes());
    }
};
test "layout fingerprint ignores free words but distinguishes policy constants and frame roles" {
    var a = Sink{ .hash = Hash.init(.{}) };
    var b = Sink{ .hash = Hash.init(.{}) };
    try a.words(&.{ .layout, .free, .steps }, &.{ 3, 7, 9 });
    try b.words(&.{ .layout, .free, .steps }, &.{ 3, 8, 10 });
    try std.testing.expectEqual(a.hash.finalResult(), b.hash.finalResult());
    b = .{ .hash = Hash.init(.{}) };
    try b.words(&.{ .layout, .free, .steps }, &.{ 2, 7, 9 });
    try std.testing.expect(!std.mem.eql(u8, &a.hash.finalResult(), &b.hash.finalResult()));
    b = .{ .hash = Hash.init(.{}) };
    try b.words(&.{ .layout, .steps, .free }, &.{ 3, 7, 9 });
    try std.testing.expect(!std.mem.eql(u8, &a.hash.finalResult(), &b.hash.finalResult()));
}

test "layout admission rejects zero steps before logarithm or setup allocation" {
    const public = A.Public{
        .cpu = .{ .statement = .{ .program = .{ .base = 0, .words = &.{} }, .steps = 0, .initial_pc = 0, .final_pc = 0, .initial_registers = @splat(0), .final_registers = @splat(0), .cells = &.{}, .register_clocks = @splat(0), .memory_clocks = &.{}, .opcodes = @splat(false) }, .division_requests = 0, .keccak_calls = 0 },
        .geometry = .chunk512,
        .before = @splat(0),
        .after = @splat(0),
        .policy_identity = @splat(0),
        .ram = null,
    };
    try std.testing.expectError(error.InvalidRecursionLeafSteps, digest(public));
}
