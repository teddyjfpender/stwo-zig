//! Bounded native-GKR v2 physical-worker container. The receiver supplies the
//! expected kind/ordinal and complete source roster. Decoding grants no proof
//! authority: the worker must still verify GKR and PCS under its source key.
const std = @import("std");
const V2 = @import("v2.zig");
const S = @import("section.zig");
const R = @import("roster.zig");
pub const MAGIC: u32 = 0x324e5652; // RVN2, distinct from the numerical section.
pub const VERSION: u32 = 2;
pub const HEADER_WORDS: usize = 8;
pub const MAX_PCS_BYTES: usize = 64 * 1024 * 1024;
pub const Kind = enum(u32) { cpu = 1, truth = 2 };
pub const Expected = struct { kind: Kind, ordinal: u32 };
pub const Decoded = struct {
    section: S.Section,
    /// Borrows the input container; keep that allocation alive through PCS.
    pcs: []const u8,
    pub fn deinit(self: *Decoded, a: std.mem.Allocator) void {
        self.section.deinit(a);
        self.* = undefined;
    }
};
fn requireExpected(expected: Expected) !void {
    if (expected.ordinal >= 256) return error.NativeGkrWorkerOrdinal;
}
fn read(bytes: []const u8, index: usize) u32 {
    return std.mem.readInt(u32, bytes[4 * index ..][0..4], .little);
}
fn put(bytes: []u8, index: usize, value: u32) void {
    std.mem.writeInt(u32, bytes[4 * index ..][0..4], value, .little);
}
pub fn encode(a: std.mem.Allocator, expected: Expected, roster: *const R.Roster, section: *const S.Section, pcs: []const u8) ![]u8 {
    try requireExpected(expected);
    try V2.validate(roster);
    try V2.requireSalt(section.salt);
    if (pcs.len == 0 or pcs.len > MAX_PCS_BYTES) return error.NativeGkrWorkerPcsSize;
    const words = try V2.encode(a, roster, section);
    defer a.free(words);
    const section_bytes = try std.math.mul(usize, words.len, 4);
    const total = try std.math.add(usize, HEADER_WORDS * 4, try std.math.add(usize, section_bytes, pcs.len));
    const bytes = try a.alloc(u8, total);
    errdefer a.free(bytes);
    const header = [_]u32{ MAGIC, VERSION, @intFromEnum(expected.kind), expected.ordinal, @intCast(words.len), @intCast(pcs.len), 0, 0 };
    for (header, 0..) |word, i| put(bytes, i, word);
    for (words, HEADER_WORDS..) |word, i| put(bytes, i, word);
    @memcpy(bytes[HEADER_WORDS * 4 + section_bytes ..], pcs);
    return bytes;
}
pub fn decode(a: std.mem.Allocator, expected: Expected, roster: *const R.Roster, bytes: []const u8) !Decoded {
    try requireExpected(expected);
    try V2.validate(roster);
    if (bytes.len < HEADER_WORDS * 4 or read(bytes, 0) != MAGIC or read(bytes, 1) != VERSION) return error.NativeGkrWorkerHeader;
    if (read(bytes, 2) != @intFromEnum(expected.kind) or read(bytes, 3) != expected.ordinal) return error.NativeGkrWorkerAuthority;
    if (read(bytes, 6) != 0 or read(bytes, 7) != 0) return error.NativeGkrWorkerReserved;
    // The source geometry fixes the numerical length before any allocation.
    const count = S.wordCount(roster);
    if (read(bytes, 4) != count) return error.NativeGkrWorkerSectionSize;
    const pcs_length: usize = read(bytes, 5);
    if (pcs_length == 0 or pcs_length > MAX_PCS_BYTES) return error.NativeGkrWorkerPcsSize;
    const end = try std.math.add(usize, HEADER_WORDS * 4, try std.math.mul(usize, count, 4));
    if (bytes.len != try std.math.add(usize, end, pcs_length)) return error.NativeGkrWorkerLength;
    const words = try a.alloc(u32, count);
    defer a.free(words);
    for (words, HEADER_WORDS..) |*word, i| word.* = read(bytes, i);
    var section = try V2.decode(a, roster, words);
    errdefer section.deinit(a);
    try V2.requireSalt(section.salt);
    return .{ .section = section, .pcs = bytes[end..] };
}
fn allocationProbe(a: std.mem.Allocator, expected: Expected, roster: *const R.Roster, bytes: []const u8) !void {
    var decoded = try decode(a, expected, roster, bytes);
    defer decoded.deinit(a);
}

test "native worker v2 frame rejects domains bounds truncation and class substitution" {
    const a = std.testing.allocator;
    const Builder = struct {
        pub fn build(_: @This(), allocator: std.mem.Allocator, roster: *const R.Roster, _: V2.LocalElements) !S.Inputs {
            return S.syntheticInputs(allocator, roster, 0x51eed);
        }
    };
    var roster = try V2.derive(a, &.{R.ComponentSpec{ .origin = .{ 0, 13 }, .row_log = 3, .terms = .{ 2, 1, 0, 0 } }});
    defer roster.deinit();
    const channel = S.RawChannel.init();
    const scope = S.Scope{ .ordinal = 7, .statement = @splat(1), .fixed = @splat(2), .main = @splat(3), .shared = @splat(4) };
    var section = try V2.proveCpu(a, &channel, &roster, &scope, Builder{});
    defer section.deinit(a);
    const expected = Expected{ .kind = .cpu, .ordinal = 7 };
    // Opaque bytes here test framing only; this is not a physical PCS proof.
    const pcs = "opaque-PCS-framing-fixture";
    const bytes = try encode(a, expected, &roster, &section, pcs);
    defer a.free(bytes);
    var decoded = try decode(a, expected, &roster, bytes);
    defer decoded.deinit(a);
    try std.testing.expectEqualSlices(u8, pcs, decoded.pcs);
    var ch = channel;
    var verified = try V2.verify(a, &ch, &roster, &scope, &decoded.section);
    defer verified.deinit(a);
    try std.testing.checkAllAllocationFailures(a, allocationProbe, .{ expected, &roster, bytes });
    for (0..HEADER_WORDS) |field| {
        const bad = try a.dupe(u8, bytes);
        defer a.free(bad);
        put(bad, field, read(bad, field) + 1);
        if (decode(a, expected, &roster, bad)) |accepted| {
            var owner = accepted;
            owner.deinit(a);
            return error.BadNativeWorkerFrameAccepted;
        } else |_| {}
    }
    for ([_]usize{ 0, HEADER_WORDS * 4 - 1, HEADER_WORDS * 4, bytes.len - 1 }) |length| {
        if (decode(a, expected, &roster, bytes[0..length])) |accepted| {
            var owner = accepted;
            owner.deinit(a);
            return error.TruncatedNativeWorkerFrameAccepted;
        } else |_| {}
    }
    const trailing = try a.alloc(u8, bytes.len + 1);
    defer a.free(trailing);
    @memcpy(trailing[0..bytes.len], bytes);
    trailing[bytes.len] = 0;
    try std.testing.expectError(error.NativeGkrWorkerLength, decode(a, expected, &roster, trailing));
    const bad = try a.dupe(u8, bytes);
    defer a.free(bad);
    // Numerical-section version is independently pinned to v2 too.
    put(bad, HEADER_WORDS + 1, 1);
    try std.testing.expectError(error.MalformedNativeGkrSection, decode(a, expected, &roster, bad));
    @memcpy(bad, bytes);
    put(bad, HEADER_WORDS + 4, @import("stwo_core").fields.m31.Modulus);
    try std.testing.expectError(error.NonCanonicalNativeGkrWord, decode(a, expected, &roster, bad));
    @memcpy(bad, bytes);
    put(bad, HEADER_WORDS + 4, 64);
    try std.testing.expectError(error.NativeGkrSaltOutOfRange, decode(a, expected, &roster, bad));
    var other = try V2.derive(a, &.{R.ComponentSpec{ .origin = .{ 0, 13 }, .row_log = 4, .terms = .{ 2, 1, 0, 0 } }});
    defer other.deinit();
    try std.testing.expectError(error.NativeGkrWorkerSectionSize, decode(a, expected, &other, bytes));
    try std.testing.expectError(error.NativeGkrWorkerOrdinal, decode(a, .{ .kind = .cpu, .ordinal = 256 }, &roster, bytes));
}
