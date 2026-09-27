//! Owned canonical public-input decoding, independent of proof custody.
const std = @import("std");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const PublicData = @import("../air/public_data_v2.zig").PublicDataV2;
pub const MAX_INPUT_BYTES: usize = 128 * 1024;

pub const OwnedExpectedV1 = struct {
    allocator: std.mem.Allocator,
    words: []M31,
    data: PublicData,
    pub fn decode(allocator: std.mem.Allocator, bytes: []const u8) !OwnedExpectedV1 {
        if (bytes.len == 0 or bytes.len > MAX_INPUT_BYTES) return error.DetachedPublicInputSizeMismatch;
        const parsed = try std.json.parseFromSlice([]const u32, allocator, bytes, .{});
        defer parsed.deinit();
        if (parsed.value.len == 0) return error.DetachedPublicInputSizeMismatch;
        const words = try allocator.alloc(M31, parsed.value.len);
        errdefer allocator.free(words);
        for (parsed.value, words) |value, *word| {
            if (value >= core.fields.m31.Modulus) return error.DetachedNoncanonicalPublicWord;
            word.* = M31.fromCanonical(value);
        }
        return .{ .allocator = allocator, .words = words, .data = try PublicData.authenticate(words) };
    }
    pub fn deinit(self: *OwnedExpectedV1) void {
        self.allocator.free(self.words);
        self.* = undefined;
    }
};

pub fn encodeExpected(allocator: std.mem.Allocator, expected: *const PublicData) ![]u8 {
    _ = try expected.metadata();
    const words = try allocator.alloc(u32, expected.words().len);
    defer allocator.free(words);
    for (expected.words(), words) |word, *value| value.* = word.toU32();
    const bytes = try std.json.Stringify.valueAlloc(allocator, words, .{});
    errdefer allocator.free(bytes);
    if (bytes.len > MAX_INPUT_BYTES) return error.DetachedPublicInputSizeMismatch;
    return bytes;
}
