//! Independent fixed schedule for the original Frame.words cut. The existing
//! full-hash Builder owns all compression algebra and wire numbering.
const std = @import("std");
const core = @import("stwo_core");
const geometry = @import("../blake3_words_tail_v1.zig");
const hash = @import("blake3_hash_plan.zig");
pub const MAX_WINDOWS: usize = 4;
pub const Limits = struct {
    max_words: usize = 64 * 1024 * 1024,
    max_calls: usize = 8 * 1024 * 1024,
    pub fn require(self: Limits, words: usize, windows: usize) !void {
        if (windows == 0 or windows > MAX_WINDOWS or words > self.max_words) return error.Blake3TailResourceLimit;
        const shape = try geometry.Geometry.init(words);
        const blocks = shape.frame_bytes / 64 + @intFromBool(shape.frame_bytes % 64 != 0);
        const original_calls = try std.math.add(usize, blocks, shape.chunks - 1);
        const total = try std.math.add(usize, original_calls, try std.math.mul(usize, windows, 16 + shape.range_count));
        if (total > self.max_calls or total >= core.fields.m31.Modulus / @import("blake3_compression_plan.zig").WIRE_COUNT) return error.Blake3TailResourceLimit;
    }
};
pub const Plan = struct {
    allocator: std.mem.Allocator,
    geometry: geometry.Geometry,
    windows: usize,
    tail: []hash.Plan,
    prefix: hash.Plan,
    pub fn init(a: std.mem.Allocator, words: usize, windows: usize, limits: Limits) !Plan {
        try limits.require(words, windows);
        const shape = try geometry.Geometry.init(words);
        const tail = try a.alloc(hash.Plan, shape.range_count);
        errdefer a.free(tail);
        var count: usize = 0;
        errdefer for (tail[0..count]) |*item| item.deinit();
        for (shape.frontier(), tail) |range, *item| {
            item.* = try hash.buildSubtreeAt(a, shape.frame_bytes, range.first, range.count);
            count += 1;
            // One domain-bound input root and each original window consume the
            // same CV; no public constant or copied host digest supplies it.
            for (item.output) |wire| item.uses[wire] = @intCast(windows + 1);
        }
        var prefix = try hash.buildPrefixFold(a, shape.frame_bytes);
        errdefer prefix.deinit();
        return .{ .allocator = a, .geometry = shape, .windows = windows, .tail = tail, .prefix = prefix };
    }
    pub fn deinit(self: *Plan) void {
        for (self.tail) |*item| item.deinit();
        self.allocator.free(self.tail);
        self.prefix.deinit();
        self.* = undefined;
    }
    pub fn require(self: *const Plan, words: usize, windows: usize, limits: Limits) !void {
        try limits.require(words, windows);
        try self.geometry.require(words);
        if (self.windows != windows or self.tail.len != self.geometry.range_count) return error.UntrustedBlake3TailPlan;
        var wanted = try init(self.allocator, words, windows, limits);
        defer wanted.deinit();
        try equalPlan(&self.prefix, &wanted.prefix);
        for (self.tail, wanted.tail) |*actual, *expected| try equalPlan(actual, expected);
    }
};
fn equalPlan(actual: *const hash.Plan, expected: *const hash.Plan) !void {
    if (actual.input_len != expected.input_len or !std.mem.eql(u32, actual.uses, expected.uses) or !std.meta.eql(actual.output, expected.output)) return error.UntrustedBlake3TailPlan;
    inline for (.{ "sources", "calls", "g", "xor" }) |name| {
        const left = @field(actual, name);
        const right = @field(expected, name);
        if (left.len != right.len) return error.UntrustedBlake3TailPlan;
        for (left, right) |a, b| if (!std.meta.eql(a, b)) return error.UntrustedBlake3TailPlan;
    }
}
