//! Precollection immutable input policy. Contains no provisional source files,
//! event census, seal or verifier receipt. Actual source pins are late-bound.
const std = @import("std");
const Sources = @import("block_v5_initial_sources_v1.zig");
const Plan = @import("block_v5_readonly_input_plan_v1.zig");
pub const Limits = Plan.Limits;
pub const Authority = struct {
    layout: @import("../runner/memory_state.zig").MemoryLayout,
    initial_rw_root: [32]u8,
    public_input_sha256: [32]u8,
    public_input_len: u64,
    pub fn fromSources(source: Sources.Pins) !Authority {
        try source.validate();
        return .{ .layout = source.layout, .initial_rw_root = source.initial_rw_root, .public_input_sha256 = source.public_input_sha256, .public_input_len = source.public_input_len };
    }
    pub fn requireInput(self: Authority, bytes: []const u8) !void {
        try Sources.validateLayout(self.layout);
        if (self.layout.input_base & 3 != 0 or self.public_input_len > Sources.MAX_INPUT_WORDS * 4 or
            self.public_input_len > self.layout.input_end - self.layout.input_base or std.mem.allEqual(u8, &self.initial_rw_root, 0)) return error.InvalidReadonlyInputSelectionAuthority;
        if (bytes.len != self.public_input_len or !std.meta.eql(Sources.sha256(bytes), self.public_input_sha256)) return error.UntrustedReadonlyInputBytes;
    }
    pub fn requireSource(self: Authority, actual: Sources.Pins) !void {
        if (!std.meta.eql(self, try fromSources(actual))) return error.StaleReadonlyInputSourceAuthority;
    }
};
pub const Pins = struct {
    authority: Authority,
    addresses: []const u32,
    expected_digest: [32]u8,
    limits: Limits = .{},
};
pub const Owned = struct {
    a: std.mem.Allocator,
    authority: Authority,
    addresses: []u32,
    intervals: []Plan.Interval,
    limits: Limits,
    digest: [32]u8,
    pub fn deinit(self: *Owned) void {
        self.a.free(self.addresses);
        self.a.free(self.intervals);
        self.* = undefined;
    }
    pub fn find(self: *const Owned, address: u32) !usize {
        return Plan.findInterval(self.intervals, address);
    }
    /// Check independent pins AND canonical values, including mutations of
    /// public owned arrays after admission. This creates no proof authority.
    pub fn require(self: *const Owned, pins: Pins, bytes: []const u8) !void {
        if (!std.meta.eql(self.authority, pins.authority) or !std.meta.eql(self.limits, pins.limits) or
            !std.mem.eql(u32, self.addresses, pins.addresses) or !std.meta.eql(self.digest, pins.expected_digest)) return error.StaleReadonlyInputSelection;
        var canonical = try admit(self.a, pins, bytes);
        defer canonical.deinit();
        if (!std.meta.eql(self.digest, canonical.digest) or self.intervals.len != canonical.intervals.len) return error.StaleReadonlyInputSelection;
        for (self.intervals, canonical.intervals) |value, expected| if (!std.meta.eql(value, expected)) return error.StaleReadonlyInputSelection;
    }
};
pub fn derive(a: std.mem.Allocator, authority: Authority, bytes: []const u8, addresses: []const u32, limits: Limits) !Owned {
    try authority.requireInput(bytes);
    const intervals = try Plan.deriveIntervals(a, authority.layout, bytes, addresses, limits);
    errdefer a.free(intervals);
    const roster = try a.dupe(u32, addresses);
    errdefer a.free(roster);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/readonly-input-selection/v1\x00");
    hash.update(&authority.initial_rw_root);
    hash.update(&authority.public_input_sha256);
    put(&hash, authority.public_input_len);
    inline for (std.meta.fields(@TypeOf(authority.layout))) |field| put(&hash, @field(authority.layout, field.name));
    put(&hash, limits.max_words);
    put(&hash, limits.max_intervals);
    put(&hash, intervals.len);
    for (intervals) |interval| {
        put(&hash, interval.lower);
        put(&hash, interval.upper);
        put(&hash, @intFromBool(interval.readonly));
        put(&hash, interval.value);
    }
    return .{ .a = a, .authority = authority, .addresses = roster, .intervals = intervals, .limits = limits, .digest = hash.finalResult() };
}
pub fn admit(a: std.mem.Allocator, pins: Pins, bytes: []const u8) !Owned {
    var selected = try derive(a, pins.authority, bytes, pins.addresses, pins.limits);
    errdefer selected.deinit();
    if (!std.meta.eql(selected.digest, pins.expected_digest)) return error.UntrustedReadonlyInputSelection;
    return selected;
}
fn put(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var raw: [8]u8 = undefined;
    std.mem.writeInt(u64, &raw, @intCast(value), .little);
    hash.update(&raw);
}
