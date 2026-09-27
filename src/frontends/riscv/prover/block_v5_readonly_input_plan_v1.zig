//! Public input is mutable by default. This independently pinned subset is
//! usable only after every source access has a freshly proved classification.
const std = @import("std");
const Sources = @import("block_v5_initial_sources_v1.zig");
pub const WORD_LIMIT: u32 = 1 << 30;
pub const VERSION: u32 = 1;
pub const Limits = struct { max_words: usize = 1_000_000, max_intervals: usize = 2_000_001 };
pub const Pins = struct {
    source: Sources.Pins,
    /// Aligned byte addresses, sorted and unique. Source alone is not an
    /// immutable promise: the AIR must check every selected before/after.
    addresses: []const u32,
    expected_digest: [32]u8,
    limits: Limits = .{},
};
pub const Interval = struct { lower: u32, upper: u32, readonly: bool, value: u32 };
pub const Owned = struct {
    a: std.mem.Allocator,
    intervals: []Interval,
    digest: [32]u8,
    pub fn deinit(self: *Owned) void {
        self.a.free(self.intervals);
        self.* = undefined;
    }
    pub fn find(self: Owned, address: u32) !usize {
        return findInterval(self.intervals, address);
    }
};
pub fn findInterval(intervals: []const Interval, address: u32) !usize {
    if (address & 3 != 0) return error.UnalignedReadonlyInputAccess;
    const word = address / 4;
    var lo: usize = 0;
    var hi = intervals.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (intervals[mid].upper <= word) lo = mid + 1 else hi = mid;
    }
    if (lo == intervals.len or intervals[lo].lower > word) return error.InvalidReadonlyInputPartition;
    return lo;
}
/// Derive values and the complete complement from independently supplied input
/// bytes. A supplied value, interval or host access census is never authority.
pub fn derive(a: std.mem.Allocator, source: Sources.Pins, input: []const u8, addresses: []const u32, limits: Limits) !Owned {
    try source.validate();
    if (input.len != source.public_input_len or !std.meta.eql(Sources.sha256(input), source.public_input_sha256)) return error.UntrustedReadonlyInputBytes;
    const values = try deriveIntervals(a, source.layout, input, addresses, limits);
    errdefer a.free(values);
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("stwo-zig/block-v5/readonly-input-plan/v1\x00");
    hash.update(&(try source.digest()));
    hash.update(&source.public_input_sha256);
    put(&hash, source.public_input_len);
    put(&hash, limits.max_words);
    put(&hash, limits.max_intervals);
    put(&hash, values.len);
    for (values) |interval| {
        put(&hash, interval.lower);
        put(&hash, interval.upper);
        put(&hash, @intFromBool(interval.readonly));
        put(&hash, interval.value);
    }
    return .{ .a = a, .intervals = values, .digest = hash.finalResult() };
}
/// Canonical interval/value kernel shared by the early immutable selection
/// and late-bound Plan v1. Caller has already checked its bytes/layout authority.
pub fn deriveIntervals(a: std.mem.Allocator, layout: @import("../runner/memory_state.zig").MemoryLayout, input: []const u8, addresses: []const u32, limits: Limits) ![]Interval {
    if (addresses.len > limits.max_words or limits.max_intervals == 0) return error.ReadonlyInputPlanResourceLimit;
    const max_intervals = try std.math.add(usize, try std.math.mul(usize, addresses.len, 2), 1);
    if (max_intervals > limits.max_intervals) return error.ReadonlyInputPlanResourceLimit;
    // Validate all addresses before allocating; no unchecked u32 increments.
    for (addresses, 0..) |address, index| {
        if ((address & 3) != 0 or !layout.isInputAddr(address) or
            (index != 0 and address <= addresses[index - 1])) return error.InvalidReadonlyInputAddressRoster;
        _ = try Sources.inputWordAt(layout, input, address);
    }
    var intervals: std.ArrayList(Interval) = .empty;
    errdefer intervals.deinit(a);
    try intervals.ensureTotalCapacity(a, max_intervals);
    var next: u32 = 0;
    for (addresses) |address| {
        const word = address / 4;
        if (next < word) intervals.appendAssumeCapacity(.{ .lower = next, .upper = word, .readonly = false, .value = 0 });
        intervals.appendAssumeCapacity(.{ .lower = word, .upper = word + 1, .readonly = true, .value = try Sources.inputWordAt(layout, input, address) });
        next = word + 1;
    }
    if (next < WORD_LIMIT) intervals.appendAssumeCapacity(.{ .lower = next, .upper = WORD_LIMIT, .readonly = false, .value = 0 });
    return intervals.toOwnedSlice(a);
}
pub fn admit(a: std.mem.Allocator, pins: Pins, input: []const u8) !Owned {
    var plan = try derive(a, pins.source, input, pins.addresses, pins.limits);
    errdefer plan.deinit();
    if (!std.meta.eql(plan.digest, pins.expected_digest)) return error.UntrustedReadonlyInputPlan;
    return plan;
}
fn put(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}
