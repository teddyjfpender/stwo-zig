//! One independently admitted sorted-record ingress. The owner and device
//! buffer survive witness generation; success does not authorize a receipt.
const std = @import("std");
const core = @import("stwo_core");
const Protocol = @import("block_v5_ram_lanes_protocol_v1.zig");
const Interaction = @import("block_v5_ram_lanes_interaction_v1.zig");
const Q = core.fields.qm31.QM31;
pub const Buffer = struct {
    handle: *anyopaque,
    contents: *anyopaque,
    byte_length: usize,
    /// Actual local owning allocation's budget, not serialized proof metadata.
    budget_owner: ?*@import("stwo_prover_engine").host_budget_allocator.SharedHostBudget = null,
};
pub const Summary = struct { sorted_ingress_bytes: usize, histogram_ingress_bytes: usize, claim_readback_bytes: usize, status_readback_bytes: usize, device_blit_bytes: usize };
pub const Lease = struct {
    claim: Protocol.Claim,
    buffer: Buffer,
    uploaded_bytes: usize = 0,
    counter_values: []const u32,
    request_count: u64,
    context: *anyopaque,
    release: *const fn (*anyopaque) void,
    pub fn require(self: *const Lease, expected: Protocol.Claim, cap: usize) !void {
        try expected.validate();
        const length = try std.math.mul(usize, expected.events, 24);
        if (!std.meta.eql(self.claim, expected) or self.buffer.byte_length != length or self.uploaded_bytes > length) return error.InvalidSecureRamSource;
        if (length > cap) return error.SecureRamSourceCap;
    }
    pub fn copyCounter(self: *const Lease, destination: *@import("block_v5_range16_v1.zig").Counter) !void {
        const Range = @import("block_v5_range16_v1.zig");
        if (self.counter_values.len != Range.TABLE_SIZE or destination.values.len != Range.TABLE_SIZE or destination.total != 0) return error.InvalidV5Range16Counter;
        var total: u64 = 0;
        for (self.counter_values) |value| {
            if (value >= core.fields.m31.Modulus) return error.InvalidV5Range16Counter;
            total = try std.math.add(u64, total, value);
        }
        const bounds = @import("../air/block/word_memory_v5.zig").rangeCountBounds(self.claim.legacy());
        if (total != self.request_count or total > Range.MAX_REQUESTS or total < bounds.minimum or total > bounds.maximum) return error.InvalidV5Range16Counter;
        @memcpy(destination.values, self.counter_values);
        destination.total = total;
    }
    pub fn deinit(self: *Lease) void {
        self.release(self.context);
        self.* = undefined;
    }
};
/// CPU boundary consists only of the25 independently pinned public words.
/// Record words remain full u32; field reduction would discard high bits.
pub fn metadata(geometry: Protocol.Claim) ![25]u32 {
    try geometry.validate();
    var result: [25]u32 = @splat(0);
    result[0] = @truncate(geometry.first_event);
    result[1] = @truncate(geometry.first_event >> 32);
    result[2] = @truncate(geometry.total_events);
    result[3] = @truncate(geometry.total_events >> 32);
    result[4] = geometry.events;
    result[5] = geometry.row_log;
    result[6] = @intFromBool(geometry.preceding != null);
    if (geometry.preceding) |event| eventWords(result[7..13], event);
    eventWords(result[13..19], geometry.first);
    eventWords(result[19..25], geometry.last);
    return result;
}
pub fn eventWords(out: []u32, event: anytype) void {
    std.debug.assert(out.len == 6);
    out[0] = event.space;
    out[1] = event.address;
    out[2] = @truncate(event.clock);
    out[3] = @truncate(event.clock >> 32);
    out[4] = event.before;
    out[5] = event.after;
}
/// Histogram custody is derived from exact typed integer witness rows one
/// event at a time. This stack-only calculation emits no committed columns.
pub fn addRangeRequests(counter: *@import("block_v5_range16_v1.zig").Counter, prior: ?@import("../air/block/memory_transition.zig").Transition, event: @import("../air/block/memory_transition.zig").Transition) !void {
    const Word = @import("../air/block/word_memory_v5.zig");
    const cells = try Word.witness(prior, event);
    var secure: [27]Q = undefined;
    for (cells, &secure) |cell, *out| out.* = Q.fromBase(cell);
    const one = Q.one();
    const zero = Q.zero();
    const fixed = Word.Fixed{ .active = one, .first = zero, .last = zero, .global_first = zero, .global_last = zero, .domain_last = zero, .ordinal = @splat(zero), .previous_ordinal = @splat(zero) };
    for (Word.rangePoints(fixed, secure)) |point| if (!point.weight.isZero()) {
        if (!point.weight.eql(one)) return error.InvalidV5Range16Counter;
        const coordinates = point.value.toM31Array();
        if (!coordinates[1].isZero() or !coordinates[2].isZero() or !coordinates[3].isZero()) return error.InvalidV5Range16Counter;
        try counter.add(coordinates[0].toU32());
    };
}
pub fn count(value: Q) !u64 {
    const words = value.toM31Array();
    if (!words[1].isZero() or !words[2].isZero() or !words[3].isZero() or words[0].toU32() >= core.fields.m31.Modulus) return error.InvalidSecureRamClaimCount;
    return words[0].toU32();
}
/// Explicit bounded transcript readback:23 QM31 totals, never the92 columns.
pub fn claim(totals: [23]Q, geometry: Protocol.Claim, expected_requests: u64) !Interaction.Claim {
    const result = Interaction.Claim{ .event_count = geometry.events, .transition_sum = totals[0], .link_sum = totals[1], .initial_sum = totals[2], .endpoint_sum = totals[3], .endpoint_count = try count(totals[4]), .range_count = try count(totals[5]), .range_sums = totals[6..23].* };
    _ = try Interaction.normalize(result, geometry);
    if (result.range_count != expected_requests) return error.SecureRamRangeCensusMismatch;
    return result;
}
