//! Algebraic conversion of freshly proved lane requests to the unchanged
//! global word buses. This helper supplies no standalone closure authority.
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Interaction = @import("block_v5_ram_lanes_interaction_v1.zig");
const Word = @import("block_v5_word_memory_interaction_v1.zig");
pub const Buses = struct {
    transition_sum: Q,
    link_sum: Q,
    initial_sum: Q,
    endpoint_sum: Q,
    endpoint_count: u64,
    range_count: u64,
    word_range_sums: [Word.RANGE_BATCHES]Q,
    pub fn rangeSum(self: Buses) Q {
        var sum = Q.zero();
        for (self.word_range_sums) |value| sum = sum.add(value);
        return sum;
    }
    pub fn registerEndpointSum(_: Buses) Q {
        return Q.zero();
    }
    pub fn registerEndpointCount(_: Buses) u64 {
        return 0;
    }
};
/// Same range positions regroup associatively; the rational request multiset,
/// endpoints and transition tuples do not change. Never fabricate a v4 proof
/// receipt with actual lane roots or its virtual legacy log.
pub fn buses(value: Interaction.Claim) Buses {
    var ranges: [Word.RANGE_BATCHES]Q = undefined;
    for (&ranges, 0..) |*out, index| out.* = value.range_sums[2 * index].add(if (2 * index + 1 < value.range_sums.len) value.range_sums[2 * index + 1] else Q.zero());
    return .{ .transition_sum = value.transition_sum, .link_sum = value.link_sum, .initial_sum = value.initial_sum, .endpoint_sum = value.endpoint_sum, .endpoint_count = value.endpoint_count, .range_count = value.range_count, .word_range_sums = ranges };
}
