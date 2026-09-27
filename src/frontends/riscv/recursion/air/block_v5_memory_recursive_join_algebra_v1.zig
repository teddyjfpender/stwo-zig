//! Exact PAGE source / sorted RAM / range equations. Transition remains OPEN.
//! Inputs must be routed from original recursively verified child coordinates.
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Interaction = @import("../../prover/block_v5_ram_lanes_interaction_v1.zig");
const Forest = @import("../block_v5_memory_source_page_forest_algebra_v1.zig");
const Batch = @import("../../prover/block_v5_memory_source_batch_protocol_v1.zig");
const Range = @import("../../prover/block_v5_range16_v1.zig");
pub fn Lane(comptime S: type) type {
    return struct { event_count: S, transition: S, predecessor: S, initial: S, endpoint: S, endpoint_count: S, range_count: S, ranges: [Interaction.RANGE_PLANES]S };
}
pub fn Provider(comptime S: type) type {
    return struct { sum: S, count: S };
}
pub fn base(comptime S: type, count: u64) !S {
    if (count >= core.fields.m31.Modulus) return error.RecursiveMemoryFieldCensusOverflow;
    return S.fromBase(M.fromCanonical(@intCast(count)));
}
/// Exact original per-shard requester closure, never a pooled global range sum.
pub fn rangeGroup(comptime S: type, sink: anytype, shard: Range.Shard, provider: Provider(S), lanes: []const Lane(S)) !void {
    if (lanes.len != shard.instance_count or shard.request_count == 0 or shard.request_count > Range.MAX_REQUESTS) return error.UntrustedRecursiveMemoryRangeGroup;
    var sum = provider.sum;
    var count = S.zero();
    for (lanes) |lane| {
        for (lane.ranges) |request| sum = sum.add(request);
        count = count.add(lane.range_count);
    }
    try sink.zero(sum);
    try sink.zero(count.sub(try base(S, shard.request_count)));
    try sink.zero(provider.count.sub(try base(S, shard.request_count)));
}
/// Original PAGE-only closure is repeated in-circuit, then its TWO open source
/// endpoint coordinates close against actual sorted RAM. Native/caller access,
/// state/register windows, bytes/tables and final accounting are still OPEN.
pub fn close(comptime S: type, sink: anytype, admitted: *const Batch.Admission, source: [Forest.CLAIM_COUNT]S, lanes: []const Lane(S), event_counts: []const u64, request_counts: []const u64) !S {
    if (lanes.len != event_counts.len or lanes.len != request_counts.len) return error.UntrustedRecursiveMemoryCensus;
    try Forest.close(S, admitted, source, sink);
    const decoded = Forest.decode(S, source);
    var transition = S.zero();
    var predecessor = S.zero();
    var initial = decoded.source.initial;
    var endpoint = decoded.source.endpoint.neg();
    var endpoint_count = S.zero();
    for (lanes, event_counts, request_counts) |lane, events, requests| {
        try sink.zero(lane.event_count.sub(try base(S, events)));
        try sink.zero(lane.range_count.sub(try base(S, requests)));
        transition = transition.add(lane.transition);
        predecessor = predecessor.add(lane.predecessor);
        initial = initial.add(lane.initial);
        endpoint = endpoint.add(lane.endpoint);
        endpoint_count = endpoint_count.add(lane.endpoint_count);
    }
    try sink.zero(predecessor);
    try sink.zero(initial);
    try sink.zero(endpoint);
    try sink.zero(endpoint_count.sub(try base(S, admitted.source.records(.endpoints))));
    return transition;
}
pub const complete_block_authority = false;
