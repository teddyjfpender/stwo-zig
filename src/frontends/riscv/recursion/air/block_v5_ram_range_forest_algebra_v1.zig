//! Compact requester propagation and exact local original range-provider close.
const G = @import("../block_v5_ram_range_forest_plan_v1.zig");
pub const CLAIM_COUNT: usize = 22;
pub fn close(comptime S: type, sink: anytype, node: G.Node, children: []const [CLAIM_COUNT]S, output: [CLAIM_COUNT]S) !void {
    if (children.len != node.child_count or children.len == 0 or children.len > 4) return error.UntrustedRamRangeForestAlgebra;
    var combined: [CLAIM_COUNT]S = @splat(S.zero());
    var provider = S.zero();
    var provider_count: u32 = 0;
    for (children, node.children[0..node.child_count]) |part, ref| {
        if (ref == .range) {
            if (node.kind != .shard or ref.range != node.shards.first) return error.UntrustedRamRangeForestAlgebra;
            provider = provider.add(part[0]);
            provider_count += 1;
            continue;
        }
        for (&combined, part) |*value, input| value.* = value.add(input);
        // An aggregate only consumes roots whose own shard range is CLOSED.
        // No opposite shard deficits can cancel in a global parent.
        if (node.kind == .aggregate) for (part[5..]) |value| try sink.zero(value);
    }
    for (combined[0..5], output[0..5]) |value, claimed| try sink.zero(value.sub(claimed));
    if (node.kind == .partial) {
        if (provider_count != 0) return error.UntrustedRamRangeForestAlgebra;
        for (combined[5..], output[5..]) |value, claimed| try sink.zero(value.sub(claimed));
    } else {
        if (node.kind == .shard) {
            if (provider_count != 1) return error.UntrustedRamRangeForestAlgebra;
            for (combined[5..]) |request| provider = provider.add(request);
            try sink.zero(provider);
        } else if (provider_count != 0) return error.UntrustedRamRangeForestAlgebra;
        for (output[5..]) |value| try sink.zero(value);
    }
}
pub const complete_block_authority = false;
