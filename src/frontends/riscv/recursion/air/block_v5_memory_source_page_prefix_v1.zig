//! Original PAGE first-six-root and semantic prefix bodies, shared by live
//! statement recording and capture-free routing. No verifier authority is made.
const Protocol = @import("../../prover/block_v5_memory_source_unified_page_protocol_v1.zig");
const Original = @import("../../prover/block_v5_memory_source_unified_page_proof_v1.zig");
const Semantic = @import("../../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
pub fn sourceFirst(comptime kind: Semantic.Kind, channel: anytype, plan: anytype, pin: anytype) !void {
    if (kind == .raw) {
        try @import("../../prover/block_v5_memory_source_packed_sha_replay_v1.zig").replayInto(channel, plan, pin);
    } else {
        Protocol.mixFoldFirst(channel, plan, pin);
        for (pin.roots) |root| channel.mixRoot(root);
    }
}
pub fn beginSemantic(comptime kind: Semantic.Kind, channel: anytype, premix_identity: [32]u8, epoch: Protocol.SourceEpoch, graph: *const Semantic.Prepared, claims: Semantic.Claims) !void {
    channel.mixRoot(Original.ForKind(kind).abiId());
    try Protocol.beginSemantic(channel, kind, premix_identity, epoch, graph, claims);
}
