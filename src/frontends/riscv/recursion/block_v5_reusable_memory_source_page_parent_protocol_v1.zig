//! Distinct typed PAGE raw/fold reusable parent identities and actual original
//! public-supply arithmetic. Neither can relabel a legacy child protocol.
const Semantic = @import("../prover/block_v5_memory_source_page_semantic_columns_v1.zig");
pub fn ForKind(comptime kind: Semantic.Kind) type {
    const Bus = @import("block_v5_memory_source_page_recursive_public_bus_v1.zig").ForKind(kind);
    return @import("block_v5_reusable_fused_parent_protocol_v1.zig").ForBus(Bus, if (kind == .raw) .{ .claim = 0x50524351, .key = 0x50524b31, .admission = 0x50524131, .proof = 0x50525031 } else .{ .claim = 0x50464351, .key = 0x50464b31, .admission = 0x50464131, .proof = 0x50465031 });
}
