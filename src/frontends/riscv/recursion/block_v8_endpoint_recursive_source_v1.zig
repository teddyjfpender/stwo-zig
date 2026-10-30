//! Finite recursive theorem families. The local family has no snapshot or RAM
// provider policy; its committed endpoint root is an open late-bridge port.
pub const Family = enum { whole_window, local_open };
pub fn For(comptime family: Family) type {
    return struct {
        pub const is_local = family == .local_open;
        pub const Statement = if (is_local) @import("../prover/block_v8_endpoint_local_statement_v1.zig") else @import("../prover/block_v8_endpoint_whole_statement_v1.zig");
        pub const Proof = if (is_local) @import("../prover/block_v8_endpoint_local_proof_v1.zig") else @import("../prover/block_v8_endpoint_whole_proof_v1.zig");
        pub const Scope = if (is_local) @import("../prover/block_v8_endpoint_local_scope_v1.zig") else @import("../prover/block_v8_endpoint_whole_scope_v1.zig");
        pub const Context = if (is_local) @import("../prover/block_v8_endpoint_local_context_v1.zig") else @import("../prover/block_v8_endpoint_whole_context_v1.zig");
        pub const Ledger = if (is_local) @import("../prover/block_v8_endpoint_local_ledger_v1.zig") else @import("../prover/block_v8_endpoint_whole_ledger_v1.zig");
        pub const Placement = if (is_local) @import("../prover/block_v8_endpoint_local_placement_v1.zig") else @import("../prover/block_v8_endpoint_whole_placement_v1.zig");
        pub const TRACE_TREES = Placement.TRACE_TREES;
        pub const FIRST_ROOTS = Placement.SOURCE_COUNT + 1;
        pub const PUBLIC_CIRCUIT: u32 = if (is_local) 4_200_084 else 4_200_083;
        pub const PROFILE_TAG: u32 = if (is_local) 0x42384c46 else 0x42384546;
        pub const IDENTITY_TAG: u32 = if (is_local) 0x42384c49 else 0x42384549;
        pub const SCHEDULE_TAG: u32 = if (is_local) 0x42384c53 else 0x42384553;
        pub const VALUES_TAG: u32 = if (is_local) 0x42384c56 else 0x42384556;
        pub const ROSTER_TAG: u32 = if (is_local) 0x42384c52 else 0x42384552;
        pub const tags: @import("block_v6_direct_batch_protocol_v1.zig").Domains = if (is_local) .{ .key = 0x42384c4b, .public_input = 0x42384c49, .proof = 0x42384c50, .claims = 0x42384c43 } else .{ .key = 0x4238454b, .public_input = 0x42384549, .proof = 0x42384550, .claims = 0x42384543 };
    };
}
