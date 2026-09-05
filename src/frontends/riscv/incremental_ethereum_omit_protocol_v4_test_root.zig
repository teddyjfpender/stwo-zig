//! Focused gate for the omitted-provider V4 route protocol (grafts G2 + G3).
//!
//! The pins, the pre-Tree0 frame and the per-shard leaf authority are pure
//! authority and algebra: no prove path calls them yet. This root compiles and
//! runs their unit gates on their own, so a drift in the pinned residency
//! request, in the frame's transcript order, or in the leaf authority's
//! bindings is a named failure here rather than a proof-identity surprise
//! after a ten-minute product build.

comptime {
    _ = @import("prover/incremental_ethereum_omit_protocol_v4_test.zig");
}
