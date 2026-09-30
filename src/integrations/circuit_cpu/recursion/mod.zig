//! Recursion orchestration on the CPU circuit prover (design §7).

/// The leaf wrap: `prove_leaf` steps 4-8 (design §7.1).
pub const leaf_wrap = @import("leaf_wrap.zig");
/// Topology identity (design §3.5).
pub const topology_key = @import("topology_key.zig");
/// The byte-bounded per-topology LRU (design §9.3).
pub const topology_cache = @import("topology_cache.zig");

test {
    _ = leaf_wrap;
    _ = topology_key;
    _ = topology_cache;
}
