//! Recursion orchestration on the CPU circuit prover (design §7): the leaf
//! wrap of `crates/leaf_prover`, and the canonical multiverifier shape, the
//! pair reduction and the tree driver of
//! `crates/stwo_run_and_prove_recursive_tree`, and registry generation of
//! `crates/circuit_params` (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! These live in the CPU integration rather than the circuit frontend
//! (design §2.2 lists `recursion/` under the frontend) because a wrap or a
//! fold proves (the prover engine and CPU backend) and reads and writes the
//! recursion wire formats, neither of which the frontend may depend on.

/// The leaf wrap: `prove_leaf` steps 4-8 (design §7.1, M8).
pub const leaf_wrap = @import("leaf_wrap.zig");
/// Topology identity (design §3.5).
pub const topology_key = @import("topology_key.zig");
/// The byte-bounded per-topology LRU (design §9.3).
pub const topology_cache = @import("topology_cache.zig");
/// The canonical multiverifier (design §7.2, M9).
pub const canonical = @import("canonical.zig");
/// `circuit-params --registry` (design §7.3, M9).
pub const circuit_params = @import("circuit_params.zig");
/// The pair reduction (design §7.2, M9).
pub const fold = @import("fold.zig");
/// The recursive tree driver and root files (design §7.2, M9).
pub const tree = @import("tree.zig");

pub const CanonicalCircuit = canonical.CanonicalCircuit;
pub const Fold = fold.Fold;
pub const LayerEntry = fold.LayerEntry;
pub const Stats = tree.Stats;

test {
    _ = leaf_wrap;
    _ = topology_key;
    _ = topology_cache;
    _ = canonical;
    _ = circuit_params;
    _ = fold;
    _ = tree;
}
