//! Recursive-tree orchestration (design §7.2-7.3, milestone M9): the
//! canonical multiverifier shape, the pair reduction and the tree driver of
//! `crates/stwo_run_and_prove_recursive_tree`, and registry generation of
//! `crates/circuit_params` (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230).
//!
//! These live in the CPU integration rather than the circuit frontend
//! (design §2.2 lists `recursion/` under the frontend) because a fold proves
//! (the prover engine and CPU backend) and reads and writes the recursion
//! wire formats, neither of which the frontend may depend on.

pub const canonical = @import("canonical.zig");
pub const circuit_params = @import("circuit_params.zig");
pub const fold = @import("fold.zig");
pub const tree = @import("tree.zig");

pub const CanonicalCircuit = canonical.CanonicalCircuit;
pub const Fold = fold.Fold;
pub const LayerEntry = fold.LayerEntry;
pub const Stats = tree.Stats;

test {
    _ = canonical;
    _ = circuit_params;
    _ = fold;
    _ = tree;
}
