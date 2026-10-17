//! Focused gate for the sparse-memory commitment soundness constraints.
//!
//! Covers the Merkle node child/parent multiplicity binding, the boundary
//! table's initial-row clock binding, the verifier-recomputable initial RW
//! root, and the statement program-shape bound, without compiling the full
//! frontend inventory.

test {
    _ = @import("air/memory_commitment/merkle_node.zig");
    _ = @import("air/memory_commitment/interaction.zig");
    _ = @import("air/memory_commitment/incremental_boundary_interaction_v3.zig");
    _ = @import("air/memory_commitment/boundary.zig");
    _ = @import("air/memory_commitment/sparse_merkle.zig");
    _ = @import("prover/statement_validation.zig");
}
