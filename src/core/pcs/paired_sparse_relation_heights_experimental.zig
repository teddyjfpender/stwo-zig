//! Audit-only accepted relation for experimental CAS07/XDM05.
//! Production PCS does not dispatch this verifier or certify soundness.

const generic = @import("paired_sparse_relation_generic.zig");
const Relation = generic.Relation(
    @import("paired_sparse_cascade_heights_experimental.zig"),
    @import("transposed_merkle_sparse_heights_experimental.zig"),
);

pub const AcceptedRelation = Relation.AcceptedRelation;
pub const verifyAndExtract = Relation.verifyAndExtract;
