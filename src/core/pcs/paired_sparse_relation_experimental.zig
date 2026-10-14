//! Audit-only accepted relation for experimental CAS05/XDM04.
//! The shared checker also serves CAS07/XDM05 without changing either wire.

const generic = @import("paired_sparse_relation_generic.zig");
const Relation = generic.Relation(
    @import("paired_sparse_cascade_experimental.zig"),
    @import("transposed_merkle_sparse.zig"),
);

pub const AcceptedRelation = Relation.AcceptedRelation;
pub const verifyAndExtract = Relation.verifyAndExtract;
