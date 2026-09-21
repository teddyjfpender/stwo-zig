//! Integration binding for the shared detached_leaf_tuple_diagnostic_v2 owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_leaf_tuple_diagnostic_v2;

pub const TupleLedger = owner.TupleLedger;
pub const TupleContribution = owner.TupleContribution;
pub const TupleClosureReport = owner.TupleClosureReport;
pub const RelationDomain = owner.RelationDomain;
pub const RelationRole = owner.RelationRole;
pub const COMPONENT_COUNT = owner.COMPONENT_COUNT;
pub const VERBOSE_ENV = owner.VERBOSE_ENV;
pub const RED_DOMAIN_MASK = owner.RED_DOMAIN_MASK;
pub const AuthorityClass = owner.AuthorityClass;
pub const ResidualKind = owner.ResidualKind;
pub const ExpectedCounterpart = owner.ExpectedCounterpart;
pub const Provenance = owner.Provenance;
pub const UnmatchedGroup = owner.UnmatchedGroup;
pub const Report = owner.Report;
pub const classify = owner.classify;

test "SegmentV2 tuple classifier preserves exact unmatched provenance" {
    try owner.testMovedLeafCohort0();
}
