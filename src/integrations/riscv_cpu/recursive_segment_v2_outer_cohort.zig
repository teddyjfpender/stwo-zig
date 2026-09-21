//! Integration binding for the shared detached_leaf_cohort_v2 owner.
const owner = @import("stwo_riscv_frontend").recursion.detached_leaf_cohort_v2.For(@import("recursive_segment_v2_leaf_outer.zig"), @import("recursive_fri_outer.zig"));

pub const FORMAT_VERSION = owner.FORMAT_VERSION;
pub const GENERATED_FORMAT_VERSION = owner.GENERATED_FORMAT_VERSION;
pub const AUTHORITY_TRANSCRIPT_DOMAIN = owner.AUTHORITY_TRANSCRIPT_DOMAIN;
pub const COMPONENT_COUNT = owner.COMPONENT_COUNT;
pub const UNIVERSAL_COMPONENT_COUNT = owner.UNIVERSAL_COMPONENT_COUNT;
pub const CORE_FIRST_ROW = owner.CORE_FIRST_ROW;
pub const CORE_LAST_ROW = owner.CORE_LAST_ROW;
pub const CORE_ROW_COUNT = owner.CORE_ROW_COUNT;
pub const CORE_ROW_MASK = owner.CORE_ROW_MASK;
pub const ALL_COMPONENT_MASK = owner.ALL_COMPONENT_MASK;
pub const HOT_COHORT_TREE_OVERHEAD_HEAP_ALLOCATIONS = owner.HOT_COHORT_TREE_OVERHEAD_HEAP_ALLOCATIONS;
pub const HOT_TREE_HEAP_ALLOCATIONS = owner.HOT_TREE_HEAP_ALLOCATIONS;
pub const INTERACTION_GENERATION_IS_COLD = owner.INTERACTION_GENERATION_IS_COLD;
pub const FAILS_AT_WHOLE_TREE_BOUNDARY = owner.FAILS_AT_WHOLE_TREE_BOUNDARY;
pub const SHARED_ROW34_PROVIDER_INSTANCE_COUNT = owner.SHARED_ROW34_PROVIDER_INSTANCE_COUNT;
pub const RED_TUPLE_DOMAIN_MASK = owner.RED_TUPLE_DOMAIN_MASK;
pub const PUBLIC_WIRE_BOUNDARY_TRANSCRIPT_DOMAIN = owner.PUBLIC_WIRE_BOUNDARY_TRANSCRIPT_DOMAIN;
pub const AuthorityInputs = owner.AuthorityInputs;
pub const GeneratedInteractionsV2 = owner.GeneratedInteractionsV2;
pub const RecursiveTranscriptPrefixSourceV1 = owner.RecursiveTranscriptPrefixSourceV1;
pub const OuterAdmissionBoundariesV2 = owner.OuterAdmissionBoundariesV2;
pub const Components = owner.Components;
pub const Error = owner.Error;
pub const Cohort = owner.Cohort;
pub const independentlyRebuild = owner.independentlyRebuild;

test "SegmentV2 concrete cohort pins complete ownership and hot publication" {
    try owner.testMovedLeafCohort0();
}
