//! Fixed protocol tags shared by parameter admission and witness writers.
pub const QueryPositionKind = enum(u32) {
    trace_tree = 1,
    deep = 2,
    fri_fold = 3,
    fri_merkle = 4,
    last_layer = 5,
};

pub const vm_input = struct {
    pub const SEGMENT_VERIFIER_ID: u32 = 0;
    pub const CHALLENGE_SCOPE: u32 = 1;
    pub const COMPOSITION_RANDOMNESS_KIND: u32 = 1;
    pub const OODS_POINT_KIND: u32 = 2;
    pub const RECURSION_CLAIMED_SUM_KIND: u32 = 5;
    pub const SAMPLED_VALUE_KIND: u32 = 6;
    pub const TRANSCRIPT_CLAIMED_SUM_KIND: u32 = 5;
    pub const VM_CLAIMED_SUM_KIND: u32 = 12;
};
pub const trace_merkle = struct {
    pub const LEAF_TAG: u32 = 1;
    pub const TRACE_POSITION_KIND: u32 = 1;
};
pub const fri_leaf = struct {
    pub const LEAF_TAG: u32 = 1;
};
pub const fri_anchor = struct {
    pub const FRI_MERKLE_KIND: u32 = @intFromEnum(QueryPositionKind.fri_merkle);
};
pub const control = struct {
    pub const OFFSET_FIELD: u32 = 2;
    pub const POSITION_FIELD: u32 = 1;
};
pub const input = struct {
    pub const COEFFICIENT_KIND: u32 = 8;
    pub const FRI_ALPHA_KIND: u32 = 4;
    pub const FRI_FOLD_KIND: u32 = 3;
    pub const LAST_LAYER_KIND: u32 = 5;
    pub const OFFSET_FIELD: u32 = 2;
    pub const POSITION_FIELD: u32 = 1;
};
pub const pcs = struct {
    pub const DEEP_POSITION_KIND: u32 = 2;
    pub const DEEP_RANDOMNESS_KIND: u32 = 3;
    pub const OODS_POINT_KIND: u32 = 2;
    pub const SAMPLED_VALUE_KIND: u32 = 6;
};

pub const relation_challenge = struct {
    pub const AIR_EVALUATION_CHALLENGE_SCOPE: u32 = 1;
    pub const VM_PUBLIC_LOGUP_CHALLENGE_SCOPE: u32 = 0;
};
