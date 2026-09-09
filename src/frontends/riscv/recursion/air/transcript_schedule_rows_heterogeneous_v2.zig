//! Exact heterogeneous schedule authorities for universal rows 8 and 9.

const generic = @import("three_lane_preprocessed_heterogeneous_v2.zig");
const relation_challenge = @import("relation_challenge_witness.zig");
const verifier_randomness = @import("verifier_randomness_witness.zig");

const RelationContext = struct {
    pub const Base = relation_challenge;
    pub const AUTHORITY_DOMAIN =
        "stwo-zig/typed-air/relation-challenge-heterogeneous/v2\x00";
    pub const count = Base.heterogeneousCount;
    pub const append = Base.appendHeterogeneousRows;
    pub const compare = Base.compareHeterogeneousRows;
    pub const logSize = Base.heterogeneousLogSize;
};

const RandomnessContext = struct {
    pub const Base = verifier_randomness;
    pub const AUTHORITY_DOMAIN =
        "stwo-zig/typed-air/verifier-randomness-heterogeneous/v2\x00";
    pub const count = Base.heterogeneousCount;
    pub const append = Base.appendHeterogeneousRows;
    pub const compare = Base.compareHeterogeneousRows;
    pub const logSize = Base.heterogeneousLogSize;
};

pub const RelationChallengePreprocessedV2 = generic.Type(RelationContext);
pub const VerifierRandomnessPreprocessedV2 = generic.Type(RandomnessContext);
