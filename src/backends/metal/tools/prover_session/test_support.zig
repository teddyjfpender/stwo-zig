//! Shared fixtures for prover-session source-level invariant tests.

const state = @import("state.zig");
const ArtifactObjectEvidence = state.ArtifactObjectEvidence;
const ArtifactObjectsEvidence = state.ArtifactObjectsEvidence;

pub fn testArtifactObjects() ArtifactObjectsEvidence {
    const value = ArtifactObjectEvidence{
        .object_id = [_]u8{0xee} ** 32,
        .bytes = 1,
        .diagnostic_path = "/artifact",
    };
    return .{
        .adapted_input = value,
        .schedule = value,
        .witness_programs = value,
        .multiplicity_feeds = value,
        .relation_templates = value,
        .fixed_tables = value,
        .composition = value,
        .composition_program = value,
        .preprocessed_evaluations = value,
        .preprocessed_tree0_merkle = value,
        .preprocessed_coefficients = value,
        .transcript_reference = null,
        .quotient_reference = null,
    };
}
