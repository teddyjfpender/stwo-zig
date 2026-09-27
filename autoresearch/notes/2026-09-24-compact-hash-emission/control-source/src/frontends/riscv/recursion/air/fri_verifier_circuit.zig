//! Canonical fixed STWO FRI arithmetic circuit for recursive verification.
//!
//! This is the Zig authority for the graph consumed by universal row 29. It
//! records the exact circle-to-line fold, subsequent line folds, routed input
//! checks, and bit-reversed last-layer evaluation into the shared canonical
//! arithmetic DAG. Non-input operations are hash-consed just like Stark-V's
//! recorder; graph identity and input identity are independently sealed.
const shard_0 = @import("fri_verifier_circuit_circuit.zig");
const shard_1 = @import("fri_verifier_circuit_builder.zig");
const shard_2 = @import("fri_verifier_circuit_build.zig");

pub const SECURE_WORD_COUNT = shard_0.SECURE_WORD_COUNT;
pub const M31_BIT_COUNT = shard_0.M31_BIT_COUNT;
pub const MAX_DOMAIN_LOG = shard_0.MAX_DOMAIN_LOG;
/// A width-two schedule can consume one domain bit per layer, so the exact
/// proof-independent upper bound is the maximum supported domain log. The old
/// value 16 rejected valid recursive outer proofs with 20 folds.
pub const MAX_FRI_LAYERS = shard_0.MAX_FRI_LAYERS;
pub const MAX_FOLD_STEP = shard_0.MAX_FOLD_STEP;
pub const MAX_FOLD_WIDTH = shard_0.MAX_FOLD_WIDTH;
pub const PROFILE_FORMAT_VERSION = shard_0.PROFILE_FORMAT_VERSION;
pub const PROFILE_DOMAIN = shard_0.PROFILE_DOMAIN;
pub const CIRCUIT_FORMAT_VERSION = shard_0.CIRCUIT_FORMAT_VERSION;
pub const CIRCUIT_DOMAIN = shard_0.CIRCUIT_DOMAIN;
pub const Error = shard_0.Error;
pub const Profile = shard_0.Profile;
pub const InputSource = shard_0.InputSource;
pub const InputBinding = shard_0.InputBinding;
pub const Witness = shard_0.Witness;
pub const Circuit = shard_0.Circuit;
pub const Evaluation = shard_0.Evaluation;
/// Builds the proof-independent canonical FRI graph. All witness assignments
/// share this graph and its exact input-node coordinates.
pub const build = shard_2.build;
pub const expectedInputCount = shard_0.expectedInputCount;
pub const expectedSource = shard_0.expectedSource;
pub const computeUseCountsInto = shard_2.computeUseCountsInto;
