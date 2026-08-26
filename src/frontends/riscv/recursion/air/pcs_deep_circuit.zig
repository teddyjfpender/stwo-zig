//! Canonical STWO PCS-DEEP arithmetic circuit for recursive verification.
//!
//! This is the proof-independent arithmetic authority behind universal row 24.
//! It reproduces the native PCS quotient law exactly: transcript-derived OODS
//! geometry, bit-reversed lifting-domain queries, two-sample periodicity,
//! stable point batching, transcript-order random powers, conjugate-line
//! quotients, and equality with the values handed to FRI. Every proof value is
//! a tracked base-field input; rows 30--32 lower the remaining graph operations.
const shard_0 = @import("pcs_deep_circuit_circuit.zig");
const shard_1 = @import("pcs_deep_circuit_builder.zig");
const shard_2 = @import("pcs_deep_circuit_build.zig");

pub const SECURE_WORD_COUNT = shard_0.SECURE_WORD_COUNT;
pub const M31_BIT_COUNT = shard_0.M31_BIT_COUNT;
pub const MAX_DOMAIN_LOG = shard_0.MAX_DOMAIN_LOG;
pub const MAX_SAMPLE_COUNT_PER_COLUMN = shard_0.MAX_SAMPLE_COUNT_PER_COLUMN;
pub const PROFILE_FORMAT_VERSION = shard_0.PROFILE_FORMAT_VERSION;
pub const PROFILE_DOMAIN = shard_0.PROFILE_DOMAIN;
pub const CIRCUIT_FORMAT_VERSION = shard_0.CIRCUIT_FORMAT_VERSION;
pub const CIRCUIT_DOMAIN = shard_0.CIRCUIT_DOMAIN;
pub const InputSource = shard_0.InputSource;
pub const InputBinding = shard_0.InputBinding;
pub const Error = shard_0.Error;
pub const TreeProfile = shard_0.TreeProfile;
pub const SamplePointLayout = shard_0.SamplePointLayout;
/// Verifier-owned PCS geometry. `sample_layouts` is flattened tree/column
/// order. It preserves exact point order because the native PCS assigns DEEP
/// powers in that order and applies the two-sample periodicity term to the
/// second point. Counts alone are therefore insufficient protocol metadata.
pub const Profile = shard_0.Profile;
pub const Witness = shard_0.Witness;
pub const Circuit = shard_0.Circuit;
pub const Evaluation = shard_0.Evaluation;
/// Builds the proof-independent graph. The implementation is deliberately
/// flat and capacity-planned: graph construction is cold, while evaluation is
/// a single forward pass with no recursion or per-node allocation.
pub const build = shard_2.build;
pub const computeUseCountsInto = shard_2.computeUseCountsInto;
