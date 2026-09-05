//! Authenticated PCS-DEEP circuit schedule and allocation-free row-24 writer.
//!
//! The cold compiler derives source order and wire multiplicities from a
//! separately sealed arithmetic graph. The hot writer performs no allocation,
//! hashing, inversion, or dynamic dispatch and commits only after every shape,
//! authority, mode, and alias check succeeds.
const shard_0 = @import("pcs_deep_input_witness_reference.zig");
const shard_1 = @import("pcs_deep_input_witness_preprocessed.zig");

pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
pub const SECURE_WORD_COUNT = shard_0.SECURE_WORD_COUNT;
pub const M31_BIT_COUNT = shard_0.M31_BIT_COUNT;
pub const SAMPLED_VALUE_KIND = shard_0.SAMPLED_VALUE_KIND;
pub const OODS_POINT_KIND = shard_0.OODS_POINT_KIND;
pub const DEEP_RANDOMNESS_KIND = shard_0.DEEP_RANDOMNESS_KIND;
pub const DEEP_POSITION_KIND = shard_0.DEEP_POSITION_KIND;
pub const MAIN_COLUMN_COUNT = shard_0.MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = shard_0.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = shard_0.ProofKind;
pub const SEGMENT_VERIFIER_ID = shard_0.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = shard_0.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = shard_0.RIGHT_RECURSION_VERIFIER_ID;
pub const BINDING_FORMAT_VERSION = shard_0.BINDING_FORMAT_VERSION;
pub const BINDING_DOMAIN = shard_0.BINDING_DOMAIN;
pub const BINDING_DIGEST_HEX = shard_0.BINDING_DIGEST_HEX;
pub const BINDING_DIGEST = shard_0.BINDING_DIGEST;
pub const REFERENCE_FORMAT_VERSION = shard_0.REFERENCE_FORMAT_VERSION;
pub const REFERENCE_DOMAIN = shard_0.REFERENCE_DOMAIN;
pub const SCHEDULE_FORMAT_VERSION = shard_0.SCHEDULE_FORMAT_VERSION;
pub const SCHEDULE_DOMAIN = shard_0.SCHEDULE_DOMAIN;
pub const Error = shard_0.Error;
pub const MainSource = shard_0.MainSource;
pub const PreprocessedSource = shard_0.PreprocessedSource;
pub const Slot = shard_0.Slot;
pub const Binding = shard_0.Binding;
pub const Executor = shard_1.Executor;
pub const TreeProfile = shard_0.TreeProfile;
pub const LaneProfile = shard_0.LaneProfile;
pub const Source = shard_0.Source;
pub const InputBinding = shard_0.InputBinding;
pub const Lane = shard_0.Lane;
pub const Reference = shard_0.Reference;
pub const Row = shard_0.Row;
pub const LaneWitness = shard_0.LaneWitness;
pub const InputWitness = shard_0.InputWitness;
pub const MainRow = shard_1.MainRow;
pub const Preprocessed = shard_1.Preprocessed;
pub const logicalRow = shard_1.logicalRow;
/// Allocation-free assembly after the reference, schedule, and complete input
/// witness have passed their bulk checks. This prevents an O(rows * graph)
/// validation loop while interaction rows are prepared.
pub const logicalInputs = shard_1.logicalInputs;
pub const expectedSource = shard_0.expectedSource;
pub const profileMatchesTrace = shard_0.profileMatchesTrace;
pub const computeReferenceDigest = shard_1.computeReferenceDigest;
