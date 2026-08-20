//! Authenticated query-route preprocessing and allocation-free row-21 writer.
//!
//! Route geometry is verifier-owned. Construction derives every trace, DEEP,
//! FRI-fold, FRI-Merkle, and last-layer row once; hot witness generation only
//! applies the sealed bit weights directly into final column-major storage.
const shard_0 = @import("query_mapping_witness_preprocessed_source.zig");
const shard_1 = @import("query_mapping_witness_preprocessed.zig");

pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
pub const SEGMENT_VERIFIER_ID = shard_0.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = shard_0.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = shard_0.RIGHT_RECURSION_VERIFIER_ID;
pub const MAIN_COLUMN_COUNT = shard_0.MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = shard_0.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = shard_0.ProofKind;
pub const QueryWitness = shard_0.QueryWitness;
pub const BINDING_FORMAT_VERSION = shard_0.BINDING_FORMAT_VERSION;
pub const BINDING_DOMAIN = shard_0.BINDING_DOMAIN;
pub const BINDING_DIGEST_HEX = shard_0.BINDING_DIGEST_HEX;
pub const BINDING_DIGEST = shard_0.BINDING_DIGEST;
pub const REFERENCE_FORMAT_VERSION = shard_0.REFERENCE_FORMAT_VERSION;
pub const REFERENCE_DOMAIN = shard_0.REFERENCE_DOMAIN;
pub const Error = shard_0.Error;
pub const MainSource = shard_0.MainSource;
pub const PreprocessedSource = shard_0.PreprocessedSource;
pub const Slot = shard_0.Slot;
pub const Binding = shard_0.Binding;
pub const Executor = shard_1.Executor;
pub const QueryPositionKind = shard_0.QueryPositionKind;
pub const LaneProfile = shard_0.LaneProfile;
pub const Reference = shard_0.Reference;
pub const Row = shard_0.Row;
pub const MainRow = shard_1.MainRow;
pub const Preprocessed = shard_1.Preprocessed;
pub const mainRow = shard_1.mainRow;
pub const logicalRow = shard_1.logicalRow;
pub const shiftedWeights = shard_0.shiftedWeights;
pub const preprocessedTreeWeights = shard_0.preprocessedTreeWeights;
pub const applyWeights = shard_1.applyWeights;
