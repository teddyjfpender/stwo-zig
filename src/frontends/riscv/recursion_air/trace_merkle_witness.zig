//! Authenticated trace-leaf schedule and allocation-free direct row-23 writer.
//!
//! Preprocessing seals the exact stable log-size ordering and exact control
//! sequence from verifier-owned plans. The hot path streams Poseidon2 states
//! directly into final SoA columns without allocation or intermediate rows.
const shard_0 = @import("trace_merkle_witness_contract.zig");
const shard_1 = @import("trace_merkle_witness_preprocessed.zig");

pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
pub const LEAF_TAG = shard_0.LEAF_TAG;
pub const TRACE_POSITION_KIND = shard_0.TRACE_POSITION_KIND;
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
pub const Error = shard_0.Error;
pub const MainSource = shard_0.MainSource;
pub const PreprocessedSource = shard_0.PreprocessedSource;
pub const Slot = shard_0.Slot;
pub const Binding = shard_0.Binding;
pub const Executor = shard_1.Executor;
pub const TreeProfile = shard_0.TreeProfile;
pub const LaneProfile = shard_0.LaneProfile;
pub const Reference = shard_0.Reference;
pub const Chunk = shard_0.Chunk;
pub const Row = shard_0.Row;
pub const OpeningSet = shard_0.OpeningSet;
pub const OpeningWitness = shard_0.OpeningWitness;
pub const MainRow = shard_0.MainRow;
pub const Preprocessed = shard_1.Preprocessed;
pub const logicalRow = shard_1.logicalRow;
