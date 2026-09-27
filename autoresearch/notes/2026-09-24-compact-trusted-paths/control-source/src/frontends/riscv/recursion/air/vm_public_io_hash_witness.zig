//! Shape-derived dual sponge schedule and prepared row-14 witness.
//!
//! Construction validates row 12's sealed shape and claim words, then hashes
//! its input and output projections directly without allocating either logical
//! stream or marker/padding buffers. Prepared rows and provider calls are
//! immutable snapshots; final SoA writers are allocation-free, alias-safe, and
//! failure-atomic.
const shard_0 = @import("vm_public_io_hash_witness_contract.zig");
const shard_1 = @import("vm_public_io_hash_witness_main_witness.zig");

pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
pub const MAIN_COLUMN_COUNT = shard_0.MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = shard_0.PREPROCESSED_COLUMN_COUNT;
pub const STATE_WIDTH = shard_0.STATE_WIDTH;
pub const RATE = shard_0.RATE;
pub const Shape = shard_0.Shape;
pub const ProofKind = shard_0.ProofKind;
pub const PoseidonCall = shard_0.PoseidonCall;
pub const PoseidonExecutor = shard_1.PoseidonExecutor;
pub const POSEIDON_MAIN_COLUMN_COUNT = shard_0.POSEIDON_MAIN_COLUMN_COUNT;
pub const BINDING_FORMAT_VERSION = shard_0.BINDING_FORMAT_VERSION;
pub const BINDING_DOMAIN = shard_0.BINDING_DOMAIN;
pub const BINDING_DIGEST_HEX = shard_0.BINDING_DIGEST_HEX;
pub const BINDING_DIGEST = shard_0.BINDING_DIGEST;
pub const PREPROCESSING_FORMAT_VERSION = shard_0.PREPROCESSING_FORMAT_VERSION;
pub const PREPROCESSING_DOMAIN = shard_0.PREPROCESSING_DOMAIN;
pub const WITNESS_FORMAT_VERSION = shard_0.WITNESS_FORMAT_VERSION;
pub const WITNESS_DOMAIN = shard_0.WITNESS_DOMAIN;
pub const Error = shard_0.Error;
pub const Binding = shard_0.Binding;
pub const Chunk = shard_0.Chunk;
pub const PreprocessedRow = shard_0.PreprocessedRow;
pub const Preprocessed = shard_0.Preprocessed;
pub const Source = shard_0.Source;
pub const MainRow = shard_0.MainRow;
pub const MainWitness = shard_1.MainWitness;
pub const Executor = shard_1.Executor;
pub const logicalInputs = shard_1.logicalInputs;
pub const inputWordCount = shard_0.inputWordCount;
pub const outputWordCount = shard_0.outputWordCount;
/// Inverts row 12's two public-I/O projection schedules without allocating an
/// intermediate stream. This is also a precise executable statement of the
/// cross-component lookup boundary.
pub const sourceClaimIndex = shard_0.sourceClaimIndex;
