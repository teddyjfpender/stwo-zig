//! Schedule-owned preprocessing and prepared witness path for transcript row 4.
//!
//! The verifier plans expand into every padded non-digest frame word before a
//! proof is inspected. The source trace is then checked against that exact
//! frame/call schedule, including operation headers, draw markers, PoW nonce
//! limbs, and lane schema. A compact one-column snapshot is retained for the
//! hot writer; both final-tree writers are allocation-free and failure-atomic.
const shard_0 = @import("transcript_word_witness_binding.zig");
const shard_1 = @import("transcript_word_witness_preprocessed.zig");
const shard_2 = @import("transcript_word_witness_support.zig");

pub const MAIN_COLUMN_COUNT = shard_0.MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = shard_0.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = shard_0.ProofKind;
pub const TranscriptTrace = shard_0.TranscriptTrace;
pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
pub const SEGMENT_VERIFIER_ID = shard_0.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = shard_0.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = shard_0.RIGHT_RECURSION_VERIFIER_ID;
pub const BINDING_FORMAT_VERSION = shard_0.BINDING_FORMAT_VERSION;
pub const BINDING_DOMAIN = shard_0.BINDING_DOMAIN;
pub const BINDING_DIGEST_HEX = shard_0.BINDING_DIGEST_HEX;
pub const BINDING_DIGEST = shard_0.BINDING_DIGEST;
pub const PREPROCESSING_FORMAT_VERSION = shard_0.PREPROCESSING_FORMAT_VERSION;
pub const PREPROCESSING_DOMAIN = shard_0.PREPROCESSING_DOMAIN;
pub const PREPARED_BATCH_FORMAT_VERSION = shard_0.PREPARED_BATCH_FORMAT_VERSION;
pub const PREPARED_BATCH_DOMAIN = shard_0.PREPARED_BATCH_DOMAIN;
pub const MainSource = shard_0.MainSource;
pub const PreprocessedSource = shard_0.PreprocessedSource;
pub const Slot = shard_0.Slot;
pub const Binding = shard_0.Binding;
pub const ConstructionError = shard_0.ConstructionError;
pub const Error = shard_0.Error;
pub const Executor = shard_1.Executor;
pub const Row = shard_0.Row;
/// Exactly one retained allocation owns all three verifier-lane layouts.
pub const Preprocessed = shard_1.Preprocessed;
pub const BinarySource = shard_0.BinarySource;
pub const Source = shard_0.Source;
/// Compact immutable snapshot of the sole proof-supplied main value column.
pub const PreparedBatch = shard_1.PreparedBatch;
pub const mainRow = shard_1.mainRow;
pub const logicalRow = shard_1.logicalRow;
