//! Schedule-owned preprocessing and prepared witness path for payload row 5.
//!
//! The cold path assigns every payload slot from the verifier schedule, fixes
//! protocol/PCS constants, validates complete transcript traces, and retains
//! one compact value snapshot. Both final-tree writers are allocation-free,
//! alias-safe, and failure-atomic.
const shard_0 = @import("transcript_payload_witness_binding.zig");
const shard_1 = @import("transcript_payload_witness_source.zig");
const shard_2 = @import("transcript_payload_witness_preprocessed.zig");

pub const MAIN_COLUMN_COUNT = shard_0.MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = shard_0.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = shard_0.ProofKind;
pub const TranscriptTrace = shard_0.TranscriptTrace;
pub const VerifierInputKind = shard_0.VerifierInputKind;
pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
pub const SEGMENT_VERIFIER_ID = shard_0.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = shard_0.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = shard_0.RIGHT_RECURSION_VERIFIER_ID;
pub const PAYLOAD_WORD_OFFSET = shard_0.PAYLOAD_WORD_OFFSET;
/// Re-exported for existing row-5 callers. The verifier schedule owns these
/// protocol words so the native transcript program cannot drift from the AIR.
pub const PCS_PARAMETER_WORDS = shard_0.PCS_PARAMETER_WORDS;
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
pub const Executor = shard_2.Executor;
pub const Row = shard_0.Row;
/// Exactly one retained allocation owns every payload slot in all three lanes.
pub const Preprocessed = shard_2.Preprocessed;
pub const BinarySource = shard_1.BinarySource;
pub const Source = shard_1.Source;
/// One retained allocation snapshots every main-column value, including fixed
/// constants, so the hot writer never dereferences transcript structures.
pub const PreparedBatch = shard_2.PreparedBatch;
pub const mainRow = shard_2.mainRow;
pub const logicalRow = shard_2.logicalRow;
