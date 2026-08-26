//! Verifier-owned preprocessing and prepared witness for universal row 2.
//!
//! The cold boundary expands two admitted verifier schedules into the exact
//! Stark-V call table, validates complete recording-transcript traces, and
//! snapshots the 17 committed values.  Prepared writers operate directly on
//! caller-owned padded SoA storage with no allocation and no fallible work
//! after the shared preflight completes.
const shard_0 = @import("transcript_binding_witness_contract.zig");
const shard_1 = @import("transcript_binding_witness_preprocessed.zig");
const shard_2 = @import("transcript_binding_witness_executor.zig");

pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
pub const SEGMENT_VERIFIER_ID = shard_0.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = shard_0.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = shard_0.RIGHT_RECURSION_VERIFIER_ID;
pub const RATE = shard_0.RATE;
pub const WIDTH = shard_0.WIDTH;
pub const MAIN_COLUMN_COUNT = shard_0.MAIN_COLUMN_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = shard_0.PREPROCESSED_COLUMN_COUNT;
pub const ProofKind = shard_0.ProofKind;
pub const TranscriptTrace = shard_0.TranscriptTrace;
pub const PoseidonCall = shard_0.PoseidonCall;
pub const HashFrame = shard_0.HashFrame;
pub const HashPurpose = shard_0.HashPurpose;
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
pub const PreprocessedRow = shard_0.PreprocessedRow;
pub const Preprocessed = shard_1.Preprocessed;
pub const Lane = shard_1.Lane;
pub const BinaryLanes = shard_1.BinaryLanes;
pub const Source = shard_1.Source;
pub const MainRow = shard_1.MainRow;
pub const MainWitness = shard_1.MainWitness;
pub const Executor = shard_2.Executor;
pub const logicalInputs = shard_2.logicalInputs;
