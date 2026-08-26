//! Schedule-derived witness and shared-provider bridge for transcript row 1.
//!
//! The cold boundary authenticates every verifier schedule, complete recording
//! transcript, and recorded Poseidon2 result before retaining one compact row
//! allocation. The final transcript SoA writer and the conversion into calls
//! for the existing typed Poseidon2 provider are allocation-free and reject
//! every fallible shape, seal, or alias condition before their first store.
const shard_0 = @import("transcript_air_witness_contract.zig");
const shard_1 = @import("transcript_air_witness_prepared_batch.zig");

pub const RATE = shard_0.RATE;
pub const WIDTH = shard_0.WIDTH;
pub const MAIN_COLUMN_COUNT = shard_0.MAIN_COLUMN_COUNT;
pub const MIN_LOG_SIZE = shard_0.MIN_LOG_SIZE;
pub const MAX_LOG_SIZE = shard_0.MAX_LOG_SIZE;
pub const SEGMENT_VERIFIER_ID = shard_0.SEGMENT_VERIFIER_ID;
pub const LEFT_RECURSION_VERIFIER_ID = shard_0.LEFT_RECURSION_VERIFIER_ID;
pub const RIGHT_RECURSION_VERIFIER_ID = shard_0.RIGHT_RECURSION_VERIFIER_ID;
pub const ProofKind = shard_0.ProofKind;
pub const TranscriptTrace = shard_0.TranscriptTrace;
pub const PoseidonCall = shard_0.PoseidonCall;
pub const HashFrame = shard_0.HashFrame;
pub const HashPurpose = shard_0.HashPurpose;
pub const DRAW_TAG = shard_0.DRAW_TAG;
pub const Lane = shard_0.Lane;
pub const BinaryLanes = shard_0.BinaryLanes;
pub const Source = shard_0.Source;
pub const ProviderCall = shard_0.ProviderCall;
pub const BINDING_FORMAT_VERSION = shard_0.BINDING_FORMAT_VERSION;
pub const BINDING_DOMAIN = shard_0.BINDING_DOMAIN;
pub const BINDING_DIGEST_HEX = shard_0.BINDING_DIGEST_HEX;
pub const BINDING_DIGEST = shard_0.BINDING_DIGEST;
pub const PREPARED_BATCH_FORMAT_VERSION = shard_0.PREPARED_BATCH_FORMAT_VERSION;
pub const PREPARED_BATCH_DOMAIN = shard_0.PREPARED_BATCH_DOMAIN;
pub const Slot = shard_0.Slot;
pub const Binding = shard_0.Binding;
pub const ConstructionError = shard_0.ConstructionError;
pub const Error = shard_0.Error;
pub const Executor = shard_1.Executor;
pub const Row = shard_0.Row;
/// One retained allocation snapshots every active call in proof order.
pub const PreparedBatch = shard_1.PreparedBatch;
pub const providerCall = shard_1.providerCall;
pub const logicalRow = shard_1.logicalRow;
