//! Shape-derived sponge schedule and prepared row-13 witness.
//!
//! Construction validates row 12's sealed shape and claim words, then hashes
//! directly from that source without allocating a marker/padding stream. The
//! prepared row and Poseidon-call arrays are immutable snapshots; both final
//! SoA writers are allocation-free, alias-safe, and failure-atomic.
const shard_0 = @import("vm_public_claim_hash_witness_contract.zig");
const shard_1 = @import("vm_public_claim_hash_witness_main_witness.zig");

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
/// Low-level, shape-independent schedule helpers used by append-only
/// recursive hash programs with a distinct domain/scope.  The frozen VM-claim
/// constructors remain unchanged; callers must supply and validate their own
/// initial domain state and typed parameter row.
pub const expectedRow = shard_0.expectedRow;
pub const materialize = shard_0.materialize;
pub const callFor = shard_0.callFor;
pub const traceLogSize = shard_0.traceLogSize;
