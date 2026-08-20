//! Schedule-driven Poseidon2 transcript execution for recursive verification.
//!
//! The verifier plan is the sole ordering authority. Every transcript-bearing
//! step absorbs one fixed eight-word header and its typed payload, then records
//! the exact Poseidon2 calls consumed by universal rows 1--9. The fixed proof
//! wire supplies values only; it cannot select an operation, length, or index.
const shard_0 = @import("transcript_program_contract.zig");
const shard_1 = @import("transcript_program_execute_fixed_transcript.zig");

pub const RATE = shard_0.RATE;
pub const WIDTH = shard_0.WIDTH;
pub const STATEMENT_WORD_COUNT = shard_0.STATEMENT_WORD_COUNT;
/// The first transcript operation binds both the cryptographic suite and the
/// verifier-owned proof shape.  Keeping the two digests in one frame prevents
/// two admitted geometries from sharing a Fiat--Shamir prefix.
pub const PROTOCOL_BINDING_WORD_COUNT = shard_0.PROTOCOL_BINDING_WORD_COUNT;
pub const HEADER_WORD_COUNT = shard_0.HEADER_WORD_COUNT;
pub const DRAW_WORD_COUNT = shard_0.DRAW_WORD_COUNT;
pub const TRANSCRIPT_OPERATION_TAG = shard_0.TRANSCRIPT_OPERATION_TAG;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const IDENTITY_DOMAIN = shard_0.IDENTITY_DOMAIN;
pub const TranscriptTrace = shard_0.TranscriptTrace;
pub const PoseidonCall = shard_0.PoseidonCall;
pub const HashFrame = shard_0.HashFrame;
pub const HashPurpose = shard_0.HashPurpose;
pub const Check = shard_0.Check;
pub const StatementWords = shard_0.StatementWords;
pub const Draw = shard_0.Draw;
pub const Error = shard_0.Error;
pub const Effect = shard_0.Effect;
/// Schema-specific material absorbed at `absorb_public_claim`.
pub const PublicClaim = shard_0.PublicClaim;
/// Exact frame/call coordinates and optional semantic draw produced by one
/// transcript-bearing verifier step. PoW's temporary draw is intentionally
/// represented by `pow_checks`, not as verifier randomness.
pub const Operation = shard_0.Operation;
/// One compact owner for all trace arrays and every frame-word slice.
/// Construction performs exactly five retained allocations regardless of the
/// number of transcript operations.
pub const Execution = shard_0.Execution;
/// Executes the complete fixed transcript and publishes no partial owner on
/// failure. The proof wire should already have passed its shape-specific
/// canonicity gate; this function nevertheless rechecks every consumed word.
pub const executeFixedTranscript = shard_1.executeFixedTranscript;
pub const effect = shard_0.effect;
/// Applies one verifier-scheduled transcript operation without recording an
/// AIR trace. This is the allocation-free production seam used by a native
/// prover/verifier channel; `executeFixedTranscript` records the same operation
/// into rows 1--9 and differential tests require the two paths to agree.
pub const applyOperation = shard_1.applyOperation;
pub const applyOperationForPlan = shard_1.applyOperationForPlan;
/// Allocation-free secure-field payload absorption for the three transcript
/// operations whose wire representation is a flat sequence of QM31 limbs.
/// The header and limbs share one sponge frame; there is no staging buffer and
/// therefore no payload-size-dependent stack use.
pub const applySecureFeltOperationForPlan = shard_1.applySecureFeltOperationForPlan;
/// Applies a zero-payload draw operation and returns the exact two-QM31 draw
/// block used by relation and verifier-randomness consumers.
pub const applyDrawOperation = shard_1.applyDrawOperation;
pub const powPayload = shard_1.powPayload;
/// Checks the schedule-framed PoW candidate on a clone. The nonce operation
/// itself is persistent only when the caller later invokes
/// `absorbPowOperation`, matching STWO's verify-then-mix channel contract.
pub const verifyPowOperation = shard_1.verifyPowOperation;
pub const absorbPowOperation = shard_1.absorbPowOperation;
pub const grindPowOperation = shard_1.grindPowOperation;
pub const payloadWordCount = shard_0.payloadWordCount;
