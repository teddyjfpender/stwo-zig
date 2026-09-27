//! Production arithmetic circuits for universal recursion rows 15--17.
//!
//! Two verifier-owned graphs close the segment-leaf public boundary:
//!
//! * the claim graph proves that the fixed VM claim and the transcript-bound
//!   span statement describe the same execution; and
//! * the public-LogUp graph evaluates every public boundary inverse, includes
//!   the local unretired-sentinel `program_access` term, adds every VM AIR
//!   claimed sum, and constrains the result to zero.
//!
//! Graph construction is value-independent.  Private bit, padding, edge-tag,
//! and carry witnesses are described by fixed input coordinates and derived
//! only when an instance is prepared.  Consequently the expensive graph,
//! exact node use counts, row-15/16 input bindings, and authority seals are
//! constructed once per verifier-owned profile; the proof path performs a
//! linear materialization and topological replay.
//!
//! Semantic basis: Stark-V commit
//! `59172a201bd01f2f4b699bc2f7d4442d8ee81597`, adapted deliberately to the
//! local four-domain `air/public_logup.zig` contract.  In particular, the
//! pinned three-domain circuit is extended with the canonical self-loop
//! program term.  Omitting it would leave the local `program_access` relation
//! unclosed under recursion.
const shard_0 = @import("vm_public_semantics_circuit_contract.zig");
const shard_1 = @import("vm_public_semantics_circuit_constrain_output_header_and_addresses.zig");
const shard_2 = @import("vm_public_semantics_circuit_claim_reference.zig");
const shard_3 = @import("vm_public_semantics_circuit_logup_reference.zig");

pub const Digest = shard_0.Digest;
pub const CLAIM_GRAPH_FORMAT_VERSION = shard_0.CLAIM_GRAPH_FORMAT_VERSION;
pub const LOGUP_GRAPH_FORMAT_VERSION = shard_0.LOGUP_GRAPH_FORMAT_VERSION;
pub const CLAIM_GRAPH_DOMAIN = shard_0.CLAIM_GRAPH_DOMAIN;
pub const LOGUP_GRAPH_DOMAIN = shard_0.LOGUP_GRAPH_DOMAIN;
pub const REQUIRED_LOGUP_CHALLENGES = shard_0.REQUIRED_LOGUP_CHALLENGES;
pub const FIXED_PUBLIC_TERM_COUNT = shard_0.FIXED_PUBLIC_TERM_COUNT;
pub const U16_BASE = shard_0.U16_BASE;
pub const U16_MAX = shard_0.U16_MAX;
pub const Error = shard_0.Error;
pub const ClaimWitness = shard_0.ClaimWitness;
pub const ClaimInputSource = shard_0.ClaimInputSource;
pub const ClaimInputBinding = shard_0.ClaimInputBinding;
/// Immutable graph and row-15 authority for one fixed claim capacity.
pub const ClaimReference = shard_2.ClaimReference;
pub const ClaimPrepared = shard_2.ClaimPrepared;
pub const LogupChallengeWords = shard_2.LogupChallengeWords;
pub const LogupWitness = shard_2.LogupWitness;
pub const LogupInputSource = shard_2.LogupInputSource;
pub const LogupInputBinding = shard_2.LogupInputBinding;
/// Immutable four-domain public-LogUp graph and row-16/17 authority metadata.
pub const LogupReference = shard_3.LogupReference;
pub const LogupPrepared = shard_2.LogupPrepared;
pub const Row16Prepared = shard_2.Row16Prepared;
pub const publicTermCount = shard_2.publicTermCount;
/// Native differential oracle used by integration tests and profile admission.
pub const expectedClaimedSum = shard_3.expectedClaimedSum;
