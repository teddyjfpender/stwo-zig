//! Versioned admission for one recursive-parent proof used as a binary child.
//!
//! Frozen leaf V1 deliberately remains untouched: its 193-query, 10/16-PoW,
//! fold-four shape and codec continue to live in `fixed_profile.zig` and
//! `fixed_wire.zig`.  This module owns a distinct outer-child profile matching
//! the native outer prover's current PCS configuration: three raw queries,
//! zero PCS PoW bits, zero interaction PoW bits, blowup one, terminal degree
//! zero, and one fold per FRI layer.
//!
//! A generic `VerifiedProofCapture` is not sufficient evidence that this
//! particular outer verifier produced it.  Admission therefore also requires
//! a verifier-published receipt containing the custom transcript checkpoint,
//! exact universal claims, stable program identities, and proof scope.  A
//! caller must pin the receipt-derived seal obtained from that successful
//! verifier call.  Deriving an "expected" seal from attacker-supplied values
//! at the consumer would erase this trust boundary.
//!
//! This file does not prove a parent STARK.  It supplies the fixed profile,
//! canonical wire, transcript-continuation audit, and pair-child identity that
//! such a proof must cross after independent native verification.
const shard_0 = @import("outer_parent_child_admission_contract.zig");
const shard_1 = @import("outer_parent_child_admission_binary_pair_candidate_v1.zig");
const shard_2 = @import("outer_parent_child_admission_admit.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const WIRE_MAGIC = shard_0.WIRE_MAGIC;
pub const OUTER_FORMAT_VERSION = shard_0.OUTER_FORMAT_VERSION;
pub const OUTER_TRANSCRIPT_DOMAIN = shard_0.OUTER_TRANSCRIPT_DOMAIN;
pub const QUERY_COUNT = shard_0.QUERY_COUNT;
pub const INTERACTION_POW_BITS = shard_0.INTERACTION_POW_BITS;
pub const PCS_POW_BITS = shard_0.PCS_POW_BITS;
pub const LOG_BLOWUP_FACTOR = shard_0.LOG_BLOWUP_FACTOR;
pub const LOG_LAST_LAYER_DEGREE_BOUND = shard_0.LOG_LAST_LAYER_DEGREE_BOUND;
pub const FOLD_STEP = shard_0.FOLD_STEP;
pub const TREE_COUNT = shard_0.TREE_COUNT;
pub const CLAIMED_SUM_COUNT = shard_0.CLAIMED_SUM_COUNT;
pub const MAX_FRI_ROUNDS = shard_0.MAX_FRI_ROUNDS;
pub const MAX_DOMAIN_LOG = shard_0.MAX_DOMAIN_LOG;
pub const PROFILE_ID_DOMAIN = shard_0.PROFILE_ID_DOMAIN;
pub const COLUMN_LAYOUT_ID_DOMAIN = shard_0.COLUMN_LAYOUT_ID_DOMAIN;
pub const SAMPLE_LAYOUT_ID_DOMAIN = shard_0.SAMPLE_LAYOUT_ID_DOMAIN;
pub const CAPTURE_ID_DOMAIN = shard_0.CAPTURE_ID_DOMAIN;
pub const CLAIMS_ID_DOMAIN = shard_0.CLAIMS_ID_DOMAIN;
pub const RECEIPT_ID_DOMAIN = shard_0.RECEIPT_ID_DOMAIN;
pub const OUTER_FRI_CONFIG = shard_0.OUTER_FRI_CONFIG;
pub const OUTER_PCS_CONFIG = shard_0.OUTER_PCS_CONFIG;
/// The present integration proves a verifier subsystem, not yet the complete
/// universal recursive statement.  The scope is explicit and seal-bound so
/// upgrading it cannot be a caller-side boolean reinterpretation.
pub const ProofScope = shard_0.ProofScope;
pub const RECURSIVE_PARENT_PRODUCTION = shard_0.RECURSIVE_PARENT_PRODUCTION;
pub const Error = shard_0.Error;
pub const FriRoundV1 = shard_0.FriRoundV1;
/// Fold-one schedule with enough capacity for every admitted M31 domain.  It
/// is intentionally separate from leaf V1's 16-slot fold-four schedule.
pub const FriScheduleV1 = shard_0.FriScheduleV1;
/// Exact Poseidon channel state immediately before the generic core verifier
/// draws composition randomness.  The native outer verifier must publish it
/// transactionally beside the successful proof capture.
pub const ChannelCheckpointV1 = shard_0.ChannelCheckpointV1;
/// Values that only the outer verifier is authorized to publish.  The
/// profile seal binds this complete record; it is not a self-authenticating
/// substitute for the verifier-to-consumer custody channel.
pub const VerifierReceiptV1 = shard_0.VerifierReceiptV1;
/// Runtime-exact geometry authenticated before selecting a comptime wire.
pub const ShapeV1 = shard_0.ShapeV1;
pub const VerifierSealV1 = shard_0.VerifierSealV1;
pub const DerivedAdmissionV1 = shard_0.DerivedAdmissionV1;
/// Canonical outer wire header. The payload deliberately reuses only the
/// pointer-free field layout of `FixedStarkProofWire`; leaf-V1 validation and
/// codecs are never invoked for this profile.
pub const FixedOuterProofWireV1 = shard_1.FixedOuterProofWireV1;
/// The exact identity surface consumed by the binary-pair custody layer.
/// Existing `pair_node.VerifiedChildV1` remains valid because this is a
/// versioned child profile within the same overarching recursion protocol.
pub const BinaryPairCandidateV1 = shard_1.BinaryPairCandidateV1;
/// Runtime-shaped result for artifact producers that learn the exact outer
/// proof geometry only after the independent verifier publishes its capture.
/// The byte count is repeated beside the candidate as a native-sized value so
/// callers can publish the exact encoded payload without narrowing casts.
pub const RuntimeAdmissionV1 = shard_1.RuntimeAdmissionV1;
pub const PairChildInputsV1 = shard_0.PairChildInputsV1;
/// Producer-side helper. The trusted outer verifier calls this only after its
/// independent verifier has succeeded and publishes the result together with
/// `capture`. Consumers compare against that published value; they must not
/// call this function to bless untrusted input themselves.
pub const deriveVerifierSeal = shard_2.deriveVerifierSeal;
/// Validates first, publishes the caller-owned wire once, and derives the
/// exact pair-child proof identity from its canonical encoding. `destination`
/// remains byte-for-byte unchanged on every error.
///
/// Integration seam for the future complete `recursive_pair_outer`:
///
/// 1. snapshot `pre_core_channel`, the sealed 36-claim vector, the distinct
///    verifier-input boundary, the two-term wire closure,
///    program/manifest/statement/VK identities, and proof scope inside the
///    successful native verifier transaction;
/// 2. publish `VerifierReceiptV1`, `ProofCapture`, and `VerifierSealV1`
///    together, never re-deriving the expected seal at ingress;
/// 3. call `admit` into a generated `FixedOuterProofWireV1` whose comptime
///    dimensions equal the returned profile dimensions;
/// 4. feed `transcriptWire()` plus this candidate's native-outer transcript
///    identity to the binary row source, not leaf V1's frozen transcript plan;
/// 5. permit `verifiedChild` only after the complete parent proof and its
///    independent verifier justify flipping `RECURSIVE_PARENT_PRODUCTION`.
pub const admit = shard_2.admit;
/// Runtime counterpart of `admit` for canonical artifact producers.
///
/// The outer verifier determines column and opening geometry at runtime, so a
/// producer cannot select `FixedOuterProofWireV1` until after successful
/// verification. This entry point validates the verifier receipt, capture,
/// and expected seal first, requires the exact derived byte count, rejects
/// every alias with trusted source storage, and only then writes the canonical
/// fixed-wire encoding. `destination` remains byte-for-byte unchanged on
/// every returned error.
pub const admitRuntime = shard_2.admitRuntime;
/// Validates the same verifier publication consumed by `admitRuntime` and
/// returns the one admissible destination length. Artifact producers use this
/// before allocation; the subsequent admission repeats validation so no
/// allocation result can become a detached authority token.
pub const runtimeCanonicalByteCount = shard_2.runtimeCanonicalByteCount;
/// Allocation-free identity of the exact canonical runtime wire that
/// `admitRuntime` would publish.  This is the verifier-custody comparison seam
/// for consumers that need the proof ID without first allocating or retaining
/// a second byte encoding.  Validation and seal comparison are repeated here;
/// caller-authored capture fields never become proof authority merely because
/// they can be streamed through the hash.
pub const proofIdRuntime = shard_2.proofIdRuntime;
pub const serializedByteCount = shard_0.serializedByteCount;
pub const serializedByteCountRuntime = shard_0.serializedByteCountRuntime;
/// Validates the only mask-point layouts emitted by the admitted outer AIRs.
///
/// Current-only columns are common to every component. Two-point LogUp masks
/// have two independently authoritative conventions: shared/legacy providers
/// request `[current, previous]`, while universal typed rows request
/// `[previous, current]` and index them in that order. The native verifier
/// authenticates the sampled values, and the capture/seal hashes retain the
/// exact order; accepting both conventions here therefore does not normalize
/// or bless consumer-controlled input.
pub const validateSamplePointColumnLayout = shard_1.validateSamplePointColumnLayout;
