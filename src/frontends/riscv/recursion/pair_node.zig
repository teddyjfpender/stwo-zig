//! Authenticated shadow authority for the first canonical 2 -> 1 recursion node.
//!
//! This module fixes the protocol record that a future recursive verifier must
//! constrain. It authenticates two independently verified child identities,
//! their session-bound challenge context, relation closure, leaf count, and the
//! verification key of the parent aggregator. It does **not** verify a STARK,
//! build a recursive circuit, or produce a recursive proof.
//!
//! The parent verification-key identity is injected into both child publics and
//! carried by the authenticated node. `authenticateRoot` is the explicit seam
//! where the eventual recursion root pins that identity to the reviewed
//! aggregator VK, resolving self-reference without circular setup.
const shard_0 = @import("pair_node_contract.zig");
const shard_1 = @import("pair_node_child_evidence_v1.zig");
const shard_2 = @import("pair_node_authenticate_root_with_prepared_context.zig");

pub const Digest = shard_0.Digest;
pub const SecureFelt = shard_0.SecureFelt;
pub const ChildPosition = shard_0.ChildPosition;
pub const ChildRole = shard_0.ChildRole;
pub const PROTOCOL_SUBSTRATE_ONLY = shard_0.PROTOCOL_SUBSTRATE_ONLY;
pub const RECURSIVE_PROOF_VERIFICATION = shard_0.RECURSIVE_PROOF_VERIFICATION;
pub const RECURSIVE_PROOF_PRODUCTION = shard_0.RECURSIVE_PROOF_PRODUCTION;
pub const PRODUCTION_ACTIVATION = shard_0.PRODUCTION_ACTIVATION;
pub const MAGIC = shard_0.MAGIC;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const WIRE_SCHEMA_VERSION = shard_0.WIRE_SCHEMA_VERSION;
pub const AUTHORITY_CONTEXT_SCHEMA_VERSION = shard_0.AUTHORITY_CONTEXT_SCHEMA_VERSION;
pub const IDENTITY_FOLD_SCHEMA_VERSION = shard_0.IDENTITY_FOLD_SCHEMA_VERSION;
pub const NODE_ID_SCHEMA_VERSION = shard_0.NODE_ID_SCHEMA_VERSION;
pub const KNOWN_FLAGS = shard_0.KNOWN_FLAGS;
pub const CHILD_COUNT = shard_0.CHILD_COUNT;
pub const PRESENT = shard_0.PRESENT;
pub const MAX_KAPPA = shard_0.MAX_KAPPA;
pub const MAX_PAIR_INDEX = shard_0.MAX_PAIR_INDEX;
pub const FORMAT_ID_DOMAIN = shard_0.FORMAT_ID_DOMAIN;
pub const AUTHORITY_CONTEXT_DOMAIN = shard_0.AUTHORITY_CONTEXT_DOMAIN;
pub const STATEMENT_FOLD_DOMAIN = shard_0.STATEMENT_FOLD_DOMAIN;
pub const PROOF_FOLD_DOMAIN = shard_0.PROOF_FOLD_DOMAIN;
pub const TRANSCRIPT_FOLD_DOMAIN = shard_0.TRANSCRIPT_FOLD_DOMAIN;
pub const SUMMARY_FOLD_DOMAIN = shard_0.SUMMARY_FOLD_DOMAIN;
pub const NODE_ID_DOMAIN = shard_0.NODE_ID_DOMAIN;
pub const RECORD_ID_DOMAIN = shard_0.RECORD_ID_DOMAIN;
pub const VERIFICATION_KEY_ID_DOMAIN = shard_0.VERIFICATION_KEY_ID_DOMAIN;
pub const HEADER_ENCODED_LEN = shard_0.HEADER_ENCODED_LEN;
pub const CHILD_ENCODED_LEN = shard_0.CHILD_ENCODED_LEN;
pub const ENCODED_LEN = shard_0.ENCODED_LEN;
pub const FORMAT_ID_PREIMAGE_WORD_COUNT = shard_0.FORMAT_ID_PREIMAGE_WORD_COUNT;
pub const AUTHORITY_CONTEXT_PREIMAGE_WORD_COUNT = shard_0.AUTHORITY_CONTEXT_PREIMAGE_WORD_COUNT;
pub const ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT = shard_0.ORDINARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT;
pub const SUMMARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT = shard_0.SUMMARY_IDENTITY_FOLD_PREIMAGE_WORD_COUNT;
pub const NODE_ID_PREIMAGE_WORD_COUNT = shard_0.NODE_ID_PREIMAGE_WORD_COUNT;
pub const AuthenticationPermutationPhaseV1 = shard_0.AuthenticationPermutationPhaseV1;
pub const AuthenticationPermutationEncodingV1 = shard_0.AuthenticationPermutationEncodingV1;
pub const AuthenticationPermutationStageV1 = shard_0.AuthenticationPermutationStageV1;
/// One exact hash invocation in the successful V1 authentication call tree.
/// `unit_count` is a word count or byte count according to `encoding`.
pub const AuthenticationPermutationCallV1 = shard_0.AuthenticationPermutationCallV1;
/// Executable source-level instrumentation of every scalar Poseidon2-M31
/// permutation on the successful authentication path. Counts are derived from
/// the actual absorbed lengths, including the sponge end marker.
pub const AUTHENTICATION_PERMUTATION_CALL_TREE_V1 = shard_0.AUTHENTICATION_PERMUTATION_CALL_TREE_V1;
pub const authenticationPermutationTotal = shard_0.authenticationPermutationTotal;
/// Immutable RED baseline retained after the prepared-context optimization.
/// The 229 figure is the original conservative audit estimate; 55 and 94 are
/// exact pre-change call trees derived by the instrumentation above.
pub const AuthenticationPermutationBaselineV1 = shard_0.AuthenticationPermutationBaselineV1;
/// Checked scalar-Poseidon cost ledger for successful V1 root authentication.
/// Suite preparation is tree-cold, context preparation is authority-cold, and
/// the prepared-context form retains only transcript-authoritative outputs on
/// its hot path.
pub const AuthenticationPermutationCostV1 = shard_0.AuthenticationPermutationCostV1;
/// Exact heap-allocation ledger. All three capabilities are fixed-size values
/// and every operation accepts no allocator.
pub const AuthenticationAllocationCostV1 = shard_0.AuthenticationAllocationCostV1;
/// Poseidon2-M31 identity of the V1 wire envelope and pair-node domain suite.
/// Exact field order and identity preimages are additionally pinned by the
/// canonical codec and golden wire/fold/node vectors; this is intentionally
/// not presented as a generic reflection of the Zig struct ABI.
pub const FORMAT_ID_WORDS = shard_0.FORMAT_ID_WORDS;
pub const Error = shard_0.Error;
/// Verifier-owned context shared by both children. It intentionally carries no
/// claimed challenge-context digest: that digest is re-derived from
/// `session_id` before either child record is admitted.
pub const VerifierContextV1 = shard_0.VerifierContextV1;
/// Expected public output reconstructed by the caller from one successful
/// child-proof verification. This shadow module cannot enforce provenance;
/// copying a record's own claims here would provide no authentication. The
/// production seam must consume the actual child-verifier result type.
pub const VerifiedChildV1 = shard_0.VerifiedChildV1;
/// Authority reconstructed from an admitted context and exactly two
/// independently verified child proofs. `authenticatePair` compares every
/// encoded child-public field against these verifier-owned outputs.
pub const VerifierAuthorityV1 = shard_1.VerifierAuthorityV1;
/// One child public record. Statement/proof/transcript identities use the
/// canonical helpers in `protocol.zig`; `summary_id` is
/// `protocol.summaryId(canonical_summary_bytes)`. All four must be obtained
/// from the successful child verifier; this shadow layer never treats values
/// supplied beside unverified proof bytes as authority.
pub const ChildEvidenceV1 = shard_1.ChildEvidenceV1;
/// Fixed-capacity, pointer-free wire record for the first pair node.
pub const PairNodeRecordV1 = shard_1.PairNodeRecordV1;
pub const NodeIdentitiesV1 = shard_0.NodeIdentitiesV1;
/// Authenticated public result of the shadow fold. `proof_id` is an ordered
/// identity of the two already-verified child proofs; it is not a parent proof.
pub const AuthenticatedPairV1 = shard_1.AuthenticatedPairV1;
/// Distinct result type for the final root boundary. A caller cannot
/// accidentally treat an unpinned pair result as root-authorized.
pub const RootAuthenticatedPairV1 = shard_1.RootAuthenticatedPairV1;
/// Cold-path capability produced only after the immutable format, protocol,
/// relation, security profile, and Poseidon parameter seals agree. Reuse one
/// value across a tree to remove 39 scalar permutations from every node.
pub const PreparedProtocolSuiteV1 = shard_0.PreparedProtocolSuiteV1;
/// The expected aggregator VK is deliberately supplied by the recursion root.
/// Once the real circuit exists this value becomes a reviewed constant in the
/// root verifier, not another value accepted from the proof being checked.
pub const RootVkPinV1 = shard_1.RootVkPinV1;
/// Fixed-size, by-value snapshot of one successfully admitted root authority.
/// It is a native capability, never a wire format: callers retain the original
/// verifier-owned authority and root pin, and the hot API rejects either input
/// (or this snapshot) if it changes after preparation.
pub const PreparedRootContextV1 = shard_1.PreparedRootContextV1;
pub const prepareProtocolSuite = shard_0.prepareProtocolSuite;
/// Authority-cold preparation. The suite has already amortized immutable
/// format/protocol/parameter hashing; this pass performs the exact 17
/// context-dependent permutations once and snapshots all verifier authority.
pub const prepareRootContext = shard_1.prepareRootContext;
pub const authenticatePair = shard_1.authenticatePair;
pub const authenticatePairPrepared = shard_1.authenticatePairPrepared;
pub const authenticateRoot = shard_1.authenticateRoot;
pub const authenticateRootPrepared = shard_1.authenticateRootPrepared;
/// Hot root authentication for repeated use of one immutable verifier-owned
/// authority. This performs no suite/context hashes and no heap allocation.
/// The original authority and pin remain explicit so mutation after admission
/// is detected before the record is consumed.
pub const authenticateRootWithPreparedContext = shard_2.authenticateRootWithPreparedContext;
pub const encodeInto = shard_2.encodeInto;
pub const decodeInto = shard_2.decodeInto;
pub const recordId = shard_2.recordId;
/// Identity of the canonical aggregator verification-key encoding. The caller
/// chooses the codec by protocol version; empty encodings are never valid VKs.
pub const verificationKeyId = shard_2.verificationKeyId;
pub const formatId = shard_0.formatId;
