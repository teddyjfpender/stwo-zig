//! V2 authority for one temporal `2 -> 1` recursive aggregation node.
//!
//! The two children describe adjacent execution spans.  Every non-padding
//! child is already a complete, independently verified proof with an exact
//! 36-row global-closure receipt.  The parent never repairs one child's
//! relation total with the other child's total.  This is deliberately a
//! distinct protocol from V1's same-execution core/provider split join.
//!
//! `VerifierAuthorityV2` is a native verifier-custody boundary: consumers must
//! construct its non-empty children from the successful child verifier's
//! publication, not from values decoded beside untrusted proof bytes.  The
//! canonical record is compared field-for-field with that authority before
//! any authenticated parent is returned.
const shard_0 = @import("temporal_pair_node_contract.zig");
const shard_1 = @import("temporal_pair_node_preparation_permutation_cost_v2.zig");
const permutation_audit = @import("temporal_pair_node_permutation_audit.zig");

pub const Digest = shard_0.Digest;
pub const ProofKind = shard_0.ProofKind;
pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const AUTHORITY_SCHEMA_VERSION = shard_0.AUTHORITY_SCHEMA_VERSION;
pub const NODE_ID_SCHEMA_VERSION = shard_0.NODE_ID_SCHEMA_VERSION;
pub const CHILD_COUNT = shard_0.CHILD_COUNT;
pub const COMPLETE_ROSTER_COUNT = shard_0.COMPLETE_ROSTER_COUNT;
pub const KNOWN_FLAGS = shard_0.KNOWN_FLAGS;
pub const FORMAT_ID_DOMAIN = shard_0.FORMAT_ID_DOMAIN;
pub const JOB_ID_DOMAIN = shard_0.JOB_ID_DOMAIN;
pub const CONTEXT_ID_DOMAIN = shard_0.CONTEXT_ID_DOMAIN;
pub const CHILD_ID_DOMAIN = shard_0.CHILD_ID_DOMAIN;
pub const CLOSURE_ID_DOMAIN = shard_0.CLOSURE_ID_DOMAIN;
pub const NODE_ID_DOMAIN = shard_0.NODE_ID_DOMAIN;
pub const RECORD_ID_DOMAIN = shard_0.RECORD_ID_DOMAIN;
/// Exact successful cold-path scalar Poseidon2-M31 ledger. A complete child
/// contributes one closure-receipt hash; an empty protocol leaf contributes
/// none. The historical constants describe the implementation immediately
/// before `PreparedDerivationV2` removed repeated derivation walks.
pub const PreparationPermutationCostV2 = shard_1.PreparationPermutationCostV2;
pub const VERIFIER_CUSTODY_REQUIRED = shard_1.VERIFIER_CUSTODY_REQUIRED;
pub const SPLIT_PROOF_JOIN_COMPATIBLE = shard_1.SPLIT_PROOF_JOIN_COMPATIBLE;
pub const CROSS_CHILD_RELATION_REPAIR = shard_1.CROSS_CHILD_RELATION_REPAIR;
pub const TEMPORAL_FOLD_AUTHORITY = shard_1.TEMPORAL_FOLD_AUTHORITY;
pub const PRODUCTION_ACTIVATION = shard_1.PRODUCTION_ACTIVATION;
pub const HOT_AUTHENTICATION_HEAP_ALLOCATIONS = shard_1.HOT_AUTHENTICATION_HEAP_ALLOCATIONS;
pub const HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS = shard_1.HOT_AUTHENTICATION_SCALAR_POSEIDON_PERMUTATIONS;
pub const test_support = permutation_audit.test_support;
pub const Error = shard_0.Error;
pub const ChildPosition = shard_0.ChildPosition;
pub const ProofScope = shard_0.ProofScope;
/// Verifier-published proof and closure custody for one temporal child.
/// Empty leaves carry no proof and must use the canonical all-zero proof
/// identity fields below.
pub const VerifiedChildV2 = shard_0.VerifiedChildV2;
/// Verifier-owned context for exactly one parent slot.  `job_id` and
/// `expected_parent_statement_id` are independently derived from the child
/// statements during validation; they are not caller-selected aliases.
pub const VerifierContextV2 = shard_0.VerifierContextV2;
pub const VerifierAuthorityV2 = shard_0.VerifierAuthorityV2;
/// Pointer-free canonical authority record.  It is intentionally larger than
/// a hash-only handoff: the parent AIR needs the exact two child statements,
/// while native authentication compares all verifier publications before the
/// record is accepted.
pub const PairRecordV2 = shard_1.PairRecordV2;
pub const RootVkPinV2 = shard_0.RootVkPinV2;
pub const AuthenticatedTemporalPairV2 = shard_0.AuthenticatedTemporalPairV2;
pub const RootAuthenticatedTemporalPairV2 = shard_0.RootAuthenticatedTemporalPairV2;
/// Cold, by-value admission of one immutable verifier authority and root pin.
/// All statement and identity hashes are paid exactly once here.  The hot
/// authentication path below performs only fixed-size equality checks and
/// publishes this already derived result; it executes no Poseidon permutation
/// and allocates no memory.
pub const PreparedRootContextV2 = shard_1.PreparedRootContextV2;
pub const recordFromAuthority = shard_1.recordFromAuthority;
pub const authenticateRoot = shard_1.authenticateRoot;
pub const prepareRootContext = shard_1.prepareRootContext;
/// Repeated hot authentication for an immutable prepared node.  Passing the
/// original values remains mandatory so mutation after cold admission cannot
/// silently reuse a stale capability.
pub const authenticateRootWithPreparedContext = shard_1.authenticateRootWithPreparedContext;
pub const formatId = shard_1.formatId;
pub const jobId = shard_1.jobId;
/// Canonical position of this span in its unique next-height parent. Position
/// is already authenticated by the statement slot and must never be accepted
/// as detached caller context.
pub const positionForNextParent = shard_1.positionForNextParent;
pub const closureReceiptId = shard_0.closureReceiptId;
