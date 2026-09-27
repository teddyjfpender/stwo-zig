//! Internal segment leaf authority v2 authority shard; use segment_leaf_authority_v2.zig publicly.

pub const std = @import("std");
pub const stwo_core = @import("stwo_core");

pub const m31 = stwo_core.fields.m31;
pub const M31 = m31.M31;
pub const QM31 = stwo_core.fields.qm31.QM31;

pub const public_data_v2 = @import("../air/public_data_v2.zig");
pub const public_logup_v2 = @import("../air/public_logup_v2.zig");
pub const native_relations = @import("../air/relation_challenges.zig");
pub const statement_v1 = @import("../air/statement.zig");
pub const statement_v2 = @import("../air/statement_v2.zig");
pub const poseidon2_air = @import("../air/memory_commitment/poseidon2_air.zig");
pub const poseidon2 = @import("../air/memory_commitment/poseidon2.zig");
pub const relation = @import("../air/lang/relation.zig");
pub const channel = @import("poseidon2_channel.zig");
pub const protocol = @import("protocol.zig");
pub const segment_v2 = @import("segment_statement_v2.zig");
pub const temporal = @import("temporal_pair_node.zig");
pub const roster = @import("air/universal_roster.zig");

const contract = @import("segment_leaf_statement_contract_v2.zig");

pub const Error = public_data_v2.Error || public_logup_v2.Error ||
    statement_v2.Error || error{
    AliasedDestination,
    ArithmeticOverflow,
    AuthorityMismatch,
    ContextMismatch,
    DestinationLengthMismatch,
    InvalidManifest,
    InvalidPublication,
    InvalidTraceShape,
    NonCanonicalDigest,
    EmptyDigest,
    SourceMismatch,
    NativeVerifierCustodyMismatch,
    PoseidonCallCountMismatch,
    UnsupportedVersion,
};

pub const Digest = contract.Digest;
pub const FORMAT_VERSION = contract.FORMAT_VERSION;
pub const SCHEMA_VERSION = contract.SCHEMA_VERSION;
pub const MANIFEST_VERSION = contract.MANIFEST_VERSION;
pub const KNOWN_FLAGS = contract.KNOWN_FLAGS;
pub const WIRE_SCOPE = contract.WIRE_SCOPE;
pub const CONTEXT_SCOPE = contract.CONTEXT_SCOPE;
pub const SEGMENT_V2_VERIFIER_ID = contract.SEGMENT_V2_VERIFIER_ID;
pub const PUBLIC_LOGUP_V2_KIND = contract.PUBLIC_LOGUP_V2_KIND;
pub const PUBLICATION_BRIDGE_CIRCUIT_ID = contract.PUBLICATION_BRIDGE_CIRCUIT_ID;
pub const CONTEXT_TAG = contract.CONTEXT_TAG;
pub const LOGUP_TAG = contract.LOGUP_TAG;
pub const VERIFIED_NATIVE_LOGUP_TAG = contract.VERIFIED_NATIVE_LOGUP_TAG;
pub const FORMAT_ID_DOMAIN = contract.FORMAT_ID_DOMAIN;
pub const MANIFEST_ID_DOMAIN = contract.MANIFEST_ID_DOMAIN;
pub const VK_AUTHORITY_ID_DOMAIN = contract.VK_AUTHORITY_ID_DOMAIN;
pub const CONTEXT_ID_DOMAIN = contract.CONTEXT_ID_DOMAIN;
pub const SOURCE_ID_DOMAIN = contract.SOURCE_ID_DOMAIN;
pub const LOGUP_RELATION_ID_DOMAIN = contract.LOGUP_RELATION_ID_DOMAIN;
pub const LOGUP_PUBLICATION_ID_DOMAIN = contract.LOGUP_PUBLICATION_ID_DOMAIN;
pub const VERIFIED_NATIVE_LOGUP_ID_DOMAIN = contract.VERIFIED_NATIVE_LOGUP_ID_DOMAIN;
pub const AUTHORITY_HASH_PLAN_ID_DOMAIN = contract.AUTHORITY_HASH_PLAN_ID_DOMAIN;
pub const NATIVE_PUBLICATION_ID_DOMAIN = contract.NATIVE_PUBLICATION_ID_DOMAIN;
pub const STATEMENT_RELATION_DOMAIN = contract.STATEMENT_RELATION_DOMAIN;
pub const VERIFIER_INPUT_RELATION_DOMAIN = contract.VERIFIER_INPUT_RELATION_DOMAIN;
pub const STATEMENT_RELATION_ARITY = contract.STATEMENT_RELATION_ARITY;
pub const VERIFIER_INPUT_RELATION_ARITY = contract.VERIFIER_INPUT_RELATION_ARITY;
pub const FROZEN_V1_ROSTER_ROW = contract.FROZEN_V1_ROSTER_ROW;
pub const CONTEXT_WORD_COUNT = contract.CONTEXT_WORD_COUNT;
pub const CONTEXT_PREFIX_WORD_COUNT = contract.CONTEXT_PREFIX_WORD_COUNT;
pub const CONTEXT_SEGMENT_WIRE_ID_DIGEST_ORDINAL = contract.CONTEXT_SEGMENT_WIRE_ID_DIGEST_ORDINAL;
pub const CONTEXT_SEGMENT_WIRE_ID_START = contract.CONTEXT_SEGMENT_WIRE_ID_START;
pub const LOGUP_PUBLICATION_WORD_COUNT = contract.LOGUP_PUBLICATION_WORD_COUNT;
pub const PREPROCESSED_COLUMN_COUNT = contract.PREPROCESSED_COLUMN_COUNT;
pub const MAIN_COLUMN_COUNT = contract.MAIN_COLUMN_COUNT;
pub const INTERACTION_COLUMN_COUNT = contract.INTERACTION_COLUMN_COUNT;
pub const DIRECT_CONSTRAINT_COUNT = contract.DIRECT_CONSTRAINT_COUNT;
pub const INTERACTION_BATCH_COUNT = contract.INTERACTION_BATCH_COUNT;
pub const PROTOCOL_CONSTRAINT_DEGREE = contract.PROTOCOL_CONSTRAINT_DEGREE;
pub const HOT_HEAP_ALLOCATIONS = contract.HOT_HEAP_ALLOCATIONS;
pub const TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE = contract.TRACE_WRITES_FAIL_BEFORE_FIRST_WRITE;
pub const RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE = contract.RELATION_WRITES_FAIL_BEFORE_FIRST_WRITE;
pub const FROZEN_V1_ROW_COMPATIBLE = contract.FROZEN_V1_ROW_COMPATIBLE;
pub const REQUIRES_VERSIONED_OUTER_MANIFEST = contract.REQUIRES_VERSIONED_OUTER_MANIFEST;
pub const PRODUCTION_ACTIVATION = contract.PRODUCTION_ACTIVATION;
pub const AUTHORITY_HASH_SHARED_PROVIDER_REQUESTS_AVAILABLE = contract.AUTHORITY_HASH_SHARED_PROVIDER_REQUESTS_AVAILABLE;
pub const AUTHORITY_HASH_REQUEST_AIR_CLOSURE_AVAILABLE = contract.AUTHORITY_HASH_REQUEST_AIR_CLOSURE_AVAILABLE;
pub const AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT = contract.AUTHORITY_HASH_FIXED_PREIMAGE_WORD_COUNT;
pub const AUTHORITY_HASH_WORDS_PER_DESCRIPTOR = contract.AUTHORITY_HASH_WORDS_PER_DESCRIPTOR;
pub const Activation = contract.Activation;
pub const VerifierKeyAuthorityV2 = contract.VerifierKeyAuthorityV2;
pub const ManifestV2 = contract.ManifestV2;
pub const NativeTemporalContextV2 = contract.NativeTemporalContextV2;
pub const PerformanceV2 = contract.PerformanceV2;
pub const formatId = contract.formatId;
pub const nativeContext = contract.nativeContext;
pub const validateNativeContextSelf = contract.validateNativeContextSelf;
pub const verifierKeyAuthorityId = contract.verifierKeyAuthorityId;
pub const manifestId = contract.manifestId;
pub const emitContextIdentity = contract.emitContextIdentity;
pub const emitContextWords = contract.emitContextWords;
pub const contextId = contract.contextId;
pub const writeContextWordsAssumeValid = contract.writeContextWordsAssumeValid;
pub const ceilLog2 = contract.ceilLog2;
pub const requireDigest = contract.requireDigest;
pub const isZeroBytes = contract.isZeroBytes;
pub const WordWriter = contract.WordWriter;
pub const IdentityHasher = contract.IdentityHasher;
