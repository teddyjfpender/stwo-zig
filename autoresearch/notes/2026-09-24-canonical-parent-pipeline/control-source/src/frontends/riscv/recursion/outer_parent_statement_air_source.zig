//! Binary-parent statement AIR source and universal committed-trace adapter.
//!
//! This is the first proof-dependent parent-AIR seam after authenticated child
//! ingestion. It mirrors Stark-V's multiverifier rule: both child public
//! statements are bound to the exact native-verifier receipts and common
//! preprocessing root, folded in canonical left/right order, and compared to
//! the verifier-owned parent execution-statement ID before row 10, row 11, or
//! row 35 can be committed.
//!
//! Each native verifier publication carries the exact canonical 412-word
//! statement preimage beside its receipt. This source decodes only those
//! verifier-owned words, binds them to the authenticated child custody, and
//! never accepts a caller-supplied statement fallback. Production readiness
//! remains false until a parent STARK is independently verified.
const shard_0 = @import("outer_parent_statement_air_source_contract.zig");
const shard_1 = @import("outer_parent_statement_air_source_prepared.zig");
const shard_2 = @import("outer_parent_statement_air_source_fill_interactions_committed.zig");
const shard_3 = @import("outer_parent_statement_air_source_audit_interaction_domains.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const STATEMENT_PUBLICATION_FORMAT_VERSION = shard_0.STATEMENT_PUBLICATION_FORMAT_VERSION;
pub const STATEMENT_PUBLICATION_ID_DOMAIN = shard_0.STATEMENT_PUBLICATION_ID_DOMAIN;
pub const SOURCE_ID_DOMAIN = shard_0.SOURCE_ID_DOMAIN;
pub const CHILD_COUNT = shard_0.CHILD_COUNT;
pub const STATEMENT_CIRCUIT_ID = shard_0.STATEMENT_CIRCUIT_ID;
pub const STATEMENT_INPUT_LOG_SIZE = shard_0.STATEMENT_INPUT_LOG_SIZE;
pub const STATEMENT_SEMANTICS_LOG_SIZE = shard_0.STATEMENT_SEMANTICS_LOG_SIZE;
pub const RANGE_CHECK_LOG_SIZE = shard_0.RANGE_CHECK_LOG_SIZE;
pub const STATEMENT_INPUT_TRACE_SIZE = shard_0.STATEMENT_INPUT_TRACE_SIZE;
pub const STATEMENT_SEMANTICS_TRACE_SIZE = shard_0.STATEMENT_SEMANTICS_TRACE_SIZE;
pub const RANGE_CHECK_TRACE_SIZE = shard_0.RANGE_CHECK_TRACE_SIZE;
pub const STATEMENT_INPUT_PARAMETERS = shard_0.STATEMENT_INPUT_PARAMETERS;
pub const STATEMENT_SEMANTICS_PARAMETERS = shard_0.STATEMENT_SEMANTICS_PARAMETERS;
pub const ProductionStatus = shard_0.ProductionStatus;
pub const CURRENT_STATUS = shard_0.CURRENT_STATUS;
pub const NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS = shard_0.NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS;
pub const COMPLETE_PARENT_STARK_VERIFIED = shard_0.COMPLETE_PARENT_STARK_VERIFIED;
pub const HOT_TRACE_HEAP_ALLOCATIONS = shard_0.HOT_TRACE_HEAP_ALLOCATIONS;
pub const HOT_PAIR_AUTHENTICATIONS_PER_TRACE_FILL = shard_0.HOT_PAIR_AUTHENTICATIONS_PER_TRACE_FILL;
pub const COLD_HEAP_ALLOCATIONS_PER_PREPARED = shard_0.COLD_HEAP_ALLOCATIONS_PER_PREPARED;
/// A fresh end-to-end preparation authenticates the pair once, in the parent
/// source constructor. The statement publication and AIR construction remain
/// in the same transaction and consume that already authenticated local.
pub const FUSED_PAIR_AUTHENTICATIONS_PER_PREPARE = shard_0.FUSED_PAIR_AUTHENTICATIONS_PER_PREPARE;
/// The formerly composed parent -> publication -> AIR path authenticated the
/// same retained pair three more times. The fused entry point removes those
/// redundant walks; each walk is the measured prepared-root cost below.
pub const FUSED_PAIR_REAUTHENTICATIONS_AVOIDED = shard_0.FUSED_PAIR_REAUTHENTICATIONS_AVOIDED;
pub const FUSED_PAIR_PERMUTATIONS_AVOIDED = shard_0.FUSED_PAIR_PERMUTATIONS_AVOIDED;
pub const Error = shard_0.Error;
/// Canonical statement words published by one successful native verifier and
/// cryptographically bound to one exact child of one authenticated parent.
pub const VerifiedStatementPublicationV1 = shard_0.VerifiedStatementPublicationV1;
/// Validates the parent once and publishes both verifier-owned statements as
/// one failure-atomic transaction.
pub const publishVerifierStatementsInto = shard_1.publishVerifierStatementsInto;
pub const ParentAirPublicV1 = shard_0.ParentAirPublicV1;
pub const StatementInputAdapter = shard_1.StatementInputAdapter;
pub const StatementSemanticsAdapter = shard_1.StatementSemanticsAdapter;
pub const RangeCheckAdapter = shard_1.RangeCheckAdapter;
pub const PreprocessedColumns = shard_1.PreprocessedColumns;
pub const MainColumns = shard_1.MainColumns;
pub const InteractionColumns = shard_1.InteractionColumns;
pub const Claims = shard_1.Claims;
pub const RosterClaims = shard_1.RosterClaims;
pub const Components = shard_1.Components;
pub const DomainAudits = shard_1.DomainAudits;
pub const Workspace = shard_0.Workspace;
pub const Prepared = shard_1.Prepared;
pub const committedRow = shard_1.committedRow;
/// One ownership unit for the complete verified-child -> parent-statement AIR
/// preparation transaction. This is intentionally the only entry point that
/// may reuse a freshly authenticated parent without authenticating it again.
/// The bypass is not exposed as a caller-constructible token: child bundles,
/// authority, verifier-published statements, and the resulting AIR are joined
/// here.
pub const AuthenticatedPrepared = shard_1.AuthenticatedPrepared;
pub const loweringLane = shard_1.loweringLane;
pub const installLogSizes = shard_1.installLogSizes;
pub const statementInputComponent = shard_1.statementInputComponent;
pub const statementSemanticsComponent = shard_1.statementSemanticsComponent;
pub const components = shard_1.components;
pub const bindPreprocessedCommitted = shard_1.bindPreprocessedCommitted;
pub const bindMainCommitted = shard_1.bindMainCommitted;
pub const bindInteractionsCommitted = shard_1.bindInteractionsCommitted;
/// Writes binary row 10, row 11, and shared row 35 preprocessing in final
/// committed order. All fallible witness generation is staged in worker-owned
/// logical storage; caller columns remain untouched on every error.
pub const fillPreprocessedCommitted = shard_2.fillPreprocessedCommitted;
/// Writes the authenticated binary statements and exact row-11 circuit input
/// vector into Tree 1. Validation and staging complete before the first caller
/// cell is changed.
pub const fillMainCommitted = shard_2.fillMainCommitted;
/// Generates all three interaction contributions as one failure-atomic hot
/// transaction. A single Montgomery batch inversion covers both typed rows
/// and the 2^16 provider; no heap allocation occurs.
pub const fillInteractionsCommitted = shard_2.fillInteractionsCommitted;
/// Cold provenance audit over the exact logical rows used by the committed
/// interaction writer. In particular this makes the fourth row-10 PARENT emit
/// and row-11 PARENT consume independently observable in the tuple ledger.
pub const auditInteractionDomains = shard_3.auditInteractionDomains;
