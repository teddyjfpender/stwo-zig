//! Production outer-proof source for segment rows 10, 11, and 35.
//!
//! This module is deliberately an assembly boundary, not a second semantic
//! implementation. Row 10 borrows its statement only from
//! `segment_leaf_authority.Prepared`; row 11 borrows the exact input order and
//! values of the sealed statement-semantics circuit; and row 35 borrows the
//! complete two-owner range ledger from `segment_range_authority.Prepared`.
//! The typed AIR definitions, witness bindings, relation plans, native range
//! provider, and arithmetic-lowering graph are all authenticated here before
//! any committed cell is written.
//!
//! The hot interaction path performs one bulk QM31 inversion across all
//! 73,728 row/batch terms. It materializes no AoS relation-row buffers and
//! performs no allocation. All destinations remain untouched until every
//! denominator, source, shape, and closure check has succeeded.
const shard_0 = @import("segment_statement_outer_source_contract.zig");
const shard_1 = @import("segment_statement_outer_source_authority.zig");
const shard_2 = @import("segment_statement_outer_source_prepared.zig");
const shard_3 = @import("segment_statement_outer_source_fill_interactions_committed.zig");

pub const FORMAT_VERSION = shard_0.FORMAT_VERSION;
pub const STATEMENT_CIRCUIT_ID = shard_0.STATEMENT_CIRCUIT_ID;
pub const ROSTER_ROWS = shard_0.ROSTER_ROWS;
/// Machine-readable global closure ownership for every relation surface
/// touched by rows 10 and 11. `positive` denotes the emit/provider side of the
/// LogUp scalar and `negative` its consume/request side. A row claim aggregates
/// several such domains, so whole-row claims must never be compared edge by
/// edge; the all-36 driver closes the union of these edges.
pub const ClosureEdge = shard_0.ClosureEdge;
pub const GLOBAL_CLOSURE_EDGES = shard_0.GLOBAL_CLOSURE_EDGES;
pub const StatementInputAdapter = shard_0.StatementInputAdapter;
pub const StatementSemanticsAdapter = shard_0.StatementSemanticsAdapter;
pub const RangeCheckAdapter = shard_0.RangeCheckAdapter;
pub const STATEMENT_INPUT_LOG_SIZE = shard_0.STATEMENT_INPUT_LOG_SIZE;
pub const STATEMENT_SEMANTICS_LOG_SIZE = shard_0.STATEMENT_SEMANTICS_LOG_SIZE;
pub const RANGE_CHECK_LOG_SIZE = shard_0.RANGE_CHECK_LOG_SIZE;
pub const STATEMENT_INPUT_TRACE_SIZE = shard_0.STATEMENT_INPUT_TRACE_SIZE;
pub const STATEMENT_SEMANTICS_TRACE_SIZE = shard_0.STATEMENT_SEMANTICS_TRACE_SIZE;
pub const RANGE_CHECK_TRACE_SIZE = shard_0.RANGE_CHECK_TRACE_SIZE;
pub const STATEMENT_INPUT_PARAMETERS = shard_0.STATEMENT_INPUT_PARAMETERS;
pub const STATEMENT_SEMANTICS_PARAMETERS = shard_0.STATEMENT_SEMANTICS_PARAMETERS;
pub const LogSizes = shard_0.LogSizes;
/// The graph-only seal is distinct from the full row-11 circuit identity.
/// It pins the exact wire vocabulary consumed by rows 30--32 after the
/// allocation-free typed conversion performed below.
pub const LOWERING_GRAPH_DIGEST_HEX = shard_0.LOWERING_GRAPH_DIGEST_HEX;
pub const LOWERING_GRAPH_DIGEST = shard_0.LOWERING_GRAPH_DIGEST;
pub const Error = shard_0.Error;
/// Independent audit helper for regenerating the pinned graph-only receipt.
/// Production admission compares the same digest without retaining a second
/// circuit instance.
pub const computeLoweringGraphDigest = shard_0.computeLoweringGraphDigest;
/// Final, committed-order Tree-0 destinations. Row 35 includes the native
/// table framework's leading `is_first` column before its two tuple columns.
pub const PreprocessedColumns = shard_0.PreprocessedColumns;
/// Final, committed-order Tree-1 destinations.
pub const MainColumns = shard_0.MainColumns;
/// Final, committed-order Tree-2 destinations.
pub const InteractionColumns = shard_0.InteractionColumns;
/// Proof-visible claimed sums in exact roster order. This is the verifier-side
/// adapter input; it deliberately contains no prover-only ledger diagnostic.
pub const RosterClaims = shard_0.RosterClaims;
/// The proof-visible roster claims plus the independently signed request side
/// of the complete row-35 ledger. Only `verifyRangeClosure` is local: row 10's
/// verifier-input consume closes against row 5; its two statement-scope emits
/// close against row 11; row 11's wire emits close against rows 30--32; and row
/// 35 closes the combined range requests of rows 11 and 12. Consequently the
/// scalar sum of rows 10, 11, and 35 is intentionally not required to vanish.
pub const Claims = shard_0.Claims;
pub const DomainAudits = shard_0.DomainAudits;
/// Type-stable roster-order component bundle for the all-36 driver.
pub const Components = shard_0.Components;
/// Cold, proof-independent authority. Every owned object is built once and
/// then borrowed by proof workers at a stable address.
pub const Authority = shard_1.Authority;
pub const committedRow = shard_1.committedRow;
/// Binds a complete global Tree-0 slice to these three non-contiguous roster
/// placements. The returned arrays borrow the caller's columns; no allocation
/// or copy occurs.
pub const bindPreprocessedCommitted = shard_1.bindPreprocessedCommitted;
/// Allocation-free global Tree-1 view in the same roster placements.
pub const bindMainCommitted = shard_1.bindMainCommitted;
/// Allocation-free global Tree-2 view. Claims returned by the subsequent fill
/// bind at roster indices 10, 11, and 35 through `Claims.bindInto`.
pub const bindInteractionsCommitted = shard_1.bindInteractionsCommitted;
/// Worker-private reusable storage. The row-35 counter and both trace scratch
/// slabs are retained across proofs; every hot fill below is allocation-free.
pub const Workspace = shard_1.Workspace;
/// Proof-dependent immutable source. Its row-10 statement copy, row-11 dense
/// input vector, graph evaluation, and row-35 snapshot all originate in one
/// transaction from the admitted leaf.
pub const Prepared = shard_2.Prepared;
/// Fills all three Tree-0 contributions directly in final committed order.
/// The temporary logical slab is reused between rows 10 and 11.
pub const fillPreprocessedCommitted = shard_2.fillPreprocessedCommitted;
/// Fills all three Tree-1 contributions directly in final committed order.
pub const fillMainCommitted = shard_2.fillMainCommitted;
/// Fills rows 10, 11, and 35 as one fail-atomic interaction transaction.
/// One Montgomery batch inversion covers both two-batch typed components and
/// the full native 2^16 provider. Returned claims are in roster order.
pub const fillInteractionsCommitted = shard_3.fillInteractionsCommitted;
/// Cold relation-domain provenance for rows 10, 11, and 35. The two typed
/// rows replay their authenticated plans over the same logical witnesses as
/// the committed interaction fill. Row 35 has exactly one native provider
/// domain, so its decomposition is direct and still checked against the
/// proof-visible claim.
pub const auditInteractionDomains = shard_3.auditInteractionDomains;
pub const TOTAL_INTERACTION_TERMS = shard_1.TOTAL_INTERACTION_TERMS;
