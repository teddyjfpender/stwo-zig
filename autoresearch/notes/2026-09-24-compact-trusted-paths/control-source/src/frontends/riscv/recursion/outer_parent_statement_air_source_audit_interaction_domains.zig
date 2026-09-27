//! Internal outer parent statement air source authority shard; use outer_parent_statement_air_source.zig publicly.

const dependency_0 = @import("outer_parent_statement_air_source_contract.zig");
const dependency_1 = @import("outer_parent_statement_air_source_prepared.zig");
const dependency_2 = @import("outer_parent_statement_air_source_fill_interactions_committed.zig");

const CHILD_COUNT = dependency_0.CHILD_COUNT;
const Claims = dependency_1.Claims;
const DomainAudits = dependency_1.DomainAudits;
const QM31 = dependency_0.QM31;
const RANGE_CHECK_LOG_SIZE = dependency_0.RANGE_CHECK_LOG_SIZE;
const RANGE_CHECK_TRACE_SIZE = dependency_0.RANGE_CHECK_TRACE_SIZE;
const STATEMENT_CIRCUIT_ID = dependency_0.STATEMENT_CIRCUIT_ID;
const STATEMENT_INPUT_LOG_SIZE = dependency_0.STATEMENT_INPUT_LOG_SIZE;
const STATEMENT_SEMANTICS_LOG_SIZE = dependency_0.STATEMENT_SEMANTICS_LOG_SIZE;
const Workspace = dependency_0.Workspace;
const binaryStatementWitness = dependency_2.binaryStatementWitness;
const fixed_wire = dependency_0.fixed_wire;
const relation = dependency_0.relation;
const relation_interaction = dependency_0.relation_interaction;
const roster = dependency_0.roster;
const row10_relation = dependency_0.row10_relation;
const row10_witness = dependency_0.row10_witness;
const row11_relation = dependency_0.row11_relation;
const row11_witness = dependency_0.row11_witness;
const segment_source = dependency_0.segment_source;
const shared_provider = dependency_0.shared_provider;
const universal = dependency_0.universal;

/// Cold provenance audit over the exact logical rows used by the committed
/// interaction writer. In particular this makes the fourth row-10 PARENT emit
/// and row-11 PARENT consume independently observable in the tuple ledger.
pub fn auditInteractionDomains(
    comptime dimensions: fixed_wire.Dimensions,
    authority: *const segment_source.Authority,
    workspace: *Workspace,
    prepared: anytype,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
    claims: Claims,
    tuple_ledger: ?*relation_interaction.TupleLedger,
) !DomainAudits {
    dimensions.validate();
    try prepared.validateHot(authority, workspace);
    try relations.validate();
    try provider_relations.validateAgainst(relations);
    try claims.verifyRangeClosure();

    const statement_input_rows = try workspace.allocator.alloc(
        row10_relation.Row,
        authority.statement_input_preprocessing.rows.len,
    );
    defer workspace.allocator.free(statement_input_rows);
    const witness = binaryStatementWitness(prepared);
    for (
        statement_input_rows,
        authority.statement_input_preprocessing.rows,
    ) |*destination, source| destination.* = try row10_witness.logicalRow(
        source,
        witness,
    );

    const statement_semantics_rows = try workspace.allocator.alloc(
        row11_relation.Row,
        authority.statement_semantics_preprocessing.rows.len,
    );
    defer workspace.allocator.free(statement_semantics_rows);
    for (
        statement_semantics_rows,
        authority.statement_semantics_preprocessing.rows,
        prepared.statement_values,
    ) |*destination, source, value| destination.* =
        try row11_witness.logicalRow(source, value, .binary_node);

    if (tuple_ledger) |ledger| {
        try authority.statement_input_relation.appendPreparedTupleContributions(
            ledger,
            @intCast(@intFromEnum(roster.Component.statement_input)),
            statement_input_rows,
            relation_interaction.allDomainMask(),
        );
        try authority.statement_semantics_relation.appendPreparedTupleContributions(
            ledger,
            @intCast(@intFromEnum(roster.Component.statement_semantics_input)),
            statement_semantics_rows,
            relation_interaction.allDomainMask(),
        );
    }

    var range_values = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT;
    range_values[@intFromEnum(relation.Domain.range_check_8_8)] =
        claims.range_check;
    return .{
        .statement_input = try authority.statement_input_relation.auditPreparedDomainSums(
            workspace.allocator,
            statement_input_rows,
            relations,
            claims.statement_input,
        ),
        .statement_semantics = try authority.statement_semantics_relation.auditPreparedDomainSums(
            workspace.allocator,
            statement_semantics_rows,
            relations,
            claims.statement_semantics,
        ),
        .range_check = .{
            .values = range_values,
            .total = claims.range_check,
            .logical_rows = RANGE_CHECK_TRACE_SIZE,
            .event_terms = RANGE_CHECK_TRACE_SIZE,
        },
    };
}

comptime {
    if (CHILD_COUNT != 2 or STATEMENT_CIRCUIT_ID != 11 or
        STATEMENT_INPUT_LOG_SIZE != 11 or
        STATEMENT_SEMANTICS_LOG_SIZE != 11 or RANGE_CHECK_LOG_SIZE != 16)
    {
        @compileError("outer parent statement AIR geometry drifted");
    }
}
