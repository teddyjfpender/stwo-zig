//! Internal segment statement outer source authority shard; use segment_statement_outer_source.zig publicly.

const dependency_0 = @import("segment_statement_outer_source_contract.zig");
const dependency_1 = @import("segment_statement_outer_source_authority.zig");
const dependency_2 = @import("segment_statement_outer_source_prepared.zig");

const AddressRange = dependency_2.AddressRange;
const Authority = dependency_1.Authority;
const Claims = dependency_0.Claims;
const DomainAudits = dependency_0.DomainAudits;
const Error = dependency_0.Error;
const InteractionColumns = dependency_0.InteractionColumns;
const M31 = dependency_0.M31;
const Prepared = dependency_2.Prepared;
const QM31 = dependency_0.QM31;
const RANGE_CHECK_LOG_SIZE = dependency_0.RANGE_CHECK_LOG_SIZE;
const RANGE_CHECK_TRACE_SIZE = dependency_0.RANGE_CHECK_TRACE_SIZE;
const ROW10_TERM_COUNT = dependency_1.ROW10_TERM_COUNT;
const ROW11_TERM_COUNT = dependency_1.ROW11_TERM_COUNT;
const STATEMENT_INPUT_LOG_SIZE = dependency_0.STATEMENT_INPUT_LOG_SIZE;
const STATEMENT_INPUT_TRACE_SIZE = dependency_0.STATEMENT_INPUT_TRACE_SIZE;
const STATEMENT_SEMANTICS_LOG_SIZE = dependency_0.STATEMENT_SEMANTICS_LOG_SIZE;
const STATEMENT_SEMANTICS_TRACE_SIZE = dependency_0.STATEMENT_SEMANTICS_TRACE_SIZE;
const TOTAL_INTERACTION_TERMS = dependency_1.TOTAL_INTERACTION_TERMS;
const Workspace = dependency_1.Workspace;
const fields = dependency_0.fields;
const committedRow = dependency_1.committedRow;
const fillRangeTerms = dependency_2.fillRangeTerms;
const fillStatementInputTerms = dependency_2.fillStatementInputTerms;
const fillStatementSemanticsTerms = dependency_2.fillStatementSemanticsTerms;
const leaf_owner = dependency_0.leaf_owner;
const lookup_schema = dependency_0.lookup_schema;
const objectRange = dependency_2.objectRange;
const preflightColumnSet = dependency_2.preflightColumnSet;
const prepareFrameworkResult = dependency_2.prepareFrameworkResult;
const public_data_mod = dependency_0.public_data_mod;
const range_bridge = dependency_0.range_bridge;
const relation = dependency_0.relation;
const relation_interaction = dependency_0.relation_interaction;
const roster = dependency_0.roster;
const row10_air = dependency_0.row10_air;
const row10_relation = dependency_0.row10_relation;
const row10_witness = dependency_0.row10_witness;
const row11_air = dependency_0.row11_air;
const row11_relation = dependency_0.row11_relation;
const row11_witness = dependency_0.row11_witness;
const shared_provider = dependency_0.shared_provider;
const sliceRange = dependency_2.sliceRange;
const statement_circuit = dependency_0.statement_circuit;
const std = dependency_0.std;
const universal = dependency_0.universal;

/// Fills rows 10, 11, and 35 as one fail-atomic interaction transaction.
/// One Montgomery batch inversion covers both two-batch typed components and
/// the full native 2^16 provider. Returned claims are in roster order.
pub fn fillInteractionsCommitted(
    authority: *const Authority,
    workspace: *Workspace,
    prepared: *const Prepared,
    leaf_preprocessing: *const leaf_owner.Preprocessing,
    data: *const public_data_mod.PublicData,
    leaf: *const leaf_owner.Prepared,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
    columns: *InteractionColumns,
) !Claims {
    try prepared.validateAgainst(
        authority,
        workspace,
        leaf_preprocessing,
        data,
        leaf,
    );
    try relations.validate();
    try provider_relations.validateAgainst(relations);

    var destination_ranges: [TOTAL_INTERACTION_COLUMNS]AddressRange = undefined;
    var destination_count: usize = 0;
    try preflightColumnSet(
        &columns.statement_input,
        STATEMENT_INPUT_TRACE_SIZE,
        &destination_ranges,
        &destination_count,
        workspace,
    );
    try preflightColumnSet(
        &columns.statement_semantics,
        STATEMENT_SEMANTICS_TRACE_SIZE,
        &destination_ranges,
        &destination_count,
        workspace,
    );
    try preflightColumnSet(
        &columns.range_check,
        RANGE_CHECK_TRACE_SIZE,
        &destination_ranges,
        &destination_count,
        workspace,
    );
    try rejectInteractionSourceAliases(
        destination_ranges[0..destination_count],
        authority,
        prepared,
        relations,
        provider_relations,
    );

    const numerators = workspace.secure_storage[0..TOTAL_INTERACTION_TERMS];
    const denominators = workspace.secure_storage[TOTAL_INTERACTION_TERMS .. 2 * TOTAL_INTERACTION_TERMS];
    const inverses = workspace.secure_storage[2 * TOTAL_INTERACTION_TERMS .. 3 * TOTAL_INTERACTION_TERMS];

    try fillStatementInputTerms(
        authority,
        prepared,
        relations,
        numerators[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
        denominators[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
    );
    try fillStatementSemanticsTerms(
        authority,
        prepared,
        relations,
        numerators[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
        denominators[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
    );
    fillRangeTerms(
        prepared,
        provider_relations,
        numerators[RANGE_TERM_OFFSET..],
        denominators[RANGE_TERM_OFFSET..],
    );

    fields.batchInverseInPlace(QM31, denominators, inverses) catch
        return error.ZeroDenominator;

    const statement_input_claim = try prepareFrameworkResult(
        row10_relation.Runtime,
        STATEMENT_INPUT_TRACE_SIZE,
        numerators[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
        denominators[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
        inverses[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
    );
    const statement_semantics_claim = try prepareFrameworkResult(
        row11_relation.Runtime,
        STATEMENT_SEMANTICS_TRACE_SIZE,
        numerators[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
        denominators[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
        inverses[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
    );
    const range_claims = prepareRangeResult(
        prepared,
        numerators[RANGE_TERM_OFFSET..],
        denominators[RANGE_TERM_OFFSET..],
        inverses[RANGE_TERM_OFFSET..],
    );

    const result = Claims{
        .statement_input = statement_input_claim,
        .statement_semantics = statement_semantics_claim,
        .range_check = range_claims.provider,
        .range_requests = range_claims.requests,
    };
    // This is the final fallible operation in the transaction.  Caller-owned
    // interaction columns are still untouched if the independently derived
    // request/provider sides fail to close.
    try result.verifyRangeClosure();

    writeFrameworkResult(
        row10_relation.Runtime,
        STATEMENT_INPUT_LOG_SIZE,
        denominators[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
        inverses[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
        &columns.statement_input,
    );
    writeFrameworkResult(
        row11_relation.Runtime,
        STATEMENT_SEMANTICS_LOG_SIZE,
        denominators[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
        inverses[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
        &columns.statement_semantics,
    );
    writeRangeResult(
        denominators[RANGE_TERM_OFFSET..],
        &columns.range_check,
    );

    return result;
}

/// Cold relation-domain provenance for rows 10, 11, and 35. The two typed
/// rows replay their authenticated plans over the same logical witnesses as
/// the committed interaction fill. Row 35 has exactly one native provider
/// domain, so its decomposition is direct and still checked against the
/// proof-visible claim.
pub fn auditInteractionDomains(
    authority: *const Authority,
    workspace: *Workspace,
    prepared: *const Prepared,
    leaf_preprocessing: *const leaf_owner.Preprocessing,
    data: *const public_data_mod.PublicData,
    leaf: *const leaf_owner.Prepared,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
    claims: Claims,
    tuple_ledger: ?*relation_interaction.TupleLedger,
) !DomainAudits {
    try prepared.validateAgainst(
        authority,
        workspace,
        leaf_preprocessing,
        data,
        leaf,
    );
    try relations.validate();
    try provider_relations.validateAgainst(relations);
    try claims.verifyRangeClosure();

    const statement_input_rows = try workspace.allocator.alloc(
        row10_relation.Row,
        authority.statement_input_preprocessing.rows.len,
    );
    defer workspace.allocator.free(statement_input_rows);
    for (
        statement_input_rows,
        authority.statement_input_preprocessing.rows,
    ) |*destination, source| destination.* = try row10_witness.logicalRow(
        source,
        .{ .segment_leaf = &prepared.statement_words },
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
        try row11_witness.logicalRow(source, value, .segment_leaf);

    var range_values = [_]QM31{QM31.zero()} ** universal.RELATION_COUNT;
    range_values[@intFromEnum(relation.Domain.range_check_8_8)] =
        claims.range_check;
    var range_total = QM31.zero();
    for (range_values) |value| range_total = range_total.add(value);
    if (!range_total.eql(claims.range_check)) return error.ClaimMismatch;

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
            .total = range_total,
            .logical_rows = RANGE_CHECK_TRACE_SIZE,
            .event_terms = RANGE_CHECK_TRACE_SIZE,
        },
    };
}

pub const RangeClaims = struct {
    provider: QM31,
    requests: QM31,
};

pub fn prepareRangeResult(
    prepared: *const Prepared,
    numerators: []const QM31,
    cumulative: []QM31,
    inverses: []const QM31,
) RangeClaims {
    std.debug.assert(numerators.len == RANGE_CHECK_TRACE_SIZE);
    std.debug.assert(cumulative.len == RANGE_CHECK_TRACE_SIZE);
    std.debug.assert(inverses.len == RANGE_CHECK_TRACE_SIZE);
    var provider_claim = QM31.zero();
    var request_claim = QM31.zero();
    const counter = prepared.range.provider().counter.values;
    for (0..RANGE_CHECK_TRACE_SIZE) |logical_row| {
        const term = numerators[logical_row].mul(inverses[logical_row]);
        provider_claim = provider_claim.add(term);
        cumulative[logical_row] = provider_claim;
        std.debug.assert(
            numerators[logical_row].eql(QM31.fromBase(counter[logical_row]).neg()),
        );
        // The source ledger stores one negative multiplicity per request.
        // Reconstruct its claim independently from that signed counter; do
        // not manufacture closure by merely negating the provider total.
        request_claim = request_claim.add(
            QM31.fromBase(counter[logical_row]).mul(inverses[logical_row]),
        );
    }
    return .{ .provider = provider_claim, .requests = request_claim };
}

pub fn writeFrameworkResult(
    comptime Runtime: type,
    log_size: u32,
    cumulative: []const QM31,
    final_prefix: []const QM31,
    columns: *[Runtime.INTERACTION_COLUMN_COUNT][]M31,
) void {
    const size = @as(usize, 1) << @intCast(log_size);
    const final_start = (Runtime.BATCH_COUNT - 1) * size;
    for (0..size) |logical_row| {
        const destination = committedRow(logical_row, log_size);
        for (0..Runtime.BATCH_COUNT) |batch| {
            const value = if (batch + 1 < Runtime.BATCH_COUNT)
                cumulative[batch * size + logical_row]
            else
                final_prefix[final_start + logical_row];
            writeSecure(columns, batch, destination, value);
        }
    }
}

pub fn writeRangeResult(
    cumulative: []const QM31,
    columns: *[range_bridge.INTERACTION_COLUMN_COUNT][]M31,
) void {
    for (cumulative, 0..) |value, logical_row| {
        const destination = committedRow(logical_row, RANGE_CHECK_LOG_SIZE);
        const words = value.toM31Array();
        for (words, columns) |word, column| column[destination] = word;
    }
}

pub fn writeSecure(
    columns: anytype,
    secure_column: usize,
    row: usize,
    value: QM31,
) void {
    const words = value.toM31Array();
    for (words, 0..) |word, coordinate|
        columns.*[4 * secure_column + coordinate][row] = word;
}

pub fn rejectInteractionSourceAliases(
    destinations: []const AddressRange,
    authority: *const Authority,
    prepared: *const Prepared,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
) Error!void {
    const protected = [_]AddressRange{
        try objectRange(authority),
        try objectRange(prepared),
        try objectRange(relations),
        try objectRange(provider_relations),
        try sliceRange(M31, prepared.statement_values),
        try objectRange(&prepared.statement_words),
        try sliceRange(QM31, prepared.circuit_evaluation.storage),
        try sliceRange(M31, prepared.range.provider().counter.values),
        try sliceRange(row10_witness.Row, authority.statement_input_preprocessing.rows),
        try sliceRange(row11_witness.Row, authority.statement_semantics_preprocessing.rows),
    };
    for (destinations) |destination| for (protected) |source| {
        if (destination.overlaps(source)) return error.AliasedInput;
    };
}
pub const ROW10_TERM_OFFSET: usize = 0;
pub const ROW11_TERM_OFFSET = ROW10_TERM_COUNT;
pub const RANGE_TERM_OFFSET = ROW10_TERM_COUNT + ROW11_TERM_COUNT;
pub const TOTAL_INTERACTION_COLUMNS = row10_air.INTERACTION_COLUMN_COUNT +
    row11_air.INTERACTION_COLUMN_COUNT + range_bridge.INTERACTION_COLUMN_COUNT;

comptime {
    if (STATEMENT_INPUT_TRACE_SIZE != 2048 or
        STATEMENT_SEMANTICS_TRACE_SIZE != 2048 or
        RANGE_CHECK_TRACE_SIZE != 65_536 or
        row10_relation.Runtime.BATCH_COUNT != 2 or
        row11_relation.Runtime.BATCH_COUNT != 2 or
        range_bridge.INTERACTION_BATCH_COUNT != 1 or
        TOTAL_INTERACTION_TERMS != 73_728 or
        statement_circuit.INPUT_COUNT > STATEMENT_SEMANTICS_TRACE_SIZE or
        statement_circuit.INPUT_COUNT + statement_circuit.NODE_COUNT >
            TOTAL_INTERACTION_TERMS or
        lookup_schema.logSize(.range_check_8_8) != RANGE_CHECK_LOG_SIZE)
    {
        @compileError("segment statement outer-source frozen geometry drifted");
    }
}
