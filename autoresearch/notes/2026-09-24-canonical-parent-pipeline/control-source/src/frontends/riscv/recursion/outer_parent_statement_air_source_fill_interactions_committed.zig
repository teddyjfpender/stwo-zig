//! Internal outer parent statement air source authority shard; use outer_parent_statement_air_source.zig publicly.

const dependency_0 = @import("outer_parent_statement_air_source_contract.zig");
const dependency_1 = @import("outer_parent_statement_air_source_prepared.zig");

const AddressRange = dependency_0.AddressRange;
const Claims = dependency_1.Claims;
const Error = dependency_0.Error;
const InteractionColumns = dependency_1.InteractionColumns;
const M31 = dependency_0.M31;
const MainColumns = dependency_1.MainColumns;
const PreprocessedColumns = dependency_1.PreprocessedColumns;
const QM31 = dependency_0.QM31;
const RANGE_CHECK_LOG_SIZE = dependency_0.RANGE_CHECK_LOG_SIZE;
const RANGE_CHECK_TRACE_SIZE = dependency_0.RANGE_CHECK_TRACE_SIZE;
const ROW10_INTERACTION_TERMS = dependency_0.ROW10_INTERACTION_TERMS;
const ROW10_PREPROCESSED_CELLS = dependency_0.ROW10_PREPROCESSED_CELLS;
const ROW11_INTERACTION_TERMS = dependency_0.ROW11_INTERACTION_TERMS;
const STATEMENT_INPUT_LOG_SIZE = dependency_0.STATEMENT_INPUT_LOG_SIZE;
const STATEMENT_INPUT_TRACE_SIZE = dependency_0.STATEMENT_INPUT_TRACE_SIZE;
const STATEMENT_SEMANTICS_LOG_SIZE = dependency_0.STATEMENT_SEMANTICS_LOG_SIZE;
const STATEMENT_SEMANTICS_TRACE_SIZE = dependency_0.STATEMENT_SEMANTICS_TRACE_SIZE;
const TOTAL_INTERACTION_TERMS = dependency_0.TOTAL_INTERACTION_TERMS;
const TOTAL_PREPROCESSED_COLUMNS = dependency_1.TOTAL_PREPROCESSED_COLUMNS;
const TREE0_LOGICAL_CELLS = dependency_0.TREE0_LOGICAL_CELLS;
const TREE1_LOGICAL_CELLS = dependency_0.TREE1_LOGICAL_CELLS;
const Workspace = dependency_0.Workspace;
const fields = dependency_0.fields;
const fixed_wire = dependency_0.fixed_wire;
const logicalColumns = dependency_1.logicalColumns;
const committedRow = dependency_1.committedRow;
const objectRange = dependency_0.objectRange;
const preflightColumnSet = dependency_1.preflightColumnSet;
const range_bridge = dependency_0.range_bridge;
const rejectAuthorityAliases = dependency_1.rejectAuthorityAliases;
const row10_relation = dependency_0.row10_relation;
const row10_witness = dependency_0.row10_witness;
const row11_relation = dependency_0.row11_relation;
const row11_witness = dependency_0.row11_witness;
const scatterLogical = dependency_1.scatterLogical;
const segment_source = dependency_0.segment_source;
const shared_provider = dependency_0.shared_provider;
const sliceRange = dependency_0.sliceRange;
const std = dependency_0.std;
const universal = dependency_0.universal;

/// Writes binary row 10, row 11, and shared row 35 preprocessing in final
/// committed order. All fallible witness generation is staged in worker-owned
/// logical storage; caller columns remain untouched on every error.
pub fn fillPreprocessedCommitted(
    authority: *const segment_source.Authority,
    workspace: *Workspace,
    columns: *PreprocessedColumns,
) !void {
    try authority.validateSeals();
    try workspace.validate();
    var ranges: [TOTAL_PREPROCESSED_COLUMNS]AddressRange = undefined;
    var count: usize = 0;
    try preflightColumnSet(
        &columns.statement_input,
        STATEMENT_INPUT_TRACE_SIZE,
        &ranges,
        &count,
        workspace,
    );
    try preflightColumnSet(
        &columns.statement_semantics,
        STATEMENT_SEMANTICS_TRACE_SIZE,
        &ranges,
        &count,
        workspace,
    );
    try preflightColumnSet(
        &columns.range_check,
        RANGE_CHECK_TRACE_SIZE,
        &ranges,
        &count,
        workspace,
    );
    try rejectAuthorityAliases(ranges[0..count], authority);

    var row10_logical: [row10_witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    logicalColumns(
        row10_witness.PREPROCESSED_COLUMN_COUNT,
        STATEMENT_INPUT_TRACE_SIZE,
        workspace.logical_storage[0..ROW10_PREPROCESSED_CELLS],
        &row10_logical,
    );
    var row11_logical: [row11_witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    logicalColumns(
        row11_witness.PREPROCESSED_COLUMN_COUNT,
        STATEMENT_SEMANTICS_TRACE_SIZE,
        workspace.logical_storage[ROW10_PREPROCESSED_CELLS..TREE0_LOGICAL_CELLS],
        &row11_logical,
    );
    try authority.statement_input_executor.generatePreprocessedInto(
        &authority.statement_input_preprocessing,
        &row10_logical,
    );
    try authority.statement_semantics_executor.generatePreprocessedInto(
        &authority.statement_semantics_preprocessing,
        &row11_logical,
    );

    scatterLogical(
        row10_witness.PREPROCESSED_COLUMN_COUNT,
        STATEMENT_INPUT_LOG_SIZE,
        &row10_logical,
        &columns.statement_input,
    );
    scatterLogical(
        row11_witness.PREPROCESSED_COLUMN_COUNT,
        STATEMENT_SEMANTICS_LOG_SIZE,
        &row11_logical,
        &columns.statement_semantics,
    );
    @memset(columns.range_check[0], M31.zero());
    columns.range_check[0][committedRow(0, RANGE_CHECK_LOG_SIZE)] = M31.one();
    for (0..RANGE_CHECK_TRACE_SIZE) |logical_row| {
        const destination = committedRow(logical_row, RANGE_CHECK_LOG_SIZE);
        columns.range_check[1][destination] = M31.fromCanonical(
            @intCast(logical_row & 0xff),
        );
        columns.range_check[2][destination] = M31.fromCanonical(
            @intCast(logical_row >> 8),
        );
    }
}

/// Writes the authenticated binary statements and exact row-11 circuit input
/// vector into Tree 1. Validation and staging complete before the first caller
/// cell is changed.
pub fn fillMainCommitted(
    comptime dimensions: fixed_wire.Dimensions,
    authority: *const segment_source.Authority,
    workspace: *Workspace,
    prepared: anytype,
    columns: *MainColumns,
) !void {
    dimensions.validate();
    try prepared.validateHot(authority, workspace);
    var ranges: [TOTAL_MAIN_COLUMNS]AddressRange = undefined;
    var count: usize = 0;
    try preflightColumnSet(
        &columns.statement_input,
        STATEMENT_INPUT_TRACE_SIZE,
        &ranges,
        &count,
        workspace,
    );
    try preflightColumnSet(
        &columns.statement_semantics,
        STATEMENT_SEMANTICS_TRACE_SIZE,
        &ranges,
        &count,
        workspace,
    );
    try preflightColumnSet(
        &columns.range_check,
        RANGE_CHECK_TRACE_SIZE,
        &ranges,
        &count,
        workspace,
    );
    try rejectMainAliases(
        ranges[0..count],
        authority,
        prepared,
    );

    const row10_cells = row10_witness.MAIN_COLUMN_COUNT *
        STATEMENT_INPUT_TRACE_SIZE;
    var row10_logical: [row10_witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    logicalColumns(
        row10_witness.MAIN_COLUMN_COUNT,
        STATEMENT_INPUT_TRACE_SIZE,
        workspace.logical_storage[0..row10_cells],
        &row10_logical,
    );
    var row11_logical: [row11_witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    logicalColumns(
        row11_witness.MAIN_COLUMN_COUNT,
        STATEMENT_SEMANTICS_TRACE_SIZE,
        workspace.logical_storage[row10_cells..TREE1_LOGICAL_CELLS],
        &row11_logical,
    );
    try authority.statement_input_executor.generateMainInto(
        &authority.statement_input_preprocessing,
        &row10_logical,
        binaryStatementWitness(prepared),
    );
    try authority.statement_semantics_executor.generateMainInto(
        &authority.statement_semantics_preprocessing,
        &row11_logical,
        prepared.statement_values,
        .binary_node,
    );

    scatterLogical(
        row10_witness.MAIN_COLUMN_COUNT,
        STATEMENT_INPUT_LOG_SIZE,
        &row10_logical,
        &columns.statement_input,
    );
    scatterLogical(
        row11_witness.MAIN_COLUMN_COUNT,
        STATEMENT_SEMANTICS_LOG_SIZE,
        &row11_logical,
        &columns.statement_semantics,
    );
    for (prepared.range.provider().counter.values, 0..) |value, logical_row|
        columns.range_check[0][committedRow(logical_row, RANGE_CHECK_LOG_SIZE)] =
            value;
}

/// Generates all three interaction contributions as one failure-atomic hot
/// transaction. A single Montgomery batch inversion covers both typed rows
/// and the 2^16 provider; no heap allocation occurs.
pub fn fillInteractionsCommitted(
    comptime dimensions: fixed_wire.Dimensions,
    authority: *const segment_source.Authority,
    workspace: *Workspace,
    prepared: anytype,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
    columns: *InteractionColumns,
) !Claims {
    dimensions.validate();
    try prepared.validateHot(authority, workspace);
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
    try rejectInteractionAliases(
        destination_ranges[0..destination_count],
        authority,
        prepared,
        relations,
        provider_relations,
    );

    const numerators = workspace.secure_storage[0..TOTAL_INTERACTION_TERMS];
    const cumulative = workspace.secure_storage[TOTAL_INTERACTION_TERMS .. 2 * TOTAL_INTERACTION_TERMS];
    const inverses = workspace.secure_storage[2 * TOTAL_INTERACTION_TERMS .. 3 * TOTAL_INTERACTION_TERMS];
    try fillStatementInputTerms(
        authority,
        prepared,
        relations,
        numerators[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
        cumulative[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
    );
    try fillStatementSemanticsTerms(
        authority,
        prepared,
        relations,
        numerators[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
        cumulative[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
    );
    fillRangeTerms(
        prepared,
        provider_relations,
        numerators[RANGE_TERM_OFFSET..],
        cumulative[RANGE_TERM_OFFSET..],
    );
    fields.batchInverseInPlace(QM31, cumulative, inverses) catch
        return error.ZeroDenominator;

    const statement_input_claim = try prepareFrameworkResult(
        row10_relation.Runtime,
        STATEMENT_INPUT_TRACE_SIZE,
        numerators[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
        cumulative[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
        inverses[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
    );
    const statement_semantics_claim = try prepareFrameworkResult(
        row11_relation.Runtime,
        STATEMENT_SEMANTICS_TRACE_SIZE,
        numerators[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
        cumulative[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
        inverses[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
    );
    const range_claims = prepareRangeResult(
        prepared,
        numerators[RANGE_TERM_OFFSET..],
        cumulative[RANGE_TERM_OFFSET..],
        inverses[RANGE_TERM_OFFSET..],
    );
    const result = Claims{
        .statement_input = statement_input_claim,
        .statement_semantics = statement_semantics_claim,
        .range_check = range_claims.provider,
        .range_requests = range_claims.requests,
    };
    try result.verifyRangeClosure();

    writeFrameworkResult(
        row10_relation.Runtime,
        STATEMENT_INPUT_LOG_SIZE,
        cumulative[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
        inverses[ROW10_TERM_OFFSET..ROW11_TERM_OFFSET],
        &columns.statement_input,
    );
    writeFrameworkResult(
        row11_relation.Runtime,
        STATEMENT_SEMANTICS_LOG_SIZE,
        cumulative[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
        inverses[ROW11_TERM_OFFSET..RANGE_TERM_OFFSET],
        &columns.statement_semantics,
    );
    writeRangeResult(cumulative[RANGE_TERM_OFFSET..], &columns.range_check);
    return result;
}

pub fn binaryStatementWitness(prepared: anytype) row10_witness.StatementWitness {
    return .{ .binary_node = .{
        .left = &prepared.left_words,
        .right = &prepared.right_words,
        .parent = &prepared.parent_words,
    } };
}

pub fn fillStatementInputTerms(
    authority: *const segment_source.Authority,
    prepared: anytype,
    relations: *const universal.UniversalRelations,
    numerators: []QM31,
    denominators: []QM31,
) !void {
    if (numerators.len != ROW10_INTERACTION_TERMS or
        denominators.len != numerators.len)
    {
        return error.InvalidTraceShape;
    }
    const witness = binaryStatementWitness(prepared);
    for (0..STATEMENT_INPUT_TRACE_SIZE) |logical_row| {
        const pairs = if (logical_row <
            authority.statement_input_preprocessing.rows.len)
        blk: {
            const row = try row10_witness.logicalRow(
                authority.statement_input_preprocessing.rows[logical_row],
                witness,
            );
            break :blk try authority.statement_input_relation.preparedRowPairs(
                row,
                relations,
            );
        } else paddingPairs(row10_relation.Runtime.BATCH_COUNT);
        writeTerms(
            row10_relation.Runtime.BATCH_COUNT,
            STATEMENT_INPUT_TRACE_SIZE,
            logical_row,
            pairs,
            numerators,
            denominators,
        );
    }
}

pub fn fillStatementSemanticsTerms(
    authority: *const segment_source.Authority,
    prepared: anytype,
    relations: *const universal.UniversalRelations,
    numerators: []QM31,
    denominators: []QM31,
) !void {
    if (numerators.len != ROW11_INTERACTION_TERMS or
        denominators.len != numerators.len)
    {
        return error.InvalidTraceShape;
    }
    for (0..STATEMENT_SEMANTICS_TRACE_SIZE) |logical_row| {
        const pairs = if (logical_row <
            authority.statement_semantics_preprocessing.rows.len)
        blk: {
            const row = try row11_witness.logicalRow(
                authority.statement_semantics_preprocessing.rows[logical_row],
                prepared.statement_values[logical_row],
                .binary_node,
            );
            break :blk try authority.statement_semantics_relation.preparedRowPairs(
                row,
                relations,
            );
        } else paddingPairs(row11_relation.Runtime.BATCH_COUNT);
        writeTerms(
            row11_relation.Runtime.BATCH_COUNT,
            STATEMENT_SEMANTICS_TRACE_SIZE,
            logical_row,
            pairs,
            numerators,
            denominators,
        );
    }
}

pub fn fillRangeTerms(
    prepared: anytype,
    provider_relations: *const shared_provider.SharedProviderRelations,
    numerators: []QM31,
    denominators: []QM31,
) void {
    std.debug.assert(numerators.len == RANGE_CHECK_TRACE_SIZE);
    std.debug.assert(denominators.len == RANGE_CHECK_TRACE_SIZE);
    const counter = prepared.range.provider().counter.values;
    for (0..RANGE_CHECK_TRACE_SIZE) |logical_row| {
        const tuple = [2]M31{
            M31.fromCanonical(@intCast(logical_row & 0xff)),
            M31.fromCanonical(@intCast(logical_row >> 8)),
        };
        numerators[logical_row] = QM31.fromBase(counter[logical_row]).neg();
        denominators[logical_row] =
            provider_relations.native.range_check_8_8.combineBase(tuple);
    }
}

pub fn writeTerms(
    comptime batch_count: usize,
    size: usize,
    logical_row: usize,
    pairs: [batch_count]@import("../air/logup.zig").RowPair,
    numerators: []QM31,
    denominators: []QM31,
) void {
    for (pairs, 0..) |pair, batch| {
        const index = batch * size + logical_row;
        numerators[index] = pair.n1.mul(pair.d2).add(pair.n2.mul(pair.d1));
        denominators[index] = pair.d1.mul(pair.d2);
    }
}

pub fn prepareFrameworkResult(
    comptime Runtime: type,
    size: usize,
    numerators: []QM31,
    cumulative: []QM31,
    inverses: []QM31,
) !QM31 {
    if (numerators.len != Runtime.BATCH_COUNT * size or
        cumulative.len != numerators.len or inverses.len != numerators.len)
    {
        return error.InvalidTraceShape;
    }
    var claimed_sum = QM31.zero();
    for (0..size) |logical_row| {
        var within_row = QM31.zero();
        for (0..Runtime.BATCH_COUNT) |batch| {
            const index = batch * size + logical_row;
            within_row = within_row.add(numerators[index].mul(inverses[index]));
            if (batch + 1 < Runtime.BATCH_COUNT)
                cumulative[index] = within_row;
        }
        numerators[logical_row] = within_row;
        claimed_sum = claimed_sum.add(within_row);
    }
    const shift = claimed_sum.divM31(M31.fromU64(size)) catch
        return error.InvalidTraceShape;
    var prefix = QM31.zero();
    const final_start = (Runtime.BATCH_COUNT - 1) * size;
    for (0..size) |logical_row| {
        prefix = prefix.add(numerators[logical_row]).sub(shift);
        inverses[final_start + logical_row] = prefix;
    }
    if (!prefix.isZero()) return error.PrefixClosureMismatch;
    return claimed_sum;
}

pub const RangeClaims = struct {
    provider: QM31,
    requests: QM31,
};

pub fn prepareRangeResult(
    prepared: anytype,
    numerators: []const QM31,
    cumulative: []QM31,
    inverses: []const QM31,
) RangeClaims {
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

pub fn paddingPairs(comptime count: usize) [count]@import("../air/logup.zig").RowPair {
    return [_]@import("../air/logup.zig").RowPair{.{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    }} ** count;
}

pub fn rejectMainAliases(
    destinations: []const AddressRange,
    authority: *const segment_source.Authority,
    prepared: anytype,
) Error!void {
    try rejectAuthorityAliases(destinations, authority);
    const protected = [_]AddressRange{
        try objectRange(prepared),
        try sliceRange(M31, prepared.statement_values),
        try sliceRange(QM31, prepared.circuit_evaluation.storage),
        try sliceRange(M31, prepared.range.provider().counter.values),
    };
    for (destinations) |destination| for (protected) |source| {
        if (destination.overlaps(source)) return error.AliasedInput;
    };
}

pub fn rejectInteractionAliases(
    destinations: []const AddressRange,
    authority: *const segment_source.Authority,
    prepared: anytype,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
) Error!void {
    try rejectMainAliases(
        destinations,
        authority,
        prepared,
    );
    const protected = [_]AddressRange{
        try objectRange(relations),
        try objectRange(provider_relations),
    };
    for (destinations) |destination| for (protected) |source| {
        if (destination.overlaps(source)) return error.AliasedInput;
    };
}
pub const ROW10_TERM_OFFSET: usize = 0;
pub const ROW11_TERM_OFFSET = ROW10_INTERACTION_TERMS;
pub const RANGE_TERM_OFFSET = ROW10_INTERACTION_TERMS + ROW11_INTERACTION_TERMS;
pub const TOTAL_MAIN_COLUMNS = row10_witness.MAIN_COLUMN_COUNT +
    row11_witness.MAIN_COLUMN_COUNT +
    range_bridge.PHYSICAL_MAIN_COLUMN_COUNT;
pub const TOTAL_INTERACTION_COLUMNS = row10_relation.Runtime.INTERACTION_COLUMN_COUNT +
    row11_relation.Runtime.INTERACTION_COLUMN_COUNT +
    range_bridge.INTERACTION_COLUMN_COUNT;
