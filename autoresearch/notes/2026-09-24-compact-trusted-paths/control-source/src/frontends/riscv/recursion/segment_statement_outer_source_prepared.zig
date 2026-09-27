//! Internal segment statement outer source authority shard; use segment_statement_outer_source.zig publicly.

const dependency_0 = @import("segment_statement_outer_source_contract.zig");
const dependency_1 = @import("segment_statement_outer_source_authority.zig");

const Authority = dependency_1.Authority;
const Error = dependency_0.Error;
const M31 = dependency_0.M31;
const MainColumns = dependency_0.MainColumns;
const PreprocessedColumns = dependency_0.PreprocessedColumns;
const QM31 = dependency_0.QM31;
const RANGE_CHECK_LOG_SIZE = dependency_0.RANGE_CHECK_LOG_SIZE;
const RANGE_CHECK_TRACE_SIZE = dependency_0.RANGE_CHECK_TRACE_SIZE;
const STATEMENT_INPUT_LOG_SIZE = dependency_0.STATEMENT_INPUT_LOG_SIZE;
const STATEMENT_INPUT_TRACE_SIZE = dependency_0.STATEMENT_INPUT_TRACE_SIZE;
const STATEMENT_SEMANTICS_LOG_SIZE = dependency_0.STATEMENT_SEMANTICS_LOG_SIZE;
const STATEMENT_SEMANTICS_TRACE_SIZE = dependency_0.STATEMENT_SEMANTICS_TRACE_SIZE;
const Workspace = dependency_1.Workspace;
const baseInputs = dependency_1.baseInputs;
const committedRow = dependency_1.committedRow;
const graph_mod = dependency_0.graph_mod;
const leaf_owner = dependency_0.leaf_owner;
const lowering = dependency_0.lowering;
const public_data_mod = dependency_0.public_data_mod;
const range_bridge = dependency_0.range_bridge;
const range_owner = dependency_0.range_owner;
const row10_relation = dependency_0.row10_relation;
const row10_witness = dependency_0.row10_witness;
const row11_relation = dependency_0.row11_relation;
const row11_witness = dependency_0.row11_witness;
const secureSlicesEql = dependency_1.secureSlicesEql;
const shared_provider = dependency_0.shared_provider;
const statement_circuit = dependency_0.statement_circuit;
const std = dependency_0.std;
const universal = dependency_0.universal;
const validateStatementInputAuthority = dependency_1.validateStatementInputAuthority;

/// Proof-dependent immutable source. Its row-10 statement copy, row-11 dense
/// input vector, graph evaluation, and row-35 snapshot all originate in one
/// transaction from the admitted leaf.
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    statement_words: statement_circuit.StatementWords,
    circuit_evaluation: statement_circuit.Evaluation,
    statement_values: []M31,
    range: range_owner.Prepared,

    pub fn init(
        allocator: std.mem.Allocator,
        authority: *const Authority,
        workspace: *Workspace,
        leaf_preprocessing: *const leaf_owner.Preprocessing,
        data: *const public_data_mod.PublicData,
        leaf: *const leaf_owner.Prepared,
    ) !Prepared {
        try authority.validateSeals();
        try workspace.validate();
        try leaf.validateAgainst(leaf_preprocessing, data);
        try validateStatementInputAuthority(authority, leaf_preprocessing);

        const statement_words = leaf.statement.words;
        var circuit_evaluation = try authority.circuit.evaluate(
            allocator,
            statement_circuit.Witness.forSegment(&statement_words),
        );
        errdefer circuit_evaluation.deinit();
        const statement_values = try allocator.alloc(
            M31,
            statement_circuit.INPUT_COUNT,
        );
        errdefer allocator.free(statement_values);
        try baseInputs(circuit_evaluation.inputs(), statement_values);

        const sources = rangeSources(
            authority,
            leaf_preprocessing,
            data,
            leaf,
            statement_values,
        );
        var range = try range_owner.Prepared.init(
            allocator,
            &workspace.range,
            sources,
        );
        errdefer range.deinit();

        var result = Prepared{
            .allocator = allocator,
            .statement_words = statement_words,
            .circuit_evaluation = circuit_evaluation,
            .statement_values = statement_values,
            .range = range,
        };
        // The three local errdefers retain ownership until successful return;
        // aggregate cleanup here would overlap them on a late admission error.
        try result.validateAgainst(
            authority,
            workspace,
            leaf_preprocessing,
            data,
            leaf,
        );
        return result;
    }

    pub fn deinit(self: *Prepared) void {
        self.range.deinit();
        self.allocator.free(self.statement_values);
        self.circuit_evaluation.deinit();
        self.* = undefined;
    }

    /// Allocation-free end-to-end revalidation. Replaying the circuit catches
    /// mutation of any internal lowering value, not only public inputs or zero
    /// outputs. The reusable secure slab supplies all replay scratch.
    pub fn validateAgainst(
        self: *const Prepared,
        authority: *const Authority,
        workspace: *Workspace,
        leaf_preprocessing: *const leaf_owner.Preprocessing,
        data: *const public_data_mod.PublicData,
        leaf: *const leaf_owner.Prepared,
    ) !void {
        try authority.validateSeals();
        try workspace.validate();
        try leaf.validateAgainst(leaf_preprocessing, data);
        try validateStatementInputAuthority(authority, leaf_preprocessing);
        if (!m31SlicesEql(&self.statement_words, &leaf.statement.words) or
            self.statement_values.len != statement_circuit.INPUT_COUNT or
            !std.mem.eql(
                u8,
                &self.circuit_evaluation.circuit_identity,
                &authority.circuit.identity_digest,
            ) or
            self.circuit_evaluation.inputs().len != statement_circuit.INPUT_COUNT or
            self.circuit_evaluation.values().len != statement_circuit.NODE_COUNT)
        {
            return error.AuthorityMismatch;
        }

        const replay = workspace.secure_storage[0 .. statement_circuit.INPUT_COUNT + statement_circuit.NODE_COUNT];
        const replay_inputs = replay[0..statement_circuit.INPUT_COUNT];
        const replay_values = replay[statement_circuit.INPUT_COUNT..];
        try authority.circuit.evaluateIntoAssumeValid(
            statement_circuit.Witness.forSegment(&self.statement_words),
            replay_inputs,
            replay_values,
        );
        if (!secureSlicesEql(replay_inputs, self.circuit_evaluation.inputs()) or
            !secureSlicesEql(replay_values, self.circuit_evaluation.values()))
        {
            return error.AuthorityMismatch;
        }
        const expected_base = workspace.logical_storage[0..statement_circuit.INPUT_COUNT];
        try baseInputs(replay_inputs, expected_base);
        if (!m31SlicesEql(expected_base, self.statement_values))
            return error.AuthorityMismatch;

        const sources = rangeSources(
            authority,
            leaf_preprocessing,
            data,
            leaf,
            self.statement_values,
        );
        try self.range.validateAgainst(&workspace.range, sources);
    }

    pub fn loweringEvaluation(self: *const Prepared) lowering.Evaluation {
        return .{
            .circuit_identity = self.circuit_evaluation.circuit_identity,
            .values = self.circuit_evaluation.values(),
        };
    }
};

/// Fills all three Tree-0 contributions directly in final committed order.
/// The temporary logical slab is reused between rows 10 and 11.
pub fn fillPreprocessedCommitted(
    authority: *const Authority,
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
    try rejectAuthoritySourceAliases(ranges[0..count], authority);

    var row10_logical: [row10_witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    logicalColumns(
        row10_witness.PREPROCESSED_COLUMN_COUNT,
        STATEMENT_INPUT_TRACE_SIZE,
        workspace.logical_storage,
        &row10_logical,
    );
    try authority.statement_input_executor.generatePreprocessedInto(
        &authority.statement_input_preprocessing,
        &row10_logical,
    );
    scatterLogical(
        row10_witness.PREPROCESSED_COLUMN_COUNT,
        STATEMENT_INPUT_LOG_SIZE,
        &row10_logical,
        &columns.statement_input,
    );

    var row11_logical: [row11_witness.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
    logicalColumns(
        row11_witness.PREPROCESSED_COLUMN_COUNT,
        STATEMENT_SEMANTICS_TRACE_SIZE,
        workspace.logical_storage,
        &row11_logical,
    );
    try authority.statement_semantics_executor.generatePreprocessedInto(
        &authority.statement_semantics_preprocessing,
        &row11_logical,
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

/// Fills all three Tree-1 contributions directly in final committed order.
pub fn fillMainCommitted(
    authority: *const Authority,
    workspace: *Workspace,
    prepared: *const Prepared,
    leaf_preprocessing: *const leaf_owner.Preprocessing,
    data: *const public_data_mod.PublicData,
    leaf: *const leaf_owner.Prepared,
    columns: *MainColumns,
) !void {
    try prepared.validateAgainst(
        authority,
        workspace,
        leaf_preprocessing,
        data,
        leaf,
    );
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
    try rejectMainSourceAliases(
        ranges[0..count],
        authority,
        prepared,
    );

    var row10_logical: [row10_witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    logicalColumns(
        row10_witness.MAIN_COLUMN_COUNT,
        STATEMENT_INPUT_TRACE_SIZE,
        workspace.logical_storage,
        &row10_logical,
    );
    try authority.statement_input_executor.generateMainInto(
        &authority.statement_input_preprocessing,
        &row10_logical,
        .{ .segment_leaf = &prepared.statement_words },
    );
    scatterLogical(
        row10_witness.MAIN_COLUMN_COUNT,
        STATEMENT_INPUT_LOG_SIZE,
        &row10_logical,
        &columns.statement_input,
    );

    var row11_logical: [row11_witness.MAIN_COLUMN_COUNT][]M31 = undefined;
    logicalColumns(
        row11_witness.MAIN_COLUMN_COUNT,
        STATEMENT_SEMANTICS_TRACE_SIZE,
        workspace.logical_storage,
        &row11_logical,
    );
    try authority.statement_semantics_executor.generateMainInto(
        &authority.statement_semantics_preprocessing,
        &row11_logical,
        prepared.statement_values,
        .segment_leaf,
    );
    scatterLogical(
        row11_witness.MAIN_COLUMN_COUNT,
        STATEMENT_SEMANTICS_LOG_SIZE,
        &row11_logical,
        &columns.statement_semantics,
    );

    try authority.range_executor.generateMainInto(
        prepared.range.provider(),
        &columns.range_check,
    );
}

pub fn rangeSources(
    authority: *const Authority,
    leaf_preprocessing: *const leaf_owner.Preprocessing,
    data: *const public_data_mod.PublicData,
    leaf: *const leaf_owner.Prepared,
    statement_values: []const M31,
) range_owner.Sources {
    return .{
        .data = data,
        .leaf_preprocessing = leaf_preprocessing,
        .leaf = leaf,
        .statement = .{
            .preprocessing = &authority.statement_semantics_preprocessing,
            .values = statement_values,
        },
    };
}

pub fn fillStatementInputTerms(
    authority: *const Authority,
    prepared: *const Prepared,
    relations: *const universal.UniversalRelations,
    numerators: []QM31,
    denominators: []QM31,
) !void {
    const size = STATEMENT_INPUT_TRACE_SIZE;
    if (numerators.len != row10_relation.Runtime.BATCH_COUNT * size or
        denominators.len != numerators.len)
    {
        return error.InvalidTraceShape;
    }
    for (0..size) |logical_row| {
        const pairs = if (logical_row <
            authority.statement_input_preprocessing.rows.len)
        blk: {
            const row = try row10_witness.logicalRow(
                authority.statement_input_preprocessing.rows[logical_row],
                .{ .segment_leaf = &prepared.statement_words },
            );
            break :blk try authority.statement_input_relation.preparedRowPairs(
                row,
                relations,
            );
        } else paddingPairs(row10_relation.Runtime.BATCH_COUNT);
        writeTerms(row10_relation.Runtime.BATCH_COUNT, size, logical_row, pairs, numerators, denominators);
    }
}

pub fn fillStatementSemanticsTerms(
    authority: *const Authority,
    prepared: *const Prepared,
    relations: *const universal.UniversalRelations,
    numerators: []QM31,
    denominators: []QM31,
) !void {
    const size = STATEMENT_SEMANTICS_TRACE_SIZE;
    if (numerators.len != row11_relation.Runtime.BATCH_COUNT * size or
        denominators.len != numerators.len)
    {
        return error.InvalidTraceShape;
    }
    for (0..size) |logical_row| {
        const pairs = if (logical_row <
            authority.statement_semantics_preprocessing.rows.len)
        blk: {
            const row = try row11_witness.logicalRow(
                authority.statement_semantics_preprocessing.rows[logical_row],
                prepared.statement_values[logical_row],
                .segment_leaf,
            );
            break :blk try authority.statement_semantics_relation.preparedRowPairs(
                row,
                relations,
            );
        } else paddingPairs(row11_relation.Runtime.BATCH_COUNT);
        writeTerms(row11_relation.Runtime.BATCH_COUNT, size, logical_row, pairs, numerators, denominators);
    }
}

pub fn fillRangeTerms(
    prepared: *const Prepared,
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

pub fn paddingPairs(comptime count: usize) [count]@import("../air/logup.zig").RowPair {
    return [_]@import("../air/logup.zig").RowPair{.{
        .n1 = QM31.zero(),
        .d1 = QM31.one(),
        .n2 = QM31.zero(),
        .d2 = QM31.one(),
    }} ** count;
}

pub fn m31SlicesEql(lhs: []const M31, rhs: []const M31) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |a, b| if (!a.eql(b)) return false;
    return true;
}

pub fn logicalColumns(
    comptime count: usize,
    size: usize,
    storage: []M31,
    result: *[count][]M31,
) void {
    std.debug.assert(storage.len >= count * size);
    for (result, 0..) |*column, index|
        column.* = storage[index * size ..][0..size];
}

pub fn scatterLogical(
    comptime count: usize,
    log_size: u32,
    source: *const [count][]M31,
    destination: *[count][]M31,
) void {
    for (source, destination) |input, output| {
        for (input, 0..) |value, logical_row|
            output[committedRow(logical_row, log_size)] = value;
    }
}

pub const AddressRange = struct {
    start: usize,
    end: usize,

    pub fn overlaps(self: AddressRange, other: AddressRange) bool {
        return self.start < other.end and other.start < self.end;
    }
};

pub fn preflightColumnSet(
    columns: anytype,
    expected_size: usize,
    ranges: []AddressRange,
    count: *usize,
    workspace: *const Workspace,
) Error!void {
    const descriptors = try objectRange(columns);
    const logical = try sliceRange(M31, workspace.logical_storage);
    const secure = try sliceRange(QM31, workspace.secure_storage);
    const range_counter = try sliceRange(M31, workspace.range.counter.values);
    for (columns.*, 0..) |column, local| {
        _ = local;
        if (column.len != expected_size or count.* >= ranges.len)
            return error.InvalidTraceShape;
        const destination = try sliceRange(M31, column);
        if (destination.overlaps(descriptors) or destination.overlaps(logical) or
            destination.overlaps(secure) or destination.overlaps(range_counter))
        {
            return error.AliasedDestination;
        }
        for (ranges[0..count.*]) |prior| if (destination.overlaps(prior))
            return error.AliasedDestination;
        ranges[count.*] = destination;
        count.* += 1;
    }
}

pub fn rejectAuthoritySourceAliases(
    destinations: []const AddressRange,
    authority: *const Authority,
) Error!void {
    const protected = [_]AddressRange{
        try objectRange(authority),
        try sliceRange(
            row10_witness.Row,
            authority.statement_input_preprocessing.rows,
        ),
        try sliceRange(
            row11_witness.Row,
            authority.statement_semantics_preprocessing.rows,
        ),
        try sliceRange(graph_mod.Node, authority.lowering_nodes),
    };
    try rejectProtectedRanges(destinations, &protected);
}

pub fn rejectMainSourceAliases(
    destinations: []const AddressRange,
    authority: *const Authority,
    prepared: *const Prepared,
) Error!void {
    const protected = [_]AddressRange{
        try objectRange(authority),
        try objectRange(prepared),
        try sliceRange(
            row10_witness.Row,
            authority.statement_input_preprocessing.rows,
        ),
        try sliceRange(
            row11_witness.Row,
            authority.statement_semantics_preprocessing.rows,
        ),
        try sliceRange(M31, prepared.statement_values),
        try objectRange(&prepared.statement_words),
        try sliceRange(QM31, prepared.circuit_evaluation.storage),
        try sliceRange(M31, prepared.range.provider().counter.values),
    };
    try rejectProtectedRanges(destinations, &protected);
}

pub fn rejectProtectedRanges(
    destinations: []const AddressRange,
    protected: []const AddressRange,
) Error!void {
    for (destinations) |destination| for (protected) |source| {
        if (destination.overlaps(source)) return error.AliasedInput;
    };
}

pub fn sliceRange(comptime T: type, values: []const T) Error!AddressRange {
    const bytes = std.math.mul(usize, values.len, @sizeOf(T)) catch
        return error.ArithmeticOverflow;
    const start = @intFromPtr(values.ptr);
    return .{
        .start = start,
        .end = std.math.add(usize, start, bytes) catch
            return error.ArithmeticOverflow,
    };
}

pub fn objectRange(pointer: anytype) Error!AddressRange {
    const info = @typeInfo(@TypeOf(pointer));
    if (info != .pointer or info.pointer.size != .one)
        @compileError("outer-source alias guards require a single-item pointer");
    const start = @intFromPtr(pointer);
    return .{
        .start = start,
        .end = std.math.add(usize, start, @sizeOf(info.pointer.child)) catch
            return error.ArithmeticOverflow,
    };
}
pub const TOTAL_PREPROCESSED_COLUMNS = row10_witness.PREPROCESSED_COLUMN_COUNT +
    row11_witness.PREPROCESSED_COLUMN_COUNT +
    range_bridge.FRAMEWORK_PREPROCESSED_COLUMN_COUNT;
pub const TOTAL_MAIN_COLUMNS = row10_witness.MAIN_COLUMN_COUNT +
    row11_witness.MAIN_COLUMN_COUNT + range_bridge.PHYSICAL_MAIN_COLUMN_COUNT;
