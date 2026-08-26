//! Internal segment statement outer source authority shard; use segment_statement_outer_source.zig publicly.

const dependency_0 = @import("segment_statement_outer_source_contract.zig");

const Claims = dependency_0.Claims;
const Components = dependency_0.Components;
const Error = dependency_0.Error;
const InteractionColumns = dependency_0.InteractionColumns;
const LOWERING_GRAPH_DIGEST = dependency_0.LOWERING_GRAPH_DIGEST;
const M31 = dependency_0.M31;
const MainColumns = dependency_0.MainColumns;
const PreprocessedColumns = dependency_0.PreprocessedColumns;
const QM31 = dependency_0.QM31;
const RANGE_CHECK_LOG_SIZE = dependency_0.RANGE_CHECK_LOG_SIZE;
const RANGE_CHECK_TRACE_SIZE = dependency_0.RANGE_CHECK_TRACE_SIZE;
const RangeCheckAdapter = dependency_0.RangeCheckAdapter;
const RosterClaims = dependency_0.RosterClaims;
const STATEMENT_CIRCUIT_ID = dependency_0.STATEMENT_CIRCUIT_ID;
const STATEMENT_INPUT_LOG_SIZE = dependency_0.STATEMENT_INPUT_LOG_SIZE;
const STATEMENT_INPUT_PARAMETERS = dependency_0.STATEMENT_INPUT_PARAMETERS;
const STATEMENT_INPUT_TRACE_SIZE = dependency_0.STATEMENT_INPUT_TRACE_SIZE;
const STATEMENT_SEMANTICS_LOG_SIZE = dependency_0.STATEMENT_SEMANTICS_LOG_SIZE;
const STATEMENT_SEMANTICS_PARAMETERS = dependency_0.STATEMENT_SEMANTICS_PARAMETERS;
const STATEMENT_SEMANTICS_TRACE_SIZE = dependency_0.STATEMENT_SEMANTICS_TRACE_SIZE;
const StatementInputAdapter = dependency_0.StatementInputAdapter;
const StatementSemanticsAdapter = dependency_0.StatementSemanticsAdapter;
const convertGraphNodes = dependency_0.convertGraphNodes;
const core_utils = dependency_0.core_utils;
const graph_mod = dependency_0.graph_mod;
const leaf_owner = dependency_0.leaf_owner;
const lowering = dependency_0.lowering;
const manifest_mod = dependency_0.manifest_mod;
const range_bridge = dependency_0.range_bridge;
const range_owner = dependency_0.range_owner;
const relation = dependency_0.relation;
const roster = dependency_0.roster;
const row10RowsEql = dependency_0.row10RowsEql;
const row10_air = dependency_0.row10_air;
const row10_relation = dependency_0.row10_relation;
const row10_witness = dependency_0.row10_witness;
const row11_air = dependency_0.row11_air;
const row11_relation = dependency_0.row11_relation;
const row11_witness = dependency_0.row11_witness;
const shared_provider = dependency_0.shared_provider;
const statement_circuit = dependency_0.statement_circuit;
const std = dependency_0.std;
const universal = dependency_0.universal;

/// Cold, proof-independent authority. Every owned object is built once and
/// then borrowed by proof workers at a stable address.
pub const Authority = struct {
    allocator: std.mem.Allocator,
    /// Canonical row-10 schedule owned by this authority.  It is deliberately
    /// not a borrowed pointer into `leaf_owner.Preprocessing`: authorities may
    /// be returned by value or moved into a worker without creating a dangling
    /// self-external reference.  Leaf admission still receives and validates
    /// the complete leaf preprocessing explicitly.
    statement_input_preprocessing: row10_witness.Preprocessed,

    statement_input_definition: row10_air.Definition,
    statement_input_relation: row10_relation.Plan,
    statement_input_executor: row10_witness.Executor,

    circuit: statement_circuit.Circuit,
    statement_semantics_preprocessing: row11_witness.Preprocessed,
    statement_semantics_definition: row11_air.Definition,
    statement_semantics_relation: row11_relation.Plan,
    statement_semantics_executor: row11_witness.Executor,

    lowering_nodes: []graph_mod.Node,
    lowering_graph: graph_mod.CircuitGraph,

    range_definition: range_bridge.Definition,
    range_relation: range_bridge.RelationPlan,
    range_executor: range_bridge.Executor,

    pub fn init(
        allocator: std.mem.Allocator,
        leaf_preprocessing: *const leaf_owner.Preprocessing,
    ) !Authority {
        try leaf_preprocessing.validate();

        var statement_input_preprocessing = try row10_witness.Preprocessed.init(
            allocator,
        );
        errdefer statement_input_preprocessing.deinit();
        if (statement_input_preprocessing.log_size !=
            leaf_preprocessing.statement_input.log_size or
            !row10RowsEql(
                statement_input_preprocessing.rows,
                leaf_preprocessing.statement_input.rows,
            ) or
            !std.mem.eql(
                u8,
                &statement_input_preprocessing.authority_digest,
                &leaf_preprocessing.statement_input.authority_digest,
            ))
        {
            return error.AuthorityMismatch;
        }

        var statement_input_definition = try row10_air.build(allocator);
        errdefer statement_input_definition.deinit();
        const statement_input_binding = try row10_witness.Binding.canonical(
            &statement_input_definition,
        );
        const statement_input_executor = try row10_witness.Executor.init(
            &statement_input_definition,
            &statement_input_binding,
        );
        const statement_input_relation = try row10_relation.authenticate(
            &statement_input_definition,
        );

        var circuit = try statement_circuit.build(allocator);
        errdefer circuit.deinit();
        var statement_semantics_preprocessing = try row11_witness.Preprocessed.init(
            allocator,
            STATEMENT_CIRCUIT_ID,
            circuit.inputBindings(),
        );
        errdefer statement_semantics_preprocessing.deinit();
        var statement_semantics_definition = try row11_air.build(allocator);
        errdefer statement_semantics_definition.deinit();
        const statement_semantics_binding = try row11_witness.Binding.canonical(
            &statement_semantics_definition,
        );
        const statement_semantics_executor = try row11_witness.Executor.init(
            &statement_semantics_definition,
            &statement_semantics_binding,
        );
        const statement_semantics_relation = try row11_relation.authenticate(
            &statement_semantics_definition,
        );

        const lowering_nodes = try allocator.alloc(
            graph_mod.Node,
            circuit.graph().nodes().len,
        );
        errdefer allocator.free(lowering_nodes);
        convertGraphNodes(circuit.graph().nodes(), lowering_nodes);
        const graph_digest = graph_mod.computeGraphDigest(
            lowering_nodes,
            circuit.graph().outputs(),
        );
        if (!std.mem.eql(u8, &graph_digest, &LOWERING_GRAPH_DIGEST))
            return error.GraphDigestMismatch;
        const lowering_graph = try graph_mod.CircuitGraph.authenticate(
            lowering_nodes,
            circuit.graph().outputs(),
            LOWERING_GRAPH_DIGEST,
        );

        var range_definition = try range_bridge.build(allocator);
        errdefer range_definition.deinit();
        const range_binding = try range_bridge.Binding.canonical(&range_definition);
        const range_executor = try range_bridge.Executor.init(
            &range_definition,
            &range_binding,
        );
        const range_relation = try range_bridge.authenticateRelation(
            &range_definition,
        );

        var result = Authority{
            .allocator = allocator,
            .statement_input_preprocessing = statement_input_preprocessing,
            .statement_input_definition = statement_input_definition,
            .statement_input_relation = statement_input_relation,
            .statement_input_executor = statement_input_executor,
            .circuit = circuit,
            .statement_semantics_preprocessing = statement_semantics_preprocessing,
            .statement_semantics_definition = statement_semantics_definition,
            .statement_semantics_relation = statement_semantics_relation,
            .statement_semantics_executor = statement_semantics_executor,
            .lowering_nodes = lowering_nodes,
            .lowering_graph = lowering_graph,
            .range_definition = range_definition,
            .range_relation = range_relation,
            .range_executor = range_executor,
        };
        // Until this function returns, the field-local errdefers above retain
        // ownership.  Do not also deinit `result` on a late validation error:
        // that would free the same allocations twice under OOM injection.
        try result.validate();
        return result;
    }

    pub fn deinit(self: *Authority) void {
        self.range_definition.deinit();
        self.allocator.free(self.lowering_nodes);
        self.statement_semantics_definition.deinit();
        self.statement_semantics_preprocessing.deinit();
        self.circuit.deinit();
        self.statement_input_definition.deinit();
        self.statement_input_preprocessing.deinit();
        self.* = undefined;
    }

    /// Cold exhaustive admission, including the circuit's derived-use audit.
    pub fn validate(self: *const Authority) !void {
        try self.circuit.validate();
        try self.validateSealsInner();
    }

    /// Allocation-free proof-path admission. The expensive derived-use audit
    /// is done once by `init`; this still rechecks all externally mutable
    /// semantic, relation, schedule, provider, and graph seals.
    pub fn validateSeals(self: *const Authority) Error!void {
        self.validateSealsInner() catch return error.AuthorityMismatch;
    }

    fn validateSealsInner(self: *const Authority) !void {
        try self.statement_input_preprocessing.validate();
        try self.statement_input_definition.validate();
        try self.statement_input_relation.validateAgainst(
            &self.statement_input_definition.arena,
            row10_air.SEMANTIC_DIGEST,
            self.statement_input_definition.events.ordered(),
        );
        const row10_binding = try row10_witness.Binding.canonical(
            &self.statement_input_definition,
        );
        if (!std.meta.eql(row10_binding, self.statement_input_executor.binding) or
            !std.mem.eql(
                u8,
                &self.statement_input_executor.binding_digest,
                &row10_witness.BINDING_DIGEST,
            )) return error.AuthorityMismatch;

        if (!std.mem.eql(u8, &self.circuit.identity_digest, &statement_circuit.IDENTITY_DIGEST))
            return error.AuthorityMismatch;
        try self.statement_semantics_preprocessing.validate();
        if (self.statement_semantics_preprocessing.log_size !=
            STATEMENT_SEMANTICS_LOG_SIZE or
            self.statement_semantics_preprocessing.circuit_id !=
                STATEMENT_CIRCUIT_ID)
        {
            return error.AuthorityMismatch;
        }
        try self.statement_semantics_definition.validate();
        try self.statement_semantics_relation.validateAgainst(
            &self.statement_semantics_definition.arena,
            row11_air.SEMANTIC_DIGEST,
            self.statement_semantics_definition.events.ordered(),
        );
        const row11_binding = try row11_witness.Binding.canonical(
            &self.statement_semantics_definition,
        );
        if (!std.meta.eql(row11_binding, self.statement_semantics_executor.binding) or
            !std.mem.eql(
                u8,
                &self.statement_semantics_executor.binding_digest,
                &row11_witness.BINDING_DIGEST,
            )) return error.AuthorityMismatch;

        try self.lowering_graph.validate();
        try validateGraphBridge(self);

        try self.range_definition.validate();
        try self.range_executor.validate();
        try self.range_relation.validateAgainst(
            &self.range_definition.arena,
            range_bridge.SEMANTIC_DIGEST,
            self.range_definition.events,
        );
        try range_owner.SourceAuthority.pinned().validate();

        if (self.statement_input_preprocessing.log_size !=
            STATEMENT_INPUT_LOG_SIZE or
            self.statement_input_preprocessing.rows.len !=
                row10_air.STATEMENT_LANE_COUNT * row10_air.CANONICAL_WORD_COUNT)
        {
            return error.AuthorityMismatch;
        }
    }

    pub fn loweringLane(self: *const Authority) lowering.Lane {
        return .{
            .circuit_id = STATEMENT_CIRCUIT_ID,
            .active_in = .segment,
            .circuit_identity = self.circuit.identity_digest,
            .graph = self.lowering_graph,
        };
    }

    pub fn statementInputGeometry(_: *const Authority) manifest_mod.Geometry {
        return StatementInputAdapter.manifestGeometry(
            .statement_input,
            STATEMENT_INPUT_LOG_SIZE,
        );
    }

    pub fn statementSemanticsGeometry(_: *const Authority) manifest_mod.Geometry {
        return StatementSemanticsAdapter.manifestGeometry(
            .statement_semantics_input,
            STATEMENT_SEMANTICS_LOG_SIZE,
        );
    }

    pub fn rangeGeometry(_: *const Authority) manifest_mod.Geometry {
        return RangeCheckAdapter.manifestGeometry();
    }

    pub fn statementInputComponent(
        self: *const Authority,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        claimed_sum: QM31,
    ) !StatementInputAdapter {
        return StatementInputAdapter.init(
            &self.statement_input_definition,
            self.statement_input_relation,
            manifest,
            .statement_input,
            STATEMENT_INPUT_LOG_SIZE,
            STATEMENT_INPUT_PARAMETERS,
            relations,
            claimed_sum,
        );
    }

    pub fn statementSemanticsComponent(
        self: *const Authority,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        claimed_sum: QM31,
    ) !StatementSemanticsAdapter {
        return StatementSemanticsAdapter.init(
            &self.statement_semantics_definition,
            self.statement_semantics_relation,
            manifest,
            .statement_semantics_input,
            STATEMENT_SEMANTICS_LOG_SIZE,
            STATEMENT_SEMANTICS_PARAMETERS,
            relations,
            claimed_sum,
        );
    }

    pub fn rangeComponent(
        self: *const Authority,
        manifest: *const manifest_mod.Manifest,
        provider_relations: *const shared_provider.SharedProviderRelations,
        relations: *const universal.UniversalRelations,
        claimed_sum: QM31,
    ) !RangeCheckAdapter {
        return RangeCheckAdapter.init(
            &self.range_definition,
            &self.range_executor,
            manifest,
            provider_relations,
            relations,
            claimed_sum,
        );
    }

    pub fn components(
        self: *const Authority,
        manifest: *const manifest_mod.Manifest,
        relations: *const universal.UniversalRelations,
        provider_relations: *const shared_provider.SharedProviderRelations,
        claims: RosterClaims,
    ) !Components {
        return .{
            .statement_input = try self.statementInputComponent(
                manifest,
                relations,
                claims.statement_input,
            ),
            .statement_semantics = try self.statementSemanticsComponent(
                manifest,
                relations,
                claims.statement_semantics,
            ),
            .range_check = try self.rangeComponent(
                manifest,
                provider_relations,
                relations,
                claims.range_check,
            ),
        };
    }

    /// Installs the exact variable logs without touching the other 33 rows.
    pub fn installLogSizes(
        _: *const Authority,
        logs: *[roster.COMPONENT_COUNT]u32,
    ) void {
        logs[@intFromEnum(roster.Component.statement_input)] =
            STATEMENT_INPUT_LOG_SIZE;
        logs[@intFromEnum(roster.Component.statement_semantics_input)] =
            STATEMENT_SEMANTICS_LOG_SIZE;
        logs[@intFromEnum(roster.Component.range_check_8_8)] =
            RANGE_CHECK_LOG_SIZE;
    }
};

/// Binds a complete global Tree-0 slice to these three non-contiguous roster
/// placements. The returned arrays borrow the caller's columns; no allocation
/// or copy occurs.
pub fn bindPreprocessedCommitted(
    authority: *const Authority,
    manifest: *const manifest_mod.Manifest,
    columns: [][]M31,
) !PreprocessedColumns {
    if (columns.len != manifest.total_preprocessed_columns)
        return error.InvalidTraceShape;
    const row10 = try checkedPlacement(
        manifest,
        .statement_input,
        authority.statementInputGeometry(),
    );
    const row11 = try checkedPlacement(
        manifest,
        .statement_semantics_input,
        authority.statementSemanticsGeometry(),
    );
    const row35 = try checkedPlacement(
        manifest,
        .range_check_8_8,
        authority.rangeGeometry(),
    );
    return .{
        .statement_input = try columnWindow(
            row10_witness.PREPROCESSED_COLUMN_COUNT,
            columns,
            row10.preprocessed_offset,
        ),
        .statement_semantics = try columnWindow(
            row11_witness.PREPROCESSED_COLUMN_COUNT,
            columns,
            row11.preprocessed_offset,
        ),
        .range_check = try columnWindow(
            range_bridge.FRAMEWORK_PREPROCESSED_COLUMN_COUNT,
            columns,
            row35.preprocessed_offset,
        ),
    };
}

/// Allocation-free global Tree-1 view in the same roster placements.
pub fn bindMainCommitted(
    authority: *const Authority,
    manifest: *const manifest_mod.Manifest,
    columns: [][]M31,
) !MainColumns {
    if (columns.len != manifest.total_main_columns)
        return error.InvalidTraceShape;
    const row10 = try checkedPlacement(
        manifest,
        .statement_input,
        authority.statementInputGeometry(),
    );
    const row11 = try checkedPlacement(
        manifest,
        .statement_semantics_input,
        authority.statementSemanticsGeometry(),
    );
    const row35 = try checkedPlacement(
        manifest,
        .range_check_8_8,
        authority.rangeGeometry(),
    );
    return .{
        .statement_input = try columnWindow(
            row10_witness.MAIN_COLUMN_COUNT,
            columns,
            row10.main_offset,
        ),
        .statement_semantics = try columnWindow(
            row11_witness.MAIN_COLUMN_COUNT,
            columns,
            row11.main_offset,
        ),
        .range_check = try columnWindow(
            range_bridge.PHYSICAL_MAIN_COLUMN_COUNT,
            columns,
            row35.main_offset,
        ),
    };
}

/// Allocation-free global Tree-2 view. Claims returned by the subsequent fill
/// bind at roster indices 10, 11, and 35 through `Claims.bindInto`.
pub fn bindInteractionsCommitted(
    authority: *const Authority,
    manifest: *const manifest_mod.Manifest,
    columns: [][]M31,
) !InteractionColumns {
    if (columns.len != manifest.total_interaction_columns)
        return error.InvalidTraceShape;
    const row10 = try checkedPlacement(
        manifest,
        .statement_input,
        authority.statementInputGeometry(),
    );
    const row11 = try checkedPlacement(
        manifest,
        .statement_semantics_input,
        authority.statementSemanticsGeometry(),
    );
    const row35 = try checkedPlacement(
        manifest,
        .range_check_8_8,
        authority.rangeGeometry(),
    );
    return .{
        .statement_input = try columnWindow(
            row10_air.INTERACTION_COLUMN_COUNT,
            columns,
            row10.interaction_offset,
        ),
        .statement_semantics = try columnWindow(
            row11_air.INTERACTION_COLUMN_COUNT,
            columns,
            row11.interaction_offset,
        ),
        .range_check = try columnWindow(
            range_bridge.INTERACTION_COLUMN_COUNT,
            columns,
            row35.interaction_offset,
        ),
    };
}

/// Worker-private reusable storage. The row-35 counter and both trace scratch
/// slabs are retained across proofs; every hot fill below is allocation-free.
pub const Workspace = struct {
    allocator: std.mem.Allocator,
    range: range_owner.Workspace,
    logical_storage: []M31,
    secure_storage: []QM31,

    pub fn init(allocator: std.mem.Allocator) !Workspace {
        var range = try range_owner.Workspace.init(allocator);
        errdefer range.deinit(allocator);
        const logical_storage = try allocator.alloc(M31, MAX_LOGICAL_CELLS);
        errdefer allocator.free(logical_storage);
        const secure_storage = try allocator.alloc(QM31, SECURE_SCRATCH_COUNT);
        return .{
            .allocator = allocator,
            .range = range,
            .logical_storage = logical_storage,
            .secure_storage = secure_storage,
        };
    }

    pub fn deinit(self: *Workspace) void {
        self.allocator.free(self.secure_storage);
        self.allocator.free(self.logical_storage);
        self.range.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn validate(self: *const Workspace) !void {
        try self.range.validateGeometry();
        if (self.logical_storage.len != MAX_LOGICAL_CELLS or
            self.secure_storage.len != SECURE_SCRATCH_COUNT)
        {
            return error.InvalidTraceShape;
        }
    }
};

/// Keeps the proof's complete leaf preprocessing in the chain of custody
/// without retaining a move-sensitive borrowed pointer in `Authority`.
pub fn validateStatementInputAuthority(
    authority: *const Authority,
    leaf_preprocessing: *const leaf_owner.Preprocessing,
) !void {
    try leaf_preprocessing.validate();
    const expected = &authority.statement_input_preprocessing;
    const supplied = &leaf_preprocessing.statement_input;
    if (expected.log_size != supplied.log_size or
        !row10RowsEql(expected.rows, supplied.rows) or
        !std.mem.eql(
            u8,
            &expected.authority_digest,
            &supplied.authority_digest,
        ))
    {
        return error.AuthorityMismatch;
    }
}

pub fn baseInputs(inputs: []const QM31, destination: []M31) Error!void {
    if (inputs.len != destination.len) return error.InvalidTraceShape;
    for (inputs, destination) |input, *output| {
        const words = input.toM31Array();
        if (!words[1].isZero() or !words[2].isZero() or !words[3].isZero())
            return error.NonBaseCircuitInput;
        output.* = words[0];
    }
}

pub fn secureSlicesEql(lhs: []const QM31, rhs: []const QM31) bool {
    if (lhs.len != rhs.len) return false;
    for (lhs, rhs) |a, b| if (!a.eql(b)) return false;
    return true;
}

pub fn validateGraphBridge(authority: *const Authority) Error!void {
    const source = authority.circuit.graph();
    if (source.nodes().len != authority.lowering_nodes.len or
        source.outputs().len != authority.lowering_graph.outputs.len or
        !std.mem.eql(u32, source.outputs(), authority.lowering_graph.outputs) or
        !std.mem.eql(
            u8,
            &authority.lowering_graph.identity_digest,
            &LOWERING_GRAPH_DIGEST,
        )) return error.AuthorityMismatch;
    for (source.nodes(), authority.lowering_nodes) |node, converted| {
        var expected: [1]graph_mod.Node = undefined;
        convertGraphNodes(&.{node}, &expected);
        if (!std.meta.eql(expected[0], converted)) return error.AuthorityMismatch;
    }
}

pub fn checkedPlacement(
    manifest: *const manifest_mod.Manifest,
    row: roster.Component,
    expected: manifest_mod.Geometry,
) !manifest_mod.Placement {
    const placement = try manifest.placement(row);
    if (!std.meta.eql(placement.geometry, expected))
        return error.AuthorityMismatch;
    return placement;
}

pub fn columnWindow(
    comptime count: usize,
    columns: [][]M31,
    raw_offset: u32,
) Error![count][]M31 {
    const offset: usize = raw_offset;
    const end = std.math.add(usize, offset, count) catch
        return error.ArithmeticOverflow;
    if (end > columns.len) return error.InvalidTraceShape;
    var result: [count][]M31 = undefined;
    for (&result, 0..) |*column, index|
        column.* = columns[offset + index];
    return result;
}

pub inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return core_utils.bitReverseIndex(
        core_utils.cosetIndexToCircleDomainIndex(logical_row, log_size),
        log_size,
    );
}

pub const MAX_DIRECT_COLUMNS = @max(
    row10_witness.PREPROCESSED_COLUMN_COUNT,
    row11_witness.PREPROCESSED_COLUMN_COUNT,
);
pub const MAX_LOGICAL_CELLS = MAX_DIRECT_COLUMNS * STATEMENT_SEMANTICS_TRACE_SIZE;
pub const ROW10_TERM_COUNT = row10_relation.Runtime.BATCH_COUNT *
    STATEMENT_INPUT_TRACE_SIZE;
pub const ROW11_TERM_COUNT = row11_relation.Runtime.BATCH_COUNT *
    STATEMENT_SEMANTICS_TRACE_SIZE;
pub const RANGE_TERM_COUNT = RANGE_CHECK_TRACE_SIZE;
pub const TOTAL_INTERACTION_TERMS =
    ROW10_TERM_COUNT + ROW11_TERM_COUNT + RANGE_TERM_COUNT;
pub const SECURE_SCRATCH_COUNT = 3 * TOTAL_INTERACTION_TERMS;
