//! Internal outer parent statement air source authority shard; use outer_parent_statement_air_source.zig publicly.

const dependency_0 = @import("outer_parent_statement_air_source_contract.zig");

const AddressRange = dependency_0.AddressRange;
const CHILD_COUNT = dependency_0.CHILD_COUNT;
const COMPLETE_PARENT_STARK_VERIFIED = dependency_0.COMPLETE_PARENT_STARK_VERIFIED;
const CURRENT_STATUS = dependency_0.CURRENT_STATUS;
const Error = dependency_0.Error;
const FORMAT_VERSION = dependency_0.FORMAT_VERSION;
const M31 = dependency_0.M31;
const NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS = dependency_0.NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS;
const ParentAirPublicV1 = dependency_0.ParentAirPublicV1;
const ProductionStatus = dependency_0.ProductionStatus;
const QM31 = dependency_0.QM31;
const STATEMENT_CIRCUIT_ID = dependency_0.STATEMENT_CIRCUIT_ID;
const STATEMENT_INPUT_LOG_SIZE = dependency_0.STATEMENT_INPUT_LOG_SIZE;
const STATEMENT_INPUT_PARAMETERS = dependency_0.STATEMENT_INPUT_PARAMETERS;
const STATEMENT_SEMANTICS_LOG_SIZE = dependency_0.STATEMENT_SEMANTICS_LOG_SIZE;
const STATEMENT_SEMANTICS_PARAMETERS = dependency_0.STATEMENT_SEMANTICS_PARAMETERS;
const VerifiedStatementPublicationV1 = dependency_0.VerifiedStatementPublicationV1;
const Workspace = dependency_0.Workspace;
const baseInputs = dependency_0.baseInputs;
const channel = dependency_0.channel;
const fixed_wire = dependency_0.fixed_wire;
const lowering = dependency_0.lowering;
const m31SlicesEql = dependency_0.m31SlicesEql;
const manifest_mod = dependency_0.manifest_mod;
const objectRange = dependency_0.objectRange;
const pair_node = dependency_0.pair_node;
const parent_source = dependency_0.parent_source;
const publicFromParent = dependency_0.publicFromParent;
const range_bridge = dependency_0.range_bridge;
const range_owner = dependency_0.range_owner;
const rejectWorkspaceAliases = dependency_0.rejectWorkspaceAliases;
const relation_interaction = dependency_0.relation_interaction;
const roster = dependency_0.roster;
const row10_air = dependency_0.row10_air;
const row10_relation = dependency_0.row10_relation;
const row10_witness = dependency_0.row10_witness;
const row11_air = dependency_0.row11_air;
const row11_relation = dependency_0.row11_relation;
const row11_witness = dependency_0.row11_witness;
const secureSlicesEql = dependency_0.secureSlicesEql;
const segment_source = dependency_0.segment_source;
const shared_provider = dependency_0.shared_provider;
const sliceRange = dependency_0.sliceRange;
const sourceId = dependency_0.sourceId;
const span_statement = dependency_0.span_statement;
const statementId = dependency_0.statementId;
const statementPublicationId = dependency_0.statementPublicationId;
const statement_circuit = dependency_0.statement_circuit;
const std = dependency_0.std;
const typed_component = dependency_0.typed_component;
const universal = dependency_0.universal;
const validatePublicRecord = dependency_0.validatePublicRecord;
const validatePublications = dependency_0.validatePublications;

/// Validates the parent once and publishes both verifier-owned statements as
/// one failure-atomic transaction.
pub fn publishVerifierStatementsInto(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *[CHILD_COUNT]VerifiedStatementPublicationV1,
    parent: *const parent_source.Prepared(dimensions),
    suite: *const pair_node.PreparedProtocolSuiteV1,
) Error!void {
    try parent.validate(suite);
    try publishVerifierStatementsAfterAuthenticatedParent(
        dimensions,
        destination,
        parent,
    );
}

pub fn publishVerifierStatementsAfterAuthenticatedParent(
    comptime dimensions: fixed_wire.Dimensions,
    destination: *[CHILD_COUNT]VerifiedStatementPublicationV1,
    parent: *const parent_source.Prepared(dimensions),
) Error!void {
    var staged: [CHILD_COUNT]VerifiedStatementPublicationV1 = undefined;
    for (&staged, parent.transcript.children, 0..) |*publication, child, index| {
        const words = child.statement_words;
        const statement = try span_statement.SpanStatement.fromCanonicalWords(&words);
        const public = parent.statement.children[index];
        const custody = parent.witness.custody[index];
        publication.* = .{
            .child_index = @intCast(index),
            .position = public.position,
            .role = public.role,
            .parent_source_id = parent.source_id,
            .profile_id = custody.profile_id,
            .capture_id = custody.capture_id,
            .receipt_id = custody.receipt_id,
            .preprocessed_root = public.preprocessed_root,
            .statement_id = public.statement_id,
            .proof_id = public.proof_id,
            .transcript_id = public.transcript_id,
            .summary_id = public.summary_id,
            .statement = statement,
            .words = words,
            .binding_id = undefined,
        };
        if (!std.meta.eql(statementId(&words), publication.statement_id))
            return error.StatementPublicationMismatch;
        publication.binding_id = statementPublicationId(publication);
        try publication.validateAgainst(parent);
    }
    if (std.meta.eql(staged[0].binding_id, staged[1].binding_id))
        return error.DuplicatePublication;
    destination.* = staged;
}

pub const StatementInputAdapter = typed_component.Component(
    row10_air,
    row10_relation,
);
pub const StatementSemanticsAdapter = typed_component.Component(
    row11_air,
    row11_relation,
);
pub const RangeCheckAdapter = shared_provider.RangeCheck8x8Adapter;

pub const PreprocessedColumns = segment_source.PreprocessedColumns;
pub const MainColumns = segment_source.MainColumns;
pub const InteractionColumns = segment_source.InteractionColumns;
pub const Claims = segment_source.Claims;
pub const RosterClaims = segment_source.RosterClaims;

pub const Components = struct {
    statement_input: StatementInputAdapter,
    statement_semantics: StatementSemanticsAdapter,
    range_check: RangeCheckAdapter,
};

pub const DomainAudits = struct {
    statement_input: relation_interaction.DomainAudit,
    statement_semantics: relation_interaction.DomainAudit,
    range_check: relation_interaction.DomainAudit,
};

pub fn Prepared(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    const ParentPrepared = parent_source.Prepared(dimensions);

    return struct {
        allocator: std.mem.Allocator,
        format_version: u16 = FORMAT_VERSION,
        status: ProductionStatus = CURRENT_STATUS,
        public: ParentAirPublicV1,
        left_statement: span_statement.SpanStatement,
        right_statement: span_statement.SpanStatement,
        parent_statement: span_statement.SpanStatement,
        left_words: span_statement.StatementWords,
        right_words: span_statement.StatementWords,
        parent_words: span_statement.StatementWords,
        circuit_evaluation: statement_circuit.Evaluation,
        statement_values: []M31,
        range: range_owner.Prepared,
        source_id: channel.Digest,

        const Self = @This();

        pub fn productionReady(_: *const Self) bool {
            return NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS and
                COMPLETE_PARENT_STARK_VERIFIED;
        }

        pub fn init(
            allocator: std.mem.Allocator,
            authority: *const segment_source.Authority,
            workspace: *Workspace,
            parent: *const ParentPrepared,
            suite: *const pair_node.PreparedProtocolSuiteV1,
            publications: *const [CHILD_COUNT]VerifiedStatementPublicationV1,
        ) Error!Self {
            authority.validateSeals() catch return error.AuthorityMismatch;
            try workspace.validate();
            try parent.validate(suite);
            return initAfterAuthenticatedParent(
                allocator,
                authority,
                workspace,
                parent,
                publications,
            );
        }

        fn initAfterAuthenticatedParent(
            allocator: std.mem.Allocator,
            authority: *const segment_source.Authority,
            workspace: *Workspace,
            parent: *const ParentPrepared,
            publications: *const [CHILD_COUNT]VerifiedStatementPublicationV1,
        ) Error!Self {
            try validatePublications(parent, publications);

            const parent_statement = try span_statement.SpanStatement.fold(
                publications[0].statement,
                publications[1].statement,
            );
            const parent_words = try parent_statement.canonicalWords();
            if (!std.meta.eql(
                statementId(&parent_words),
                parent.statement.execution_statement_id,
            )) return error.ParentStatementIdMismatch;

            var circuit_evaluation = try authority.circuit.evaluate(
                allocator,
                statement_circuit.Witness.forBinary(
                    &publications[0].words,
                    &publications[1].words,
                    &parent_words,
                ),
            );
            errdefer circuit_evaluation.deinit();
            const statement_values = try allocator.alloc(
                M31,
                statement_circuit.INPUT_COUNT,
            );
            errdefer allocator.free(statement_values);
            try baseInputs(circuit_evaluation.inputs(), statement_values);

            var range = try range_owner.Prepared.init(
                allocator,
                &workspace.range,
                .{
                    .preprocessing = &authority.statement_semantics_preprocessing,
                    .values = statement_values,
                    .left = &publications[0].words,
                    .right = &publications[1].words,
                    .parent = &parent_words,
                },
            );
            errdefer range.deinit();

            var result = Self{
                .allocator = allocator,
                .public = publicFromParent(parent, publications),
                .left_statement = publications[0].statement,
                .right_statement = publications[1].statement,
                .parent_statement = parent_statement,
                .left_words = publications[0].words,
                .right_words = publications[1].words,
                .parent_words = parent_words,
                .circuit_evaluation = circuit_evaluation,
                .statement_values = statement_values,
                .range = range,
                .source_id = undefined,
            };
            result.source_id = sourceId(&result);
            try result.validateAfterAuthenticatedParent(
                authority,
                workspace,
                parent,
                publications,
            );
            return result;
        }

        pub fn deinit(self: *Self) void {
            self.range.deinit();
            self.allocator.free(self.statement_values);
            self.circuit_evaluation.deinit();
            self.* = undefined;
        }

        /// Allocation-free mutation detection and graph replay.
        pub fn validateAgainst(
            self: *const Self,
            authority: *const segment_source.Authority,
            workspace: *Workspace,
            parent: *const ParentPrepared,
            suite: *const pair_node.PreparedProtocolSuiteV1,
            publications: *const [CHILD_COUNT]VerifiedStatementPublicationV1,
        ) Error!void {
            try parent.validate(suite);
            try self.validateAfterAuthenticatedParent(
                authority,
                workspace,
                parent,
                publications,
            );
        }

        fn validateAfterAuthenticatedParent(
            self: *const Self,
            authority: *const segment_source.Authority,
            workspace: *Workspace,
            parent: *const ParentPrepared,
            publications: *const [CHILD_COUNT]VerifiedStatementPublicationV1,
        ) Error!void {
            try self.validateHot(authority, workspace);
            try validatePublications(parent, publications);
            const expected_public = publicFromParent(parent, publications);
            if (!std.meta.eql(self.public, expected_public) or
                !std.meta.eql(self.left_statement, publications[0].statement) or
                !std.meta.eql(self.right_statement, publications[1].statement) or
                !m31SlicesEql(&self.left_words, &publications[0].words) or
                !m31SlicesEql(&self.right_words, &publications[1].words))
            {
                return error.SourceIdentityMismatch;
            }
        }

        /// Allocation-free proof hot-path validation. The expensive native
        /// pair authentication was already completed by `init`; every retained
        /// statement, circuit value, range count, and source seal is replayed
        /// locally without another Poseidon pair-node walk.
        pub fn validateHot(
            self: *const Self,
            authority: *const segment_source.Authority,
            workspace: *Workspace,
        ) Error!void {
            if (self.format_version != FORMAT_VERSION or
                self.status != CURRENT_STATUS or self.public.format_version != FORMAT_VERSION or
                self.public.status != CURRENT_STATUS or self.productionReady())
            {
                return error.ProductionStatusMismatch;
            }
            authority.validateSeals() catch return error.AuthorityMismatch;
            try workspace.validate();
            try rejectWorkspaceAliases(self, workspace);
            try validatePublicRecord(&self.public);
            const expected_parent = try span_statement.SpanStatement.fold(
                self.left_statement,
                self.right_statement,
            );
            const expected_left_words = try self.left_statement.canonicalWords();
            const expected_right_words = try self.right_statement.canonicalWords();
            const expected_parent_words = try expected_parent.canonicalWords();
            if (!std.meta.eql(self.parent_statement, expected_parent) or
                !m31SlicesEql(&self.left_words, &expected_left_words) or
                !m31SlicesEql(&self.right_words, &expected_right_words) or
                !m31SlicesEql(&self.parent_words, &expected_parent_words) or
                !std.meta.eql(statementId(&self.left_words), self.public.child_statement_ids[0]) or
                !std.meta.eql(statementId(&self.right_words), self.public.child_statement_ids[1]) or
                !std.meta.eql(
                    statementId(&expected_parent_words),
                    self.public.execution_statement_id,
                ) or
                !std.meta.eql(self.source_id, sourceId(self)) or
                self.statement_values.len != statement_circuit.INPUT_COUNT or
                !std.mem.eql(
                    u8,
                    &self.circuit_evaluation.circuit_identity,
                    &authority.circuit.identity_digest,
                ) or
                self.circuit_evaluation.inputs().len != statement_circuit.INPUT_COUNT or
                self.circuit_evaluation.values().len != statement_circuit.NODE_COUNT)
            {
                return error.SourceIdentityMismatch;
            }

            const replay = workspace.secure_storage[0 .. statement_circuit.INPUT_COUNT + statement_circuit.NODE_COUNT];
            const replay_inputs = replay[0..statement_circuit.INPUT_COUNT];
            const replay_values = replay[statement_circuit.INPUT_COUNT..];
            try authority.circuit.evaluateIntoAssumeValid(
                statement_circuit.Witness.forBinary(
                    &self.left_words,
                    &self.right_words,
                    &self.parent_words,
                ),
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
            try self.range.validateAgainst(&workspace.range, .{
                .preprocessing = &authority.statement_semantics_preprocessing,
                .values = self.statement_values,
                .left = &self.left_words,
                .right = &self.right_words,
                .parent = &self.parent_words,
            });
        }

        pub fn loweringEvaluation(self: *const Self) lowering.Evaluation {
            return .{
                .circuit_identity = self.circuit_evaluation.circuit_identity,
                .values = self.circuit_evaluation.values(),
            };
        }
    };
}

/// One ownership unit for the complete verified-child -> parent-statement AIR
/// preparation transaction. This is intentionally the only entry point that
/// may reuse a freshly authenticated parent without authenticating it again.
/// The bypass is not exposed as a caller-constructible token: child bundles,
/// authority, verifier-published statements, and the resulting AIR are joined
/// here.
pub fn AuthenticatedPrepared(comptime dimensions: fixed_wire.Dimensions) type {
    dimensions.validate();
    const ParentPrepared = parent_source.Prepared(dimensions);
    const AirPrepared = Prepared(dimensions);
    const Bundle = parent_source.ChildBundle(dimensions);

    return struct {
        parent: ParentPrepared,
        publications: [CHILD_COUNT]VerifiedStatementPublicationV1,
        air: AirPrepared,

        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            authority: *const segment_source.Authority,
            workspace: *Workspace,
            encoding_scratch: []u8,
            parent_inputs: parent_source.AuthorityInputsV1,
            children: [CHILD_COUNT]Bundle,
        ) Error!Self {
            var parent: ParentPrepared = undefined;
            try ParentPrepared.prepareInto(
                &parent,
                encoding_scratch,
                parent_inputs,
                children,
            );

            var publications: [CHILD_COUNT]VerifiedStatementPublicationV1 = undefined;
            try publishVerifierStatementsAfterAuthenticatedParent(
                dimensions,
                &publications,
                &parent,
            );
            var air = try AirPrepared.initAfterAuthenticatedParent(
                allocator,
                authority,
                workspace,
                &parent,
                &publications,
            );
            errdefer air.deinit();
            return .{
                .parent = parent,
                .publications = publications,
                .air = air,
            };
        }

        pub fn deinit(self: *Self) void {
            self.air.deinit();
            self.* = undefined;
        }

        /// Allocation-free cold revalidation. The parent source is rebuilt
        /// from exact custody inputs once, then the retained AIR is checked
        /// against that authenticated local without a second pair walk.
        pub fn validateAgainst(
            self: *const Self,
            authority: *const segment_source.Authority,
            workspace: *Workspace,
            encoding_scratch: []u8,
            parent_inputs: parent_source.AuthorityInputsV1,
            children: [CHILD_COUNT]Bundle,
        ) Error!void {
            try self.parent.validateAgainst(
                encoding_scratch,
                parent_inputs,
                children,
            );
            try self.air.validateAfterAuthenticatedParent(
                authority,
                workspace,
                &self.parent,
                &self.publications,
            );
        }

        pub fn validateHot(
            self: *const Self,
            authority: *const segment_source.Authority,
            workspace: *Workspace,
        ) Error!void {
            try self.air.validateHot(authority, workspace);
        }
    };
}

pub fn loweringLane(authority: *const segment_source.Authority) lowering.Lane {
    return .{
        .circuit_id = STATEMENT_CIRCUIT_ID,
        .active_in = .binary,
        .circuit_identity = authority.circuit.identity_digest,
        .graph = authority.lowering_graph,
    };
}

pub fn installLogSizes(
    authority: *const segment_source.Authority,
    logs: *[roster.COMPONENT_COUNT]u32,
) void {
    authority.installLogSizes(logs);
}

pub fn statementInputComponent(
    authority: *const segment_source.Authority,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    claimed_sum: QM31,
) !StatementInputAdapter {
    return StatementInputAdapter.init(
        &authority.statement_input_definition,
        authority.statement_input_relation,
        manifest,
        .statement_input,
        STATEMENT_INPUT_LOG_SIZE,
        STATEMENT_INPUT_PARAMETERS,
        relations,
        claimed_sum,
    );
}

pub fn statementSemanticsComponent(
    authority: *const segment_source.Authority,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    claimed_sum: QM31,
) !StatementSemanticsAdapter {
    return StatementSemanticsAdapter.init(
        &authority.statement_semantics_definition,
        authority.statement_semantics_relation,
        manifest,
        .statement_semantics_input,
        STATEMENT_SEMANTICS_LOG_SIZE,
        STATEMENT_SEMANTICS_PARAMETERS,
        relations,
        claimed_sum,
    );
}

pub fn components(
    authority: *const segment_source.Authority,
    manifest: *const manifest_mod.Manifest,
    relations: *const universal.UniversalRelations,
    provider_relations: *const shared_provider.SharedProviderRelations,
    claims: RosterClaims,
) !Components {
    return .{
        .statement_input = try statementInputComponent(
            authority,
            manifest,
            relations,
            claims.statement_input,
        ),
        .statement_semantics = try statementSemanticsComponent(
            authority,
            manifest,
            relations,
            claims.statement_semantics,
        ),
        .range_check = try authority.rangeComponent(
            manifest,
            provider_relations,
            relations,
            claims.range_check,
        ),
    };
}

pub fn bindPreprocessedCommitted(
    authority: *const segment_source.Authority,
    manifest: *const manifest_mod.Manifest,
    columns: [][]M31,
) !PreprocessedColumns {
    return segment_source.bindPreprocessedCommitted(authority, manifest, columns);
}

pub fn bindMainCommitted(
    authority: *const segment_source.Authority,
    manifest: *const manifest_mod.Manifest,
    columns: [][]M31,
) !MainColumns {
    return segment_source.bindMainCommitted(authority, manifest, columns);
}

pub fn bindInteractionsCommitted(
    authority: *const segment_source.Authority,
    manifest: *const manifest_mod.Manifest,
    columns: [][]M31,
) !InteractionColumns {
    return segment_source.bindInteractionsCommitted(authority, manifest, columns);
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

pub inline fn committedRow(logical_row: usize, log_size: u32) usize {
    return segment_source.committedRow(logical_row, log_size);
}

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
    for (columns.*) |column| {
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

pub fn rejectAuthorityAliases(
    destinations: []const AddressRange,
    authority: *const segment_source.Authority,
) Error!void {
    const protected = [_]AddressRange{
        try objectRange(authority),
        try sliceRange(row10_witness.Row, authority.statement_input_preprocessing.rows),
        try sliceRange(row11_witness.Row, authority.statement_semantics_preprocessing.rows),
    };
    for (destinations) |destination| for (protected) |source| {
        if (destination.overlaps(source)) return error.AliasedInput;
    };
}
pub const TOTAL_PREPROCESSED_COLUMNS = row10_witness.PREPROCESSED_COLUMN_COUNT +
    row11_witness.PREPROCESSED_COLUMN_COUNT +
    range_bridge.FRAMEWORK_PREPROCESSED_COLUMN_COUNT;
