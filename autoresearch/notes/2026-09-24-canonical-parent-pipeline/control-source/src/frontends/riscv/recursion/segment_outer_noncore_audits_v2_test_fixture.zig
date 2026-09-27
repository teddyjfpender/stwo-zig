//! Focused shard of segment_outer_noncore_audits_v2_test.zig; import that suite facade.

const dependency_0 = @import("segment_outer_noncore_audits_v2_test_owned_boundary_traces.zig");

const InputProviderTrace = dependency_0.InputProviderTrace;
const OwnedBoundaryTraces = dependency_0.OwnedBoundaryTraces;
const OwnedStatementDestinations = dependency_0.OwnedStatementDestinations;
const OwnedTree = dependency_0.OwnedTree;
const QM31 = dependency_0.QM31;
const boundary_authority = dependency_0.boundary_authority;
const buildManifest = dependency_0.buildManifest;
const channel = dependency_0.channel;
const config = dependency_0.config;
const copyBoundaryTree2 = dependency_0.copyBoundaryTree2;
const copyInputProviderTree2 = dependency_0.copyInputProviderTree2;
const copyRangeTree2 = dependency_0.copyRangeTree2;
const input_provider_authority = dependency_0.input_provider_authority;
const input_provider_support = dependency_0.input_provider_support;
const manifest_mod = dependency_0.manifest_mod;
const public_components = dependency_0.public_components;
const public_data_support = dependency_0.public_data_support;
const public_source = dependency_0.public_source;
const public_support = dependency_0.public_support;
const qm31 = dependency_0.qm31;
const range_authority = dependency_0.range_authority;
const range_bridge = dependency_0.range_bridge;
const relation = dependency_0.relation;
const relation_interaction = dependency_0.relation_interaction;
const schedule = dependency_0.schedule;
const shared_provider = dependency_0.shared_provider;
const statement_components = dependency_0.statement_components;
const statement_source = dependency_0.statement_source;
const std = dependency_0.std;
const subject = dependency_0.subject;
const testPlan = dependency_0.testPlan;
const transcript = dependency_0.transcript;
const transcript_components = dependency_0.transcript_components;
const transcript_source = dependency_0.transcript_source;
const universal = dependency_0.universal;

test "non-core custody rebuilds and installs the exact 22 Tree-2 rows" {
    const fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    var audits = [_]relation_interaction.DomainAudit{zeroAudit()} **
        subject.COMPONENT_COUNT;
    var claims = [_]QM31{qm31(900)} ** subject.COMPONENT_COUNT;
    const core_claim_sentinel = qm31(900);
    var occupied = subject.CORE_ROW_MASK;
    const receipt = try subject.rebuildAndInstall(
        std.testing.allocator,
        fixture.inputs(),
        &audits,
        &claims,
        &occupied,
    );
    try subject.validateAgainstInputs(
        &receipt,
        std.testing.allocator,
        fixture.inputs(),
    );
    try std.testing.expectEqual(subject.ALL_ROW_MASK, occupied);
    try std.testing.expectEqual(subject.NONCORE_ROW_MASK, receipt.row_mask);

    for (subject.NONCORE_ROW_INDICES, receipt.rows, receipt.claims) |
        row,
        audit,
        claim,
    | {
        try std.testing.expectEqualDeep(audit, audits[row]);
        try std.testing.expect(claim.eql(claims[row]));
        try std.testing.expect(audit.total.eql(claim));
    }
    for (subject.CORE_FIRST_ROW..subject.CORE_LAST_ROW + 1) |row| {
        try std.testing.expectEqualDeep(zeroAudit(), audits[row]);
        try std.testing.expect(claims[row].eql(core_claim_sentinel));
    }

    var recomputed = [_]QM31{QM31.zero()} ** subject.DOMAIN_COUNT;
    for (receipt.rows) |audit| {
        for (audit.values, 0..) |value, domain|
            recomputed[domain] = recomputed[domain].add(value);
    }
    try std.testing.expectEqualDeep(recomputed, receipt.domain_residuals);

    // The receipt's claims are those in the actual non-core Tree-2 writers,
    // including the native row-35 table and both capture-backed boundary rows.
    const row35_final = range_bridge.committedRow(range_bridge.TABLE_SIZE - 1);
    const row35_placement = fixture.manifest.placements[35].?;
    const row35_tree_claim = QM31.fromM31(
        fixture.tree2.columns[row35_placement.interaction_offset + 0][row35_final],
        fixture.tree2.columns[row35_placement.interaction_offset + 1][row35_final],
        fixture.tree2.columns[row35_placement.interaction_offset + 2][row35_final],
        fixture.tree2.columns[row35_placement.interaction_offset + 3][row35_final],
    );
    try std.testing.expect(row35_tree_claim.eql(try receipt.claimAt(35)));

    // Row 17 is the exact schedule-derived VM public LogUp control owner: 70
    // public accumulation steps plus one global-zero assertion. Its two typed
    // effects account for 142 audit terms, while sparse multiplicities leave
    // 72 active relation events (71 step consumes and one external wire
    // consume). The row must retain both domains instead of collapsing them
    // into the legacy one-row relay geometry.
    const row17 = try receipt.auditAt(17);
    try std.testing.expectEqual(subject.ROW17_LOGICAL_ROWS, row17.logical_rows);
    try std.testing.expectEqual(
        subject.ROW17_TYPED_EVENT_TERMS,
        row17.event_terms,
    );
    try std.testing.expectEqual(@as(usize, 72), subject.ROW17_ACTIVE_RELATION_EVENTS);
    try std.testing.expect(row17.values[
        @intFromEnum(relation.Domain.recursion_step)
    ].add(row17.values[
        @intFromEnum(relation.Domain.recursion_wire)
    ]).eql(row17.total));
    try std.testing.expect(
        (try receipt.claimAt(17)).eql(fixture.public_claims.control_relay),
    );
}

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    public_fixture: public_support.Fixture,
    plan: schedule.Plan,
    program: transcript.Program,
    execution: transcript.Execution,
    transcript_prepared: transcript_source.PreparedV2,
    statement_destinations: OwnedStatementDestinations,
    statement_source_authority: statement_source.AuthorityV2,
    statement_prepared: statement_source.PreparedV2,
    public_prepared: public_source.PreparedV2,
    boundary_authority: boundary_authority.AuthorityV2,
    boundary_workspace: boundary_authority.WorkspaceV2,
    boundary_traces: OwnedBoundaryTraces,
    boundary_prepared: boundary_authority.PreparedNativeVerifierOuterAuthorityV2,
    input_provider_sources: input_provider_support.VerifiedSources,
    input_provider_owner: input_provider_authority.AuthorityV2,
    input_provider_workspace: *input_provider_authority.WorkspaceV2,
    input_provider_trace: *InputProviderTrace,
    input_provider_prepared: input_provider_authority.PreparedAuthorityV2,
    manifest: manifest_mod.Manifest,
    transcript_owner: transcript_components.Source,
    transcript_workspace: transcript_components.Workspace,
    statement_owner: statement_components.AuthorityV2,
    statement_workspace: statement_components.WorkspaceV2,
    public_owner: public_components.Source,
    public_workspace: public_components.Workspace,
    relations: universal.UniversalRelations,
    provider_relations: shared_provider.SharedProviderRelations,
    range_workspace: range_authority.WorkspaceV2,
    range_prepared: range_authority.PreparedV2,
    range_owner: range_authority.ProviderAuthorityV2,
    range_interaction: range_authority.ProviderInteractionV2,
    tree2: OwnedTree,
    transcript_claims: transcript_components.Claims,
    statement_claims: statement_components.ClaimsV2,
    public_claims: public_components.Claims,

    pub fn init(allocator: std.mem.Allocator) !*Fixture {
        const self = try allocator.create(Fixture);
        errdefer allocator.destroy(self);
        self.allocator = allocator;
        self.public_fixture = try public_support.Fixture.init(allocator);
        errdefer self.public_fixture.deinit();
        self.plan = try testPlan(allocator);
        errdefer self.plan.deinit();
        self.program = try transcript.Program.init(
            allocator,
            &self.plan,
            config,
            &self.public_fixture.owned_public.data,
            &public_support.component_descs,
            &public_support.infra_descs,
        );
        errdefer self.program.deinit();
        const trace_commitments = [_]channel.Digest{
            public_data_support.id("noncore-tree-0"),
            public_data_support.id("noncore-tree-1"),
            public_data_support.id("noncore-tree-2"),
            public_data_support.id("noncore-tree-3"),
        };
        var native_claims: [transcript.COMPONENT_CLAIM_COUNT]QM31 = undefined;
        for (&native_claims, 0..) |*value, index| value.* = qm31(index + 10);
        var sampled_values: [3]QM31 = undefined;
        for (&sampled_values, 0..) |*value, index| value.* = qm31(index + 100);
        const fri_commitments = [_]channel.Digest{
            public_data_support.id("noncore-fri-0"),
            public_data_support.id("noncore-fri-1"),
            public_data_support.id("noncore-fri-2"),
            public_data_support.id("noncore-fri-3"),
        };
        const coefficients = [_]QM31{qm31(200)};
        self.execution = try transcript.execute(
            allocator,
            &self.program,
            &self.public_fixture.owned_public.data,
            .{
                .trace_commitments = &trace_commitments,
                .interaction_pow = 0,
                .claimed_sums = &native_claims,
                .sampled_values = &sampled_values,
                .fri_commitments = &fri_commitments,
                .last_layer_coefficients = &coefficients,
                .pcs_pow = 0,
            },
        );
        errdefer self.execution.deinit();
        const evidence = try self.execution.evidence(&self.program);
        self.transcript_prepared = try transcript_source.preflight(
            &self.program,
            &self.execution,
            &evidence,
            &self.plan,
            config,
            &self.public_fixture.owned_public.data,
            &public_support.component_descs,
            &public_support.infra_descs,
        );

        const statement_manifest = try statement_source.preflight(
            &self.public_fixture.owned_public.data,
            &self.public_fixture.source_prepared,
            &self.transcript_prepared,
            self.program.statement_authority_id,
        );
        self.statement_destinations = try OwnedStatementDestinations.init(
            allocator,
            statement_manifest,
        );
        errdefer self.statement_destinations.deinit();
        self.statement_source_authority = try statement_source.AuthorityV2.init(
            allocator,
        );
        errdefer self.statement_source_authority.deinit();
        var statement_source_workspace = statement_source.WorkspaceV2{};
        self.statement_prepared = undefined;
        try statement_source.prepareInto(
            &self.statement_prepared,
            &statement_source_workspace,
            &self.statement_source_authority,
            self.statement_destinations.destinations(),
            &self.public_fixture.owned_public.data,
            &self.public_fixture.source_prepared,
            &self.transcript_prepared,
            self.program.statement_authority_id,
        );
        self.public_prepared = try public_source.preflight(
            self.public_fixture.inputs(),
        );

        const boundary_shape = try boundary_authority.preflight(
            &self.public_fixture.owned_public.data,
            &self.public_fixture.keys,
        );
        self.boundary_authority = try boundary_authority.AuthorityV2.init(
            allocator,
        );
        errdefer self.boundary_authority.deinit();
        self.boundary_workspace = try boundary_authority.WorkspaceV2.init(
            allocator,
            &boundary_shape.manifest,
        );
        errdefer self.boundary_workspace.deinit();
        self.boundary_traces = try OwnedBoundaryTraces.init(
            allocator,
            &boundary_shape.manifest,
        );
        errdefer self.boundary_traces.deinit();
        self.relations = universal.UniversalRelations.dummy();
        self.input_provider_sources = try input_provider_support.VerifiedSources.init(
            allocator,
            &self.public_fixture.owned_public.data,
        );
        errdefer self.input_provider_sources.deinit();
        self.boundary_prepared =
            undefined;
        try boundary_authority.prepareNativeVerifierInto(
            &self.boundary_prepared,
            &self.boundary_workspace,
            &self.boundary_authority,
            self.boundary_traces.traces(),
            &self.public_fixture.owned_public.data,
            &self.public_fixture.keys,
            &self.public_fixture.relations,
            &self.public_fixture.native_sums,
            &self.input_provider_sources.receipt,
            &input_provider_support.component_descs,
            &input_provider_support.infra_descs,
            &self.relations,
        );

        self.input_provider_owner =
            try input_provider_authority.AuthorityV2.init(allocator);
        errdefer self.input_provider_owner.deinit();
        self.input_provider_workspace =
            try allocator.create(input_provider_authority.WorkspaceV2);
        errdefer allocator.destroy(self.input_provider_workspace);
        self.input_provider_workspace.* =
            try input_provider_authority.WorkspaceV2.init(allocator);
        errdefer self.input_provider_workspace.deinit();
        self.input_provider_trace = try allocator.create(InputProviderTrace);
        errdefer allocator.destroy(self.input_provider_trace);
        self.input_provider_trace.* = .{};
        self.input_provider_prepared = undefined;
        try input_provider_authority.prepareInto(
            &self.input_provider_prepared,
            self.input_provider_workspace,
            &self.input_provider_owner,
            self.input_provider_trace.trace(),
            .{
                .capture = &self.boundary_prepared,
                .vm_context = &self.input_provider_sources.vm_context,
            },
            &self.relations,
        );

        self.manifest = try buildManifest(
            &self.transcript_prepared,
            &self.statement_prepared,
            &self.public_prepared,
            &self.boundary_prepared,
        );
        try manifest_mod.validateAgainstSources(
            &self.manifest,
            &self.transcript_prepared.manifest,
            &self.statement_prepared.manifest,
            &self.public_prepared.manifest,
            &self.boundary_prepared.manifest,
        );
        self.transcript_owner = try transcript_components.Source.init(
            allocator,
            &self.transcript_prepared,
            &self.manifest,
        );
        errdefer self.transcript_owner.deinit();
        self.transcript_workspace = try transcript_components.Workspace.init(
            allocator,
            &self.transcript_prepared,
        );
        errdefer self.transcript_workspace.deinit();
        try self.transcript_workspace.prepare(
            &self.transcript_owner,
            &self.transcript_prepared,
            &self.manifest,
            .{
                .program = &self.program,
                .execution = &self.execution,
                .evidence = &evidence,
                .plan = &self.plan,
                .pcs_config = config,
                .data = &self.public_fixture.owned_public.data,
                .component_descs = &public_support.component_descs,
                .infra_descs = &public_support.infra_descs,
            },
        );
        self.statement_owner = try statement_components.AuthorityV2.init(
            allocator,
        );
        errdefer self.statement_owner.deinit();
        self.statement_workspace = try statement_components.WorkspaceV2.init(
            allocator,
            &self.statement_prepared,
        );
        errdefer self.statement_workspace.deinit();
        self.public_owner = try public_components.Source.init(
            allocator,
            &self.public_prepared,
            &self.manifest,
        );
        errdefer self.public_owner.deinit();
        self.public_workspace = try public_components.Workspace.init(
            allocator,
            &self.public_prepared,
        );
        errdefer self.public_workspace.deinit();
        try self.public_workspace.prepare(
            &self.public_owner,
            &self.public_prepared,
            &self.manifest,
            self.public_fixture.inputs(),
        );

        self.tree2 = try OwnedTree.init(allocator, &self.manifest);
        errdefer self.tree2.deinit();
        self.transcript_claims = try transcript_components.fillInteractionInto(
            &self.transcript_owner,
            &self.transcript_workspace,
            &self.transcript_prepared,
            &self.manifest,
            &self.relations,
            self.tree2.columns,
        );
        self.statement_claims = try statement_components.fillInteractionInto(
            &self.statement_owner,
            &self.statement_workspace,
            &self.statement_prepared,
            self.statement_destinations.logical_rows,
            &self.manifest,
            &self.relations,
            self.tree2.columns,
        );
        self.public_claims = try public_components.fillInteractionInto(
            &self.public_owner,
            &self.public_workspace,
            &self.public_prepared,
            &self.manifest,
            &self.relations,
            self.tree2.columns,
        );

        self.range_workspace = try range_authority.WorkspaceV2.init(allocator);
        errdefer self.range_workspace.deinit(allocator);
        const range_sources = range_authority.SourcesV2{
            .statement = &self.statement_prepared,
            .logical_rows = self.statement_destinations.logical_rows,
        };
        self.range_prepared = try range_authority.PreparedV2.init(
            allocator,
            &self.range_workspace,
            range_sources,
        );
        errdefer self.range_prepared.deinit();
        self.provider_relations = try shared_provider.SharedProviderRelations.init(
            &self.relations,
        );
        self.range_interaction = try self.range_prepared.generateProviderInteraction(
            allocator,
            &self.provider_relations,
        );
        errdefer self.range_interaction.deinit();
        self.range_owner = try range_authority.ProviderAuthorityV2.init(allocator);
        errdefer self.range_owner.deinit();

        copyRangeTree2(&self.tree2, &self.manifest, &self.range_interaction);
        copyBoundaryTree2(&self.tree2, &self.manifest, &self.boundary_traces);
        copyInputProviderTree2(&self.tree2, &self.manifest, self.input_provider_trace);

        return self;
    }

    pub fn deinit(self: *Fixture) void {
        self.range_interaction.deinit();
        self.range_owner.deinit();
        self.range_prepared.deinit();
        self.range_workspace.deinit(self.allocator);
        self.tree2.deinit();
        self.public_workspace.deinit();
        self.public_owner.deinit();
        self.statement_workspace.deinit();
        self.statement_owner.deinit();
        self.transcript_workspace.deinit();
        self.transcript_owner.deinit();
        self.boundary_traces.deinit();
        self.boundary_workspace.deinit();
        self.boundary_authority.deinit();
        self.input_provider_workspace.deinit();
        self.allocator.destroy(self.input_provider_workspace);
        self.allocator.destroy(self.input_provider_trace);
        self.input_provider_owner.deinit();
        self.input_provider_sources.deinit();
        self.statement_source_authority.deinit();
        self.statement_destinations.deinit();
        self.execution.deinit();
        self.program.deinit();
        self.plan.deinit();
        self.public_fixture.deinit();
        const allocator = self.allocator;
        self.* = undefined;
        allocator.destroy(self);
    }

    pub fn inputs(self: *const Fixture) subject.InputsV2 {
        return .{
            .manifest = &self.manifest,
            .relations = &self.relations,
            .transcript = .{
                .owner = &self.transcript_owner,
                .workspace = &self.transcript_workspace,
                .prepared = &self.transcript_prepared,
                .claims = self.transcript_claims,
            },
            .statement = .{
                .authority = &self.statement_owner,
                .prepared = &self.statement_prepared,
                .logical_rows = self.statement_destinations.logical_rows,
                .claims = self.statement_claims,
            },
            .public = .{
                .owner = &self.public_owner,
                .workspace = &self.public_workspace,
                .prepared = &self.public_prepared,
                .claims = self.public_claims,
            },
            .range = .{
                .authority = &self.range_owner,
                .prepared = &self.range_prepared,
                .sources = .{
                    .statement = &self.statement_prepared,
                    .logical_rows = self.statement_destinations.logical_rows,
                },
                .provider_relations = &self.provider_relations,
                .interaction = &self.range_interaction,
            },
            .boundary = .{
                .authority = &self.boundary_authority,
                .prepared = &self.boundary_prepared,
            },
            .verifier_input_provider = .{
                .authority = &self.input_provider_owner,
                .prepared = &self.input_provider_prepared,
                .vm_context = &self.input_provider_sources.vm_context,
            },
        };
    }
};

pub fn zeroAudit() relation_interaction.DomainAudit {
    return .{
        .values = [_]QM31{QM31.zero()} ** subject.DOMAIN_COUNT,
        .total = QM31.zero(),
        .logical_rows = 0,
        .event_terms = 0,
    };
}

pub fn noncoreIndex(row: u8) ?usize {
    for (subject.NONCORE_ROW_INDICES, 0..) |candidate, index|
        if (candidate == row) return index;
    return null;
}
