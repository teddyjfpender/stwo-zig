const std = @import("std");
const stwo_core = @import("stwo_core");
const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const relation = @import("../air/lang/relation.zig");
const air = @import("air/segment_publication_input_provider_v2.zig");
const binding = @import("air/segment_publication_input_provider_relation_v2.zig");
const witness = @import("air/segment_publication_input_provider_witness_v2.zig");
const component = @import("air/segment_publication_input_provider_component_v2.zig");
const authority = @import("segment_publication_input_provider_authority_v2.zig");
const exact_support = @import("segment_publication_input_provider_test_support.zig");
const universal = @import("air/universal_challenges.zig");
const boundary_air = @import("segment_leaf_outer_air_v2.zig");
const boundary = @import("segment_leaf_outer_authority_v2.zig");
const leaf_source = @import("segment_leaf_authority_v2.zig");
const public_support = @import("segment_public_outer_test_support.zig");
const public_data_v2 = @import("../air/public_data_v2.zig");
const native_relations = @import("../air/relation_challenges.zig");
const opcode_entries = @import("../air/lookups/opcode_entries.zig");
const statement_v1 = @import("../air/statement.zig");
const statement_v2 = @import("../air/statement_v2.zig");
const trace_mod = @import("../runner/trace.zig");
const vm_air_profile = @import("vm_air_profile.zig");
const vm_leaf_context = @import("vm_leaf_context.zig");

const component_descs = [_]statement_v1.FamilyComponentDesc{
    .{
        .family = .base_alu_reg,
        .log_size = 5,
        .n_rows = 17,
        .n_columns = trace_mod.nColumnsForFamily(.base_alu_reg),
    },
    .{
        .family = .base_alu_imm,
        .log_size = 5,
        .n_rows = 19,
        .n_columns = trace_mod.nColumnsForFamily(.base_alu_imm),
    },
};

const infra_descs = [_]statement_v1.InfraComponentDesc{.{
    .kind = .program,
    .log_size = 5,
    .n_rows = 11,
    .n_columns = 4,
}};

test "publication-input provider pins typed semantic and geometry" {
    try std.testing.expectEqualStrings(
        air.SEMANTIC_DIGEST_HEX,
        &std.fmt.bytesToHex(
            try air.computeSemanticDigest(std.testing.allocator),
            .lower,
        ),
    );
    var definition = try air.build(std.testing.allocator);
    defer definition.deinit();
    try std.testing.expectEqual(
        air.EXPECTED_STATIC_PROFILE,
        try air.staticProfile(&definition),
    );
    const plan = try binding.authenticate(&definition);
    try std.testing.expectEqual(@as(u16, 10), plan.compiled_node_count);
    try std.testing.expectEqual(
        @as(usize, 139),
        witness.LOGICAL_ROW_COUNT,
    );
    try std.testing.expectEqual(@as(u8, 38), component.PROPOSED_ROSTER_ROW);
    try std.testing.expect(authority.SOURCE_AIR_AUTHORITY_AVAILABLE);
    try std.testing.expect(authority.COMMITTED_SOURCE_AVAILABLE);
    try std.testing.expect(authority.ROSTER_INTEGRATION_AVAILABLE);
}

test "capture-backed provider emits exact disjoint 55 and 84 tuple classes" {
    var fixture = try exact_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    const inputs = fixture.inputs();
    const prepared = try witness.preflight(inputs);

    var provider_trace = ProviderTrace{};
    try witness.writeInto(&prepared, provider_trace.destinations());
    for (provider_trace.events) |event| try event.validate();

    var consumes: [witness.LUP2_WORD_COUNT]leaf_source.VerifierInputEventV2 =
        undefined;
    try leaf_source.writeVerifiedNativeVerifierInputEventsInto(
        &fixture.capture.public_logup,
        &consumes,
    );
    for (
        provider_trace.events[0..witness.LUP2_WORD_COUNT],
        consumes,
        0..,
    ) |emit, consume, index| {
        try std.testing.expectEqual(consume.domain, emit.domain);
        try std.testing.expectEqual(@as(@TypeOf(emit.role), .emit), emit.role);
        try std.testing.expectEqual(@as(@TypeOf(consume.role), .consume), consume.role);
        for (consume.tuple, emit.tuple[0..5]) |expected, actual|
            try std.testing.expect(expected.eql(actual));
        try std.testing.expectEqual(@as(u32, @intCast(index)), emit.logical_row);
    }

    var logical_row: usize = witness.LUP2_WORD_COUNT;
    for (fixture.sources.vm_context.detailed_claims, 0..) |claim, item| {
        for (claim.toM31Array(), 0..) |limb, limb_index| {
            const event = provider_trace.events[logical_row];
            try std.testing.expectEqual(air.DETAILED_VERIFIER_ID, event.tuple[0].toU32());
            try std.testing.expectEqual(air.DETAILED_SOURCE_KIND, event.tuple[1].toU32());
            try std.testing.expectEqual(@as(u32, @intCast(item)), event.tuple[2].toU32());
            try std.testing.expectEqual(@as(u32, @intCast(limb_index)), event.tuple[3].toU32());
            try std.testing.expect(limb.eql(event.tuple[4]));
            logical_row += 1;
        }
    }
    try std.testing.expectEqual(witness.LOGICAL_ROW_COUNT, logical_row);
    for (provider_trace.main[0][witness.LOGICAL_ROW_COUNT..]) |word|
        try std.testing.expect(word.isZero());
    for (provider_trace.preprocessed) |column| {
        for (column[witness.LOGICAL_ROW_COUNT..]) |word|
            try std.testing.expect(word.isZero());
    }
}

test "committed provider closes row37 separately and retains row18 residual" {
    var fixture = try exact_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var owner = try authority.AuthorityV2.init(std.testing.allocator);
    defer owner.deinit();
    var workspace = try authority.WorkspaceV2.init(std.testing.allocator);
    defer workspace.deinit();
    var provider_trace = ProviderTrace{};
    var prepared: authority.PreparedAuthorityV2 = undefined;
    try authority.prepareInto(
        &prepared,
        &workspace,
        &owner,
        provider_trace.trace(),
        fixture.inputs(),
        &fixture.outer_relations,
    );
    try prepared.validateAgainst(fixture.inputs(), &fixture.outer_relations);
    try std.testing.expect(
        prepared.lup2_publisher_claim.add(prepared.row37_consumer_claim).isZero(),
    );
    try std.testing.expect(prepared.claimed_sum.eql(
        prepared.lup2_publisher_claim.add(prepared.detailed_publisher_claim),
    ));

    // Row 38 is a single-domain publisher even though its source rows have
    // two independently authenticated tuple classes. Reuse the production
    // plan, rows, inversion workspace, and committed destination to pin that
    // the 55 + 84 split cannot leak a claim into any other universal domain.
    var regenerated_trace = provider_trace.trace();
    const domain_claims = try authority.Framework
        .generatePreparedIntoWithDomainSums(
        &workspace.interaction_workspace,
        &owner.relation_plan,
        &workspace.logical_rows,
        authority.TRACE_LOG_SIZE,
        &fixture.outer_relations,
        &regenerated_trace.interaction,
    );
    try std.testing.expect(domain_claims.claimed_sum.eql(prepared.claimed_sum));
    const expected_domain = @intFromEnum(
        relation.Domain.recursion_verifier_input_word,
    );
    for (domain_claims.by_domain, 0..) |domain_claim, domain_index| {
        if (domain_index == expected_domain) {
            try std.testing.expect(domain_claim.eql(prepared.claimed_sum));
        } else {
            try std.testing.expect(domain_claim.isZero());
        }
    }
    try authority.verifyTrace(
        &prepared,
        &workspace,
        &owner,
        provider_trace.trace(),
        fixture.inputs(),
        &fixture.outer_relations,
    );

    provider_trace.main[0][witness.LUP2_WORD_COUNT] =
        provider_trace.main[0][witness.LUP2_WORD_COUNT].add(M31.one());
    try std.testing.expectError(
        error.TraceMutation,
        authority.verifyTrace(
            &prepared,
            &workspace,
            &owner,
            provider_trace.trace(),
            fixture.inputs(),
            &fixture.outer_relations,
        ),
    );
}

test "both authenticated inputs fail before caller-owned writes" {
    var fixture = try exact_support.Fixture.init(std.testing.allocator);
    defer fixture.deinit();
    var owner = try authority.AuthorityV2.init(std.testing.allocator);
    defer owner.deinit();
    var workspace = try authority.WorkspaceV2.init(std.testing.allocator);
    defer workspace.deinit();
    var provider_trace = ProviderTrace{};
    provider_trace.fill(M31.fromCanonical(77));
    var prepared = sentinelReceipt();
    const trace_before = provider_trace;
    const receipt_before = prepared;

    fixture.sources.vm_context.detailed_claims[0] =
        fixture.sources.vm_context.detailed_claims[0].add(QM31.one());
    try std.testing.expectError(
        error.ContextDigestMismatch,
        authority.prepareInto(
            &prepared,
            &workspace,
            &owner,
            provider_trace.trace(),
            fixture.inputs(),
            &fixture.outer_relations,
        ),
    );
    try std.testing.expectEqualDeep(receipt_before, prepared);
    try std.testing.expectEqualDeep(trace_before, provider_trace);
    fixture.sources.vm_context.detailed_claims[0] =
        fixture.sources.vm_context.detailed_claims[0].sub(QM31.one());

    fixture.capture.identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidPublication,
        authority.prepareInto(
            &prepared,
            &workspace,
            &owner,
            provider_trace.trace(),
            fixture.inputs(),
            &fixture.outer_relations,
        ),
    );
    try std.testing.expectEqualDeep(receipt_before, prepared);
    try std.testing.expectEqualDeep(trace_before, provider_trace);
}

const ProviderTrace = struct {
    preprocessed: [air.PREPROCESSED_COLUMN_COUNT][witness.TRACE_ROW_COUNT]M31 =
        undefined,
    main: [air.PHYSICAL_MAIN_COLUMN_COUNT][witness.TRACE_ROW_COUNT]M31 =
        undefined,
    interaction: [air.INTERACTION_COLUMN_COUNT][witness.TRACE_ROW_COUNT]M31 =
        undefined,
    rows: [witness.LOGICAL_ROW_COUNT]binding.Row = undefined,
    events: [witness.ACTIVE_RELATION_EVENT_COUNT]witness.RelationEventV2 =
        undefined,

    fn destinations(self: *ProviderTrace) witness.DestinationsV2 {
        var preprocessed: [air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&preprocessed, &self.preprocessed) |*destination, *source|
            destination.* = source;
        var main: [air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&main, &self.main) |*destination, *source| destination.* = source;
        return .{
            .main = main,
            .preprocessed = preprocessed,
            .logical_rows = &self.rows,
            .relation_events = &self.events,
        };
    }

    fn trace(self: *ProviderTrace) authority.TraceV2 {
        var preprocessed: [air.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&preprocessed, &self.preprocessed) |*destination, *source|
            destination.* = source;
        var main: [air.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&main, &self.main) |*destination, *source| destination.* = source;
        var interaction: [air.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&interaction, &self.interaction) |*destination, *source|
            destination.* = source;
        return .{
            .preprocessed = preprocessed,
            .main = main,
            .interaction = interaction,
        };
    }

    fn fill(self: *ProviderTrace, value: M31) void {
        for (&self.preprocessed) |*column| @memset(column, value);
        for (&self.main) |*column| @memset(column, value);
        for (&self.interaction) |*column| @memset(column, value);
        @memset(std.mem.asBytes(&self.rows), @as(u8, 0xA5));
        @memset(std.mem.asBytes(&self.events), @as(u8, 0xA5));
    }
};

const Fixture = struct {
    allocator: std.mem.Allocator,
    public_fixture: public_support.Fixture,
    boundary_owner: boundary.AuthorityV2,
    boundary_workspace: boundary.WorkspaceV2,
    boundary_traces: OwnedBoundaryTraces,
    capture: boundary.PreparedNativeVerifierOuterAuthorityV2,
    vm_context: vm_leaf_context.Context,
    outer_relations: universal.UniversalRelations,

    fn init(allocator: std.mem.Allocator) !Fixture {
        var public_fixture = try public_support.Fixture.init(allocator);
        errdefer public_fixture.deinit();
        const receipt = try verifiedReceipt(&public_fixture.owned_public.data);
        var vm_context = try verifiedContext(
            allocator,
            &public_fixture.owned_public.data,
        );
        errdefer vm_context.deinit();
        const shape = try boundary.preflight(
            &public_fixture.owned_public.data,
            &public_fixture.keys,
        );
        var boundary_owner = try boundary.AuthorityV2.init(allocator);
        errdefer boundary_owner.deinit();
        var boundary_workspace = try boundary.WorkspaceV2.init(
            allocator,
            &shape.manifest,
        );
        errdefer boundary_workspace.deinit();
        var boundary_traces = try OwnedBoundaryTraces.init(
            allocator,
            &shape.manifest,
        );
        errdefer boundary_traces.deinit();
        var outer_relations = universal.UniversalRelations.dummy();
        var capture: boundary.PreparedNativeVerifierOuterAuthorityV2 = undefined;
        try boundary.prepareNativeVerifierInto(
            &capture,
            &boundary_workspace,
            &boundary_owner,
            boundary_traces.traces(),
            &public_fixture.owned_public.data,
            &public_fixture.keys,
            &public_fixture.relations,
            &public_fixture.native_sums,
            &receipt,
            &component_descs,
            &infra_descs,
            &outer_relations,
        );
        return .{
            .allocator = allocator,
            .public_fixture = public_fixture,
            .boundary_owner = boundary_owner,
            .boundary_workspace = boundary_workspace,
            .boundary_traces = boundary_traces,
            .capture = capture,
            .vm_context = vm_context,
            .outer_relations = outer_relations,
        };
    }

    fn deinit(self: *Fixture) void {
        self.vm_context.deinit();
        self.boundary_traces.deinit();
        self.boundary_workspace.deinit();
        self.boundary_owner.deinit();
        self.public_fixture.deinit();
        self.* = undefined;
    }

    fn inputs(self: *const Fixture) witness.InputsV2 {
        return .{ .capture = &self.capture, .vm_context = &self.vm_context };
    }
};

const OwnedBoundaryTraces = struct {
    allocator: std.mem.Allocator,
    storage: []M31,
    statement_preprocessed: [boundary_air.Statement.PREPROCESSED_COLUMN_COUNT][]M31,
    statement_main: [boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    statement_interaction: [boundary_air.Statement.INTERACTION_COLUMN_COUNT][]M31,
    public_preprocessed: [boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31,
    public_main: [boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31,
    public_interaction: [boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31,

    fn init(
        allocator: std.mem.Allocator,
        manifest: *const boundary.OuterManifestV2,
    ) !OwnedBoundaryTraces {
        const statement_rows: usize = manifest.components[0].trace_rows;
        const public_rows: usize = manifest.components[1].trace_rows;
        const statement_columns = boundary_air.Statement.PREPROCESSED_COLUMN_COUNT +
            boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT +
            boundary_air.Statement.INTERACTION_COLUMN_COUNT;
        const public_columns = boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT +
            boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT +
            boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT;
        const statement_words = try std.math.mul(
            usize,
            statement_rows,
            statement_columns,
        );
        const public_words = try std.math.mul(
            usize,
            public_rows,
            public_columns,
        );
        const storage = try allocator.alloc(
            M31,
            try std.math.add(usize, statement_words, public_words),
        );
        errdefer allocator.free(storage);
        var at: usize = 0;
        var statement_preprocessed: [boundary_air.Statement.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&statement_preprocessed) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var statement_main: [boundary_air.Statement.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&statement_main) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var statement_interaction: [boundary_air.Statement.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&statement_interaction) |*column| {
            column.* = storage[at..][0..statement_rows];
            at += statement_rows;
        }
        var public_preprocessed: [boundary_air.PublicLogUp.PREPROCESSED_COLUMN_COUNT][]M31 = undefined;
        for (&public_preprocessed) |*column| {
            column.* = storage[at..][0..public_rows];
            at += public_rows;
        }
        var public_main: [boundary_air.PublicLogUp.PHYSICAL_MAIN_COLUMN_COUNT][]M31 = undefined;
        for (&public_main) |*column| {
            column.* = storage[at..][0..public_rows];
            at += public_rows;
        }
        var public_interaction: [boundary_air.PublicLogUp.INTERACTION_COLUMN_COUNT][]M31 = undefined;
        for (&public_interaction) |*column| {
            column.* = storage[at..][0..public_rows];
            at += public_rows;
        }
        std.debug.assert(at == storage.len);
        return .{
            .allocator = allocator,
            .storage = storage,
            .statement_preprocessed = statement_preprocessed,
            .statement_main = statement_main,
            .statement_interaction = statement_interaction,
            .public_preprocessed = public_preprocessed,
            .public_main = public_main,
            .public_interaction = public_interaction,
        };
    }

    fn deinit(self: *OwnedBoundaryTraces) void {
        self.allocator.free(self.storage);
        self.* = undefined;
    }

    fn traces(self: *OwnedBoundaryTraces) boundary.TracesV2 {
        return .{
            .statement = .{
                .preprocessed = self.statement_preprocessed,
                .main = self.statement_main,
                .interaction = self.statement_interaction,
            },
            .public_logup = .{
                .preprocessed = self.public_preprocessed,
                .main = self.public_main,
                .interaction = self.public_interaction,
            },
        };
    }
};

fn verifiedReceipt(
    data: *const public_data_v2.PublicDataV2,
) !statement_v2.VerifiedReceipt {
    var components: [statement_v1.MAX_COMPONENTS]statement_v1.FamilyComponentDesc =
        undefined;
    @memcpy(components[0..component_descs.len], &component_descs);
    var infra: [statement_v1.MAX_INFRA_COMPONENTS]statement_v1.InfraComponentDesc =
        undefined;
    @memcpy(infra[0..infra_descs.len], &infra_descs);
    const core_public = try statement_v2.canonicalCorePublicData(data);
    const core = statement_v1.RiscVStatement{
        .n_components = component_descs.len,
        .component_descs = components,
        .initial_pc = core_public.initial_pc,
        .final_pc = core_public.final_pc,
        .total_steps = core_public.clock,
        .public_data = core_public,
        .n_infra = infra_descs.len,
        .infra_descs = infra,
    };
    const statement = try statement_v2.RiscVStatementV2.init(core, data.*);
    return statement.verifiedReceipt();
}

fn verifiedContext(
    allocator: std.mem.Allocator,
    data: *const public_data_v2.PublicDataV2,
) !vm_leaf_context.Context {
    var statement: statement_v1.RiscVStatement = undefined;
    statement.n_components = component_descs.len;
    @memcpy(statement.component_descs[0..component_descs.len], &component_descs);
    statement.n_infra = infra_descs.len;
    @memcpy(statement.infra_descs[0..infra_descs.len], &infra_descs);
    const core_public = try statement_v2.canonicalCorePublicData(data);
    statement.initial_pc = core_public.initial_pc;
    statement.final_pc = core_public.final_pc;
    statement.total_steps = core_public.clock;
    statement.public_data = core_public;

    var claim: statement_v1.RiscVInteractionClaim = undefined;
    claim.initZeroInto();
    claim.n_components = component_descs.len;
    claim.n_infra = infra_descs.len;
    var next: u32 = 1;
    for (component_descs, 0..) |descriptor, index| {
        for (claim.opcode_claims[index][0..opcode_entries.batchCount(descriptor.family)]) |*slot| {
            slot.* = qm31(next);
            next += 4;
        }
    }
    for (infra_descs, 0..) |descriptor, index| {
        for (0..statement_v1.nClaimedSumsForInfra(descriptor.kind)) |sum| {
            try claim.setInfraClaim(descriptor.kind, index, sum, qm31(next));
            next += 4;
        }
    }
    const component_count = 2 * component_descs.len + infra_descs.len;
    const facts = try allocator.alloc(vm_air_profile.testing.Facts, component_count);
    defer allocator.free(facts);
    try vm_air_profile.testing.expectedFacts(&statement, facts);
    const profile = try vm_air_profile.testing.deriveFromFacts(&statement, facts);
    try std.testing.expectEqual(
        @as(u32, witness.DETAILED_CLAIM_COUNT),
        profile.claimed_sum_count,
    );
    const relations = native_relations.Relations.dummy();
    return vm_leaf_context.testing.initFromProfile(
        allocator,
        &statement,
        &claim,
        &relations,
        profile,
    );
}

fn sentinelReceipt() authority.PreparedAuthorityV2 {
    var result: authority.PreparedAuthorityV2 = undefined;
    @memset(std.mem.asBytes(&result), @as(u8, 0xA5));
    return result;
}

fn qm31(seed: u32) QM31 {
    return QM31.fromU32Unchecked(seed, seed + 1, seed + 2, seed + 3);
}
