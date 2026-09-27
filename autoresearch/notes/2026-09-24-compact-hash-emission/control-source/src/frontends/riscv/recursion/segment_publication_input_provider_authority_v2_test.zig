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
const leaf_source = @import("segment_leaf_authority_v2.zig");
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
    for (provider_trace.events) |event| try event.validate(prepared.shape);

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
        workspace.logical_rows,
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

test "publication provider preserves all 88 retained segment claims and rejects source mutation" {
    const allocator = std.testing.allocator;
    const support = @import("ethereum_leaf_context_v1_test_support.zig");
    var fixture = try exact_support.Fixture.initWithCore(allocator, support.retainedSegmentZeroCore());
    defer fixture.deinit();
    const source = try witness.preflight(fixture.inputs());
    try std.testing.expectEqual(@as(u32, 88), source.shape.claim_count);
    try std.testing.expectEqual(@as(u32, 407), source.shape.logical_row_count);
    try std.testing.expectEqual(@as(usize, 512), source.shape.traceRowCount());
    var owner = try authority.AuthorityV2.init(allocator);
    defer owner.deinit();
    var workspace = try authority.WorkspaceV2.initForShape(allocator, source.shape);
    defer workspace.deinit();
    var output = try authority.WorkspaceV2.initForShape(allocator, source.shape);
    defer output.deinit();
    var prepared: authority.PreparedAuthorityV2 = undefined;
    try authority.prepareInto(&prepared, &workspace, &owner, output.stagedTrace(), fixture.inputs(), &fixture.outer_relations);
    try authority.verifyTrace(&prepared, &workspace, &owner, output.stagedTrace(), fixture.inputs(), &fixture.outer_relations);
    try std.testing.expectError(error.AliasedDestination, authority.verifyTrace(&prepared, &workspace, &owner, workspace.stagedTrace(), fixture.inputs(), &fixture.outer_relations));
    var row: usize = witness.LUP2_WORD_COUNT;
    for (source.detailed_claims) |claim| {
        for (claim.toM31Array()) |limb| {
            try std.testing.expect(limb.eql(output.stagedTrace().main[0][row]));
            try workspace.relation_events[row].validate(source.shape);
            row += 1;
        }
    }
    try std.testing.expectEqual(source.shape.logical_row_count, row);
    for (output.stagedTrace().main[0][row..]) |word| try std.testing.expect(word.isZero());

    const output_before = try allocator.dupe(M31, output.storage);
    defer allocator.free(output_before);
    fixture.sources.vm_context.detailed_claims[87] = fixture.sources.vm_context.detailed_claims[87].add(QM31.one());
    try std.testing.expectError(error.InvalidPreparedSource, witness.writeInto(&source, .{
        .main = output.stagedTrace().main,
        .preprocessed = output.stagedTrace().preprocessed,
        .logical_rows = output.logical_rows,
        .relation_events = output.relation_events,
    }));
    try std.testing.expectEqualSlices(M31, output_before, output.storage);
    fixture.sources.vm_context.detailed_claims[87] = fixture.sources.vm_context.detailed_claims[87].sub(QM31.one());

    var wrong_workspace = try authority.WorkspaceV2.init(allocator);
    defer wrong_workspace.deinit();
    const prepared_before = prepared;
    try std.testing.expectError(error.WorkspaceMismatch, authority.prepareInto(&prepared, &wrong_workspace, &owner, output.stagedTrace(), fixture.inputs(), &fixture.outer_relations));
    try std.testing.expectEqualDeep(prepared_before, prepared);
    try std.testing.expectEqualSlices(M31, output_before, output.storage);

    const logical_rows = workspace.logical_rows;
    workspace.logical_rows = std.mem.bytesAsSlice(binding.Row, std.mem.sliceAsBytes(workspace.storage[0 .. logical_rows.len * air.LOGICAL_INPUT_COUNT]));
    defer workspace.logical_rows = logical_rows;
    try std.testing.expectError(error.AliasedDestination, authority.prepareInto(&prepared, &workspace, &owner, output.stagedTrace(), fixture.inputs(), &fixture.outer_relations));
    try std.testing.expectEqualDeep(prepared_before, prepared);
    try std.testing.expectEqualSlices(M31, output_before, output.storage);
}

test "publication provider rejects independently valid context for another segment" {
    const allocator = std.testing.allocator;
    var fixture = try exact_support.Fixture.init(allocator);
    defer fixture.deinit();
    const public_support = @import("../air/public_data_v2_test_support.zig");
    const public_data = @import("../air/public_data_v2.zig");
    const other_fixture = try public_support.Fixture.init();
    const other_source = other_fixture.leftSource();
    const words = try public_support.encode(allocator, &other_source);
    defer allocator.free(words);
    const other_public = try public_data.PublicDataV2.authenticate(words);
    var context = try exact_support.verifiedContext(allocator, &other_public);
    defer context.deinit();
    try context.validate();
    try fixture.capture.validate();
    try std.testing.expectEqual(fixture.sources.vm_context.detailed_claims.len, context.detailed_claims.len);
    try std.testing.expectError(error.InvalidInputPair, witness.preflight(.{
        .capture = &fixture.capture,
        .vm_context = &context,
    }));
}

test "publication provider releases partial workspace allocations and bounds shape" {
    try std.testing.expectError(error.InvalidInputPair, authority.Shape.init(0));
    try std.testing.expectError(error.InvalidInputPair, authority.Shape.init(std.math.maxInt(usize)));
    const Check = struct {
        fn run(allocator: std.mem.Allocator) !void {
            var workspace = try authority.WorkspaceV2.initForShape(allocator, try authority.Shape.init(88));
            defer workspace.deinit();
            try workspace.validate();
        }
    };
    try std.testing.checkAllAllocationFailures(std.testing.allocator, Check.run, .{});
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

fn sentinelReceipt() authority.PreparedAuthorityV2 {
    var result: authority.PreparedAuthorityV2 = undefined;
    @memset(std.mem.asBytes(&result), @as(u8, 0xA5));
    return result;
}
