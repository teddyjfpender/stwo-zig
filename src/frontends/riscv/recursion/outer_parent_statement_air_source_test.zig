//! End-to-end custody and hostile tests for the binary parent AIR source.

const std = @import("std");
const stwo_core = @import("stwo_core");

const M31 = stwo_core.fields.m31.M31;

const admission = @import("outer_parent_child_admission.zig");
const air_source = @import("outer_parent_statement_air_source.zig");
const parent_source = @import("outer_parent_statement_source.zig");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");
const span_statement = @import("span_statement.zig");
const leaf_owner = @import("segment_leaf_authority.zig");
const segment_source = @import("segment_statement_outer_source.zig");
const transcript_support = @import("outer_parent_transcript_source_test.zig");
const vm_claim = @import("vm_public_claim.zig");
const lowering = @import("air/verifier_arithmetic_lowering.zig");
const row10_relation = @import("air/statement_input_relation.zig");
const row10_witness = @import("air/statement_input_witness.zig");
const row11_relation = @import("air/statement_semantics_input_relation.zig");
const row11_witness = @import("air/statement_semantics_input_witness.zig");
const range_bridge = @import("air/range_check_8_8_bridge.zig");
const shared_provider = @import("air/universal_shared_provider.zig");
const universal = @import("air/universal_challenges.zig");
const relation = @import("../air/lang/relation.zig");

const Dimensions = transcript_support.TEST_DIMENSIONS;
const ParentPrepared = parent_source.Prepared(Dimensions);
const AirPrepared = air_source.Prepared(Dimensions);

test "outer parent statement AIR source binds verifier custody through canonical fold" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    try fixture.prepared.validateAgainst(
        &fixture.authority,
        &fixture.workspace,
        &fixture.parent,
        &fixture.suite,
        &fixture.publications,
    );
    try std.testing.expect(!fixture.prepared.productionReady());
    try std.testing.expect(air_source.NATIVE_VERIFIER_PUBLISHES_STATEMENT_WORDS);
    try std.testing.expect(!air_source.COMPLETE_PARENT_STARK_VERIFIED);
    try std.testing.expectEqual(
        @as(usize, 0),
        air_source.HOT_PAIR_AUTHENTICATIONS_PER_TRACE_FILL,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        air_source.HOT_TRACE_HEAP_ALLOCATIONS,
    );
    try std.testing.expectEqual(
        @as(usize, 3),
        air_source.COLD_HEAP_ALLOCATIONS_PER_PREPARED,
    );
    try std.testing.expectEqual(
        fixture.parent.source_id,
        fixture.prepared.public.parent_source_id,
    );
    try std.testing.expectEqual(
        fixture.parent.statement.parent_vk_id,
        fixture.prepared.public.parent_vk_id,
    );
    try std.testing.expectEqual(
        fixture.parent.statement.execution_statement_id,
        fixture.prepared.public.execution_statement_id,
    );
    try std.testing.expectEqual(
        fixture.parent.statement.children[0].preprocessed_root,
        fixture.prepared.public.child_preprocessed_roots[0],
    );
    try std.testing.expectEqual(
        lowering.Mode.binary,
        air_source.loweringLane(&fixture.authority).active_in,
    );
}

test "outer parent statement publications reject swaps and detached mutations" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    var swapped = fixture.publications;
    std.mem.swap(
        air_source.VerifiedStatementPublicationV1,
        &swapped[0],
        &swapped[1],
    );
    try std.testing.expectError(
        error.StatementPublicationMismatch,
        AirPrepared.init(
            std.testing.allocator,
            &fixture.authority,
            &fixture.workspace,
            &fixture.parent,
            &fixture.suite,
            &swapped,
        ),
    );

    var mutated = fixture.publications;
    mutated[0].capture_id[0] ^= 1;
    try std.testing.expectError(
        error.StatementPublicationMismatch,
        AirPrepared.init(
            std.testing.allocator,
            &fixture.authority,
            &fixture.workspace,
            &fixture.parent,
            &fixture.suite,
            &mutated,
        ),
    );

    mutated = fixture.publications;
    mutated[1].words[17] = mutated[1].words[17].add(M31.one());
    try std.testing.expectError(
        error.StatementPublicationMismatch,
        AirPrepared.init(
            std.testing.allocator,
            &fixture.authority,
            &fixture.workspace,
            &fixture.parent,
            &fixture.suite,
            &mutated,
        ),
    );
}

test "fused authenticated parent preparation performs one pair authentication" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const bundles = .{
        fixture.left.bundle(fixture.left_binding),
        fixture.right.bundle(fixture.right_binding),
    };
    var fused = try air_source.AuthenticatedPrepared(Dimensions).init(
        std.testing.allocator,
        &fixture.authority,
        &fixture.workspace,
        fixture.scratch,
        .{
            .pair = fixture.pair,
            .verified = &fixture.verifier_authority,
            .suite = &fixture.suite,
        },
        bundles,
    );
    defer fused.deinit();

    try std.testing.expectEqual(
        @as(usize, 1),
        air_source.FUSED_PAIR_AUTHENTICATIONS_PER_PREPARE,
    );
    try std.testing.expectEqual(
        @as(usize, 3),
        air_source.FUSED_PAIR_REAUTHENTICATIONS_AVOIDED,
    );
    try std.testing.expectEqual(
        @as(usize, 165),
        air_source.FUSED_PAIR_PERMUTATIONS_AVOIDED,
    );
    try std.testing.expectEqual(
        pair_node.AuthenticationPermutationCostV1.successful_prepared_root,
        fused.parent.performance.pair_authentication_permutations,
    );
    try std.testing.expectEqual(fixture.parent.source_id, fused.parent.source_id);
    try std.testing.expectEqual(fixture.prepared.source_id, fused.air.source_id);
    try fused.validateAgainst(
        &fixture.authority,
        &fixture.workspace,
        fixture.scratch,
        .{
            .pair = fixture.pair,
            .verified = &fixture.verifier_authority,
            .suite = &fixture.suite,
        },
        bundles,
    );
    try fused.validateHot(&fixture.authority, &fixture.workspace);

    fused.publications[0].capture_id[0] ^= 1;
    try std.testing.expectError(
        error.StatementPublicationMismatch,
        fused.validateAgainst(
            &fixture.authority,
            &fixture.workspace,
            fixture.scratch,
            .{
                .pair = fixture.pair,
                .verified = &fixture.verifier_authority,
                .suite = &fixture.suite,
            },
            bundles,
        ),
    );
}

test "outer parent statement AIR retained circuit and range snapshots fail closed" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const original = fixture.prepared.statement_values[0];
    fixture.prepared.statement_values[0] = original.add(M31.one());
    try std.testing.expectError(
        error.AuthorityMismatch,
        fixture.prepared.validateAgainst(
            &fixture.authority,
            &fixture.workspace,
            &fixture.parent,
            &fixture.suite,
            &fixture.publications,
        ),
    );
    fixture.prepared.statement_values[0] = original;

    const count = fixture.prepared.range.range_check.counter.values[0];
    fixture.prepared.range.range_check.counter.values[0] = count.add(M31.one());
    try std.testing.expectError(
        error.AuthorityMismatch,
        fixture.prepared.validateAgainst(
            &fixture.authority,
            &fixture.workspace,
            &fixture.parent,
            &fixture.suite,
            &fixture.publications,
        ),
    );
    fixture.prepared.range.range_check.counter.values[0] = count;
}

test "outer parent statement AIR commits the unique parent lane in all three trees" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit();

    var pp10 = try OwnedColumns(row10_witness.PREPROCESSED_COLUMN_COUNT).init(
        allocator,
        air_source.STATEMENT_INPUT_TRACE_SIZE,
    );
    defer pp10.deinit();
    var pp11 = try OwnedColumns(row11_witness.PREPROCESSED_COLUMN_COUNT).init(
        allocator,
        air_source.STATEMENT_SEMANTICS_TRACE_SIZE,
    );
    defer pp11.deinit();
    var pp35 = try OwnedColumns(range_bridge.FRAMEWORK_PREPROCESSED_COLUMN_COUNT).init(
        allocator,
        air_source.RANGE_CHECK_TRACE_SIZE,
    );
    defer pp35.deinit();
    var preprocessed = air_source.PreprocessedColumns{
        .statement_input = pp10.columns,
        .statement_semantics = pp11.columns,
        .range_check = pp35.columns,
    };
    try air_source.fillPreprocessedCommitted(
        &fixture.authority,
        &fixture.workspace,
        &preprocessed,
    );

    const parent_lane_row = 3 * span_statement.SPAN_STATEMENT_CANONICAL_WORDS;
    const parent_lane_committed = air_source.committedRow(
        parent_lane_row,
        air_source.STATEMENT_INPUT_LOG_SIZE,
    );
    try std.testing.expectEqual(M31.one(), pp10.columns[3][parent_lane_committed]);
    try std.testing.expectEqual(M31.zero(), pp10.columns[1][parent_lane_committed]);
    try std.testing.expectEqual(M31.zero(), pp10.columns[2][parent_lane_committed]);

    var main10 = try OwnedColumns(row10_witness.MAIN_COLUMN_COUNT).init(
        allocator,
        air_source.STATEMENT_INPUT_TRACE_SIZE,
    );
    defer main10.deinit();
    var main11 = try OwnedColumns(row11_witness.MAIN_COLUMN_COUNT).init(
        allocator,
        air_source.STATEMENT_SEMANTICS_TRACE_SIZE,
    );
    defer main11.deinit();
    var main35 = try OwnedColumns(range_bridge.PHYSICAL_MAIN_COLUMN_COUNT).init(
        allocator,
        air_source.RANGE_CHECK_TRACE_SIZE,
    );
    defer main35.deinit();
    var main = air_source.MainColumns{
        .statement_input = main10.columns,
        .statement_semantics = main11.columns,
        .range_check = main35.columns,
    };
    try air_source.fillMainCommitted(
        Dimensions,
        &fixture.authority,
        &fixture.workspace,
        &fixture.prepared,
        &main,
    );
    try std.testing.expectEqual(
        fixture.prepared.parent_words[0],
        main10.columns[1][parent_lane_committed],
    );
    try std.testing.expectEqual(
        fixture.prepared.left_words[0],
        main10.columns[1][
            air_source.committedRow(
                span_statement.SPAN_STATEMENT_CANONICAL_WORDS,
                air_source.STATEMENT_INPUT_LOG_SIZE,
            )
        ],
    );
    try std.testing.expect(
        fixture.prepared.range.provider().counter.signedTotal().eql(
            M31.zero().sub(M31.fromU64(fixture.prepared.range.request_count)),
        ),
    );

    const relations = universal.UniversalRelations.dummy();
    const provider_relations = try shared_provider.SharedProviderRelations.init(
        &relations,
    );
    var interaction10 = try OwnedColumns(row10_relation.Runtime.INTERACTION_COLUMN_COUNT).init(
        allocator,
        air_source.STATEMENT_INPUT_TRACE_SIZE,
    );
    defer interaction10.deinit();
    var interaction11 = try OwnedColumns(row11_relation.Runtime.INTERACTION_COLUMN_COUNT).init(
        allocator,
        air_source.STATEMENT_SEMANTICS_TRACE_SIZE,
    );
    defer interaction11.deinit();
    var interaction35 = try OwnedColumns(range_bridge.INTERACTION_COLUMN_COUNT).init(
        allocator,
        air_source.RANGE_CHECK_TRACE_SIZE,
    );
    defer interaction35.deinit();
    var interactions = air_source.InteractionColumns{
        .statement_input = interaction10.columns,
        .statement_semantics = interaction11.columns,
        .range_check = interaction35.columns,
    };
    const claims = try air_source.fillInteractionsCommitted(
        Dimensions,
        &fixture.authority,
        &fixture.workspace,
        &fixture.prepared,
        &relations,
        &provider_relations,
        &interactions,
    );
    try claims.verifyRangeClosure();
    try std.testing.expect(!claims.statement_input.isZero());
    try std.testing.expect(!claims.statement_semantics.isZero());
    const audits = try air_source.auditInteractionDomains(
        Dimensions,
        &fixture.authority,
        &fixture.workspace,
        &fixture.prepared,
        &relations,
        &provider_relations,
        claims,
        null,
    );
    try std.testing.expect(audits.statement_input.total.eql(claims.statement_input));
    try std.testing.expect(audits.statement_semantics.total.eql(
        claims.statement_semantics,
    ));
    const statement_domain = @intFromEnum(relation.Domain.recursion_statement_word);
    try std.testing.expect(
        audits.statement_input.values[statement_domain].add(
            audits.statement_semantics.values[statement_domain],
        ).isZero(),
    );
}

const Fixture = struct {
    allocator: std.mem.Allocator,
    left: transcript_support.AdmittedChild,
    right: transcript_support.AdmittedChild,
    left_binding: admission.PairChildInputsV1,
    right_binding: admission.PairChildInputsV1,
    pair: @import("outer_parent_transcript_source.zig").PairInputsV1,
    verifier_authority: pair_node.VerifierAuthorityV1,
    suite: pair_node.PreparedProtocolSuiteV1,
    scratch: []u8,
    parent: ParentPrepared,
    publications: [air_source.CHILD_COUNT]air_source.VerifiedStatementPublicationV1,
    leaf_preprocessing: leaf_owner.Preprocessing,
    authority: segment_source.Authority,
    workspace: air_source.Workspace,
    prepared: AirPrepared,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const triple = try twoExecuted();
        const parent_words = try triple.parent.canonicalWords();
        var left = try transcript_support.AdmittedChild.initWithStatement(
            allocator,
            0,
            transcript_support.digest(11),
            triple.left,
        );
        errdefer left.deinit();
        var right = try transcript_support.AdmittedChild.initWithStatement(
            allocator,
            1,
            transcript_support.digest(11),
            triple.right,
        );
        errdefer right.deinit();

        var pair = try transcript_support.honestPairInputs();
        pair.context.execution_statement_id = statementId(&parent_words);
        const relation_total = pair_node.SecureFelt{ .limbs = .{ 17, 19, 23, 29 } };
        const left_binding = try transcript_support.childBinding(
            &left,
            pair,
            0,
            relation_total,
        );
        const right_binding = try transcript_support.childBinding(
            &right,
            pair,
            1,
            relation_total.neg(),
        );
        const verifier_authority = authorityFromBindings(
            pair.context,
            .{ left_binding, right_binding },
            .{ left.candidate, right.candidate },
        );
        const suite = try pair_node.prepareProtocolSuite();
        const scratch = try allocator.alloc(
            u8,
            admission.serializedByteCount(Dimensions),
        );
        errdefer allocator.free(scratch);
        var parent: ParentPrepared = undefined;
        try ParentPrepared.prepareInto(
            &parent,
            scratch,
            .{ .pair = pair, .verified = &verifier_authority, .suite = &suite },
            .{
                left.bundle(left_binding),
                right.bundle(right_binding),
            },
        );
        var publications: [air_source.CHILD_COUNT]air_source.VerifiedStatementPublicationV1 =
            undefined;
        try air_source.publishVerifierStatementsInto(
            Dimensions,
            &publications,
            &parent,
            &suite,
        );

        var leaf_preprocessing = try leaf_owner.Preprocessing.init(
            allocator,
            try vm_claim.Shape.init(3, 3),
        );
        errdefer leaf_preprocessing.deinit();
        var authority = try segment_source.Authority.init(
            allocator,
            &leaf_preprocessing,
        );
        errdefer authority.deinit();
        var workspace = try air_source.Workspace.init(allocator);
        errdefer workspace.deinit();
        var prepared = try AirPrepared.init(
            allocator,
            &authority,
            &workspace,
            &parent,
            &suite,
            &publications,
        );
        errdefer prepared.deinit();
        return .{
            .allocator = allocator,
            .left = left,
            .right = right,
            .left_binding = left_binding,
            .right_binding = right_binding,
            .pair = pair,
            .verifier_authority = verifier_authority,
            .suite = suite,
            .scratch = scratch,
            .parent = parent,
            .publications = publications,
            .leaf_preprocessing = leaf_preprocessing,
            .authority = authority,
            .workspace = workspace,
            .prepared = prepared,
        };
    }

    fn deinit(self: *Fixture) void {
        self.prepared.deinit();
        self.workspace.deinit();
        self.authority.deinit();
        self.leaf_preprocessing.deinit();
        self.allocator.free(self.scratch);
        self.right.deinit();
        self.left.deinit();
        self.* = undefined;
    }
};

const Triple = struct {
    left: span_statement.SpanStatement,
    right: span_statement.SpanStatement,
    parent: span_statement.SpanStatement,
};

fn twoExecuted() !Triple {
    const job = try fixtureJob(2, 10);
    const left = try fixtureLeaf(
        job,
        0,
        0,
        4,
        try fixtureState(0),
        try fixtureState(1),
    );
    const right = try fixtureLeaf(
        job,
        1,
        4,
        6,
        try fixtureState(1),
        try fixtureState(2),
    );
    return .{
        .left = left,
        .right = right,
        .parent = try span_statement.SpanStatement.fold(left, right),
    };
}

fn fixtureJob(segment_count: u32, total_cycles: u64) !span_statement.JobContext {
    return span_statement.JobContext.init(
        try span_statement.CompleteExecution.init(
            fixtureDigest(1),
            fixtureDigest(2),
            try fixtureState(0),
            try fixtureState(segment_count),
            fixtureDigest(3),
            fixtureDigest(4),
            total_cycles,
        ),
        segment_count,
    );
}

fn fixtureLeaf(
    job: span_statement.JobContext,
    index: u32,
    first_cycle: u64,
    cycle_count: u64,
    entry: span_statement.MachineState,
    exit_state: span_statement.MachineState,
) !span_statement.SpanStatement {
    const input = if (index == 0)
        try span_statement.EdgeClaim.present(job.complete.public_input)
    else
        span_statement.EdgeClaim.absent();
    const output = if (@as(u64, index) + 1 == job.segment_count)
        try span_statement.EdgeClaim.present(job.complete.public_output)
    else
        span_statement.EdgeClaim.absent();
    return span_statement.SpanStatement.segmentLeaf(
        job,
        index,
        try span_statement.ExecutedSpan.init(
            index,
            1,
            first_cycle,
            cycle_count,
            entry,
            exit_state,
            input,
            output,
        ),
    );
}

fn fixtureState(seed: u32) !span_statement.MachineState {
    var registers = [_]u32{0} ** 32;
    registers[1] = seed;
    return span_statement.MachineState.init(
        seed *% 4,
        registers,
        fixtureDigest(seed + 10),
        fixtureDigest(seed + 20),
    );
}

fn fixtureDigest(seed: u32) span_statement.Digest {
    var result: span_statement.Digest = undefined;
    for (&result, 0..) |*value, index| value.* =
        seed + @as(u32, @intCast(index));
    return result;
}

fn statementId(words: *const span_statement.StatementWords) [8]u32 {
    var canonical: [span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (words, &canonical) |word, *output| output.* = word.toU32();
    return protocol.statementId(&canonical);
}

fn authorityFromBindings(
    context: pair_node.VerifierContextV1,
    bindings: [air_source.CHILD_COUNT]admission.PairChildInputsV1,
    candidates: [air_source.CHILD_COUNT]admission.BinaryPairCandidateV1,
) pair_node.VerifierAuthorityV1 {
    var children: [air_source.CHILD_COUNT]pair_node.VerifiedChildV1 = undefined;
    for (&children, bindings, candidates) |*target, binding, candidate| target.* = .{
        .position = binding.position,
        .role = binding.role,
        .leaf_index = binding.leaf_index,
        .pair_index = binding.pair_index,
        .leaf_count = binding.leaf_count,
        .protocol_id = protocol.PROTOCOL_ID_WORDS,
        .session_id = binding.session_id,
        .challenge_context_id = binding.challenge_context_id,
        .authority_context_id = binding.authority_context_id,
        .parent_vk_id = binding.parent_vk_id,
        .statement_id = binding.statement_id,
        .proof_id = candidate.proof_id,
        .transcript_id = candidate.transcript_id,
        .summary_id = binding.summary_id,
        .event_count = binding.event_count,
        .signed_relation_total = binding.signed_relation_total,
    };
    return .{ .context = context, .children = children };
}

fn OwnedColumns(comptime count: usize) type {
    return struct {
        allocator: std.mem.Allocator,
        storage: []M31,
        columns: [count][]M31,

        const Self = @This();

        fn init(allocator: std.mem.Allocator, row_count: usize) !Self {
            const storage = try allocator.alloc(M31, count * row_count);
            @memset(storage, M31.zero());
            var columns: [count][]M31 = undefined;
            for (&columns, 0..) |*column, index|
                column.* = storage[index * row_count ..][0..row_count];
            return .{
                .allocator = allocator,
                .storage = storage,
                .columns = columns,
            };
        }

        fn deinit(self: *Self) void {
            self.allocator.free(self.storage);
            self.* = undefined;
        }
    };
}
