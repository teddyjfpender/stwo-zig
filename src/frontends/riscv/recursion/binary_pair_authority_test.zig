const std = @import("std");
const stwo_core = @import("stwo_core");
const authority = @import("binary_pair_authority.zig");
const channel = @import("poseidon2_channel.zig");
const fixed_profile = @import("fixed_profile.zig");
const fixed_wire = @import("fixed_wire.zig");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");
const span_statement = @import("span_statement.zig");
const statement_circuit = @import("statement_semantics_circuit.zig");
const statement_input = @import("air/statement_input_witness.zig");
const schedule = @import("air/verifier_schedule.zig");
const transcript_program = @import("transcript_program.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

const DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = 4,
    .claimed_sum_count = 2,
    .sampled_value_count = 3,
    .queried_value_count = 4 * protocol.FRI_QUERY_COUNT,
    .trace_path_count = 4 * protocol.FRI_QUERY_COUNT,
    .fri_layer_count = 1,
    .query_count = protocol.FRI_QUERY_COUNT,
    .maximum_fold_width = 16,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 5,
};
const Wire = fixed_wire.FixedStarkProofWire(DIMENSIONS);

test "R-009 binary pair authority pins its honest capability boundary" {
    try std.testing.expectEqual(@as(u16, 1), authority.FORMAT_VERSION);
    try std.testing.expectEqual(@as(usize, 11), authority.LAST_SNAPSHOTTED_ROW);
    try std.testing.expectEqual(@as(usize, 16), authority.LAST_INACTIVE_VM_ROW);
    try std.testing.expectEqual(
        @as(usize, 17),
        authority.BINARY_PUBLIC_LOGUP_CONTROL_ROW,
    );
    try std.testing.expectEqual(@as(usize, 35), authority.SHARED_RANGE_ROW);
    try std.testing.expectEqual(@as(u32, 16), authority.SHARED_RANGE_LOG_SIZE);
    try std.testing.expect(!authority.RECURSIVE_PROOF_PRODUCTION);
    try (authority.RowContract{}).validate();
}

test "R-009 binary pair authority contract fails closed" {
    var contract = authority.RowContract{};
    contract.active_transcript_lanes = 1;
    try std.testing.expectError(
        error.TranscriptSnapshotMismatch,
        contract.validate(),
    );
    contract = .{};
    contract.active_public_logup_control_lanes = 0;
    try std.testing.expectError(
        error.TranscriptSnapshotMismatch,
        contract.validate(),
    );
}

test "R-009 binary pair authority generic custody path typechecks and omits atomically" {
    const allocator = std.testing.allocator;
    const shape = try testShape();
    const schedule_shape = try schedule.ScheduleShape.fromV1(shape);
    var vm_plan = try schedule.Plan.initShape(
        allocator,
        schedule.VM_PROGRAM_SPEC_V1,
        schedule_shape,
    );
    defer vm_plan.deinit();
    var recursion_plan = try schedule.Plan.initShape(
        allocator,
        schedule.RECURSION_PROGRAM_SPEC_V1,
        schedule_shape,
    );
    defer recursion_plan.deinit();
    var transcript_preprocessing = try authority.TranscriptPreprocessing.init(
        allocator,
        &vm_plan,
        &recursion_plan,
    );
    defer transcript_preprocessing.deinit();
    var statement_preprocessing = try statement_input.Preprocessed.init(allocator);
    defer statement_preprocessing.deinit();
    var semantics = try statement_circuit.build(allocator);
    defer semantics.deinit();
    var validation_workspace = try authority.ValidationWorkspace.init(allocator);
    defer validation_workspace.deinit();
    const wire = try allocator.create(Wire);
    defer allocator.destroy(wire);
    wire.* = std.mem.zeroes(Wire);

    const session = id("typed-binary-session");
    const context = pair_node.VerifierContextV1{
        .session_id = session,
        .job_id = id("typed-binary-job"),
        .execution_statement_id = id("typed-binary-parent"),
        .public_call_commitment = protocol.emptyCallCommitment(),
        .event_count = 0,
        .session_leaf_count = 2,
        .pair_index = 0,
        .aggregator_vk_id = try pair_node.verificationKeyId("pair-vk-v1"),
    };
    const Child = authority.FixedChild(DIMENSIONS);
    const omitted = Child{
        .shape = shape,
        .proof = wire,
        .capture = .{
            .present = false,
            .statement = undefined,
            .canonical_summary_bytes = &.{},
            .verified = undefined,
        },
    };
    try std.testing.expectError(
        error.ChildOmitted,
        authority.Prepared(DIMENSIONS).init(
            allocator,
            .sealed_candidate,
            &vm_plan,
            .{ &recursion_plan, &recursion_plan },
            &transcript_preprocessing,
            &statement_preprocessing,
            &semantics,
            &validation_workspace,
            .{
                .context = context,
                .root_pin = .{
                    .expected_aggregator_vk_id = context.aggregator_vk_id,
                },
            },
            .{ omitted, omitted },
        ),
    );
}

test "R-009 binary pair authority authenticates two captures into exact binary rows" {
    var fixture = try HonestFixture.init(std.testing.allocator);
    defer fixture.deinit();

    var prepared = try authority.Prepared(DIMENSIONS).init(
        std.testing.allocator,
        .sealed_candidate,
        &fixture.vm_plan,
        .{ &fixture.recursion_plans[0], &fixture.recursion_plans[1] },
        &fixture.transcript_preprocessing,
        &fixture.statement_preprocessing,
        &fixture.semantics,
        &fixture.validation_workspace,
        fixture.pair_inputs,
        fixture.children(),
    );
    defer prepared.deinit();

    try prepared.validateAgainst(
        &fixture.vm_plan,
        .{ &fixture.recursion_plans[0], &fixture.recursion_plans[1] },
        &fixture.transcript_preprocessing,
        &fixture.statement_preprocessing,
        &fixture.semantics,
        &fixture.validation_workspace,
        fixture.pair_inputs.root_pin,
    );
    try std.testing.expectEqual(authority.PROOF_KIND, prepared.proofKind());
    try std.testing.expectEqual(@as(u32, 2), prepared.authenticated_root.pair.leaf_count);
    try std.testing.expectEqual(@as(u8, 2), prepared.transcript_air.lane_count);
    try std.testing.expectEqual(@as(u8, 2), prepared.contract.active_transcript_lanes);
    try std.testing.expectEqual(
        statement_input.ProofKind.binary_node,
        prepared.statementWitness().proofKind(),
    );
    const logs = try prepared.minimumLogSizes(
        &fixture.vm_plan,
        &fixture.recursion_plans[0],
        &fixture.transcript_preprocessing,
        &fixture.statement_preprocessing,
    );
    try std.testing.expectEqual(@as(usize, 12), logs.len);
    try std.testing.expect(logs[0] >= 4 and logs[11] == 11);

    const retained_input = prepared.statement_semantics.storage[0];
    prepared.statement_semantics.storage[0] = retained_input.add(QM31.one());
    try std.testing.expectError(
        error.TranscriptSnapshotMismatch,
        prepared.validateAgainst(
            &fixture.vm_plan,
            .{ &fixture.recursion_plans[0], &fixture.recursion_plans[1] },
            &fixture.transcript_preprocessing,
            &fixture.statement_preprocessing,
            &fixture.semantics,
            &fixture.validation_workspace,
            fixture.pair_inputs.root_pin,
        ),
    );
    prepared.statement_semantics.storage[0] = retained_input;
}

test "R-009 binary pair authority rejects swapped cross-session duplicate and omitted captures" {
    var fixture = try HonestFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const children = fixture.children();

    var swapped = children;
    std.mem.swap(
        authority.FixedChild(DIMENSIONS),
        &swapped[0],
        &swapped[1],
    );
    try expectInitError(error.StatementIndexMismatch, &fixture, swapped);

    var cross_session = children;
    cross_session[1].capture.verified.session_id = id("foreign-session");
    try expectInitError(error.ChildCaptureMismatch, &fixture, cross_session);

    var duplicate = children;
    duplicate[1].proof = duplicate[0].proof;
    duplicate[1].shape = duplicate[0].shape;
    duplicate[1].capture.verified.proof_id = duplicate[0].capture.verified.proof_id;
    try expectInitError(error.ChildCaptureMismatch, &fixture, duplicate);

    var omitted = children;
    omitted[1].capture.present = false;
    try expectInitError(error.ChildOmitted, &fixture, omitted);
}

fn expectInitError(
    expected: anyerror,
    fixture: *HonestFixture,
    children: [2]authority.FixedChild(DIMENSIONS),
) !void {
    var unexpected = authority.Prepared(DIMENSIONS).init(
        std.testing.allocator,
        .sealed_candidate,
        &fixture.vm_plan,
        .{ &fixture.recursion_plans[0], &fixture.recursion_plans[1] },
        &fixture.transcript_preprocessing,
        &fixture.statement_preprocessing,
        &fixture.semantics,
        &fixture.validation_workspace,
        fixture.pair_inputs,
        children,
    ) catch |actual| {
        try std.testing.expectEqual(expected, actual);
        return;
    };
    unexpected.deinit();
    return error.ExpectedAuthorityRejection;
}

const HonestFixture = struct {
    allocator: std.mem.Allocator,
    shape: fixed_profile.ProofShapeV1,
    vm_plan: schedule.Plan,
    recursion_plans: [2]schedule.Plan,
    transcript_preprocessing: authority.TranscriptPreprocessing,
    statement_preprocessing: statement_input.Preprocessed,
    semantics: statement_circuit.Circuit,
    validation_workspace: authority.ValidationWorkspace,
    wires: [2]*Wire,
    captures: [2]authority.VerifiedChildCapture,
    pair_inputs: authority.PairInputs,

    fn init(allocator: std.mem.Allocator) !HonestFixture {
        const shape = try testShape();
        var schedule_shape = try schedule.ScheduleShape.fromV1(shape);
        // Candidate-only fixture: zero-bit PoW makes the authority test fast.
        // Production admission rebuilds and requires frozen V1's 10/16 bits.
        schedule_shape.interaction_pow_bits = 0;
        schedule_shape.pcs_pow_bits = 0;
        var vm_plan = try schedule.Plan.initShape(
            allocator,
            schedule.VM_PROGRAM_SPEC_V1,
            schedule_shape,
        );
        errdefer vm_plan.deinit();
        var left_recursion_plan = try schedule.Plan.initShape(
            allocator,
            schedule.RECURSION_PROGRAM_SPEC_V1,
            schedule_shape,
        );
        errdefer left_recursion_plan.deinit();
        var right_recursion_plan = try schedule.Plan.initShape(
            allocator,
            schedule.RECURSION_PROGRAM_SPEC_V1,
            schedule_shape,
        );
        errdefer right_recursion_plan.deinit();
        var transcript_preprocessing = try authority.TranscriptPreprocessing.init(
            allocator,
            &vm_plan,
            &left_recursion_plan,
        );
        errdefer transcript_preprocessing.deinit();
        var statement_preprocessing = try statement_input.Preprocessed.init(allocator);
        errdefer statement_preprocessing.deinit();
        var semantics = try statement_circuit.build(allocator);
        errdefer semantics.deinit();
        var validation_workspace = try authority.ValidationWorkspace.init(allocator);
        errdefer validation_workspace.deinit();
        const left_wire = try allocator.create(Wire);
        errdefer allocator.destroy(left_wire);
        const right_wire = try allocator.create(Wire);
        errdefer allocator.destroy(right_wire);
        initializeWire(left_wire, shape, 11);
        initializeWire(right_wire, shape, 29);

        const statements = try testStatements();
        const parent = try span_statement.SpanStatement.fold(
            statements[0],
            statements[1],
        );
        const parent_words = try parent.canonicalWords();
        const context = pair_node.VerifierContextV1{
            .session_id = id("honest-binary-session"),
            .job_id = id("honest-binary-job"),
            .execution_statement_id = statementId(parent_words),
            .public_call_commitment = id("honest-public-calls"),
            .event_count = 2,
            .session_leaf_count = 2,
            .pair_index = 0,
            .aggregator_vk_id = try pair_node.verificationKeyId("honest-pair-vk-v1"),
        };
        const challenge = try context.challengeContextId();
        const context_id = try context.contextId();
        const summaries = [2][]const u8{ "left-summary-v1", "right-summary-v1" };
        const wires = [2]*Wire{ left_wire, right_wire };
        var captures: [2]authority.VerifiedChildCapture = undefined;
        const proof_bytes = try allocator.alloc(
            u8,
            fixed_wire.serializedByteCount(DIMENSIONS),
        );
        defer allocator.free(proof_bytes);
        const request = pair_node.SecureFelt{ .limbs = .{ 5, 7, 11, 13 } };
        for (&captures, statements, wires, summaries, 0..) |
            *capture,
            statement,
            wire,
            summary,
            index,
        | {
            const words = try statement.canonicalWords();
            var execution = try transcript_program.executeFixedTranscript(
                DIMENSIONS,
                allocator,
                if (index == 0) &left_recursion_plan else &right_recursion_plan,
                &words,
                .recursion,
                wire,
            );
            defer execution.deinit();
            try wire.encodeInto(proof_bytes, shape);
            const total = if (index == 0) request else request.neg();
            capture.* = .{
                .statement = statement,
                .canonical_summary_bytes = summary,
                .verified = .{
                    .position = if (index == 0) .left else .right,
                    .role = if (index == 0) .core_request else .poseidon2_provider,
                    .leaf_index = @intCast(index),
                    .pair_index = 0,
                    .leaf_count = 1,
                    .protocol_id = protocol.PROTOCOL_ID_WORDS,
                    .session_id = context.session_id,
                    .challenge_context_id = challenge,
                    .authority_context_id = context_id,
                    .parent_vk_id = context.aggregator_vk_id,
                    .statement_id = statementId(words),
                    .proof_id = protocol.proofId(proof_bytes),
                    .transcript_id = protocol.transcriptId(
                        transcriptDigest(execution.final_digest),
                        execution.final_draw_count,
                    ),
                    .summary_id = protocol.summaryId(summary),
                    .event_count = context.event_count,
                    .signed_relation_total = total,
                },
            };
        }
        return .{
            .allocator = allocator,
            .shape = shape,
            .vm_plan = vm_plan,
            .recursion_plans = .{ left_recursion_plan, right_recursion_plan },
            .transcript_preprocessing = transcript_preprocessing,
            .statement_preprocessing = statement_preprocessing,
            .semantics = semantics,
            .validation_workspace = validation_workspace,
            .wires = wires,
            .captures = captures,
            .pair_inputs = .{
                .context = context,
                .root_pin = .{
                    .expected_aggregator_vk_id = context.aggregator_vk_id,
                },
            },
        };
    }

    fn children(self: *HonestFixture) [2]authority.FixedChild(DIMENSIONS) {
        return .{
            .{ .shape = self.shape, .proof = self.wires[0], .capture = self.captures[0] },
            .{ .shape = self.shape, .proof = self.wires[1], .capture = self.captures[1] },
        };
    }

    fn deinit(self: *HonestFixture) void {
        self.allocator.destroy(self.wires[1]);
        self.allocator.destroy(self.wires[0]);
        self.semantics.deinit();
        self.validation_workspace.deinit();
        self.statement_preprocessing.deinit();
        self.transcript_preprocessing.deinit();
        self.recursion_plans[1].deinit();
        self.recursion_plans[0].deinit();
        self.vm_plan.deinit();
        self.* = undefined;
    }
};

fn initializeWire(wire: *Wire, shape: fixed_profile.ProofShapeV1, seed: u32) void {
    wire.* = std.mem.zeroes(Wire);
    wire.commitments[0][0] = seed;
    for (shape.tree_heights, 0..) |height, tree| {
        const start = tree * DIMENSIONS.query_count;
        for (wire.trace_paths[start..][0..DIMENSIONS.query_count]) |*path|
            path.active_depth = height;
    }
    for (&wire.fri_layers, shape.fri.active()) |*layer, round| {
        layer.active_width = round.fold_width;
        for (&layer.queries) |*query|
            query.path.active_depth = round.authentication_path_depth;
    }
}

fn testStatements() ![2]span_statement.SpanStatement {
    const initial = try machineState(0, "initial-rw");
    const middle = try machineState(4, "middle-rw");
    const final_state = try machineState(8, "final-rw");
    const input = id("public-input");
    const output = id("public-output");
    const complete = try span_statement.CompleteExecution.init(
        protocol.PROTOCOL_ID_WORDS,
        id("program"),
        initial,
        final_state,
        input,
        output,
        20,
    );
    const job = try span_statement.JobContext.init(complete, 2);
    const left = try span_statement.ExecutedSpan.init(
        0,
        1,
        0,
        10,
        initial,
        middle,
        try span_statement.EdgeClaim.present(input),
        span_statement.EdgeClaim.absent(),
    );
    const right = try span_statement.ExecutedSpan.init(
        1,
        1,
        10,
        10,
        middle,
        final_state,
        span_statement.EdgeClaim.absent(),
        try span_statement.EdgeClaim.present(output),
    );
    return .{
        try span_statement.SpanStatement.segmentLeaf(job, 0, left),
        try span_statement.SpanStatement.segmentLeaf(job, 1, right),
    };
}

fn machineState(pc: u32, label: []const u8) !span_statement.MachineState {
    return span_statement.MachineState.init(
        pc,
        .{0} ** 32,
        id(label),
        .{0} ** 8,
    );
}

fn statementId(words: span_statement.StatementWords) protocol.Digest {
    var canonical: [span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (&canonical, words) |*target, word| target.* = word.toU32();
    return protocol.statementId(&canonical);
}

fn transcriptDigest(words: [transcript_program.RATE]M31) protocol.Digest {
    var result: protocol.Digest = undefined;
    for (&result, words) |*target, word| target.* = word.toU32();
    return result;
}

fn testShape() !fixed_profile.ProofShapeV1 {
    return .{
        .air_program_id = id("binary-air"),
        .preprocessing_id = id("binary-preprocessed"),
        .table_layout_id = id("binary-layout"),
        .table_count = 4,
        .claimed_sum_count = DIMENSIONS.claimed_sum_count,
        .sampled_value_count = DIMENSIONS.sampled_value_count,
        .preprocessed_column_count = 1,
        .tree_column_counts = .{ 1, 1, 1, 1 },
        .tree_heights = .{ 5, 5, 5, 5 },
        .column_log_degree = 4,
        .proof_wire_bytes = fixed_wire.serializedByteCount(DIMENSIONS),
        .fri = try fixed_profile.FriSchedule.init(
            4,
            protocol.PCS_CONFIG.fri_config,
        ),
    };
}

fn id(label: []const u8) protocol.Digest {
    return channel.hashBytes(label, 0x4250_4154); // "BPAT"
}
