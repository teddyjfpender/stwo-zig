//! Reusable honest binary-pair authority fixture for focused frontend tests.

const std = @import("std");
const stwo_core = @import("stwo_core");
const authority = @import("binary_pair_authority.zig");
const channel = @import("poseidon2_channel.zig");
const fixed_profile = @import("fixed_profile.zig");
const fixed_wire = @import("fixed_wire.zig");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");
const poseidon2 = @import("../air/memory_commitment/poseidon2.zig");
const span_statement = @import("span_statement.zig");
const statement_circuit = @import("statement_semantics_circuit.zig");
const statement_input = @import("air/statement_input_witness.zig");
const schedule = @import("air/verifier_schedule.zig");
const transcript_program = @import("transcript_program.zig");

const M31 = stwo_core.fields.m31.M31;

pub const DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = 4,
    .claimed_sum_count = 36,
    .sampled_value_count = 19,
    .queried_value_count = 11 * protocol.FRI_QUERY_COUNT,
    .trace_path_count = 4 * protocol.FRI_QUERY_COUNT,
    .fri_layer_count = 1,
    .query_count = protocol.FRI_QUERY_COUNT,
    .maximum_fold_width = 16,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 5,
};
pub const Wire = fixed_wire.FixedStarkProofWire(DIMENSIONS);
const TRACE_COLUMN_COUNTS = [4]usize{ 1, 1, 8, 1 };

pub const HonestFixture = struct {
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

    pub fn init(allocator: std.mem.Allocator) !HonestFixture {
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

    pub fn children(self: *HonestFixture) [2]authority.FixedChild(DIMENSIONS) {
        return .{
            .{ .shape = self.shape, .proof = self.wires[0], .capture = self.captures[0] },
            .{ .shape = self.shape, .proof = self.wires[1], .capture = self.captures[1] },
        };
    }

    pub fn deinit(self: *HonestFixture) void {
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

/// Upgrades the compact pair fixture to exact authenticated Merkle paths and
/// rebinds the verifier-owned proof/transcript identifiers. Call this before
/// constructing `binary_pair_authority.Prepared`; every outer cohort can then
/// share the same admitted pair without a second synthetic proof identity.
pub fn installAuthenticatedMerkleWires(pair: *HonestFixture) !void {
    const fri_leaf = friPackedLeafDigest();
    const fri_pair = hashPair(fri_leaf, fri_leaf);
    const fri_local_root = hashPair(fri_pair, fri_pair);
    const fri_root = hashPair(fri_local_root, fri_local_root);

    const proof_bytes = try pair.allocator.alloc(
        u8,
        fixed_wire.serializedByteCount(DIMENSIONS),
    );
    defer pair.allocator.free(proof_bytes);
    for (pair.wires, &pair.captures, 0..) |wire, *capture, child_index| {
        for (TRACE_COLUMN_COUNTS, 0..) |column_count, tree| {
            var trace_root = traceLeafDigest(column_count);
            var trace_siblings: [DIMENSIONS.maximum_merkle_depth]protocol.Digest = undefined;
            for (&trace_siblings) |*sibling| {
                sibling.* = trace_root;
                trace_root = hashPair(trace_root, trace_root);
            }
            wire.commitments[tree] = trace_root;
            const paths = wire.trace_paths[tree * DIMENSIONS.query_count ..][0..DIMENSIONS.query_count];
            for (paths) |*path| {
                path.active_depth = DIMENSIONS.maximum_merkle_depth;
                for (trace_siblings, 0..) |sibling, depth|
                    path.siblings[depth] = sibling;
            }
        }
        wire.claimed_sums[0][0] = @intCast(101 + child_index);
        wire.fri_layers[0].commitment = fri_root;
        wire.fri_layers[0].active_width = DIMENSIONS.maximum_fold_width;
        for (&wire.fri_layers[0].queries) |*query| {
            query.path.active_depth = 1;
            query.path.siblings[0] = fri_local_root;
        }

        const statement_words = try capture.statement.canonicalWords();
        var execution = try transcript_program.executeFixedTranscript(
            DIMENSIONS,
            pair.allocator,
            &pair.recursion_plans[child_index],
            &statement_words,
            .recursion,
            wire,
        );
        defer execution.deinit();
        try wire.encodeInto(proof_bytes, pair.shape);
        capture.verified.proof_id = protocol.proofId(proof_bytes);
        var digest: protocol.Digest = undefined;
        for (&digest, execution.final_digest) |*target, word|
            target.* = word.toU32();
        capture.verified.transcript_id = protocol.transcriptId(
            digest,
            execution.final_draw_count,
        );
    }
}

fn traceLeafDigest(column_count: usize) protocol.Digest {
    var state = [_]M31{M31.zero()} ** poseidon2.WIDTH;
    state[poseidon2.WIDTH - 1] = M31.one();
    const rate = poseidon2.WIDTH / 2;
    const step_count = std.math.divCeil(usize, column_count + 1, rate) catch
        unreachable;
    for (0..step_count) |step| {
        const first = step * rate;
        if (column_count >= first and column_count < first + rate)
            state[column_count - first] = state[column_count - first].add(M31.one());
        poseidon2.permute(&state);
    }
    return digestFromState(state);
}

fn friPackedLeafDigest() protocol.Digest {
    var state = [_]M31{M31.zero()} ** poseidon2.WIDTH;
    state[poseidon2.WIDTH - 1] = M31.one();
    poseidon2.permute(&state);
    poseidon2.permute(&state);
    state[0] = state[0].add(M31.one());
    poseidon2.permute(&state);
    return digestFromState(state);
}

fn hashPair(left: protocol.Digest, right: protocol.Digest) protocol.Digest {
    var state: poseidon2.State = undefined;
    for (left, state[0..8]) |word, *target|
        target.* = M31.fromCanonical(word);
    for (right, state[8..16]) |word, *target|
        target.* = M31.fromCanonical(word);
    poseidon2.permute(&state);
    return digestFromState(state);
}

fn digestFromState(state: poseidon2.State) protocol.Digest {
    var result: protocol.Digest = undefined;
    for (&result, state[0..8]) |*target, word| target.* = word.toU32();
    return result;
}

fn initializeWire(wire: *Wire, shape: fixed_profile.ProofShapeV1, seed: u32) void {
    wire.* = std.mem.zeroes(Wire);
    wire.commitments[0][0] = seed;
    for (&wire.claimed_sums, 0..) |*sum, row| {
        for (sum, 0..) |*word, coordinate|
            word.* = seed + @as(u32, @intCast(4 * row + coordinate + 1));
    }
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
        .table_count = 11,
        .claimed_sum_count = DIMENSIONS.claimed_sum_count,
        .sampled_value_count = DIMENSIONS.sampled_value_count,
        .preprocessed_column_count = 1,
        .tree_column_counts = .{ 1, 1, 8, 1 },
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
