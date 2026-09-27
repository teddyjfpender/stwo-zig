//! Hostile-parity tests for the recursive-parent transcript source.

const std = @import("std");
const stwo_core = @import("stwo_core");

const admission = @import("outer_parent_child_admission.zig");
const channel = @import("poseidon2_channel.zig");
const engine = @import("engine.zig");
const fixed_wire = @import("fixed_wire.zig");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");
const span_statement = @import("span_statement.zig");
const roster = @import("air/universal_roster.zig");
const source = @import("outer_parent_transcript_source.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const ProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(engine.Hasher);
const MerklePathCapture = stwo_core.vcs_lifted.verifier.MerklePathCapture(
    engine.Hasher,
);
const FriLayerCapture = stwo_core.fri.FriLayerQueryCapture(engine.Hasher);

const TEST_COLUMN_LOG: u32 = 5;
const TEST_TREE_HEIGHTS = [admission.TREE_COUNT]u32{ 5, 5, 5, 6 };
pub const TEST_DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = admission.TREE_COUNT,
    .claimed_sum_count = admission.CLAIMED_SUM_COUNT,
    .sampled_value_count = admission.TREE_COUNT,
    .queried_value_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .trace_path_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .fri_layer_count = TEST_COLUMN_LOG,
    .query_count = admission.QUERY_COUNT,
    .maximum_fold_width = 2,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 6,
};
const Wire = admission.FixedOuterProofWireV1(TEST_DIMENSIONS);
const Bundle = source.ChildBundle(TEST_DIMENSIONS);
const Prepared = source.Prepared(TEST_DIMENSIONS);

// Shared fixtures and mutation helpers for this conformance suite.

pub const AdmittedChild = struct {
    backing: std.mem.Allocator,
    fixture: CaptureFixture,
    wire: *Wire,
    seal: admission.VerifierSealV1,
    candidate: admission.BinaryPairCandidateV1,
    statement_words: span_statement.StatementWords,

    pub fn init(
        backing: std.mem.Allocator,
        child_seed: u32,
        air_program_id: channel.Digest,
    ) !AdmittedChild {
        return initConfigured(backing, child_seed, air_program_id, null);
    }

    /// Test-only seam for parent-statement custody fixtures. The exact
    /// canonical statement is installed before the verifier seal, wire, and
    /// candidate are derived.
    pub fn initWithStatement(
        backing: std.mem.Allocator,
        child_seed: u32,
        air_program_id: channel.Digest,
        statement: span_statement.SpanStatement,
    ) !AdmittedChild {
        return initConfigured(
            backing,
            child_seed,
            air_program_id,
            statement,
        );
    }

    pub fn initConfigured(
        backing: std.mem.Allocator,
        child_seed: u32,
        air_program_id: channel.Digest,
        statement: ?span_statement.SpanStatement,
    ) !AdmittedChild {
        var fixture = try CaptureFixture.init(
            backing,
            child_seed,
            air_program_id,
        );
        errdefer fixture.deinit();
        const verified_statement = statement orelse try defaultStatement(child_seed);
        const statement_words = try verified_statement.canonicalWords();
        fixture.receipt.statement_id = statementId(&statement_words);
        const seal = try admission.deriveVerifierSeal(
            &fixture.receipt,
            &fixture.capture,
        );
        const wire = try backing.create(Wire);
        errdefer backing.destroy(wire);
        const scratch = try backing.alloc(
            u8,
            admission.serializedByteCount(TEST_DIMENSIONS),
        );
        defer backing.free(scratch);
        const candidate = try admission.admit(
            TEST_DIMENSIONS,
            wire,
            scratch,
            seal,
            &fixture.receipt,
            &fixture.capture,
        );
        return .{
            .backing = backing,
            .fixture = fixture,
            .wire = wire,
            .seal = seal,
            .candidate = candidate,
            .statement_words = statement_words,
        };
    }

    pub fn deinit(self: *AdmittedChild) void {
        self.backing.destroy(self.wire);
        self.fixture.deinit();
        self.* = undefined;
    }

    pub fn bundle(self: *const AdmittedChild, binding: admission.PairChildInputsV1) Bundle {
        return self.bundleWithSeal(binding, self.seal);
    }

    pub fn bundleWithSeal(
        self: *const AdmittedChild,
        binding: admission.PairChildInputsV1,
        seal: admission.VerifierSealV1,
    ) Bundle {
        return .{
            .capture = &self.fixture.capture,
            .receipt = &self.fixture.receipt,
            .seal = seal,
            .statement_words = &self.statement_words,
            .wire = self.wire,
            .candidate = &self.candidate,
            .binding = binding,
        };
    }
};

pub const CaptureFixture = struct {
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    receipt: admission.VerifierReceiptV1,
    capture: ProofCapture,

    pub fn init(
        backing: std.mem.Allocator,
        child_seed: u32,
        air_program_id: channel.Digest,
    ) !CaptureFixture {
        const arena = try backing.create(std.heap.ArenaAllocator);
        errdefer backing.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const allocator = arena.allocator();
        const offset = child_seed * 10_000;

        var receipt = admission.VerifierReceiptV1{
            .air_program_id = air_program_id,
            .manifest_id = digest(31),
            .statement_id = digest(51 + offset),
            .verification_key_id = digest(71),
            .component_log_sizes = [_]u32{4} ** admission.CLAIMED_SUM_COUNT,
            .pre_core_channel = .{ .digest = digest(101 + offset) },
            .claimed_sums = undefined,
            .verifier_input_boundary = .{
                587 + offset,
                593 + offset,
                0,
                0,
            },
            .wire_closure = .{
                .{ 601 + offset, 0, 0, 0 },
                .{ 607 + offset, 0, 0, 0 },
            },
        };
        for (&receipt.claimed_sums, 0..) |*value, index| value.* = .{
            @intCast(200 + offset + index), 0, 0, 0,
        };

        const commitments = try allocator.alloc(channel.Digest, admission.TREE_COUNT);
        for (commitments, 0..) |*value, index| {
            // Tree zero is the common preprocessing commitment and therefore
            // remains identical across compatible children.
            value.* = digest(if (index == 0)
                300
            else
                300 + offset + @as(u32, @intCast(index * 20)));
        }

        const column_log_sizes = try allocator.alloc([]u32, admission.TREE_COUNT);
        for (column_log_sizes, TEST_TREE_HEIGHTS) |*logs, height| {
            logs.* = try allocator.alloc(u32, 1);
            logs.*[0] = height;
        }

        const sampled_values = try allocator.alloc(QM31, admission.TREE_COUNT);
        for (sampled_values, 0..) |*value, index|
            value.* = secure(401 + offset + @as(u32, @intCast(index)));
        const queried_values = try allocator.alloc(
            M31,
            admission.TREE_COUNT * admission.QUERY_COUNT,
        );
        for (queried_values, 0..) |*value, index|
            value.* = M31.fromCanonical(501 + offset + @as(u32, @intCast(index)));
        const deep_answers = try allocator.alloc(QM31, admission.QUERY_COUNT);
        for (deep_answers, 0..) |*value, index|
            value.* = secure(551 + offset + @as(u32, @intCast(index)));
        const last_layer_coefficients = try allocator.alloc(QM31, 1);
        last_layer_coefficients[0] = secure(577 + offset);

        const fri_schedule = try admission.FriScheduleV1.init(TEST_COLUMN_LOG);
        const fri_layers = try allocator.alloc(FriLayerCapture, fri_schedule.count);
        for (fri_layers, fri_schedule.active(), 0..) |*layer, round, index| {
            layer.* = .{
                .commitment = digest(700 + offset + @as(u32, @intCast(index * 20))),
                .folding_alpha = undefined,
                .fold_step = round.fold_step,
                .fold_width = round.fold_width,
                .path_depth = round.authentication_path_depth,
                .query_count = admission.QUERY_COUNT,
                .positions = try allocator.alloc(usize, admission.QUERY_COUNT),
                .values = try allocator.alloc(
                    QM31,
                    admission.QUERY_COUNT * round.fold_width,
                ),
                .siblings = try allocator.alloc(
                    channel.Digest,
                    admission.QUERY_COUNT * round.authentication_path_depth,
                ),
            };
            for (layer.values, 0..) |*value, value_index|
                value.* = secure(800 + offset + @as(u32, @intCast(index * 20 + value_index)));
            for (layer.siblings, 0..) |*value, sibling_index|
                value.* = digest(900 + offset + @as(u32, @intCast(index * 100 + sibling_index)));
        }

        var transcript = channel.Channel{
            .digest = receipt.pre_core_channel.digest,
            .n_draws = receipt.pre_core_channel.draw_count,
        };
        const composition_randomness = transcript.drawSecureFelt();
        engine.MerkleChannel.mixRoot(
            &transcript,
            commitments[admission.TREE_COUNT - 1],
        );
        const oods_seed = transcript.drawSecureFelt();
        transcript.mixFelts(sampled_values);
        const deep_randomness = transcript.drawSecureFelt();
        for (fri_layers) |*layer| {
            engine.MerkleChannel.mixRoot(&transcript, layer.commitment);
            layer.folding_alpha = transcript.drawSecureFelt();
        }
        transcript.mixFelts(last_layer_coefficients);
        const proof_of_work: u64 = 9 + child_seed;
        std.debug.assert(transcript.verifyPowNonce(0, proof_of_work));
        transcript.mixU64(proof_of_work);
        const query_words = transcript.drawU32s();
        const raw_queries = try allocator.alloc(usize, admission.QUERY_COUNT);
        for (raw_queries, query_words[0..admission.QUERY_COUNT]) |*position, word|
            position.* = word & 63;
        const unique_queries = try uniqueSorted(allocator, raw_queries);

        const sampled_points = try allocator.alloc(
            [][]stwo_core.circle.CirclePointQM31,
            admission.TREE_COUNT,
        );
        const current = stwo_core.circle.secureFieldPointFromRandomSeed(oods_seed);
        for (sampled_points) |*columns| {
            columns.* = try allocator.alloc([]stwo_core.circle.CirclePointQM31, 1);
            columns.*[0] = try allocator.alloc(stwo_core.circle.CirclePointQM31, 1);
            columns.*[0][0] = current;
        }

        const trace_paths = try allocator.alloc(MerklePathCapture, admission.TREE_COUNT);
        for (trace_paths, TEST_TREE_HEIGHTS, 0..) |*paths, height, tree| {
            paths.* = .{
                .positions = try allocator.alloc(usize, admission.QUERY_COUNT),
                .path_depth = height,
                .siblings = try allocator.alloc(
                    channel.Digest,
                    admission.QUERY_COUNT * height,
                ),
            };
            for (raw_queries, paths.positions) |raw, *position|
                position.* = mapTreeQueryPosition(raw, 6, height);
            for (paths.siblings, 0..) |*value, index|
                value.* = digest(1_300 + offset + @as(u32, @intCast(tree * 100 + index)));
        }
        for (fri_layers, fri_schedule.active(), 0..) |*layer, _, layer_index| {
            for (raw_queries, layer.positions) |raw, *position|
                position.* = raw >> @intCast(layer_index);
        }

        return .{
            .backing = backing,
            .arena = arena,
            .receipt = receipt,
            .capture = .{
                .queries = .{ .raw = raw_queries, .unique = unique_queries },
                .commitments = commitments,
                .column_log_sizes = column_log_sizes,
                .sampled_points = sampled_points,
                .sampled_values = sampled_values,
                .queried_values = queried_values,
                .deep_answers = deep_answers,
                .trace_paths = trace_paths,
                .fri = .{ .layers = fri_layers },
                .last_layer_coefficients = last_layer_coefficients,
                .proof_of_work = proof_of_work,
                .composition_randomness = composition_randomness,
                .oods_seed = oods_seed,
                .deep_randomness = deep_randomness,
            },
        };
    }

    pub fn deinit(self: *CaptureFixture) void {
        self.capture.deinit(self.arena.allocator());
        self.arena.deinit();
        self.backing.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn honestPairInputs() !source.PairInputsV1 {
    const context = pair_node.VerifierContextV1{
        .session_id = digest(1_701),
        .job_id = digest(1_721),
        .execution_statement_id = digest(1_741),
        .public_call_commitment = digest(1_761),
        .event_count = 3,
        .session_leaf_count = 2,
        .pair_index = 0,
        .aggregator_vk_id = digest(71),
    };
    try context.validate();
    return .{
        .context = context,
        .root_pin = .{ .expected_aggregator_vk_id = context.aggregator_vk_id },
    };
}

pub fn childBinding(
    admitted: *const AdmittedChild,
    pair_inputs: source.PairInputsV1,
    index: usize,
    signed_relation_total: pair_node.SecureFelt,
) !admission.PairChildInputsV1 {
    return .{
        .position = if (index == 0) .left else .right,
        .role = if (index == 0) .core_request else .poseidon2_provider,
        .leaf_index = @intCast(index),
        .pair_index = pair_inputs.context.pair_index,
        .leaf_count = 1,
        .session_id = pair_inputs.context.session_id,
        .challenge_context_id = try pair_inputs.context.challengeContextId(),
        .authority_context_id = try pair_inputs.context.contextId(),
        .parent_vk_id = pair_inputs.context.aggregator_vk_id,
        .statement_id = admitted.candidate.shape.statement_id,
        .summary_id = digest(1_900 + @as(u32, @intCast(index * 20))),
        .event_count = pair_inputs.context.event_count,
        .signed_relation_total = signed_relation_total,
    };
}

pub fn defaultStatement(child_seed: u32) !span_statement.SpanStatement {
    const offset = 10_000 * child_seed;
    var initial_registers = [_]u32{0} ** 32;
    var final_registers = [_]u32{0} ** 32;
    initial_registers[1] = 1 + child_seed;
    final_registers[1] = 2 + child_seed;
    const initial = try span_statement.MachineState.init(
        4 + offset,
        initial_registers,
        digest(2_100 + offset),
        digest(2_120 + offset),
    );
    const final = try span_statement.MachineState.init(
        8 + offset,
        final_registers,
        digest(2_140 + offset),
        digest(2_160 + offset),
    );
    const public_input = digest(2_180 + offset);
    const public_output = digest(2_200 + offset);
    const complete = try span_statement.CompleteExecution.init(
        protocol.protocolId(),
        digest(2_220 + offset),
        initial,
        final,
        public_input,
        public_output,
        1,
    );
    const job = try span_statement.JobContext.init(complete, 1);
    const executed = try span_statement.ExecutedSpan.init(
        0,
        1,
        0,
        1,
        initial,
        final,
        try span_statement.EdgeClaim.present(public_input),
        try span_statement.EdgeClaim.present(public_output),
    );
    return span_statement.SpanStatement.segmentLeaf(job, 0, executed);
}

pub fn statementId(words: *const span_statement.StatementWords) channel.Digest {
    var canonical: [span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 = undefined;
    for (words, &canonical) |word, *target| target.* = word.toU32();
    return protocol.statementId(&canonical);
}

pub fn uniqueSorted(allocator: std.mem.Allocator, raw: []const usize) ![]usize {
    var scratch: [admission.QUERY_COUNT]usize = undefined;
    @memcpy(scratch[0..raw.len], raw);
    std.sort.heap(usize, scratch[0..raw.len], {}, lessThan);
    var count: usize = 0;
    for (scratch[0..raw.len]) |position| {
        if (count == 0 or scratch[count - 1] != position) {
            scratch[count] = position;
            count += 1;
        }
    }
    return allocator.dupe(usize, scratch[0..count]);
}

pub fn lessThan(_: void, left: usize, right: usize) bool {
    return left < right;
}

pub fn mapTreeQueryPosition(position: usize, max_log_size: u32, tree_log_size: u32) usize {
    if (max_log_size < tree_log_size) {
        return (position >> 1 << @intCast(tree_log_size - max_log_size + 1)) +
            (position & 1);
    }
    return (position >> @intCast(max_log_size - tree_log_size + 1) << 1) +
        (position & 1);
}

pub fn digest(seed: u32) channel.Digest {
    var result: channel.Digest = undefined;
    for (&result, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
    return result;
}

pub fn secure(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

pub fn qm31(value: fixed_wire.Qm31Wire) QM31 {
    return QM31.fromU32Unchecked(value[0], value[1], value[2], value[3]);
}

pub fn poison(comptime T: type, destination: *T, value: u8) [@sizeOf(T)]u8 {
    @memset(std.mem.asBytes(destination), value);
    var snapshot: [@sizeOf(T)]u8 = undefined;
    @memcpy(&snapshot, std.mem.asBytes(destination));
    return snapshot;
}

pub fn expectUnchanged(
    comptime T: type,
    destination: *const T,
    snapshot: *const [@sizeOf(T)]u8,
) !void {
    try std.testing.expectEqualSlices(
        u8,
        snapshot,
        std.mem.asBytes(destination),
    );
}

comptime {
    TEST_DIMENSIONS.validate();
}
