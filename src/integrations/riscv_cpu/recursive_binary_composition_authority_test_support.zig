const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const subject = @import("recursive_binary_composition_authority.zig");
const outer = @import("recursive_fri_outer.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const Sha256 = std.crypto.hash.sha2.Sha256;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const binary = recursion.binary_fri_outer_source;
const channel = recursion.poseidon2_channel;
const composition = recursion.air.composition_circuit;
const composition_circuit = recursion.recursion_air_composition_circuit;
const fixed_profile = recursion.fixed_profile;
const manifest_mod = recursion.air.universal_adapter_manifest;
const pair_node = recursion.pair_node;
const protocol = recursion.protocol;
const range_bridge = recursion.air.range_check_8_8_bridge;
const recorder = recursion.air.composition_graph_recorder;
const roster = recursion.air.universal_roster;
const universal_manifest = recursion.air.universal_manifest;
const ProofCapture = outer.OuterProofCapture;
const MerklePathCapture = stwo_core.vcs_lifted.verifier.MerklePathCapture(
    recursion.engine.Hasher.Hash,
);
const FriLayerCapture = stwo_core.fri.FriLayerQueryCapture(
    recursion.engine.Hasher.Hash,
);
const COLUMN_LOG_DEGREE: u32 = 5;
const QUERY_LOG: u32 = COLUMN_LOG_DEGREE + admission.LOG_BLOWUP_FACTOR;
const POSEIDON_LAYOUT_START: u32 = 2;
const CAPTURE_COLUMN_COUNTS = [admission.TREE_COUNT]usize{ 1, 1, 8, 1 };
const CAPTURE_TREE_HEIGHTS = [admission.TREE_COUNT]u32{ 5, 5, 5, 6 };

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    publication: outer.VerifiedOuterProofV1,
    circuit: composition_circuit.Circuit,
    profile: binary.TrustedCompositionProfileV1,
    shape: fixed_profile.ProofShapeV1,
    child: pair_node.VerifiedChildV1,
    input_scratch: []QM31,
    node_scratch: []QM31,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const capture_allocator = arena.allocator();

        var component_log_sizes = [_]u32{4} ** subject.ROSTER_CLAIM_COUNT;
        component_log_sizes[
            @intFromEnum(roster.Component.range_check_8_8)
        ] = range_bridge.LOG_SIZE;
        const manifest = try universal_manifest.build(component_log_sizes);
        const statement_words = try testStatementWords();
        const statement_id = statementId(&statement_words);
        const partials = [outer.POSEIDON2_PARTIAL_COUNT]QM31{
            QM31.fromU32Unchecked(11, 13, 17, 19),
            QM31.fromU32Unchecked(23, 29, 31, 37),
        };
        var claims = [_]recursion.fixed_wire.Qm31Wire{
            .{ 0, 0, 0, 0 },
        } ** subject.ROSTER_CLAIM_COUNT;
        claims[subject.POSEIDON_ROSTER_ROW] = qm31Wire(
            partials[0].add(partials[1]),
        );
        const interaction_root = digest(401);
        var receipt = admission.VerifierReceiptV1{
            .air_program_id = digest(101),
            .manifest_id = outer.manifestIdForSeal(manifest.seal),
            .statement_id = statement_id,
            .verification_key_id = digest(121),
            .component_log_sizes = component_log_sizes,
            .pre_core_channel = .{ .digest = digest(141) },
            .claimed_sums = claims,
            .verifier_input_boundary = .{ 0, 0, 0, 0 },
            .wire_closure = .{
                .{ 0, 0, 0, 0 },
                .{ 0, 0, 0, 0 },
            },
        };
        const pre_relation = admission.ChannelCheckpointV1{
            .digest = digest(161),
        };
        receipt.pre_core_channel = try outer.RelationReplayReceiptV1
            .expectedPreCoreChannel(pre_relation, &receipt, interaction_root);

        var capture = try buildCapture(
            capture_allocator,
            receipt.pre_core_channel,
            interaction_root,
        );
        errdefer capture.deinit(capture_allocator);
        const seal = try admission.deriveVerifierSeal(&receipt, &capture);
        const relation_replay = try outer.RelationReplayReceiptV1.initVerified(
            pre_relation,
            &receipt,
            seal,
            interaction_root,
        );
        const auxiliary = try outer.Poseidon2AuxiliaryClaimSealV1.initVerified(
            &receipt,
            seal,
            relation_replay.identity,
            partials,
        );
        var publication = outer.VerifiedOuterProofV1{
            .capture = capture,
            .receipt = receipt,
            .seal = seal,
            .statement_words = statement_words,
            .relation_replay = relation_replay,
            .poseidon2_partials = partials,
            .auxiliary_claim_seal = auxiliary,
        };
        try publication.validate();

        var circuit = try buildCircuit(
            allocator,
            manifest.seal,
            @intCast(capture.sampled_values.len),
            manifest.total_constraints,
        );
        errdefer circuit.deinit();
        const profile = try binary.TrustedCompositionProfileV1.sealRecorded(
            receipt.air_program_id,
            701,
            circuit.identity_digest,
            circuit.recorded.identity_digest,
            .segment_leaf,
            circuit.input_profile,
            circuit.bindings,
            POSEIDON_LAYOUT_START,
        );
        const shape = try testShape(
            receipt.air_program_id,
            capture.commitments[0],
            @intCast(capture.sampled_values.len),
        );
        const proof_id = try admission.proofIdRuntime(
            seal,
            &receipt,
            &capture,
        );
        const child = pair_node.VerifiedChildV1{
            .position = .left,
            .role = .core_request,
            .leaf_index = 0,
            .pair_index = 0,
            .leaf_count = 1,
            .protocol_id = protocol.PROTOCOL_ID_WORDS,
            .session_id = digest(201),
            .challenge_context_id = digest(221),
            .authority_context_id = digest(241),
            .parent_vk_id = receipt.verification_key_id,
            .statement_id = receipt.statement_id,
            .proof_id = proof_id,
            .transcript_id = seal.transcript_id,
            .summary_id = digest(281),
            .event_count = 3,
            .signed_relation_total = .{ .limbs = .{ 1, 2, 3, 4 } },
        };
        const input_scratch = try allocator.alloc(
            QM31,
            circuit.recorded.input_count,
        );
        errdefer allocator.free(input_scratch);
        const node_scratch = try allocator.alloc(
            QM31,
            circuit.recorded.nodes.len,
        );
        errdefer allocator.free(node_scratch);
        return .{
            .allocator = allocator,
            .arena = arena,
            .publication = publication,
            .circuit = circuit,
            .profile = profile,
            .shape = shape,
            .child = child,
            .input_scratch = input_scratch,
            .node_scratch = node_scratch,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.allocator.free(self.node_scratch);
        self.allocator.free(self.input_scratch);
        self.circuit.deinit();
        self.publication.capture.deinit(self.arena.allocator());
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn expectRejectedAtomic(fixture: *Fixture) !void {
    try expectRejectedAtomicWith(
        fixture,
        fixture.profile,
        fixture.child,
        fixture.shape,
        fixture.input_scratch,
        fixture.node_scratch,
    );
}

pub fn expectRejectedAtomicWith(
    fixture: *Fixture,
    profile: binary.TrustedCompositionProfileV1,
    child: pair_node.VerifiedChildV1,
    shape: fixed_profile.ProofShapeV1,
    input_scratch: []QM31,
    node_scratch: []QM31,
) !void {
    var destination: binary.VerifiedChildCompositionAuthority = undefined;
    @memset(std.mem.asBytes(&destination), 0xa7);
    var before: [@sizeOf(binary.VerifiedChildCompositionAuthority)]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&destination));
    if (subject.publishInto(
        &destination,
        input_scratch,
        node_scratch,
        &fixture.publication,
        profile,
        0,
        child,
        shape,
        &fixture.circuit,
    )) |_| {
        return error.ExpectedCompositionAuthorityRejection;
    } else |_| {}
    try std.testing.expectEqualSlices(
        u8,
        &before,
        std.mem.asBytes(&destination),
    );
}

pub fn expectRejectedAtomicAtIndex(fixture: *Fixture, child_index: usize) !void {
    var destination: binary.VerifiedChildCompositionAuthority = undefined;
    @memset(std.mem.asBytes(&destination), 0x5d);
    var before: [@sizeOf(binary.VerifiedChildCompositionAuthority)]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&destination));
    if (subject.publishInto(
        &destination,
        fixture.input_scratch,
        fixture.node_scratch,
        &fixture.publication,
        fixture.profile,
        child_index,
        fixture.child,
        fixture.shape,
        &fixture.circuit,
    )) |_| {
        return error.ExpectedCompositionAuthorityRejection;
    } else |_| {}
    try std.testing.expectEqualSlices(
        u8,
        &before,
        std.mem.asBytes(&destination),
    );
}

pub fn buildCircuit(
    allocator: std.mem.Allocator,
    manifest_seal: [32]u8,
    sampled_value_count: u32,
    constraint_count: u32,
) !composition_circuit.Circuit {
    const input_profile = composition.InputProfile{
        .sampled_value_count = sampled_value_count,
        .claimed_sum_count = subject.COMPOSITION_CLAIM_COUNT,
        .relation_challenge_count = subject.RELATION_CHALLENGE_COUNT,
    };
    const input_count = try composition.recursionInputCount(input_profile);
    const nodes = try allocator.alloc(composition.Node, input_count + 1);
    errdefer allocator.free(nodes);
    for (nodes[0..input_count]) |*node| node.* = .{ .op = .input };
    nodes[input_count] = .{ .op = .{ .sub = .{ .lhs = 0, .rhs = 0 } } };
    const outputs = try allocator.alloc(u32, 1);
    errdefer allocator.free(outputs);
    outputs[0] = @intCast(input_count);
    const graph_identity = composition.computeGraphDigest(nodes, outputs);
    const bindings = try allocator.alloc(
        composition.RecursionInputBinding,
        input_count,
    );
    errdefer allocator.free(bindings);
    for (bindings, 0..) |*binding, index| {
        binding.* = .{
            .node_id = @intCast(index),
            .source = composition.expectedRecursionSource(
                input_profile,
                index,
            ) orelse return error.InvalidTestCircuit,
        };
    }
    var result = composition_circuit.Circuit{
        .allocator = allocator,
        .recorded = recorder.Circuit{
            .allocator = allocator,
            .nodes = nodes,
            .outputs = outputs,
            .input_count = input_count,
            .identity_digest = graph_identity,
        },
        .bindings = bindings,
        .input_profile = input_profile,
        .manifest_seal = manifest_seal,
        .statistics = .{
            .constraints_per_kind = .{
                constraint_count,
                constraint_count,
                constraint_count,
            },
            .roster_rows_per_kind = .{
                subject.ROSTER_CLAIM_COUNT,
                subject.ROSTER_CLAIM_COUNT,
                subject.ROSTER_CLAIM_COUNT,
            },
            .sampled_values = sampled_value_count,
            .graph_inputs = input_count,
            .graph_nodes = nodes.len,
            .composition_log_size = 17,
            .composition_log_split = 1,
            .quotient_max_log_degree_bound = 16,
            .fri_log_blowup = 1,
        },
        .identity_digest = undefined,
    };
    result.identity_digest = circuitIdentity(&result);
    try result.validate();
    return result;
}

pub fn circuitIdentity(circuit: *const composition_circuit.Circuit) [32]u8 {
    var hash = Sha256.init(.{});
    hash.update(composition_circuit.CIRCUIT_DOMAIN);
    hashInteger(&hash, u16, composition_circuit.FORMAT_VERSION);
    hash.update(&circuit.manifest_seal);
    hash.update(&circuit.recorded.identity_digest);
    hashInteger(&hash, u32, circuit.input_profile.sampled_value_count);
    hashInteger(&hash, u32, circuit.input_profile.claimed_sum_count);
    hashInteger(&hash, u32, circuit.input_profile.relation_challenge_count);
    for (circuit.statistics.constraints_per_kind) |count|
        hashInteger(&hash, u64, @intCast(count));
    for (circuit.statistics.roster_rows_per_kind) |count|
        hashInteger(&hash, u8, count);
    hashInteger(&hash, u64, @intCast(circuit.statistics.sampled_values));
    hashInteger(&hash, u64, @intCast(circuit.statistics.graph_inputs));
    hashInteger(&hash, u64, @intCast(circuit.statistics.graph_nodes));
    hashInteger(&hash, u32, circuit.statistics.composition_log_size);
    hashInteger(&hash, u32, circuit.statistics.composition_log_split);
    hashInteger(
        &hash,
        u32,
        circuit.statistics.quotient_max_log_degree_bound,
    );
    hashInteger(&hash, u32, circuit.statistics.fri_log_blowup);
    return hash.finalResult();
}

pub fn hashInteger(hash: *Sha256, comptime T: type, value: T) void {
    var bytes: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &bytes, value, .little);
    hash.update(&bytes);
}

pub fn buildCapture(
    allocator: std.mem.Allocator,
    pre_core: admission.ChannelCheckpointV1,
    interaction_root: channel.Digest,
) !ProofCapture {
    const commitments = try allocator.alloc(channel.Digest, admission.TREE_COUNT);
    commitments[0] = digest(301);
    commitments[1] = digest(321);
    commitments[2] = interaction_root;
    commitments[3] = digest(341);

    const column_log_sizes = try allocator.alloc([]u32, admission.TREE_COUNT);
    for (column_log_sizes, CAPTURE_COLUMN_COUNTS, CAPTURE_TREE_HEIGHTS) |
        *logs,
        count,
        height,
    | {
        logs.* = try allocator.alloc(u32, count);
        @memset(logs.*, height);
    }

    var transcript = channel.Channel{
        .digest = pre_core.digest,
        .n_draws = pre_core.draw_count,
    };
    const composition_randomness = transcript.drawSecureFelt();
    recursion.engine.MerkleChannel.mixRoot(&transcript, commitments[3]);
    const oods_seed = transcript.drawSecureFelt();
    const current = stwo_core.circle.secureFieldPointFromRandomSeed(oods_seed);
    const step = stwo_core.poly.circle.canonic.CanonicCoset.new(
        COLUMN_LOG_DEGREE,
    ).step();
    const previous = current.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });

    const sampled_points = try allocator.alloc(
        [][]CirclePointQM31,
        admission.TREE_COUNT,
    );
    var sampled_value_count: usize = 0;
    for (sampled_points, CAPTURE_COLUMN_COUNTS, 0..) |*columns, count, tree| {
        columns.* = try allocator.alloc([]CirclePointQM31, count);
        for (columns.*, 0..) |*points, column_index| {
            const point_count: usize = if (tree == 2) 2 else 1;
            points.* = try allocator.alloc(CirclePointQM31, point_count);
            if (tree == 2) {
                points.*[0] = current;
                points.*[1] = previous;
            } else {
                _ = column_index;
                points.*[0] = current;
            }
            sampled_value_count += point_count;
        }
    }
    const sampled_values = try allocator.alloc(QM31, sampled_value_count);
    for (sampled_values, 0..) |*value, index|
        value.* = secure(501 + @as(u32, @intCast(index)));
    transcript.mixFelts(sampled_values);
    const deep_randomness = transcript.drawSecureFelt();

    const fri_schedule = try admission.FriScheduleV1.init(COLUMN_LOG_DEGREE);
    const fri_layers = try allocator.alloc(FriLayerCapture, fri_schedule.count);
    for (fri_layers, fri_schedule.active(), 0..) |*layer, round, index| {
        layer.* = .{
            .commitment = digest(601 + @as(u32, @intCast(index * 20))),
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
            value.* = secure(701 + @as(u32, @intCast(index * 20 + value_index)));
        for (layer.siblings, 0..) |*value, sibling_index|
            value.* = digest(801 + @as(u32, @intCast(index * 100 + sibling_index)));
        recursion.engine.MerkleChannel.mixRoot(&transcript, layer.commitment);
        layer.folding_alpha = transcript.drawSecureFelt();
    }
    const last_layer_coefficients = try allocator.alloc(QM31, 1);
    last_layer_coefficients[0] = secure(901);
    transcript.mixFelts(last_layer_coefficients);
    const proof_of_work: u64 = 9;
    std.debug.assert(transcript.verifyPowNonce(admission.PCS_POW_BITS, proof_of_work));
    transcript.mixU64(proof_of_work);
    const query_words = transcript.drawU32s();
    const raw_queries = try allocator.alloc(usize, admission.QUERY_COUNT);
    const query_mask = (@as(u32, 1) << @intCast(QUERY_LOG)) - 1;
    for (raw_queries, query_words[0..admission.QUERY_COUNT]) |*position, word|
        position.* = word & query_mask;
    const unique_queries = try uniqueSorted(allocator, raw_queries);

    const queried_value_count = blk: {
        var total: usize = 0;
        for (CAPTURE_COLUMN_COUNTS) |count| total += count;
        break :blk total * admission.QUERY_COUNT;
    };
    const queried_values = try allocator.alloc(M31, queried_value_count);
    for (queried_values, 0..) |*value, index|
        value.* = M31.fromCanonical(1_001 + @as(u32, @intCast(index)));
    const deep_answers = try allocator.alloc(QM31, admission.QUERY_COUNT);
    for (deep_answers, 0..) |*value, index|
        value.* = secure(1_101 + @as(u32, @intCast(index)));

    const trace_paths = try allocator.alloc(MerklePathCapture, admission.TREE_COUNT);
    for (trace_paths, CAPTURE_TREE_HEIGHTS, 0..) |*paths, height, tree| {
        paths.* = .{
            .positions = try allocator.alloc(usize, admission.QUERY_COUNT),
            .path_depth = height,
            .siblings = try allocator.alloc(
                channel.Digest,
                admission.QUERY_COUNT * height,
            ),
        };
        for (raw_queries, paths.positions) |raw, *position|
            position.* = mapTreeQueryPosition(raw, QUERY_LOG, height);
        for (paths.siblings, 0..) |*value, index|
            value.* = digest(1_201 + @as(u32, @intCast(tree * 100 + index)));
    }
    var consumed_folds: u32 = 0;
    for (fri_layers, fri_schedule.active()) |*layer, round| {
        for (raw_queries, layer.positions) |raw, *position|
            position.* = raw >> @intCast(consumed_folds);
        consumed_folds += round.fold_step;
    }

    return .{
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
    };
}

pub fn testShape(
    air_program_id: channel.Digest,
    preprocessing_id: channel.Digest,
    sampled_value_count: u32,
) !fixed_profile.ProofShapeV1 {
    return .{
        .air_program_id = air_program_id,
        .preprocessing_id = preprocessing_id,
        .table_layout_id = digest(1_401),
        .table_count = 11,
        .claimed_sum_count = subject.ROSTER_CLAIM_COUNT,
        .sampled_value_count = sampled_value_count,
        .preprocessed_column_count = 1,
        .tree_column_counts = .{ 1, 1, 8, 1 },
        .tree_heights = .{ 5, 5, 5, 6 },
        .column_log_degree = 5,
        .proof_wire_bytes = 1,
        .fri = try fixed_profile.FriSchedule.init(
            5,
            protocol.PCS_CONFIG.fri_config,
        ),
    };
}

pub fn testStatementWords() !recursion.span_statement.StatementWords {
    const initial = try recursion.span_statement.MachineState.init(
        4,
        .{0} ** 32,
        digest(1_501),
        .{0} ** 8,
    );
    const final_state = try recursion.span_statement.MachineState.init(
        8,
        .{0} ** 32,
        digest(1_521),
        .{0} ** 8,
    );
    const public_input = digest(1_541);
    const public_output = digest(1_561);
    const complete = try recursion.span_statement.CompleteExecution.init(
        protocol.protocolId(),
        digest(1_581),
        initial,
        final_state,
        public_input,
        public_output,
        1,
    );
    const job = try recursion.span_statement.JobContext.init(complete, 1);
    const executed = try recursion.span_statement.ExecutedSpan.init(
        0,
        1,
        0,
        1,
        initial,
        final_state,
        try recursion.span_statement.EdgeClaim.present(public_input),
        try recursion.span_statement.EdgeClaim.present(public_output),
    );
    const statement = try recursion.span_statement.SpanStatement.segmentLeaf(
        job,
        0,
        executed,
    );
    return statement.canonicalWords();
}

pub fn statementId(words: *const recursion.span_statement.StatementWords) channel.Digest {
    var canonical: [recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 =
        undefined;
    for (words, &canonical) |word, *target| target.* = word.toU32();
    return protocol.statementId(&canonical);
}

pub fn qm31Wire(value: QM31) recursion.fixed_wire.Qm31Wire {
    var result: recursion.fixed_wire.Qm31Wire = undefined;
    for (value.toM31Array(), &result) |coordinate, *word|
        word.* = coordinate.toU32();
    return result;
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
    for (&result, 0..) |*word, index|
        word.* = seed + @as(u32, @intCast(index));
    return result;
}

pub fn secure(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}
