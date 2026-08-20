const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const subject = @import("recursive_temporal_child_authority.zig");
const outer = @import("recursive_fri_outer.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const recursion = frontend.recursion;
const admission = recursion.outer_parent_child_admission;
const channel = recursion.poseidon2_channel;
const protocol = recursion.protocol;
const range_bridge = recursion.air.range_check_8_8_bridge;
const roster = recursion.air.universal_roster;
const temporal = recursion.temporal_pair_node;
const universal_manifest = recursion.air.universal_manifest;
const global_closure = recursion.binary_global_closure_outer_source;
const RelationDomain = @TypeOf(
    @as(global_closure.DomainClaimV1, undefined).domain,
);

const ProofCapture = outer.OuterProofCapture;
const MerklePathCapture = stwo_core.vcs_lifted.verifier.MerklePathCapture(
    recursion.engine.Hasher,
);
const FriLayerCapture = stwo_core.fri.FriLayerQueryCapture(
    recursion.engine.Hasher,
);

const COLUMN_LOG_DEGREE: u32 = 4;
const QUERY_LOG: u32 = COLUMN_LOG_DEGREE + admission.LOG_BLOWUP_FACTOR;
const TREE_HEIGHT: u32 = QUERY_LOG;
const DIMENSIONS = recursion.fixed_wire.Dimensions{
    .commitment_count = admission.TREE_COUNT,
    .claimed_sum_count = admission.CLAIMED_SUM_COUNT,
    .sampled_value_count = admission.TREE_COUNT,
    .queried_value_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .trace_path_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .fri_layer_count = COLUMN_LOG_DEGREE,
    .query_count = admission.QUERY_COUNT,
    .maximum_fold_width = 2,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = TREE_HEIGHT,
};
const Wire = admission.FixedOuterProofWireV1(DIMENSIONS);

pub const ClosureFixtureV2 = struct {
    prepared: global_closure.PreparedAuthorityV2,
    input: global_closure.ClosureInputV2,

    pub fn init() !ClosureFixtureV2 {
        const range_value = testQm31(19, 23, 29, 31);
        const wire_value = testQm31(89, 97, 101, 103);
        const verifier_input_value = testQm31(107, 109, 113, 127);
        const base_prepared = try global_closure.prepareAuthority();
        var rows: [global_closure.PREFIX_ROW_COUNT]global_closure.RowClaimsV1 =
            undefined;
        for (&rows, 0..) |*row, row_index|
            row.* = emptyClosureRow(@enumFromInt(row_index));

        setClosureDomain(&rows[0], .recursion_wire, testQm31(3, 5, 7, 11));
        setClosureDomain(
            &rows[1],
            .recursion_wire,
            testQm31(3, 5, 7, 11).neg(),
        );
        setClosureDomain(&rows[2], .recursion_wire, wire_value);
        setClosureDomain(
            &rows[3],
            .recursion_verifier_input_word,
            verifier_input_value,
        );
        setClosureDomain(&rows[10], .range_check_8_8, range_value);
        setClosureDomain(&rows[17], .recursion_step, testQm31(37, 41, 43, 47));
        setClosureDomain(
            &rows[18],
            .recursion_step,
            testQm31(37, 41, 43, 47).neg(),
        );
        setClosureDomain(&rows[20], .poseidon2, testQm31(53, 59, 61, 67));
        setClosureDomain(
            &rows[34],
            .poseidon2,
            testQm31(53, 59, 61, 67).neg(),
        );
        for (&rows) |*row| recomputeClosureRow(row);

        const provider = try global_closure.ProviderClaimV1.init(
            &base_prepared,
            shaDigest("temporal-test-range-provider-snapshot"),
            range_value.neg(),
        );
        const wire_evidence = global_closure.BoundaryEvidenceV2{
            .source_authority_id = shaDigest("temporal-test-wire-source"),
            .snapshot_id = shaDigest("temporal-test-wire-snapshot"),
            .tuple_provenance_id = shaDigest("temporal-test-wire-provenance"),
            .tuple_count = 29,
            .claimed_sum = wire_value.neg(),
        };
        const verifier_input_evidence = global_closure.BoundaryEvidenceV2{
            .source_authority_id = shaDigest("temporal-test-input-source"),
            .snapshot_id = shaDigest("temporal-test-input-snapshot"),
            .tuple_provenance_id = shaDigest("temporal-test-input-provenance"),
            .tuple_count = 16,
            .claimed_sum = verifier_input_value.neg(),
        };
        const authorities = try global_closure.BoundaryAuthoritiesV2.init(
            try global_closure.BoundarySourceV2.init(.wire, wire_evidence),
            try global_closure.BoundarySourceV2.init(
                .verifier_input,
                verifier_input_evidence,
            ),
        );
        const prepared = try global_closure.prepareAuthorityV2(authorities);
        const boundaries = try global_closure.PublicBoundariesV2.init(
            &prepared,
            wire_evidence,
            verifier_input_evidence,
        );
        return .{
            .prepared = prepared,
            .input = try global_closure.ClosureInputV2.init(
                &prepared,
                &rows,
                &provider,
                boundaries,
            ),
        };
    }
};

pub fn emptyClosureRow(row: roster.Component) global_closure.RowClaimsV1 {
    var domains: [global_closure.DOMAIN_COUNT]global_closure.DomainClaimV1 =
        undefined;
    for (&domains, 0..) |*claim, domain_index| claim.* = .{
        .active = 0,
        .domain = @enumFromInt(domain_index),
        .value = QM31.zero(),
    };
    return .{
        .row = row,
        .domains = domains,
        .claimed_sum = QM31.zero(),
    };
}

pub fn setClosureDomain(
    row: *global_closure.RowClaimsV1,
    domain: RelationDomain,
    value: QM31,
) void {
    const claim = &row.domains[@intFromEnum(domain)];
    claim.active = 1;
    claim.value = value;
}

pub fn recomputeClosureRow(row: *global_closure.RowClaimsV1) void {
    var total = QM31.zero();
    for (row.domains) |claim| total = total.add(claim.value);
    row.claimed_sum = total;
}

pub fn expectClosurePreflightRejectedAtomic(
    receipt: *const global_closure.ClosureReceiptV2,
) !void {
    var destination: subject.ClosureReceiptPreflightV2 = undefined;
    @memset(std.mem.asBytes(&destination), 0x93);
    var before: [@sizeOf(subject.ClosureReceiptPreflightV2)]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&destination));
    if (subject.preflightClosureReceiptV2Into(&destination, receipt)) |_| {
        return error.ExpectedClosurePreflightRejection;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&destination));
}

pub fn expectClosurePreflightErrorAtomic(
    expected: anyerror,
    receipt: *const global_closure.ClosureReceiptV2,
) !void {
    var destination: subject.ClosureReceiptPreflightV2 = undefined;
    @memset(std.mem.asBytes(&destination), 0x5b);
    var before: [@sizeOf(subject.ClosureReceiptPreflightV2)]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&destination));
    try std.testing.expectError(
        expected,
        subject.preflightClosureReceiptV2Into(&destination, receipt),
    );
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&destination));
}

pub fn testQm31(a: u32, b: u32, c: u32, d: u32) QM31 {
    return QM31.fromU32Unchecked(a, b, c, d);
}

pub fn shaDigest(label: []const u8) [subject.GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8 {
    var result: [subject.GLOBAL_CLOSURE_DIGEST_BYTE_COUNT]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(label, &result, .{});
    return result;
}

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    publication: outer.VerifiedOuterProofV1,
    wire: Wire,
    candidate: admission.BinaryPairCandidateV1,
    encoding_scratch: []u8,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        return initAtSlot(allocator, 0);
    }

    pub fn initAtSlot(
        allocator: std.mem.Allocator,
        segment_index: u32,
    ) !Fixture {
        if (segment_index > 1) return error.InvalidTestSegmentIndex;
        const arena = try allocator.create(std.heap.ArenaAllocator);
        errdefer allocator.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const capture_allocator = arena.allocator();

        var component_log_sizes = [_]u32{4} ** admission.CLAIMED_SUM_COUNT;
        component_log_sizes[@intFromEnum(roster.Component.range_check_8_8)] =
            range_bridge.LOG_SIZE;
        const manifest = try universal_manifest.build(component_log_sizes);
        const statement_words = try testStatementWords(segment_index);
        const statement_id = statementId(&statement_words);
        const zero_wire = recursion.fixed_wire.Qm31Wire{ 0, 0, 0, 0 };
        const claimed_sums = [_]recursion.fixed_wire.Qm31Wire{zero_wire} **
            admission.CLAIMED_SUM_COUNT;
        const partials = [_]QM31{QM31.zero()} ** outer.POSEIDON2_PARTIAL_COUNT;
        const interaction_root = digest(401);
        var receipt = admission.VerifierReceiptV1{
            .air_program_id = digest(101),
            .manifest_id = outer.manifestIdForSeal(manifest.seal),
            .statement_id = statement_id,
            .verification_key_id = digest(121),
            .component_log_sizes = component_log_sizes,
            .pre_core_channel = .{ .digest = digest(141) },
            .claimed_sums = claimed_sums,
            .verifier_input_boundary = zero_wire,
            .wire_closure = .{ zero_wire, zero_wire },
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

        const encoding_scratch = try allocator.alloc(
            u8,
            admission.serializedByteCount(DIMENSIONS),
        );
        errdefer allocator.free(encoding_scratch);
        var wire: Wire = undefined;
        const candidate = try admission.admit(
            DIMENSIONS,
            &wire,
            encoding_scratch,
            publication.seal,
            &publication.receipt,
            &publication.capture,
        );
        return .{
            .allocator = allocator,
            .arena = arena,
            .publication = publication,
            .wire = wire,
            .candidate = candidate,
            .encoding_scratch = encoding_scratch,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.allocator.free(self.encoding_scratch);
        self.publication.capture.deinit(self.arena.allocator());
        self.arena.deinit();
        self.allocator.destroy(self.arena);
        self.* = undefined;
    }
};

pub fn expectInspectionRejectedAtomic(fixture: *Fixture) !void {
    var destination: subject.DerivedVerifierFieldsV1 = undefined;
    @memset(std.mem.asBytes(&destination), 0xc7);
    var before: [@sizeOf(subject.DerivedVerifierFieldsV1)]u8 = undefined;
    @memcpy(&before, std.mem.asBytes(&destination));
    if (subject.inspectInto(
        DIMENSIONS,
        &destination,
        fixture.encoding_scratch,
        &fixture.publication,
        &fixture.wire,
        &fixture.candidate,
    )) |_| {
        return error.ExpectedTemporalChildInspectionRejection;
    } else |_| {}
    try std.testing.expectEqualSlices(u8, &before, std.mem.asBytes(&destination));
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
    for (column_log_sizes) |*logs| {
        logs.* = try allocator.alloc(u32, 1);
        logs.*[0] = TREE_HEIGHT;
    }

    var transcript = channel.Channel{
        .digest = pre_core.digest,
        .n_draws = pre_core.draw_count,
    };
    const composition_randomness = transcript.drawSecureFelt();
    recursion.engine.MerkleChannel.mixRoot(&transcript, commitments[3]);
    const oods_seed = transcript.drawSecureFelt();
    const current = stwo_core.circle.secureFieldPointFromRandomSeed(oods_seed);

    const sampled_points = try allocator.alloc(
        [][]CirclePointQM31,
        admission.TREE_COUNT,
    );
    for (sampled_points) |*columns| {
        columns.* = try allocator.alloc([]CirclePointQM31, 1);
        columns.*[0] = try allocator.alloc(CirclePointQM31, 1);
        columns.*[0][0] = current;
    }
    const sampled_values = try allocator.alloc(QM31, admission.TREE_COUNT);
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

    const queried_values = try allocator.alloc(
        M31,
        admission.TREE_COUNT * admission.QUERY_COUNT,
    );
    for (queried_values, 0..) |*value, index|
        value.* = M31.fromCanonical(1_001 + @as(u32, @intCast(index)));
    const deep_answers = try allocator.alloc(QM31, admission.QUERY_COUNT);
    for (deep_answers, 0..) |*value, index|
        value.* = secure(1_101 + @as(u32, @intCast(index)));

    const trace_paths = try allocator.alloc(MerklePathCapture, admission.TREE_COUNT);
    for (trace_paths, 0..) |*paths, tree| {
        paths.* = .{
            .positions = try allocator.alloc(usize, admission.QUERY_COUNT),
            .path_depth = TREE_HEIGHT,
            .siblings = try allocator.alloc(
                channel.Digest,
                admission.QUERY_COUNT * TREE_HEIGHT,
            ),
        };
        for (raw_queries, paths.positions) |raw, *position|
            position.* = mapTreeQueryPosition(raw, QUERY_LOG, TREE_HEIGHT);
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

pub fn testStatementWords(
    segment_index: u32,
) !recursion.span_statement.StatementWords {
    const initial = try recursion.span_statement.MachineState.init(
        4,
        .{0} ** 32,
        digest(1_501),
        .{0} ** 8,
    );
    const middle = try recursion.span_statement.MachineState.init(
        8,
        .{0} ** 32,
        digest(1_521),
        .{0} ** 8,
    );
    const final_state = try recursion.span_statement.MachineState.init(
        12,
        .{0} ** 32,
        digest(1_531),
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
        2,
    );
    const job = try recursion.span_statement.JobContext.init(complete, 2);
    const executed = try recursion.span_statement.ExecutedSpan.init(
        segment_index,
        1,
        segment_index,
        1,
        if (segment_index == 0) initial else middle,
        if (segment_index == 0) middle else final_state,
        if (segment_index == 0)
            try recursion.span_statement.EdgeClaim.present(public_input)
        else
            recursion.span_statement.EdgeClaim.absent(),
        if (segment_index == 0)
            recursion.span_statement.EdgeClaim.absent()
        else
            try recursion.span_statement.EdgeClaim.present(public_output),
    );
    const statement = try recursion.span_statement.SpanStatement.segmentLeaf(
        job,
        segment_index,
        executed,
    );
    return statement.canonicalWords();
}

pub fn statementId(
    words: *const recursion.span_statement.StatementWords,
) channel.Digest {
    var canonical: [recursion.span_statement.SPAN_STATEMENT_CANONICAL_WORDS]u32 =
        undefined;
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

pub fn mapTreeQueryPosition(
    position: usize,
    max_log_size: u32,
    tree_log_size: u32,
) usize {
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

pub fn digestIsZero(value: channel.Digest) bool {
    var aggregate: u32 = 0;
    for (value) |word| aggregate |= word;
    return aggregate == 0;
}

pub fn secure(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}
