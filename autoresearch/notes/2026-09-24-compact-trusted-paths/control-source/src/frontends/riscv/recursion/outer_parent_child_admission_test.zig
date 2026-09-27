const std = @import("std");
const stwo_core = @import("stwo_core");
const admission = @import("outer_parent_child_admission.zig");
const channel = @import("poseidon2_channel.zig");
const engine = @import("engine.zig");
const fixed_wire = @import("fixed_wire.zig");
const pair_node = @import("pair_node.zig");
const protocol = @import("protocol.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;
const CirclePointQM31 = stwo_core.circle.CirclePointQM31;
const ProofCapture = stwo_core.pcs.verifier.VerifiedProofCapture(engine.Hasher);
const MerklePathCapture = stwo_core.vcs_lifted.verifier.MerklePathCapture(
    engine.Hasher,
);
const FriLayerCapture = stwo_core.fri.FriLayerQueryCapture(engine.Hasher);

const TEST_COLUMN_LOG: u32 = 5;
const TEST_TREE_HEIGHTS = [admission.TREE_COUNT]u32{ 5, 5, 5, 6 };
const TEST_DIMENSIONS = fixed_wire.Dimensions{
    .commitment_count = admission.TREE_COUNT,
    .claimed_sum_count = admission.CLAIMED_SUM_COUNT,
    .sampled_value_count = admission.TREE_COUNT + 2,
    .queried_value_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .trace_path_count = admission.TREE_COUNT * admission.QUERY_COUNT,
    .fri_layer_count = TEST_COLUMN_LOG,
    .query_count = admission.QUERY_COUNT,
    .maximum_fold_width = 2,
    .last_layer_coefficient_count = 1,
    .maximum_merkle_depth = 6,
};
const Wire = admission.FixedOuterProofWireV1(TEST_DIMENSIONS);

test "R-013 outer parent child profile is distinct from frozen leaf V1" {
    try std.testing.expectEqual(@as(usize, 3), admission.QUERY_COUNT);
    try std.testing.expectEqual(@as(u32, 0), admission.PCS_POW_BITS);
    try std.testing.expectEqual(@as(u32, 0), admission.INTERACTION_POW_BITS);
    try std.testing.expectEqual(@as(u32, 1), admission.FOLD_STEP);
    try std.testing.expectEqual(@as(usize, 36), admission.CLAIMED_SUM_COUNT);
    try std.testing.expect(protocol.FRI_QUERY_COUNT != admission.QUERY_COUNT);
    try std.testing.expect(protocol.PCS_POW_BITS != admission.PCS_POW_BITS);
    try std.testing.expect(protocol.FRI_FOLD_STEP != admission.FOLD_STEP);
    try std.testing.expect(!admission.RECURSIVE_PARENT_PRODUCTION);

    const long = try admission.FriScheduleV1.init(21);
    try std.testing.expectEqual(@as(u32, 21), long.count);
    try std.testing.expectEqual(@as(u32, 21), long.active()[0].evaluation_log - 1);
    try std.testing.expectEqual(@as(u32, 1), long.active()[20].authentication_path_depth);
}

test "R-013 verifier-captured outer proof admits one exact fixed candidate" {
    var fixture = try CaptureFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const seal = try admission.deriveVerifierSeal(
        &fixture.receipt,
        &fixture.capture,
    );

    const wire = try std.testing.allocator.create(Wire);
    defer std.testing.allocator.destroy(wire);
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(TEST_DIMENSIONS),
    );
    defer std.testing.allocator.free(scratch);
    var candidate = try admission.admit(
        TEST_DIMENSIONS,
        wire,
        scratch,
        seal,
        &fixture.receipt,
        &fixture.capture,
    );
    try candidate.validate();
    try wire.validateAgainst(&candidate, scratch);

    try std.testing.expectEqual(admission.ProofScope.verifier_subsystem, candidate.scope);
    try std.testing.expectEqual(@as(usize, 3), candidate.dimensions.query_count);
    try std.testing.expectEqual(@as(usize, 2), candidate.dimensions.maximum_fold_width);
    try std.testing.expectEqual(@as(usize, 5), candidate.dimensions.fri_layer_count);
    try std.testing.expectEqual(
        @as(u64, admission.serializedByteCount(TEST_DIMENSIONS)),
        candidate.canonical_wire_bytes,
    );
    try std.testing.expectEqual(protocol.proofId(scratch), candidate.proof_id);
    try std.testing.expectEqual(seal.profile_id, candidate.profile_id);
    try std.testing.expectEqual(seal.capture_id, candidate.capture_id);
    try std.testing.expectEqual(seal.transcript_id, candidate.transcript_id);
    try std.testing.expectEqual(
        fixture.receipt.verifier_input_boundary,
        seal.verifier_input_boundary,
    );
    try std.testing.expectEqual(
        fixture.receipt.verifier_input_boundary,
        candidate.verifier_input_boundary,
    );
    try std.testing.expectEqual(
        fixture.receipt.verifier_input_boundary,
        wire.verifier_input_boundary,
    );
    try std.testing.expect(!std.meta.eql(
        fixture.receipt.verifier_input_boundary,
        fixture.receipt.wire_closure[0],
    ));
    try std.testing.expect(!std.meta.eql(
        fixture.receipt.verifier_input_boundary,
        fixture.receipt.wire_closure[1],
    ));
    try std.testing.expect(wire.transcriptWire() == &wire.payload);
    try std.testing.expect(!candidate.productionReady());
    try std.testing.expectError(
        error.ParentProofIncomplete,
        candidate.verifiedChild(pairInputs()),
    );

    const second = try std.testing.allocator.alloc(u8, scratch.len);
    defer std.testing.allocator.free(second);
    try wire.encodeInto(&candidate, second);
    try std.testing.expectEqualSlices(u8, scratch, second);
}

test "R-013 runtime admission is byte-identical to the fixed wire codec" {
    var fixture = try CaptureFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const seal = try admission.deriveVerifierSeal(
        &fixture.receipt,
        &fixture.capture,
    );

    const fixed = try std.testing.allocator.create(Wire);
    defer std.testing.allocator.destroy(fixed);
    const fixed_bytes = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(TEST_DIMENSIONS),
    );
    defer std.testing.allocator.free(fixed_bytes);
    const fixed_candidate = try admission.admit(
        TEST_DIMENSIONS,
        fixed,
        fixed_bytes,
        seal,
        &fixture.receipt,
        &fixture.capture,
    );

    const runtime_bytes = try std.testing.allocator.alloc(u8, fixed_bytes.len);
    defer std.testing.allocator.free(runtime_bytes);
    @memset(runtime_bytes, 0xa7);
    try std.testing.expectEqual(
        runtime_bytes.len,
        try admission.runtimeCanonicalByteCount(
            seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
    const runtime = try admission.admitRuntime(
        runtime_bytes,
        seal,
        &fixture.receipt,
        &fixture.capture,
    );
    try runtime.validate();
    try std.testing.expectEqual(fixed_bytes.len, runtime.canonical_byte_count);
    try std.testing.expectEqual(fixed_candidate, runtime.candidate);
    try std.testing.expectEqualSlices(u8, fixed_bytes, runtime_bytes);
    try std.testing.expectEqual(
        protocol.proofId(runtime_bytes),
        runtime.candidate.proof_id,
    );
    try std.testing.expectEqual(
        runtime.candidate.proof_id,
        try admission.proofIdRuntime(
            seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );

    var stale_seal = seal;
    stale_seal.capture_id[0] ^= 1;
    try std.testing.expectError(
        error.ProfileSealMismatch,
        admission.proofIdRuntime(
            stale_seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
}

test "R-013 runtime admission rejects atomically before encoding" {
    var fixture = try CaptureFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const seal = try admission.deriveVerifierSeal(
        &fixture.receipt,
        &fixture.capture,
    );
    const byte_count = admission.serializedByteCount(TEST_DIMENSIONS);
    const destination = try std.testing.allocator.alloc(u8, byte_count);
    defer std.testing.allocator.free(destination);

    @memset(destination, 0x6d);
    var wrong_seal = seal;
    wrong_seal.receipt_id[0] ^= 1;
    try std.testing.expectError(
        error.ProfileSealMismatch,
        admission.admitRuntime(
            destination,
            wrong_seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
    try expectByte(destination, 0x6d);

    try std.testing.expectError(
        error.ByteLengthMismatch,
        admission.admitRuntime(
            destination[0 .. destination.len - 1],
            seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
    try expectByte(destination, 0x6d);

    const oversized = try std.testing.allocator.alloc(u8, byte_count + 1);
    defer std.testing.allocator.free(oversized);
    @memset(oversized, 0x4b);
    try std.testing.expectError(
        error.ByteLengthMismatch,
        admission.admitRuntime(
            oversized,
            seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
    try expectByte(oversized, 0x4b);

    @memset(destination, 0x6d);
    const original_point = fixture.capture.sampled_points[0][0][0];
    fixture.capture.sampled_points[0][0][0].x = original_point.x.add(QM31.one());
    defer fixture.capture.sampled_points[0][0][0] = original_point;
    try std.testing.expectError(
        error.SamplePointLayoutMismatch,
        admission.admitRuntime(
            destination,
            seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
    try expectByte(destination, 0x6d);
}

test "R-013 sampled-point layout admits both protocol conventions only" {
    const current = stwo_core.circle.secureFieldPointFromRandomSeed(secure(1_901));
    const step = stwo_core.poly.circle.canonic.CanonicCoset.new(
        TEST_COLUMN_LOG,
    ).step();
    const previous = current.sub(.{
        .x = QM31.fromBase(step.x),
        .y = QM31.fromBase(step.y),
    });

    const empty = [_]CirclePointQM31{};
    try admission.validateSamplePointColumnLayout(&empty, current, previous);
    try admission.validateSamplePointColumnLayout(&.{current}, current, previous);
    try admission.validateSamplePointColumnLayout(
        &.{ current, previous },
        current,
        previous,
    );
    try admission.validateSamplePointColumnLayout(
        &.{ previous, current },
        current,
        previous,
    );

    try std.testing.expectError(
        error.SamplePointLayoutMismatch,
        admission.validateSamplePointColumnLayout(&.{previous}, current, previous),
    );
    try std.testing.expectError(
        error.SamplePointLayoutMismatch,
        admission.validateSamplePointColumnLayout(
            &.{ current, current },
            current,
            previous,
        ),
    );
    var mutated = current;
    mutated.x = mutated.x.add(QM31.one());
    try std.testing.expectError(
        error.SamplePointLayoutMismatch,
        admission.validateSamplePointColumnLayout(
            &.{ mutated, previous },
            current,
            previous,
        ),
    );
}

test "R-013 shape profile and scope substitutions reject before publication" {
    var fixture = try CaptureFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const honest_seal = try admission.deriveVerifierSeal(
        &fixture.receipt,
        &fixture.capture,
    );
    const wire = try std.testing.allocator.create(Wire);
    defer std.testing.allocator.destroy(wire);
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(TEST_DIMENSIONS),
    );
    defer std.testing.allocator.free(scratch);

    @memset(std.mem.asBytes(wire), 0xa5);
    fixture.receipt.component_log_sizes[9] += 1;
    try std.testing.expectError(
        error.ProfileSealMismatch,
        admission.admit(
            TEST_DIMENSIONS,
            wire,
            scratch,
            honest_seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
    try expectByte(std.mem.asBytes(wire), 0xa5);
    fixture.receipt.component_log_sizes[9] -= 1;

    fixture.receipt.air_program_id[0] ^= 1;
    try std.testing.expectError(
        error.ProfileSealMismatch,
        admission.admit(
            TEST_DIMENSIONS,
            wire,
            scratch,
            honest_seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
    try expectByte(std.mem.asBytes(wire), 0xa5);
    fixture.receipt.air_program_id[0] ^= 1;

    fixture.receipt.verifier_input_boundary[2] += 1;
    try std.testing.expectError(
        error.ProfileSealMismatch,
        admission.admit(
            TEST_DIMENSIONS,
            wire,
            scratch,
            honest_seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
    try expectByte(std.mem.asBytes(wire), 0xa5);
    fixture.receipt.verifier_input_boundary[2] -= 1;

    const canonical_boundary_word = fixture.receipt.verifier_input_boundary[3];
    fixture.receipt.verifier_input_boundary[3] = stwo_core.fields.m31.Modulus;
    try std.testing.expectError(
        error.NonCanonicalCapture,
        admission.deriveVerifierSeal(&fixture.receipt, &fixture.capture),
    );
    fixture.receipt.verifier_input_boundary[3] = canonical_boundary_word;

    fixture.receipt.scope = .complete_parent;
    try std.testing.expectError(
        error.ProfileSealMismatch,
        admission.admit(
            TEST_DIMENSIONS,
            wire,
            scratch,
            honest_seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
    try expectByte(std.mem.asBytes(wire), 0xa5);
    fixture.receipt.scope = .verifier_subsystem;

    fixture.capture.column_log_sizes[0][0] += 1;
    try std.testing.expectError(
        error.InvalidColumnLayout,
        admission.deriveVerifierSeal(&fixture.receipt, &fixture.capture),
    );
    fixture.capture.column_log_sizes[0][0] -= 1;

    const raw = fixture.capture.queries.raw;
    fixture.capture.queries.raw = raw[0..2];
    try std.testing.expectError(
        error.CaptureShapeMismatch,
        admission.deriveVerifierSeal(&fixture.receipt, &fixture.capture),
    );
    fixture.capture.queries.raw = raw;
}

test "R-013 transcript query and canonical-capture mutations reject" {
    var fixture = try CaptureFixture.init(std.testing.allocator);
    defer fixture.deinit();

    fixture.receipt.pre_core_channel.digest[0] ^= 1;
    try std.testing.expectError(
        error.TranscriptMismatch,
        admission.deriveVerifierSeal(&fixture.receipt, &fixture.capture),
    );
    fixture.receipt.pre_core_channel.digest[0] ^= 1;

    const composition = fixture.capture.composition_randomness;
    fixture.capture.composition_randomness = composition.add(QM31.one());
    try std.testing.expectError(
        error.TranscriptMismatch,
        admission.deriveVerifierSeal(&fixture.receipt, &fixture.capture),
    );
    fixture.capture.composition_randomness = composition;

    const alpha = fixture.capture.fri.layers[2].folding_alpha;
    fixture.capture.fri.layers[2].folding_alpha = alpha.add(QM31.one());
    try std.testing.expectError(
        error.TranscriptMismatch,
        admission.deriveVerifierSeal(&fixture.receipt, &fixture.capture),
    );
    fixture.capture.fri.layers[2].folding_alpha = alpha;

    const query = fixture.capture.queries.raw[0];
    fixture.capture.queries.raw[0] = (query + 1) & 63;
    try std.testing.expectError(
        error.InvalidQuerySchedule,
        admission.deriveVerifierSeal(&fixture.receipt, &fixture.capture),
    );
    fixture.capture.queries.raw[0] = query;

    const commitment_word = fixture.capture.commitments[1][0];
    fixture.capture.commitments[1][0] = stwo_core.fields.m31.Modulus;
    try std.testing.expectError(
        error.NonCanonicalCapture,
        admission.deriveVerifierSeal(&fixture.receipt, &fixture.capture),
    );
    fixture.capture.commitments[1][0] = commitment_word;
}

test "R-013 fixed outer wire rejects header payload padding and alias mutations" {
    var fixture = try CaptureFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const seal = try admission.deriveVerifierSeal(
        &fixture.receipt,
        &fixture.capture,
    );
    const wire = try std.testing.allocator.create(Wire);
    defer std.testing.allocator.destroy(wire);
    const scratch = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(TEST_DIMENSIONS),
    );
    defer std.testing.allocator.free(scratch);
    var candidate = try admission.admit(
        TEST_DIMENSIONS,
        wire,
        scratch,
        seal,
        &fixture.receipt,
        &fixture.capture,
    );

    wire.format_version += 1;
    try std.testing.expectError(
        error.WireHeaderMismatch,
        wire.validateAgainst(&candidate, scratch),
    );
    wire.format_version -= 1;

    wire.verifier_input_boundary[1] += 1;
    try std.testing.expectError(
        error.WireHeaderMismatch,
        wire.validateAgainst(&candidate, scratch),
    );
    wire.verifier_input_boundary[1] -= 1;

    wire.payload.claimed_sums[0][0] += 1;
    try std.testing.expectError(
        error.WireHeaderMismatch,
        wire.validateAgainst(&candidate, scratch),
    );
    wire.payload.claimed_sums[0][0] -= 1;

    wire.payload.trace_paths[0].siblings[5] = digest(901);
    try std.testing.expectError(
        error.NonZeroMerklePadding,
        wire.validateAgainst(&candidate, scratch),
    );
    wire.payload.trace_paths[0].siblings[5] = [_]u32{0} ** channel.RATE;

    wire.payload.pcs_pow += 1;
    try std.testing.expectError(
        error.WireHeaderMismatch,
        wire.validateAgainst(&candidate, scratch),
    );
    wire.payload.pcs_pow -= 1;

    @memset(scratch, 0x77);
    candidate.proof_id[0] ^= 1;
    try std.testing.expectError(
        error.WireHeaderMismatch,
        wire.validateAgainst(&candidate, scratch),
    );
    try expectByte(scratch, 0x77);
    candidate.proof_id[0] ^= 1;

    const aliased = std.mem.asBytes(wire)[0..scratch.len];
    try std.testing.expectError(
        error.AliasedBuffer,
        wire.validateAgainst(&candidate, aliased),
    );
}

test "R-013 outer admission rejects wrong dimensions and scratch atomically" {
    var fixture = try CaptureFixture.init(std.testing.allocator);
    defer fixture.deinit();
    const seal = try admission.deriveVerifierSeal(
        &fixture.receipt,
        &fixture.capture,
    );
    const wire = try std.testing.allocator.create(Wire);
    defer std.testing.allocator.destroy(wire);
    @memset(std.mem.asBytes(wire), 0x3c);
    const short = try std.testing.allocator.alloc(
        u8,
        admission.serializedByteCount(TEST_DIMENSIONS) - 1,
    );
    defer std.testing.allocator.free(short);
    try std.testing.expectError(
        error.ByteLengthMismatch,
        admission.admit(
            TEST_DIMENSIONS,
            wire,
            short,
            seal,
            &fixture.receipt,
            &fixture.capture,
        ),
    );
    try expectByte(std.mem.asBytes(wire), 0x3c);
}

const CaptureFixture = struct {
    backing: std.mem.Allocator,
    arena: *std.heap.ArenaAllocator,
    receipt: admission.VerifierReceiptV1,
    capture: ProofCapture,

    fn init(backing: std.mem.Allocator) !CaptureFixture {
        const arena = try backing.create(std.heap.ArenaAllocator);
        errdefer backing.destroy(arena);
        arena.* = std.heap.ArenaAllocator.init(backing);
        errdefer arena.deinit();
        const allocator = arena.allocator();

        var receipt = admission.VerifierReceiptV1{
            .air_program_id = digest(11),
            .manifest_id = digest(31),
            .statement_id = digest(51),
            .verification_key_id = digest(71),
            .component_log_sizes = [_]u32{4} ** admission.CLAIMED_SUM_COUNT,
            .pre_core_channel = .{ .digest = digest(101) },
            .claimed_sums = undefined,
            .verifier_input_boundary = .{ 593, 599, 0, 0 },
            .wire_closure = .{
                .{ 601, 0, 0, 0 },
                .{ 607, 0, 0, 0 },
            },
        };
        for (&receipt.claimed_sums, 0..) |*value, index| value.* = .{
            @intCast(200 + index), 0, 0, 0,
        };

        const commitments = try allocator.alloc(channel.Digest, admission.TREE_COUNT);
        for (commitments, 0..) |*value, index| value.* = digest(300 + @as(u32, @intCast(index * 20)));

        const column_log_sizes = try allocator.alloc([]u32, admission.TREE_COUNT);
        for (column_log_sizes, TEST_TREE_HEIGHTS) |*logs, height| {
            logs.* = try allocator.alloc(u32, 1);
            logs.*[0] = height;
        }

        const sampled_values = try allocator.alloc(
            QM31,
            TEST_DIMENSIONS.sampled_value_count,
        );
        for (sampled_values, 0..) |*value, index|
            value.* = secure(401 + @as(u32, @intCast(index)));
        const queried_values = try allocator.alloc(
            M31,
            admission.TREE_COUNT * admission.QUERY_COUNT,
        );
        for (queried_values, 0..) |*value, index|
            value.* = M31.fromCanonical(501 + @as(u32, @intCast(index)));
        const deep_answers = try allocator.alloc(QM31, admission.QUERY_COUNT);
        for (deep_answers, 0..) |*value, index|
            value.* = secure(551 + @as(u32, @intCast(index)));
        const last_layer_coefficients = try allocator.alloc(QM31, 1);
        last_layer_coefficients[0] = secure(577);

        const fri_schedule = try admission.FriScheduleV1.init(TEST_COLUMN_LOG);
        const fri_layers = try allocator.alloc(FriLayerCapture, fri_schedule.count);
        for (fri_layers, fri_schedule.active(), 0..) |*layer, round, index| {
            layer.* = .{
                .commitment = digest(700 + @as(u32, @intCast(index * 20))),
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
                value.* = secure(800 + @as(u32, @intCast(index * 20 + value_index)));
            for (layer.siblings, 0..) |*value, sibling_index|
                value.* = digest(900 + @as(u32, @intCast(index * 100 + sibling_index)));
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
        const proof_of_work: u64 = 9;
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
        const step = stwo_core.poly.circle.canonic.CanonicCoset.new(
            TEST_COLUMN_LOG,
        ).step();
        const previous = current.sub(.{
            .x = QM31.fromBase(step.x),
            .y = QM31.fromBase(step.y),
        });
        for (sampled_points, 0..) |*columns, tree| {
            columns.* = try allocator.alloc([]stwo_core.circle.CirclePointQM31, 1);
            const point_count: usize = if (tree < 2) 2 else 1;
            columns.*[0] = try allocator.alloc(
                stwo_core.circle.CirclePointQM31,
                point_count,
            );
            if (tree == 0) {
                columns.*[0][0] = current;
                columns.*[0][1] = previous;
            } else if (tree == 1) {
                columns.*[0][0] = previous;
                columns.*[0][1] = current;
            } else {
                columns.*[0][0] = current;
            }
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
                value.* = digest(1_300 + @as(u32, @intCast(tree * 100 + index)));
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

    fn deinit(self: *CaptureFixture) void {
        self.capture.deinit(self.arena.allocator());
        self.arena.deinit();
        self.backing.destroy(self.arena);
        self.* = undefined;
    }
};

fn pairInputs() admission.PairChildInputsV1 {
    return .{
        .position = .left,
        .role = .core_request,
        .leaf_index = 0,
        .pair_index = 0,
        .leaf_count = 1,
        .session_id = digest(1_701),
        .challenge_context_id = digest(1_721),
        .authority_context_id = digest(1_741),
        .parent_vk_id = digest(1_761),
        .statement_id = digest(1_781),
        .summary_id = digest(1_801),
        .event_count = 3,
        .signed_relation_total = pair_node.SecureFelt{ .limbs = .{ 1, 2, 3, 4 } },
    };
}

fn uniqueSorted(allocator: std.mem.Allocator, raw: []const usize) ![]usize {
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

fn lessThan(_: void, left: usize, right: usize) bool {
    return left < right;
}

fn mapTreeQueryPosition(position: usize, max_log_size: u32, tree_log_size: u32) usize {
    if (max_log_size < tree_log_size) {
        return (position >> 1 << @intCast(tree_log_size - max_log_size + 1)) +
            (position & 1);
    }
    return (position >> @intCast(max_log_size - tree_log_size + 1) << 1) +
        (position & 1);
}

fn digest(seed: u32) channel.Digest {
    var result: channel.Digest = undefined;
    for (&result, 0..) |*word, index| word.* = seed + @as(u32, @intCast(index));
    return result;
}

fn secure(value: u32) QM31 {
    return QM31.fromBase(M31.fromCanonical(value));
}

fn expectByte(bytes: []const u8, expected: u8) !void {
    for (bytes) |actual| try std.testing.expectEqual(expected, actual);
}

comptime {
    TEST_DIMENSIONS.validate();
}
