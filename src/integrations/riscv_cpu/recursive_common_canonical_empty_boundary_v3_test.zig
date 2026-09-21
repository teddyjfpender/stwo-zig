const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const public = @import("recursive_field_node_public_v2.zig");
const canonical = @import("recursive_common_canonical_empty_field_public_v2.zig");
const subject = @import("recursive_common_canonical_empty_boundary_v3.zig");
const recorder = frontend.recursion.air.composition_graph_recorder;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub fn exercise(fixture: *const public.NodePublicV2) !void {
    try checkSession(fixture);
    const allocator = std.testing.allocator;
    const schedule = try canonical.PoseidonScheduleV2.build(fixture.statement_words, fixture.coordinate);
    const words = try schedule.node_public.canonicalAirWords();
    const relations = frontend.recursion.air.universal_challenges.UniversalRelations.dummy();
    const domain = @intFromEnum(frontend.air.relation.Domain.poseidon2_io);
    const relation = try relations.getExact(.poseidon2_io);
    var sum = QM31.zero();
    var first_denominator: QM31 = undefined;
    for (schedule.calls, 0..) |call, index| {
        var input: [16]M31 = undefined;
        var generic: [16]QM31 = undefined;
        for (call.input, &input, &generic) |word, *base, *secure| {
            base.* = M31.fromCanonical(word);
            secure.* = QM31.fromBase(base.*);
        }
        var output = input;
        frontend.air.memory_commitment.poseidon2.permute(&output);
        frontend.air.memory_commitment.poseidon2_air.permuteGeneric(QM31, &generic);
        for (output, generic) |base, secure| try std.testing.expect(secure.eql(QM31.fromBase(base)));
        const denominator = try relation.combineBase(&(input ++ output));
        if (index == 0) first_denominator = denominator;
        sum = sum.sub(try denominator.inv());
    }
    var builder = recorder.Builder.init(allocator);
    defer builder.deinit();
    var symbolic: [public.AIR_WORD_COUNT]recorder.Scalar = undefined;
    for (&symbolic) |*word| word.* = (try builder.input()).value;
    const z = (try builder.input()).value;
    const alpha = (try builder.input()).value;
    const claim = (try builder.input()).value;
    try builder.activate();
    errdefer if (builder.active) builder.deactivate();
    var draws: [frontend.recursion.air.universal_challenges.RELATION_COUNT][2]recorder.Scalar = undefined;
    for (&draws, relations.elements) |*draw, element|
        draw.* = .{ recorder.Scalar.fromSecure(element.z), recorder.Scalar.fromSecure(element.alpha) };
    draws[domain] = .{ z, alpha };
    const challenges = try recorder.ChallengeSet.init(draws);
    try builder.constrainZero((try subject.record(&builder, &symbolic, &challenges)).sub(claim));
    try builder.check();
    builder.deactivate();
    var circuit = try builder.finish();
    defer circuit.deinit();
    const values = try allocator.alloc(QM31, circuit.nodes.len);
    defer allocator.free(values);
    var inputs: [public.AIR_WORD_COUNT + 3]QM31 = undefined;
    for (inputs[0..words.len], words) |*value, word| value.* = QM31.fromBase(M31.fromCanonical(word));
    inputs[words.len..].* = .{ relation.z, relation.alpha, sum };
    try circuit.evaluateInto(&inputs, values);
    const changed = [_]usize{ 0, 2, 3, 4, 5, 6, 6 + frontend.recursion.span_statement.canonical_layout.body_tag, 417, 418, 426, 434, 442, 449, 450, 451, 452 };
    for (changed) |index| {
        const original = inputs[index];
        inputs[index] = original.add(QM31.one());
        try std.testing.expectError(error.UnsatisfiedCircuit, circuit.evaluateInto(&inputs, values));
        inputs[index] = original;
    }
    inputs[words.len] = relation.z.add(first_denominator);
    try std.testing.expectError(error.DivisionByZero, circuit.evaluateInto(&inputs, values));
    std.debug.print("CANONICAL_PUBLIC_BOUNDARY_GRAPH calls=113 nodes={d} checked_mutations={d} zero_denominator_rejected=true native_permutations_match=true\n", .{ circuit.nodes.len, changed.len });
}

fn checkSession(node: *const public.NodePublicV2) !void {
    const sessions = @import("recursive_temporal_secure_parent_artifact_v1.zig");
    const manifest = @import("recursive_common_canonical_empty_universal_manifest_v2.zig");
    const Channel = frontend.recursion.poseidon2_channel.Channel;
    var authority = sessions.CanonicalEmptySessionAuthorityV1{
        .ingress_identity_sha256 = [_]u8{1} ** 32,
        .parent_statement_words = undefined,
        .profile_identity_sha256 = try manifest.profileIdentity(),
        .child_composition_manifest_sha256 = try manifest.contractIdentity(),
        .parent_outer_manifest_sha256 = try manifest.contractIdentity(),
        .verification_key_id = try manifest.verificationKeyId(),
        .next_parent_vk_id = try manifest.nextParentVkId(),
        .air_program_id = try manifest.airProgramId(),
    };
    for (node.statement_words, &authority.parent_statement_words) |word, *value| value.* = M31.fromCanonical(word);
    const session = try sessions.SessionV1.initCanonicalEmptyWrapper(authority);
    var actual = Channel{};
    try session.mixFieldInto(&actual);
    var expected = Channel{};
    expected.mixU32s(&try sessions.fieldSessionTranscriptHeader(session.source_kind, session.protocol));
    expected.mixU32s(&authority.verification_key_id);
    expected.mixU32s(&authority.next_parent_vk_id);
    expected.mixU32s(&authority.air_program_id);
    try std.testing.expectEqualDeep(expected, actual);
    try std.testing.expect(!std.meta.eql(try sessions.fieldSessionTranscriptHeader(.common_fold_field_v2, session.protocol), try sessions.fieldSessionTranscriptHeader(.canonical_empty_wrapper_v1, session.protocol)));
    try std.testing.expectError(error.InvalidSecureTemporalParentSession, sessions.fieldSessionTranscriptHeader(.fresh_ethereum_poseidon_h1, session.protocol));
    inline for (.{ "verification_key_id", "next_parent_vk_id", "air_program_id" }) |field| for (0..8) |index| {
        var changed = authority;
        @field(changed, field)[index] = (@field(changed, field)[index] + 1) % core.fields.m31.Modulus;
        const altered = try sessions.SessionV1.initCanonicalEmptyWrapper(changed);
        var channel = Channel{};
        try altered.mixFieldInto(&channel);
        try std.testing.expect(!std.meta.eql(actual, channel));
    };
    var stale = session;
    stale.identity_sha256[0] ^= 1;
    var untouched = Channel{};
    try std.testing.expectError(error.InvalidSecureTemporalParentSession, stale.mixFieldInto(&untouched));
    try std.testing.expectEqualDeep(Channel{}, untouched);
    std.debug.print("CANONICAL_FIELD_SESSION key_words=24 mutations_rejected=true role_domains_distinct=true stale_rejected_before_mix=true\n", .{});
}
