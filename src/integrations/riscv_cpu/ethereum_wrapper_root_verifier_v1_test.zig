//! Small transport/admission checks, not a substitute for the complete root proof gate.
const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const verifier = @import("ethereum_wrapper_root_verifier_v1.zig");
const transport = @import("ethereum_wrapper_root_command_v1.zig");
const manifest_mod = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
const field = @import("ethereum_wrapper_field_transcript_v1.zig");
const session_mod = @import("recursive_temporal_secure_parent_artifact_v1.zig");
const node_mod = @import("recursive_field_node_public_v2.zig");
const lowering = recursion.air.verifier_arithmetic_lowering;
const QM31 = core.fields.qm31.QM31;
const Relations = recursion.air.universal_challenges.UniversalRelations;
const terms = [_]lowering.PublicWireTerm{
    .{ .lane = 0, .active_in = .segment, .role = .emit, .circuit_id = 42, .node_id = 1, .value = QM31.one(), .multiplicity = 2 },
    .{ .lane = 0, .active_in = .segment, .role = .consume, .circuit_id = 42, .node_id = 2, .value = QM31.zero(), .multiplicity = 1 },
};

pub fn testSession(fields: ?field.SessionFieldsV1) !session_mod.SessionV1 {
    const span = recursion.span_statement;
    const digest = [_]u32{1} ** 8;
    const initial = try span.MachineState.init(0, [_]u32{0} ** 32, digest, digest);
    const final = try span.MachineState.init(4, [_]u32{0} ** 32, digest, digest);
    const complete = try span.CompleteExecution.init(recursion.protocol.PROTOCOL_ID_WORDS, digest, initial, final, digest, digest, 8);
    const job = try span.JobContext.init(complete, 1);
    const executed = try span.ExecutedSpan.init(0, 1, 0, 8, initial, final, try span.EdgeClaim.present(digest), try span.EdgeClaim.present(digest));
    const statement = try span.SpanStatement.segmentLeaf(job, 0, executed);
    return session_mod.SessionV1.initEthereumIncrementalLeafWrapperV4(.{
        .ingress_identity_sha256 = [_]u8{1} ** 32,
        .parent_statement_words = try statement.canonicalWords(),
        .profile_identity_sha256 = [_]u8{2} ** 32,
        .child_composition_manifest_sha256 = [_]u8{3} ** 32,
        .parent_outer_manifest_sha256 = [_]u8{4} ** 32,
        .verification_key_id = if (fields) |value| value.verification_key_id else [_]u32{5} ** 8,
        .next_parent_vk_id = if (fields) |value| value.next_parent_vk_id else [_]u32{6} ** 8,
        .air_program_id = if (fields) |value| value.air_program_id else [_]u32{7} ** 8,
    });
}

pub fn testKey() !verifier.KeyV1 {
    var logs: manifest_mod.LogSizesV4 = @splat(4);
    logs[34] = manifest_mod.MINIMUM_PROVIDER_LOG_SIZE;
    logs[35] = manifest_mod.RANGE_LOG_SIZE;
    const lane: recursion.air.query_bits_witness.LaneProfile = .{ .query_count = 3, .lifting_log_size = 4, .trace_tree_count = 4, .fri_layer_count = 2 };
    const session = try testSession(null);
    var key = verifier.KeyV1{
        .manifest = try manifest_mod.buildForDerivedLogSizes(logs),
        .session_fields = try field.SessionFieldsV1.fromSession(&session),
        .preprocessed_root = [_]u32{7} ** 8,
        .parameters = .{ .query_reference = try recursion.air.query_bits_witness.Reference.seal(lane, lane), .poseidon_active_rows = 1 },
        .wire_terms = &terms,
    };
    key.session_fields = try @import("ethereum_wrapper_fixed_circuit_v1.zig").sessionFields(&key);
    return key;
}

pub fn testInitialKey() !verifier.Initial38.KeyV1 {
    const ordinary = try testKey();
    var key = verifier.Initial38.KeyV1{
        .manifest = try recursion.air.ethereum_initial_input_manifest_v1.build(&ordinary.manifest, 40),
        .session_fields = ordinary.session_fields,
        .preprocessed_root = ordinary.preprocessed_root,
        .parameters = .{ .query_reference = ordinary.parameters.query_reference, .poseidon_active_rows = ordinary.parameters.poseidon_active_rows },
        .wire_terms = &terms,
    };
    key.session_fields = try @import("ethereum_wrapper_fixed_circuit_v1.zig").sessionFields(&key);
    return key;
}

test "Ethereum fixed field namespace excludes custody and binds root parameters anchors and profile" {
    const fixed = @import("ethereum_wrapper_fixed_circuit_v1.zig");
    const key = try testKey();
    try key.validate();
    const expected = try fixed.sessionFields(&key);
    var changed = key;
    // These old IDs formerly contained schedule/call-buffer custody hashes.
    // They are not inputs to the replacement fixed circuit namespace.
    changed.session_fields.verification_key_id[0] += 1;
    changed.session_fields.next_parent_vk_id[0] += 1;
    changed.session_fields.air_program_id[0] += 1;
    try std.testing.expectEqualDeep(expected, try fixed.sessionFields(&changed));
    try std.testing.expectError(error.InvalidEthereumRootFixedNamespace, changed.validate());
    changed.session_fields = expected;
    try std.testing.expectEqualDeep(expected, try fixed.sessionFields(&changed));
    changed = key;
    changed.preprocessed_root[0] += 1;
    try std.testing.expect(!std.meta.eql(expected, try fixed.sessionFields(&changed)));
    changed = key;
    changed.parameters.poseidon_active_rows += 1;
    try std.testing.expect(!std.meta.eql(expected, try fixed.sessionFields(&changed)));
    changed = key;
    var other_terms = terms;
    other_terms[0].node_id += 1;
    changed.wire_terms = &other_terms;
    try std.testing.expect(!std.meta.eql(expected, try fixed.sessionFields(&changed)));
    other_terms = terms;
    other_terms[0].value = QM31.one().add(QM31.one());
    try std.testing.expect(!std.meta.eql(expected, try fixed.sessionFields(&changed)));
    changed = key;
    changed.transcript_version += 1;
    try std.testing.expect(!std.meta.eql(expected, try fixed.sessionFields(&changed)));
    changed = key;
    changed.session_fields.protocol.fri_query_count -= 1;
    try std.testing.expectError(error.InvalidTemporalParentProtocolAuthority, fixed.sessionFields(&changed));
}

test "Ethereum root key rejects malformed fixed admission" {
    const key = try testKey();
    try key.validate();
    inline for (.{ "version", "transcript_version", "manifest_schema" }) |name| {
        var bad = key;
        @field(bad, name) += 1;
        try std.testing.expectError(error.InvalidEthereumRootKeyVersion, bad.validate());
    }
    var bad = key;
    bad.preprocessed_root = @splat(0);
    try std.testing.expectError(error.InvalidEthereumRootKey, bad.validate());
    bad = key;
    bad.preprocessed_root[0] = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidEthereumRootKey, bad.validate());
    bad = key;
    bad.wire_terms = &.{};
    try std.testing.expectError(error.InvalidEthereumRootKey, bad.validate());
    var changed_terms = terms;
    bad.wire_terms = &changed_terms;
    changed_terms[0].role = .request;
    try std.testing.expectError(error.InvalidEthereumRootKey, bad.validate());
    changed_terms = terms;
    changed_terms[0].multiplicity = 0;
    try std.testing.expectError(error.InvalidEthereumRootKey, bad.validate());
    changed_terms = terms;
    changed_terms[0].node_id = core.fields.m31.Modulus;
    try std.testing.expectError(error.InvalidEthereumRootKey, bad.validate());
    bad = key;
    bad.parameters.poseidon_active_rows = std.math.maxInt(u32);
    try std.testing.expectError(error.InvalidEthereumVerifierAdmission, bad.validate());
}

test "Ethereum root key independently pinned transport owns decoded anchors" {
    const allocator = std.testing.allocator;
    const key = try testKey();
    const bytes = try std.json.Stringify.valueAlloc(allocator, key, .{});
    defer allocator.free(bytes);
    const expected = transport.hash(bytes);
    const owner = try transport.OwnedKeyV1.admit(allocator, bytes, expected);
    defer owner.deinit();
    @memset(bytes, 0xaa);
    try owner.key().validate();
    try std.testing.expectEqualDeep(terms, owner.key().wire_terms[0..2].*);
    var changed = key;
    changed.preprocessed_root[0] += 1;
    const altered = try std.json.Stringify.valueAlloc(allocator, changed, .{});
    defer allocator.free(altered);
    try std.testing.expectError(error.EthereumRootKeyHashMismatch, transport.OwnedKeyV1.admit(allocator, altered, expected));
    // Even an independently pinned malformed document must pass structural admission.
    changed.version += 1;
    const malformed = try std.json.Stringify.valueAlloc(allocator, changed, .{});
    defer allocator.free(malformed);
    try std.testing.expectError(error.InvalidEthereumRootKeyVersion, transport.OwnedKeyV1.admit(allocator, malformed, transport.hash(malformed)));
}

test "Ethereum root wire closure uses shared constant and output signs" {
    var key = try testKey();
    const relations = Relations.dummy();
    const challenge = try relations.getExact(.recursion_wire);
    const expected = (try lowering.publicTermClaim(challenge, terms[0])).add(try lowering.publicTermClaim(challenge, terms[1]));
    try std.testing.expectEqual(expected, try key.wireClaim(&relations));
    var changed = terms;
    key.wire_terms = &changed;
    changed[0].value = QM31.fromU32Unchecked(2, 0, 0, 0);
    try std.testing.expect(!expected.eql(try key.wireClaim(&relations)));
    changed = terms;
    changed[1].role = .emit;
    try std.testing.expect(!expected.eql(try key.wireClaim(&relations)));
}

test "Ethereum root detached transcript matches native semantic frames" {
    const key = try testKey();
    const session = try testSession(key.session_fields);
    const admission = field.AdmissionV1{ .session = &session, .preprocessed_root = key.preprocessed_root, .wire_term_count = terms.len };
    var native = recursion.poseidon2_channel.Channel{};
    var detached = recursion.poseidon2_channel.Channel{};
    const words: [node_mod.AIR_WORD_COUNT]u32 = @splat(9);
    try field.mixAuthority(&native, &words);
    try field.mixAuthority(&detached, &words);
    try field.mixSession(&native, admission);
    try field.mixSessionFields(&detached, key.session_fields);
    const claims: verifier.ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    const vector = try claims.vector(&key.manifest);
    try field.mixClaims(&native, &key.manifest, &vector);
    try field.mixClaims(&detached, &key.manifest, &vector);
    const relations = Relations.dummy();
    const wire = try key.wireClaim(&relations);
    try field.mixBoundaryValues(&native, admission, wire, &claims.poseidon_partials);
    try field.mixBoundaryFields(&detached, terms.len, wire, &claims.poseidon_partials);
    try std.testing.expectEqualDeep(native.digestWords(), detached.digestWords());
    try std.testing.expectEqual(native.n_draws, detached.n_draws);
    var changed = recursion.poseidon2_channel.Channel{};
    try field.mixAuthority(&changed, &words);
    var wrong_fields = key.session_fields;
    wrong_fields.air_program_id[0] += 1;
    try field.mixSessionFields(&changed, wrong_fields);
    try field.mixClaims(&changed, &key.manifest, &vector);
    try field.mixBoundaryFields(&changed, terms.len, wire, &claims.poseidon_partials);
    try std.testing.expect(!std.meta.eql(native.digestWords(), changed.digestWords()));
}

test "Ethereum root execution endpoint rejects canonical empty before proof decoding" {
    const span = recursion.span_statement;
    const digest = [_]u32{1} ** 8;
    const initial = try span.MachineState.init(0, [_]u32{0} ** 32, digest, digest);
    const final = try span.MachineState.init(4, [_]u32{0} ** 32, digest, digest);
    const complete = try span.CompleteExecution.init(recursion.protocol.PROTOCOL_ID_WORDS, digest, initial, final, digest, digest, 8);
    const job = try span.JobContext.init(complete, 210);
    const statement = try span.SpanStatement.emptyLeaf(job, 210);
    var words: [node_mod.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&words, try statement.canonicalWords()) |*out, word| out.* = word.toU32();
    const node = try node_mod.NodePublicV2.initLeaf(try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, 210), words, digest);
    const key = try testKey();
    const claims: verifier.ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    try std.testing.expectError(error.InvalidEthereumRootPublicInputs, verifier.verify(std.testing.allocator, &key, &node, claims, 0, &.{}));
    const initial_key = try testInitialKey();
    const initial_claims: verifier.Initial38.ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    try std.testing.expectError(error.InvalidEthereumRootPublicInputs, verifier.Initial38.verify(std.testing.allocator, &initial_key, &node, initial_claims, 0, &.{}));
    var initial_capture: verifier.Initial38.ProofCapture = undefined;
    try std.testing.expectError(error.InvalidEthereumRootPublicInputs, verifier.Initial38.verifyWithCapture(std.testing.allocator, &initial_key, &node, initial_claims, 0, &.{}, &initial_capture));
    var capture: verifier.ProofCapture = undefined;
    try std.testing.expectError(error.InvalidEthereumRootPublicInputs, verifier.verifyWithCapture(std.testing.allocator, &key, &node, claims, 0, &.{}, &capture));
    try std.testing.expectError(error.InvalidEthereumRootPublicInputs, @import("ethereum_wrapper_detached_transcript_v1.zig").OwnedV1.init(std.testing.allocator, &key, &node, claims, 0, &.{}));
}

test "Ethereum initial root transport pins38 key and owns exact child geometry" {
    const allocator = std.testing.allocator;
    const key = try testInitialKey();
    try key.validate();
    const ordinary = try testKey();
    try std.testing.expect(!std.meta.eql(key.session_fields, ordinary.session_fields));
    const bytes = try std.json.Stringify.valueAlloc(allocator, key, .{});
    defer allocator.free(bytes);
    const pin = transport.hash(bytes);
    const owner = try transport.Initial38.OwnedKeyV1.admit(allocator, bytes, pin);
    defer owner.deinit();
    if (transport.OwnedKeyV1.admit(allocator, bytes, pin)) |wrong_mode| {
        wrong_mode.deinit();
        return error.InitialKeyAdmittedAsOrdinary;
    } else |_| {}
    var wrong_pin = pin;
    wrong_pin[0] ^= 1;
    try std.testing.expectError(error.EthereumRootKeyHashMismatch, transport.Initial38.OwnedKeyV1.admit(allocator, bytes, wrong_pin));
    @memset(bytes, 0xaa);
    try owner.key().validate();
    const shape = try @import("ethereum_wrapper_child_shape_v1.zig").Initial38.OwnedV1.create(allocator, owner.key());
    defer shape.deinit();
    try std.testing.expectEqual(@as(usize, 38), shape.wireDimensions().claimed_sum_count);
    try shape.validateAgainstKey(&key);
    var changed = key;
    changed.manifest.input_capacity += 1;
    try std.testing.expectError(error.ManifestSealMismatch, changed.validate());
    changed = key;
    changed.preprocessed_root[0] += 1;
    changed.session_fields = try @import("ethereum_wrapper_fixed_circuit_v1.zig").sessionFields(&changed);
    try std.testing.expectError(error.EthereumChildShapeKeyMismatch, shape.validateAgainstKey(&changed));
}

test "Ethereum root transport selects initial mode only from explicit argument" {
    const pin = "ab" ** 32;
    const ordinary = try transport.parseArguments(&.{ "bundle", pin });
    try std.testing.expect(!ordinary.initial);
    const initial = try transport.parseArguments(&.{ "--initial-v1", "bundle", pin });
    try std.testing.expect(initial.initial);
    try std.testing.expectEqualDeep(ordinary.expected_key_sha256, initial.expected_key_sha256);
    for ([_][]const []const u8{ &.{}, &.{"--initial-v1"}, &.{ "--initial-v1", "bundle" }, &.{ "--unknown", pin }, &.{ "bundle", pin, "--initial-v1" } }) |args|
        try std.testing.expectError(error.ExpectedRootDirectoryAndIndependentKeySha256, transport.parseArguments(args));
}

test "Ethereum root transport shares bundle location ownership across admitted profiles" {
    try std.testing.expect(transport.BundleLocationV1 == transport.Ordinary.BundleLocationV1);
    try std.testing.expect(transport.BundleLocationV1 == transport.Initial38.BundleLocationV1);
    var initial: transport.Initial38.BundleLocationV1 = .{
        .allocator = std.testing.allocator,
        .path = try std.testing.allocator.dupe(u8, "retained-candidate"),
        .expected_key_sha256 = [_]u8{7} ** 32,
    };
    const shared: *transport.BundleLocationV1 = &initial;
    defer shared.deinit();
    try std.testing.expectEqualStrings("retained-candidate", shared.path);
    try std.testing.expectEqualDeep([_]u8{7} ** 32, shared.expected_key_sha256);
}
