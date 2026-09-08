const std = @import("std");
const core = @import("stwo_core");
const recursion = @import("stwo_riscv_frontend").recursion;
const verifier = @import("recursive_common_fold_detached_verifier_v2.zig");
const manifest = @import("recursive_common_fold_universal_manifest_v2.zig");
const session_mod = @import("recursive_temporal_secure_parent_artifact_v1.zig");
const program_mod = @import("recursive_secure_transcript_program_v1.zig");
const field = @import("recursive_common_fold_field_public_v2.zig");
const NodePublicV2 = @import("recursive_field_node_public_v2.zig").NodePublicV2;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Capture = struct { commitments: [4]recursion.poseidon2_channel.Digest, sampled_values: [1]QM31, fri: struct { layers: [1]u8 }, last_layer_coefficients: [1]QM31, queries: struct { raw: [193]u32 } };
fn fixedKey() !verifier.EthereumKeyV1 {
    var logs = [_]u32{4} ** 36;
    logs[34] = field.MINIMUM_POSEIDON_LOG_SIZE;
    logs[35] = 16;
    var key = verifier.EthereumKeyV1{ .key = .{ .manifest = try manifest.buildForDerivedLogSizes(logs), .parameters = undefined, .preprocessed_root = .{7} ** 8, .poseidon_rows = 1 } };
    inline for (&key.key.parameters) |*parameters| @memset(parameters, M31.zero());
    try key.validate();
    return key;
}
fn parent(index: u32) !NodePublicV2 {
    const fixtures = @import("recursive_common_fold_field_public_v2_test.zig");
    const left = try fixtures.emptyLeaf(index, "left-key-fixture");
    const right = try fixtures.emptyLeaf(index + 1, "right-key-fixture");
    return (try field.PoseidonScheduleV2.build(&left, &right, try @import("recursive_node_artifact_v2.zig").TaskCoordinateV1.init(1, index / 2))).parent;
}
fn session(key: *const verifier.EthereumKeyV1, node: *const NodePublicV2, custody: u8) !session_mod.SessionV1 {
    const fields = try key.sessionFields();
    var words: recursion.span_statement.StatementWords = undefined;
    for (&words, node.statement_words) |*word, value| word.* = M31.fromCanonical(value);
    return session_mod.SessionV1.initCommonFoldFieldV2(.{ .ingress_identity_sha256 = .{custody} ** 32, .parent_statement_words = words, .profile_identity_sha256 = .{1} ** 32, .child_composition_manifest_sha256 = .{custody} ** 32, .parent_outer_manifest_sha256 = key.key.manifest.seal, .verification_key_id = fields.verification_key_id, .next_parent_vk_id = fields.next_parent_vk_id, .air_program_id = fields.air_program_id });
}

test "Ethereum fold fixed namespace excludes public custody and binds complete key" {
    const key = try fixedKey();
    const expected = try key.sessionFields();
    // Pure key/session fixtures, not accepted parent or child proofs.
    const first = try parent(210);
    const second = try parent(212);
    const a = try session(&key, &first, 11);
    const b = try session(&key, &second, 12);
    try std.testing.expect(!std.meta.eql(a.identity_sha256, b.identity_sha256));
    try std.testing.expect(!std.meta.eql(try first.canonicalAirWords(), try second.canonicalAirWords()));
    var field_a = recursion.poseidon2_channel.Channel{};
    var field_b = recursion.poseidon2_channel.Channel{};
    try a.mixFieldInto(&field_a);
    try b.mixFieldInto(&field_b);
    try std.testing.expectEqualDeep(field_a, field_b);
    try std.testing.expectEqualDeep(expected, try key.sessionFields());
    field_a.mixU32s(&try first.canonicalAirWords());
    field_b.mixU32s(&try second.canonicalAirWords());
    try std.testing.expect(!std.meta.eql(field_a, field_b));
    var changed = key;
    changed.key.preprocessed_root[0] += 1;
    try std.testing.expect(!std.meta.eql(expected, try changed.sessionFields()));
    changed = key;
    changed.key.parameters[0][0] = M31.one();
    try std.testing.expect(!std.meta.eql(expected, try changed.sessionFields()));
    changed = key;
    changed.key.poseidon_rows += 1;
    try std.testing.expect(!std.meta.eql(expected, try changed.sessionFields()));
    changed = key;
    changed.execution_profile += 1;
    try std.testing.expectError(error.InvalidEthereumFoldVerifierKey, changed.sessionFields());
    changed = key;
    changed.version += 1;
    try std.testing.expectError(error.InvalidEthereumFoldVerifierKey, changed.sessionFields());
    changed = key;
    changed.key.preprocessed_root = .{0} ** 8;
    try std.testing.expectError(error.InvalidEthereumFoldVerifierKey, changed.sessionFields());
    const legacy = try manifest.verificationKeyIdForDerivedManifest(&key.key.manifest, try key.key.validate());
    try std.testing.expect(!std.meta.eql(legacy, expected.verification_key_id));
}

test "Ethereum fold fixed transcript shares namespace and preserves legacy constructor" {
    const allocator = std.testing.allocator;
    const key = try fixedKey();
    // Geometry-only capture fixture. Neither constructor verifies this proof.
    var capture: Capture = .{ .commitments = [_]recursion.poseidon2_channel.Digest{ key.key.preprocessed_root, .{2} ** 8, .{3} ** 8, .{4} ** 8 }, .sampled_values = [_]QM31{QM31.one()}, .fri = .{ .layers = [_]u8{0} }, .last_layer_coefficients = [_]QM31{QM31.one()}, .queries = .{ .raw = [_]u32{0} ** 193 } };
    var program = try program_mod.Program.initEthereumFoldKeyV1(allocator, &key, &capture);
    defer program.deinit();
    var legacy = try program_mod.Program.init(allocator, .common_fold, &key.key.manifest, &capture);
    defer legacy.deinit();
    const fields = try key.sessionFields();
    const keys = [_]recursion.poseidon2_channel.Digest{ fields.verification_key_id, fields.next_parent_vk_id, fields.air_program_id };
    var changed_keys: usize = 0;
    for (program.operations, legacy.operations) |op, old| {
        if (op.source == .session_key) {
            for (keys[op.item], 0..) |word, index| {
                try std.testing.expectEqual(word & 0xffff, op.constant_words[2 * index]);
                try std.testing.expectEqual(word >> 16, op.constant_words[2 * index + 1]);
            }
            try std.testing.expect(!std.meta.eql(op.constant_words, old.constant_words));
            changed_keys += 1;
        } else try std.testing.expectEqualDeep(old, op);
    }
    try std.testing.expectEqual(@as(usize, 3), changed_keys);
    capture.sampled_values[0] = QM31.one().add(QM31.one());
    capture.commitments[1][0] += 1;
    capture.queries.raw[0] += 1;
    var changed_witness = try program_mod.Program.initEthereumFoldKeyV1(allocator, &key, &capture);
    defer changed_witness.deinit();
    try std.testing.expectEqualDeep(program.identity, changed_witness.identity);
    capture.commitments[0][0] += 1;
    try std.testing.expectError(error.InvalidRecursiveTranscriptProgram, program_mod.Program.initEthereumFoldKeyV1(allocator, &key, &capture));
    try std.testing.expect(!@import("ethereum_wrapper_detached_fold_v1.zig").FOLD_ADMISSION_AVAILABLE);
}

test "Ethereum fold engine replay consumes admitted key and preserves legacy fallback" {
    const allocator = std.testing.allocator;
    const key = try fixedKey();
    const capture: Capture = .{ .commitments = .{ key.key.preprocessed_root, .{2} ** 8, .{3} ** 8, .{4} ** 8 }, .sampled_values = .{QM31.one()}, .fri = .{ .layers = .{0} }, .last_layer_coefficients = .{QM31.one()}, .queries = .{ .raw = @splat(0) } };
    // Exercise the engine's actual selector without claiming fixture proof
    // validity. Full child-proof and parent lifecycle gates remain required.
    const Cohort = struct {
        admitted: ?verifier.EthereumKeyV1,
        fixed_manifest: @import("recursive_common_fold_universal_manifest_v2.zig").Manifest,
        reject: bool = false,

        pub fn ethereumDetachedVerifierKey(self: *@This()) !verifier.EthereumKeyV1 {
            if (self.reject) return error.CommonFoldCohortMismatch;
            return self.admitted orelse error.EthereumFoldFixedAdmissionRequired;
        }
        pub fn manifest(self: *@This()) *const @import("recursive_common_fold_universal_manifest_v2.zig").Manifest {
            return &self.fixed_manifest;
        }
    };
    const engine = @import("recursive_temporal_secure_parent_native_engine_v1.zig");
    var cohort: Cohort = .{ .admitted = key, .fixed_manifest = key.key.manifest };
    var actual = try engine.initCommonFoldTranscriptProgram(Cohort, allocator, &cohort, &capture);
    defer actual.deinit();
    var expected = try program_mod.Program.initEthereumFoldKeyV1(allocator, &key, &capture);
    defer expected.deinit();
    try std.testing.expectEqualDeep(expected.identity, actual.identity);
    try std.testing.expectEqualDeep(expected.operations, actual.operations);

    cohort.admitted = null;
    var fallback = try engine.initCommonFoldTranscriptProgram(Cohort, allocator, &cohort, &capture);
    defer fallback.deinit();
    var legacy = try program_mod.Program.init(allocator, .common_fold, &key.key.manifest, &capture);
    defer legacy.deinit();
    try std.testing.expectEqualDeep(legacy.identity, fallback.identity);
    try std.testing.expectEqualDeep(legacy.operations, fallback.operations);
    try std.testing.expect(!std.meta.eql(actual.identity, legacy.identity));

    cohort.admitted = key;
    cohort.admitted.?.version += 1;
    try std.testing.expectError(error.InvalidEthereumFoldVerifierKey, engine.initCommonFoldTranscriptProgram(Cohort, allocator, &cohort, &capture));
    cohort.reject = true;
    try std.testing.expectError(error.CommonFoldCohortMismatch, engine.initCommonFoldTranscriptProgram(Cohort, allocator, &cohort, &capture));
}
