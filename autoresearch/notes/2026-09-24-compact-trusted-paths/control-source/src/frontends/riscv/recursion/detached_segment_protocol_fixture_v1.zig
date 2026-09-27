//! Explicit versioned transcript for detached SegmentV2 verification.
//! Structural validation and a caller-supplied independent pin do not establish
//! that a compiler emitted a fixed circuit. Admission policy must additionally
//! establish that Tree0 and all constant/output anchors are statement-independent.
const recursion = struct {
    const detached_segment_admission_v1 = @import("detached_segment_admission_v1.zig");
    const detached_segment_authority_boundary_v1 = @import("detached_segment_authority_boundary_v1.zig");
    const detached_segment_protocol_v1 = @import("detached_segment_protocol_v1.zig");
    const detached_segment_public_inputs_v1 = @import("detached_segment_public_inputs_v1.zig");
    const poseidon2_channel = @import("poseidon2_channel.zig");
    const segment_leaf_outer_authority_v2 = @import("segment_leaf_outer_authority_v2.zig");
    const segment_leaf_statement_contract_v2 = @import("segment_leaf_statement_contract_v2.zig");
    const segment_publication_input_provider_authority_v2 = @import("segment_publication_input_provider_authority_v2.zig");
};
const air = struct {
    const query_bits_profile = @import("air/query_bits_profile.zig");
    const query_bits_witness = @import("air/query_bits_witness.zig");
    const range_check_8_8_bridge = @import("air/range_check_8_8_bridge.zig");
    const segment_outer_adapter_manifest_v2 = @import("air/segment_outer_adapter_manifest_v2.zig");
    const segment_outer_manifest_contract_v2 = @import("air/segment_outer_manifest_contract_v2.zig");
    const segment_outer_typed_catalog_v2 = @import("air/segment_outer_typed_catalog_v2.zig");
    const universal_challenges = @import("air/universal_challenges.zig");
    const universal_manifest = @import("air/universal_manifest.zig");
    const verifier_wire_claims = @import("air/verifier_wire_claims.zig");
    const vm_public_logup_control_witness_v2 = @import("air/vm_public_logup_control_witness_v2.zig");
};
const riscv_air = struct {
    const public_data_v2 = @import("../air/public_data_v2.zig");
};
const testing_support = struct {
    const public_data_v2_test_support = @import("../air/public_data_v2_test_support.zig");
};
const std = @import("std");
const core = @import("stwo_core");
const manifest_mod = air.segment_outer_manifest_contract_v2;
const lowering = air.verifier_wire_claims;
const source = recursion.segment_leaf_statement_contract_v2;
const components = recursion.detached_segment_admission_v1;
const public_inputs = recursion.detached_segment_public_inputs_v1;
const authority_boundary = recursion.detached_segment_authority_boundary_v1;
const PublicData = riscv_air.public_data_v2.PublicDataV2;
const QM31 = core.fields.qm31.QM31;
const Digest = recursion.poseidon2_channel.Digest;
const owner = recursion.detached_segment_protocol_v1;
pub const VERSION = owner.VERSION;
pub const DEVELOPMENT_ONLY = owner.DEVELOPMENT_ONLY;
pub const PCS_CONFIG = owner.PCS_CONFIG;
pub const INTERACTION_POW_BITS = owner.INTERACTION_POW_BITS;
pub const ProfileV1 = owner.ProfileV1;
pub const KeyV1 = owner.KeyV1;
pub const FixedAdmissionV1 = owner.FixedAdmissionV1;
pub const PayloadSourceV1 = owner.PayloadSourceV1;
pub const mixAdmission = owner.mixAdmission;
pub const mixInteractionPow = owner.mixInteractionPow;
pub const mixClaimsAndBoundary = owner.mixClaimsAndBoundary;

const fixture = testing_support.public_data_v2_test_support;
const test_terms = [_]lowering.PublicWireTerm{
    .{ .lane = 0, .active_in = .segment, .role = .emit, .circuit_id = 1, .node_id = 0, .value = QM31.one(), .multiplicity = 1 },
    .{ .lane = 0, .active_in = .segment, .role = .consume, .circuit_id = 1, .node_id = 1, .value = QM31.zero(), .multiplicity = 1 },
};

// Structural fixture only: the pin in these tests is not a compiled-circuit
// admission or evidence that a production lowering is statement-independent.
pub const testing = if (@import("builtin").is_test) struct {
    pub const key = testKey;
} else struct {};

fn testKey(word_count: usize, transcript_template_id: u32) !KeyV1 {
    const source_manifest = try source.ManifestV2.init(word_count);
    const boundary = try recursion.segment_leaf_outer_authority_v2.OuterManifestV2.init(source_manifest);
    var logs: air.universal_manifest.LogSizes = @splat(4);
    logs[11] = source_manifest.trace_log_size;
    logs[17] = air.vm_public_logup_control_witness_v2.TRACE_LOG_SIZE;
    logs[34] = 10;
    logs[35] = air.range_check_8_8_bridge.LOG_SIZE;
    const catalog = try air.segment_outer_typed_catalog_v2.build(logs, boundary.components);
    const manifest = try air.segment_outer_adapter_manifest_v2.assemble(&catalog, .{
        .transcript_manifest_id = @splat(transcript_template_id),
        .statement_manifest_id = @splat(2),
        .public_manifest_id = @splat(3),
        .boundary_manifest_id = boundary.identity,
        .boundary_authority_sha_id = boundary.authority_sha_id,
        .provider_authority_sha_id = recursion.segment_publication_input_provider_authority_v2.sourceAuthorityShaId(),
    });
    const lane: air.query_bits_profile.LaneProfile = .{ .query_count = 3, .lifting_log_size = 4, .trace_tree_count = 4, .fri_layer_count = 2 };
    return .{
        .manifest = manifest,
        .preprocessed_root = fixture.id("fixed-tree0"),
        .parameters = .{ .query_reference = try air.query_bits_witness.Reference.seal(lane, lane), .poseidon_active_rows = 1 },
        .source_manifest = source_manifest,
        .admitted_keys = try source.VerifierKeyAuthorityV2.init(fixture.id("segment-key"), fixture.id("parent-key")),
        .native_descriptors = .{ .components = &.{}, .infrastructure = &.{} },
        .wire_terms = &test_terms,
    };
}

pub fn testFixedProjection() !void {
    const key = try testKey(1000, 1);
    const other_template = try testKey(1000, 9);
    const pin = try key.identity();
    _ = try KeyV1.admit(key, pin);
    try std.testing.expect(!std.mem.eql(u8, &key.manifest.seal, &other_template.manifest.seal));
    try std.testing.expectEqual(pin, try other_template.identity());
    var changed = key;
    changed.preprocessed_root = fixture.id("other-tree0");
    try std.testing.expectError(error.SegmentDetachedCircuitPinMismatch, KeyV1.admit(changed, pin));
    changed = key;
    changed.pcs_config.fri_config.n_queries += 1;
    try std.testing.expectError(error.InvalidSegmentDetachedProfile, changed.validate());
    changed = key;
    changed.version += 1;
    try std.testing.expectError(error.InvalidSegmentDetachedVersion, changed.validate());
    var terms = test_terms;
    changed = key;
    changed.wire_terms = &terms;
    terms[0].value = QM31.fromU32Unchecked(2, 0, 0, 0);
    try std.testing.expectError(error.SegmentDetachedCircuitPinMismatch, KeyV1.admit(changed, pin));
    terms = test_terms;
    terms[1].value = QM31.one();
    try std.testing.expectError(error.InvalidSegmentDetachedCircuit, changed.validate());
}

pub fn testDynamicExpectedWire() !void {
    const allocator = std.testing.allocator;
    var input = try fixture.Fixture.init();
    var other = try fixture.Fixture.initWithRegister7(42);
    const words = try fixture.encode(allocator, &input.leftSource());
    defer allocator.free(words);
    const other_words = try fixture.encode(allocator, &other.leftSource());
    defer allocator.free(other_words);
    const data = try PublicData.authenticate(words);
    const other_data = try PublicData.authenticate(other_words);
    const key = try testKey(words.len, 1);
    const pin = try key.identity();
    var left = recursion.poseidon2_channel.Channel{};
    var right = recursion.poseidon2_channel.Channel{};
    try mixAdmission(&left, &key, &data);
    try mixAdmission(&right, &key, &other_data);
    try std.testing.expect(!std.meta.eql(left.digestWords(), right.digestWords()));
    try std.testing.expectEqual(pin, try key.identity());
    // A caller cannot present a mutated borrowed wire as an admitted input.
    const saved = words[0];
    defer words[0] = saved;
    words[0] = saved.add(core.fields.m31.M31.one());
    const before = left;
    if (mixAdmission(&left, &key, &data)) |_| return error.TestExpectedError else |_| {}
    try std.testing.expectEqualDeep(before, left);
}

pub fn testClaimsClosure() !void {
    const allocator = std.testing.allocator;
    var input = try fixture.Fixture.init();
    const words = try fixture.encode(allocator, &input.leftSource());
    defer allocator.free(words);
    const data = try PublicData.authenticate(words);
    const key = try testKey(words.len, 1);
    const relations = air.universal_challenges.UniversalRelations.dummy();
    const expected_statement = try public_inputs.statementClaim(&data, &key.admitted_keys, &key.source_manifest, &relations);
    const expected_wire = (try key.wireClaim(&relations)).add((try authority_boundary.derive(&data, key.native_descriptors, &relations)).claimed_sum);
    var claims: components.ClaimsV1 = .{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    claims.values[36] = expected_statement;
    claims.values[0] = expected_wire.add(expected_statement).neg();
    var channel = recursion.poseidon2_channel.Channel{};
    try mixClaimsAndBoundary(&channel, &key, &data, claims, &relations);
    const before = channel;
    claims.values[36] = claims.values[36].add(QM31.one());
    try std.testing.expectError(error.SegmentV2PublicInputClaimMismatch, mixClaimsAndBoundary(&channel, &key, &data, claims, &relations));
    try std.testing.expectEqualDeep(before, channel);
    claims.values[36] = expected_statement;
    claims.values[0] = claims.values[0].add(QM31.one());
    try std.testing.expectError(error.SegmentDetachedClaimClosureMismatch, mixClaimsAndBoundary(&channel, &key, &data, claims, &relations));
    try std.testing.expectEqualDeep(before, channel);
}

pub fn testProfiles() !void {
    const allocator = std.testing.allocator;
    const legacy = try testKey(1000, 1);
    var strong = legacy;
    strong.profile = .recursive_q193_v1;
    try std.testing.expectError(error.InvalidSegmentDetachedProfile, strong.validate());
    strong.pcs_config = strong.profile.pcsConfig();
    try std.testing.expectError(error.DetachedNativeSecurityProfileMismatch, strong.validate());
    var channel = recursion.poseidon2_channel.Channel{};
    channel.mixU32s(&.{ 71, 93 });
    const before = channel;
    try mixInteractionPow(&channel, &legacy, null);
    try std.testing.expectEqualDeep(before, channel);
    try std.testing.expectError(error.UnexpectedDetachedInteractionPow, mixInteractionPow(&channel, &legacy, 0));
    try std.testing.expectError(error.MissingDetachedInteractionPow, mixInteractionPow(&channel, &strong, null));
    var invalid: u64 = 0;
    while (channel.verifyPowNonce(strong.profile.interactionPowBits(), invalid)) invalid += 1;
    try std.testing.expectError(error.InvalidDetachedInteractionPow, mixInteractionPow(&channel, &strong, invalid));
    try std.testing.expectEqualDeep(before, channel);
    const valid = channel.grind(strong.profile.interactionPowBits());
    var expected = before;
    expected.mixU64(valid);
    try mixInteractionPow(&channel, &strong, valid);
    try std.testing.expectEqualDeep(expected, channel);

    var claims = components.ClaimsV1{ .values = @splat(QM31.zero()), .poseidon_partials = @splat(QM31.zero()) };
    const old_json = try std.json.Stringify.valueAlloc(allocator, .{ .values = claims.values, .poseidon_partials = claims.poseidon_partials }, .{});
    defer allocator.free(old_json);
    const compatible_json = try std.json.Stringify.valueAlloc(allocator, claims, .{});
    defer allocator.free(compatible_json);
    try std.testing.expectEqualStrings(old_json, compatible_json);
    claims.interaction_pow = 0;
    const nonce_json = try std.json.Stringify.valueAlloc(allocator, claims, .{});
    defer allocator.free(nonce_json);
    var decoded = try std.json.parseFromSlice(components.ClaimsV1, allocator, nonce_json, .{});
    defer decoded.deinit();
    try std.testing.expectEqual(@as(?u64, 0), decoded.value.interaction_pow);
}
