//! Explicit versioned transcript for detached SegmentV2 verification.
//! Structural validation and a caller-supplied independent pin do not establish
//! that a compiler emitted a fixed circuit. Admission policy must additionally
//! establish that Tree0 and all constant/output anchors are statement-independent.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const air = recursion.air;
const manifest_mod = air.segment_outer_adapter_manifest_v2;
const lowering = air.verifier_arithmetic_lowering;
const source = recursion.segment_leaf_authority_v2;
const components = @import("recursive_segment_v2_verifier_components.zig");
const public_inputs = @import("recursive_segment_v2_public_inputs.zig");
const authority_boundary = @import("recursive_segment_v2_authority_boundary.zig");
const PublicData = frontend.air.public_data_v2.PublicDataV2;
const QM31 = core.fields.qm31.QM31;
const Digest = recursion.poseidon2_channel.Digest;
pub const VERSION: u32 = 2;
pub const DEVELOPMENT_ONLY = true;
pub const PCS_CONFIG = recursion.outer_parent_child_admission.OUTER_PCS_CONFIG;
pub const INTERACTION_POW_BITS = recursion.outer_parent_child_admission.INTERACTION_POW_BITS;

/// Exact fixed facts consumed by detached verification. Manifest authority IDs
/// are template bookkeeping: only canonical program geometry enters this key
/// identity. No capture, source receipt, observed claim, or call-buffer digest
/// belongs here. Constant terms must come from independently admitted lowering.
pub const ProfileV1 = enum(u8) {
    development_q3_v1 = 1,
    recursive_q193_v1 = 2,

    pub fn pcsConfig(self: ProfileV1) core.pcs.PcsConfig {
        return switch (self) {
            .development_q3_v1 => PCS_CONFIG,
            .recursive_q193_v1 => recursion.protocol.PCS_CONFIG,
        };
    }

    pub fn interactionPowBits(self: ProfileV1) u32 {
        return switch (self) {
            .development_q3_v1 => INTERACTION_POW_BITS,
            .recursive_q193_v1 => recursion.protocol.INTERACTION_POW_BITS,
        };
    }
};

pub const KeyV1 = struct {
    profile: ProfileV1 = .development_q3_v1,
    pcs_config: core.pcs.PcsConfig = PCS_CONFIG,
    version: u32 = VERSION,
    manifest: manifest_mod.Manifest,
    preprocessed_root: Digest,
    parameters: components.AdmissionParametersV1,
    source_manifest: source.ManifestV2,
    admitted_keys: source.VerifierKeyAuthorityV2,
    native_descriptors: authority_boundary.DescriptorsV1,
    wire_terms: []const lowering.PublicWireTerm,

    pub fn identity(self: *const KeyV1) ![32]u8 {
        if (self.version != VERSION) return error.InvalidSegmentDetachedVersion;
        if (!std.meta.eql(self.pcs_config, self.profile.pcsConfig())) return error.InvalidSegmentDetachedProfile;
        if (self.profile == .recursive_q193_v1) {
            for ([_]air.query_bits_witness.LaneProfile{ self.parameters.query_reference.vm, self.parameters.query_reference.recursion }) |lane| {
                if (lane.query_count != recursion.protocol.FRI_QUERY_COUNT or
                    lane.trace_tree_count != recursion.protocol.COMMITMENT_TREE_COUNT or
                    lane.lifting_log_size <= recursion.protocol.FRI_LOG_BLOWUP_FACTOR)
                    return error.DetachedNativeSecurityProfileMismatch;
                const fri = try recursion.fixed_profile.FriSchedule.init(lane.lifting_log_size - recursion.protocol.FRI_LOG_BLOWUP_FACTOR, recursion.protocol.PCS_CONFIG.fri_config);
                if (lane.fri_layer_count != fri.count) return error.DetachedNativeSecurityProfileMismatch;
            }
        }
        _ = try self.parameters.validate(&self.manifest);
        if (try self.native_descriptors.callCount() > (@as(u64, 1) << @intCast(self.manifest.placements[13].?.geometry.log_size)))
            return error.InvalidSegmentDetachedCircuit;
        try self.source_manifest.validate();
        try self.admitted_keys.validate();
        if (self.source_manifest.trace_log_size != self.manifest.placements[36].?.geometry.log_size or
            self.wire_terms.len == 0 or self.wire_terms.len >= core.fields.m31.Modulus or
            std.mem.allEqual(u32, &self.preprocessed_root, 0))
            return error.InvalidSegmentDetachedCircuit;
        for (self.preprocessed_root) |word| if (word >= core.fields.m31.Modulus)
            return error.InvalidSegmentDetachedCircuit;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(switch (self.profile) {
            .development_q3_v1 => "stwo-zig/segment-v2-detached-development-circuit/v2\x00",
            .recursive_q193_v1 => "stwo-zig/segment-v2-detached-q193-circuit/v1\x00",
        });
        for ([_]u32{ VERSION, @intFromEnum(self.profile), manifest_mod.FORMAT_VERSION, manifest_mod.TRANSCRIPT_FORMAT_VERSION, self.profile.interactionPowBits(), self.pcs_config.pow_bits, self.pcs_config.fri_config.log_blowup_factor, self.pcs_config.fri_config.log_last_layer_degree_bound, @intCast(self.pcs_config.fri_config.n_queries), self.pcs_config.fri_config.fold_step }) |word| hashWord(&hash, word);
        hash.update(&manifest_mod.programGeometryShaId(&self.manifest));
        hash.update(&air.universal_challenges.registryOrderDigest());
        for (recursion.protocol.PROTOCOL_ID_WORDS) |word| hashWord(&hash, word);
        for (self.preprocessed_root) |word| hashWord(&hash, word);
        hash.update(&self.parameters.query_reference.authority_digest);
        hashWord(&hash, self.parameters.poseidon_active_rows);
        for (self.source_manifest.identity) |word| hashWord(&hash, word);
        for (self.admitted_keys.identity) |word| hashWord(&hash, word);
        try self.native_descriptors.mixIdentity(&hash);
        hashWord(&hash, @intCast(self.wire_terms.len));
        for (self.wire_terms) |term| {
            if (term.active_in != .segment or term.role == .request or
                term.circuit_id >= core.fields.m31.Modulus or term.node_id >= core.fields.m31.Modulus or
                term.multiplicity == 0 or term.multiplicity >= core.fields.m31.Modulus or
                (term.role == .consume and (!term.value.isZero() or term.multiplicity != 1)))
                return error.InvalidSegmentDetachedCircuit;
            try canonical(term.value);
            for ([_]u32{ term.lane, @intFromEnum(term.active_in), @intFromEnum(term.role), term.circuit_id, term.node_id, term.multiplicity }) |word|
                hashWord(&hash, word);
            for (term.value.toM31Array()) |word| hashWord(&hash, word.toU32());
        }
        return hash.finalResult();
    }

    pub fn validate(self: *const KeyV1) !void {
        _ = try self.identity();
    }

    /// Validate canonical fields against an independently pinned projection.
    /// This value is not an immutable owner or a compiler-policy certificate;
    /// callers must retain admitted key storage with their normal key custody.
    pub fn admit(candidate: KeyV1, independently_pinned_identity: [32]u8) !KeyV1 {
        if (!std.mem.eql(u8, &independently_pinned_identity, &try candidate.identity()))
            return error.SegmentDetachedCircuitPinMismatch;
        return candidate;
    }

    pub fn wireClaim(self: *const KeyV1, relations: *const components.Relations) !QM31 {
        try self.validate();
        const challenge = try relations.getExact(.recursion_wire);
        var total = QM31.zero();
        for (self.wire_terms) |term| total = total.add(try lowering.publicTermClaim(challenge, term));
        return total;
    }
};

pub const FixedAdmissionV1 = KeyV1;

/// Optional semantic annotations consumed by the parent AIR schedule builder.
/// These do not alter transcript bytes or admit any payload value as constant.
/// The native and recorded verifier channels intentionally have no callback.
const payload = @import("recursive_detached_payload_v1.zig");
pub const PayloadSourceV1 = payload.Source;
const beginPayload = payload.begin;

/// Called after Tree0/Tree1 commitments and before relation draws. The wire
/// uses the existing canonical PublicDataV2 frame; fixed identity has its own
/// explicit version and never includes a source-specific manifest seal.
pub fn mixAdmission(channel: anytype, admission: *const KeyV1, expected: *const PublicData) !void {
    const fixed_identity = try admission.identity();
    _ = try expected.metadata();
    const shape = try source.ManifestV2.init(expected.words().len);
    if (!std.meta.eql(shape, admission.source_manifest)) return error.SegmentV2PublicInputManifestMismatch;
    beginPayload(channel, .admission_header);
    channel.mixU32s(&.{ 0x5344_4131, VERSION, manifest_mod.COMPONENT_COUNT }); // SDA1
    var pin_words: [8]u32 = undefined;
    for (&pin_words, 0..) |*word, index|
        word.* = std.mem.readInt(u32, fixed_identity[index * 4 ..][0..4], .little);
    beginPayload(channel, .key_identity);
    channel.mixU32s(&pin_words);
    beginPayload(channel, .expected);
    try expected.mixInto(channel);
}

/// The profile owns the work threshold and its transcript position. A missing
/// nonce must never silently select the development transcript.
pub const mixInteractionPow = @import("recursive_detached_claims_v1.zig").mixInteractionPow;

/// Claims remain untrusted until STARK verification. The two independent
/// checks bind row36 to expected public input and all39 rows to fixed lowering
/// anchors. Neither public boundary is accepted as a supplied scalar.
pub fn mixClaimsAndBoundary(
    channel: anytype,
    admission: *const KeyV1,
    expected: *const PublicData,
    claims: components.ClaimsV1,
    relations: *const components.Relations,
) !void {
    const hash_boundary = try authority_boundary.derive(expected, admission.native_descriptors, relations);
    const wire_claim = (try admission.wireClaim(relations)).add(hash_boundary.claimed_sum);
    _ = try claims.vector(&admission.manifest);
    try public_inputs.verifyStatementClaim(expected, &admission.admitted_keys, &admission.source_manifest, relations, claims.values[36]);
    var total = wire_claim;
    for (claims.values) |claim| total = total.add(claim);
    if (!total.isZero()) return error.SegmentDetachedClaimClosureMismatch;
    beginPayload(channel, .claims_header);
    channel.mixU32s(&.{ 0x5344_4331, VERSION, manifest_mod.COMPONENT_COUNT }); // SDC1
    // Roster order is fixed by the admitted canonical manifest. A source-
    // dependent ClaimVector seal is deliberately not a transcript input.
    beginPayload(channel, .claims);
    channel.mixFelts(&claims.values);
    beginPayload(channel, .boundary_header);
    channel.mixU32s(&.{ 0x5344_4231, VERSION, @intCast(admission.wire_terms.len), hash_boundary.term_count, 2 }); // SDB1
    beginPayload(channel, .boundary);
    channel.mixFelts(&.{wire_claim});
    beginPayload(channel, .partials);
    channel.mixFelts(&claims.poseidon_partials);
}

fn canonical(value: QM31) !void {
    for (value.toM31Array()) |word| if (word.toU32() >= core.fields.m31.Modulus)
        return error.InvalidSegmentDetachedCircuit;
}

fn hashWord(hash: anytype, value: u32) void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    hash.update(&bytes);
}

const fixture = frontend.testing.public_data_v2_test_support;
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
    const manifest = try manifest_mod.assemble(&catalog, .{
        .transcript_manifest_id = @splat(transcript_template_id),
        .statement_manifest_id = @splat(2),
        .public_manifest_id = @splat(3),
        .boundary_manifest_id = boundary.identity,
        .boundary_authority_sha_id = boundary.authority_sha_id,
        .provider_authority_sha_id = recursion.segment_publication_input_provider_authority_v2.sourceAuthorityShaId(),
    });
    const lane: air.query_bits_witness.LaneProfile = .{ .query_count = 3, .lifting_log_size = 4, .trace_tree_count = 4, .fri_layer_count = 2 };
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

test "SegmentV2 detached fixed projection excludes source seals and pins circuit facts" {
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

test "SegmentV2 detached transcript binds dynamic expected wire without specializing the key" {
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

test "SegmentV2 detached claims share fixed lowering and expected row36 closure" {
    const allocator = std.testing.allocator;
    var input = try fixture.Fixture.init();
    const words = try fixture.encode(allocator, &input.leftSource());
    defer allocator.free(words);
    const data = try PublicData.authenticate(words);
    const key = try testKey(words.len, 1);
    const relations = components.Relations.dummy();
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

test "SegmentV2 detached profiles bind security and interaction work" {
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
