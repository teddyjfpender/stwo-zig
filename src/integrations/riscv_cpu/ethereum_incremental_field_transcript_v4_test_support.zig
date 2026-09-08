//! Retained schema-2/3 transcript snapshot for exact compatibility regression.
//! These historical frame lists intentionally do not call the current profile
//! mixers. Do not update them when adding a new admission version.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const M31 = @import("stwo_core").fields.m31.M31;
const field = @import("ethereum_incremental_field_transcript_v4.zig");
const recording = frontend.recursion.recording_poseidon_channel_v4;
const statement_v2 = frontend.air.statement_v2;
const FORMAT_VERSION = 4;
const PRE_TREE0_DOMAIN_WORDS = [3]u32{ 0x5749_5453, 0x3446_4c45, 4 };
const POST_TREE1_DOMAIN_WORDS = [3]u32{ 0x5749_5453, 0x3446_5242, 4 };

pub fn checkLegacy(profile: anytype, native: anytype, role: anytype) !void {
    try std.testing.expect(profile.schema_version == 2 or profile.schema_version == 3);
    var actual = recording.Channel.init(std.testing.allocator);
    defer actual.deinit();
    var expected = recording.Channel.init(std.testing.allocator);
    defer expected.deinit();
    actual.setContextTag(1);
    expected.setContextTag(1);
    try profile.mixPreTree0(native, role, &actual);
    try legacyPre(profile, native, role, &expected);
    actual.setContextTag(2);
    expected.setContextTag(2);
    try profile.mixPostTree1(native, role, &actual);
    try legacyPost(profile, native, &expected);
    var got = try actual.finish();
    defer got.deinit();
    var frozen = try expected.finish();
    defer frozen.deinit();
    try std.testing.expectEqualDeep(frozen.operations, got.operations);
    try std.testing.expectEqualDeep(frozen.hash_frames, got.hash_frames);
    try std.testing.expectEqualDeep(frozen.word_storage, got.word_storage);
    try std.testing.expectEqual(frozen.final_digest, got.final_digest);
}

fn legacyPre(self: anytype, native: anytype, role_aware_public: anytype, channel: anytype) !void {
    (try self.protocol.pcs.config()).mixInto(channel);
    try statement_v2.mixIntoNativeTranscript(&native.public_data, channel);
    self.base_geometry.lookup_activation.mixInto(channel);
    channel.mixU32s(&.{ PRE_TREE0_DOMAIN_WORDS[0], PRE_TREE0_DOMAIN_WORDS[1], FORMAT_VERSION, self.schema_version });
    channel.mixU32s(&.{
        self.format_version,
        self.schema_version,
        @intFromEnum(self.statement_family),
        @intFromEnum(self.boundary_policy),
        self.coordinate.segment_index,
        self.coordinate.segment_count,
        self.continuation_roots.entry,
        self.continuation_roots.exit,
        self.base_geometry.component_count,
        self.base_geometry.infrastructure_count,
        self.base_geometry.maximum_column_log_size,
    });
    channel.mixU32s(&self.segment_public_wire_id);
    mixSha256(channel, self.boundary_artifact_content_sha256);
    channel.mixU32s(&self.base_geometry.compatibility_tree_columns);
    channel.mixU32s(&self.base_geometry.physical_tree_columns);
    channel.mixU32s(&self.base_geometry.statement_authority_id);
    mixSha256(channel, self.base_geometry.identity_sha256);
    channel.mixU32s(&self.protocol.profile_words);
    channel.mixU32s(&self.protocol.protocol_id);
    mixSha256(channel, self.protocol.proof_security_identity_sha256);
    channel.mixU32s(&.{
        self.protocol.pcs.pow_bits,
        self.protocol.pcs.log_blowup_factor,
        self.protocol.pcs.query_count,
        self.protocol.pcs.fold_step,
        self.protocol.pcs.log_last_layer_degree_bound,
        self.protocol.pcs.lifting_mode,
        self.protocol.pcs.configured_security_bits,
    });
    mixSha256(channel, self.protocol.pcs.identity_sha256);
    mixSha256(channel, self.protocol.identity_sha256);
    try self.ethereum.mixIntoV2(native, channel);
    mixSha256(channel, self.ethereum_identity_sha256);
    mixSha256(channel, self.public_boundary_identity_sha256);
    const completion = role_aware_public.completion orelse
        return error.MissingCompletion;
    channel.mixU32s(&.{
        @intFromEnum(completion.kind),
        completion.address,
        completion.value,
        completion.clock,
    });
    self.bridge_geometry.mixFieldAuthority(channel);
    mixSha256(channel, self.identity_sha256);
}

fn legacyPost(self: anytype, native: anytype, channel: anytype) !void {
    const main_claim = native.core.canonicalMainClaim();
    main_claim.mixInto(channel);
    native.core.mixShardManifest(channel);
    try self.ethereum.mixIntoV2(native, channel);
    channel.mixU32s(&.{ POST_TREE1_DOMAIN_WORDS[0], POST_TREE1_DOMAIN_WORDS[1], FORMAT_VERSION, self.schema_version });
    self.bridge_geometry.mixFieldAuthority(channel);
    mixSha256(channel, self.identity_sha256);
}

fn mixSha256(channel: anytype, digest: [32]u8) void {
    var words: [16]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = std.mem.readInt(u16, digest[index * 2 ..][0..2], .little);
    channel.mixU32s(&words);
}

const FieldSink = struct {
    expected: *const recording.ExecutionV4,
    index: usize = 0,
    pub fn frame(self: *@This(), value: field.Frame) !void {
        if (self.index >= self.expected.operations.len) return error.ExtraEthereumFieldFrame;
        const op = self.expected.operations[self.index];
        try std.testing.expectEqual(@as(u32, if (value.phase == .pre_tree0) 1 else 2), op.context_tag);
        try std.testing.expectEqual(recording.Effect.mix, op.effect);
        try std.testing.expectEqual(@as(u32, 1), op.hash_count);
        try value.validateRecordedOperation(self.expected, self.index);
        _ = value.classification(); // Exhaustive classification has no fallback.
        self.index += 1;
    }
};

pub fn checkField(profile: anytype, native: anytype, role: anytype) !void {
    try std.testing.expectEqual(@as(u16, 4), profile.schema_version);
    var actual = recording.Channel.init(std.testing.allocator);
    defer actual.deinit();
    actual.setContextTag(1);
    try profile.mixPreTree0(native, role, &actual);
    actual.setContextTag(2);
    try profile.mixPostTree1(native, role, &actual);
    var execution = try actual.finish();
    defer execution.deinit();
    try execution.validate();
    var sink = FieldSink{ .expected = &execution };
    try field.emitPreTree0(profile, native, role, &sink);
    try field.emitPostTree1(profile, native, &sink);
    try std.testing.expectEqual(execution.operations.len, sink.index);
}

/// Exercise the exact final-claim order with a real admitted native statement.
/// Payloads are deterministic framing vectors, not claims of a proved witness.
pub fn checkFinalClaims(profile: anytype, native: anytype) !void {
    const allocator = std.testing.allocator;
    const QM31 = @import("stwo_core").fields.qm31.QM31;
    const statement = frontend.air.statement;
    const lookup = frontend.air.lookup_physical_manifest_v2;
    const transcript = frontend.prover_mod.guest_precompile.ethereum_transcript;
    const types = frontend.prover_mod.guest_precompile.ethereum_types;
    const manifest = lookup.Manifest.native();
    const authenticated = try lookup.AuthenticatedStatement.init(&native.core, &manifest);
    const base = try allocator.create(statement.RiscVInteractionClaim);
    defer allocator.destroy(base);
    base.initZeroInto();
    base.n_components = native.core.n_components;
    base.n_infra = native.core.n_infra;
    var next: u32 = 1;
    for (native.core.component_descs[0..native.core.n_components], 0..) |descriptor, index| {
        for (0..manifest.entryForFamily(descriptor.family).detailed_claim_count) |batch| {
            base.opcode_claims[index][batch] = QM31.fromU32Unchecked(next, 0, 0, 0);
            next += 1;
        }
    }
    for (native.core.infra_descs[0..native.core.n_infra], 0..) |descriptor, index| {
        for (0..statement.nClaimedSumsForInfra(descriptor.kind)) |sum| {
            try base.setInfraClaim(descriptor.kind, index, sum, QM31.fromU32Unchecked(next, 0, 0, 0));
            next += 1;
        }
    }
    const extension = std.mem.zeroes(types.ExtensionClaim);
    const bridge_claim = QM31.fromU32Unchecked(0x1234, 0x5678, 0x9abc, 0xdef0);
    const selected = try transcript.SelectedBaseClaimsV3.init(&native.core, &manifest, &authenticated, base);
    const selected_values = try allocator.alloc(QM31, selected.count);
    defer allocator.free(selected_values);
    try selected.write(selected_values);

    var actual = recording.Channel.init(allocator);
    defer actual.deinit();
    var expected = recording.Channel.init(allocator);
    defer expected.deinit();
    actual.setContextTag(7);
    expected.setContextTag(7);
    try transcript.mixInteractionClaimV2(&actual, &native.core, &manifest, &authenticated, base, &extension);
    try transcript.mixInteractionClaimV2(&expected, &native.core, &manifest, &authenticated, base, &extension);
    const prefix_operations = expected.operations.items.len;
    try profile.mixFinalClaims(allocator, &actual, &native.core, &manifest, &authenticated, base, bridge_claim);
    if (profile.schema_version != 2) {
        // Frozen schema-3 detailed frame encoding remains exact in schema 4.
        expected.mixU32s(&.{ 0x4757_5453, 0x3344_4245, 3, @intCast(selected.count) });
        expected.mixFelts(selected_values);
    }
    expected.mixFelts(&.{bridge_claim});
    var got = try actual.finish();
    defer got.deinit();
    var frozen = try expected.finish();
    defer frozen.deinit();
    try std.testing.expectEqual(prefix_operations + @as(usize, if (profile.schema_version == 2) 1 else 3), got.operations.len);
    try std.testing.expectEqualDeep(frozen.operations, got.operations);
    try std.testing.expectEqualDeep(frozen.hash_frames, got.hash_frames);
    try std.testing.expectEqualDeep(frozen.word_storage, got.word_storage);
    try std.testing.expectEqual(frozen.final_digest, got.final_digest);
    try got.validate();
    try std.testing.expectEqualSlices(M31, &bridge_claim.toM31Array(), try field.recordedOperationPayload(&got, got.operations.len - 1));
    if (profile.schema_version != 2) {
        const expected_header = [_]M31{
            M31.fromCanonical(0x5453),                            M31.fromCanonical(0x4757),
            M31.fromCanonical(0x4245),                            M31.fromCanonical(0x3344),
            M31.fromCanonical(3),                                 M31.zero(),
            M31.fromCanonical(@intCast(selected.count & 0xffff)), M31.fromCanonical(@intCast(selected.count >> 16)),
        };
        try std.testing.expectEqualSlices(M31, &expected_header, try field.recordedOperationPayload(&got, prefix_operations));
        try std.testing.expectEqual(selected.count * 4, (try field.recordedOperationPayload(&got, prefix_operations + 1)).len);
    }
}
