//! Event-level parity and rejection evidence for the guest proof transcript.

const std = @import("std");
const Blake2sChannel = @import("stwo_core").channel.blake2s.Blake2sChannel;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const subject = @import("proof_transcript.zig");
const artifact = @import("artifact_identity.zig");
const components = @import("component_registry.zig");
const proof_admission = @import("proof_admission.zig");
const statement_mod = @import("statement.zig");
const support = @import("main_trace_test_support.zig");
const component_order = @import("../component_order.zig");
const lookup_table_schema = @import("../lookups/tables/schema.zig");
const opcode_interaction = @import("../lookups/opcode_interaction.zig");
const merkle_node = @import("../memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const public_data = @import("../public_data.zig");
const base_statement = @import("../statement.zig");
const base_claims = @import("../transcript/claims.zig");
const base_transcript = @import("../transcript/mod.zig");

const Tag = enum(u8) {
    mix_u32s,
    mix_u64,
    mix_felts,
    pow,
    draw_secure_felts,
    tree_0,
    tree_1,
    tree_2,
};

const Event = struct {
    tag: Tag,
    payload_start: usize,
    payload_len: usize,
};

/// A lossless logical-call recorder around the production Blake2s channel.
/// Payload words are normalized to u64 only for simple event comparison; the
/// inner channel still consumes the production u32/u64/QM31 representations.
const RecordingChannel = struct {
    inner: Blake2sChannel = .{},
    events: [2048]Event = undefined,
    events_len: usize = 0,
    payload: [16 * 1024]u64 = undefined,
    payload_len: usize = 0,
    pow_state: Blake2sChannel = .{},
    has_pow_state: bool = false,

    pub fn mixU32s(self: *RecordingChannel, values: []const u32) void {
        self.inner.mixU32s(values);
        const event = self.begin(.mix_u32s);
        for (values) |value| self.append(value);
        self.finish(event);
    }

    pub fn mixU64(self: *RecordingChannel, value: u64) void {
        self.inner.mixU64(value);
        const event = self.begin(.mix_u64);
        self.append(value);
        self.finish(event);
    }

    pub fn mixFelts(self: *RecordingChannel, values: []const QM31) void {
        self.inner.mixFelts(values);
        const event = self.begin(.mix_felts);
        for (values) |value| self.appendFelt(value);
        self.finish(event);
    }

    pub fn grind(self: *RecordingChannel, bits: u32) u64 {
        const nonce = self.inner.grind(bits);
        self.pow_state = self.inner;
        self.has_pow_state = true;
        const event = self.begin(.pow);
        self.append(bits);
        self.append(nonce);
        self.finish(event);
        return nonce;
    }

    pub fn verifyPowNonce(
        self: *RecordingChannel,
        bits: u32,
        nonce: u64,
    ) bool {
        self.pow_state = self.inner;
        self.has_pow_state = true;
        const valid = self.inner.verifyPowNonce(bits, nonce);
        const event = self.begin(.pow);
        self.append(bits);
        self.append(nonce);
        self.finish(event);
        return valid;
    }

    pub fn drawSecureFelts(
        self: *RecordingChannel,
        allocator: std.mem.Allocator,
        n_felts: usize,
    ) ![]QM31 {
        const values = try self.inner.drawSecureFelts(allocator, n_felts);
        const event = self.begin(.draw_secure_felts);
        self.append(n_felts);
        for (values) |value| self.appendFelt(value);
        self.finish(event);
        return values;
    }

    fn boundary(self: *RecordingChannel, tag: Tag) void {
        std.debug.assert(tag == .tree_0 or tag == .tree_1 or tag == .tree_2);
        const event = self.begin(tag);
        self.finish(event);
    }

    fn digestBytes(self: *const RecordingChannel) [32]u8 {
        return self.inner.digestBytes();
    }

    fn eventPayload(self: *const RecordingChannel, index: usize) []const u64 {
        const event = self.events[index];
        return self.payload[event.payload_start..][0..event.payload_len];
    }

    fn count(self: *const RecordingChannel, tag: Tag) usize {
        var result: usize = 0;
        for (self.events[0..self.events_len]) |event|
            result += @intFromBool(event.tag == tag);
        return result;
    }

    fn begin(self: *RecordingChannel, tag: Tag) usize {
        std.debug.assert(self.events_len < self.events.len);
        const index = self.events_len;
        self.events_len += 1;
        self.events[index] = .{
            .tag = tag,
            .payload_start = self.payload_len,
            .payload_len = 0,
        };
        return index;
    }

    fn finish(self: *RecordingChannel, event: usize) void {
        self.events[event].payload_len =
            self.payload_len - self.events[event].payload_start;
    }

    fn appendFelt(self: *RecordingChannel, value: QM31) void {
        for (value.toM31Array()) |limb| self.append(limb.toU32());
    }

    fn append(self: *RecordingChannel, value: anytype) void {
        std.debug.assert(self.payload_len < self.payload.len);
        self.payload[self.payload_len] = @intCast(value);
        self.payload_len += 1;
    }
};

pub const Fixture = struct {
    core: base_statement.RiscVStatement,
    extension: statement_mod.ExtensionStatement,
    identity: artifact.Identity,

    pub fn init(n_guest: u32) !Fixture {
        const core = admittedCore(n_guest);
        const extension = try statement_mod.ExtensionStatement.canonical(
            &core,
            n_guest,
        );
        return .{
            .core = core,
            .extension = extension,
            .identity = try proof_admission.canonical(
                &core,
                &extension,
                .proof,
            ),
        };
    }
};

pub const OwnedInteractionClaim = struct {
    log_sizes: []u32,
    base_detail: *base_statement.RiscVInteractionClaim,
    caller: [components.caller_batch_count]QM31,
    provider: [components.provider_batch_count]QM31,
    claim: statement_mod.InteractionClaim,

    pub fn init(
        allocator: std.mem.Allocator,
        core: *const base_statement.RiscVStatement,
        extension: *const statement_mod.ExtensionStatement,
    ) !OwnedInteractionClaim {
        const log_sizes = try allocator.alloc(u32, core.nInteractionColumns());
        errdefer allocator.free(log_sizes);
        const base_detail = try allocator.create(base_statement.RiscVInteractionClaim);
        errdefer allocator.destroy(base_detail);
        base_detail.initZeroInto();
        base_detail.n_components = core.n_components;
        base_detail.n_infra = core.n_infra;
        var cursor: usize = 0;
        for (core.component_descs[0..core.n_components]) |descriptor| {
            for (0..opcode_interaction.nColumns(descriptor.family)) |_| {
                log_sizes[cursor] = descriptor.log_size;
                cursor += 1;
            }
        }
        for (core.infra_descs[0..core.n_infra]) |descriptor| {
            for (0..base_statement.nInteractionColsForInfra(descriptor.kind)) |_| {
                log_sizes[cursor] = descriptor.log_size;
                cursor += 1;
            }
        }
        std.debug.assert(cursor == log_sizes.len);

        const sums = [_]QM31{QM31.zero()} ** base_claims.COMPONENT_COUNT;
        const guest_sum = QM31.fromU32Unchecked(101, 202, 303, 404);
        var caller = [_]QM31{QM31.zero()} ** components.caller_batch_count;
        var provider = [_]QM31{QM31.zero()} ** components.provider_batch_count;
        caller[0] = guest_sum;
        provider[provider.len - 1] = guest_sum.neg();
        const base = base_claims.InteractionClaim.init(sums, log_sizes);
        const claim = statement_mod.InteractionClaim.init(
            base,
            guest_sum,
            guest_sum.neg(),
            extension,
        );
        std.debug.assert(claim.total().isZero());
        return .{
            .log_sizes = log_sizes,
            .base_detail = base_detail,
            .caller = caller,
            .provider = provider,
            .claim = claim,
        };
    }

    pub fn detailed(self: *const OwnedInteractionClaim) subject.DetailedInteractionClaim {
        return .{
            .base = self.base_detail,
            .caller = &self.caller,
            .provider = &self.provider,
        };
    }

    pub fn deinit(self: *OwnedInteractionClaim, allocator: std.mem.Allocator) void {
        allocator.destroy(self.base_detail);
        allocator.free(self.log_sizes);
        self.* = undefined;
    }
};

test "profile transcript records the exact accepted Tree0 Tree1 and Tree2 order" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(3);
    var interaction_claim = try OwnedInteractionClaim.init(
        allocator,
        &fixture.core,
        &fixture.extension,
    );
    defer interaction_claim.deinit(allocator);

    var channel = RecordingChannel{};
    try subject.mixProfileIdentity(
        &channel,
        &fixture.core,
        &fixture.extension,
        fixture.identity,
    );
    channel.boundary(.tree_0);
    channel.boundary(.tree_1);
    const post_tree_1_start = channel.events_len;
    const result = try subject.proveToRelations(
        allocator,
        &channel,
        &fixture.core,
        &fixture.extension,
    );
    try std.testing.expectEqual(@as(u32, 13), channel.inner.n_draws);
    const interaction_claim_start = channel.events_len;
    try subject.mixInteractionClaim(
        &channel,
        &fixture.core,
        &fixture.extension,
        &interaction_claim.claim,
        interaction_claim.detailed(),
    );
    channel.boundary(.tree_2);

    try std.testing.expectEqual(Tag.mix_u32s, channel.events[0].tag);
    const identity_payload = channel.eventPayload(0);
    try std.testing.expectEqual(
        subject.identity_domain_words.len + subject.artifact_word_count,
        identity_payload.len,
    );
    for (subject.identity_domain_words, identity_payload[0..subject.identity_domain_words.len]) |
        expected,
        actual,
    | try std.testing.expectEqual(@as(u64, expected), actual);
    const encoded = fixture.identity.encode();
    for (0..subject.artifact_word_count) |index| {
        const offset = index * @sizeOf(u32);
        const expected = std.mem.readInt(
            u32,
            encoded[offset..][0..@sizeOf(u32)],
            .little,
        );
        try std.testing.expectEqual(
            @as(u64, expected),
            identity_payload[subject.identity_domain_words.len + index],
        );
    }
    try expectEvent(&channel, 1, .tree_0, &.{});
    try expectEvent(&channel, 2, .tree_1, &.{});

    var event_index = post_tree_1_start;
    const base_main = fixture.core.canonicalMainClaim();
    for (base_main.log_sizes) |log_size| {
        try expectEvent(&channel, event_index, .mix_u64, &.{log_size});
        event_index += 1;
    }
    for (fixture.extension.components) |descriptor| {
        try expectEvent(&channel, event_index, .mix_u64, &.{descriptor.log_size});
        event_index += 1;
    }

    var base_manifest = RecordingChannel{};
    fixture.core.mixShardManifest(&base_manifest);
    for (0..base_manifest.events_len) |base_event| {
        try expectEventEqual(&channel, event_index, &base_manifest, base_event);
        event_index += 1;
    }
    try expectU32Event(
        &channel,
        event_index,
        .mix_u32s,
        &subject.extension_shard_domain_words,
    );
    event_index += 1;
    for (fixture.extension.components) |descriptor| {
        try expectDescriptorEvent(&channel, event_index, descriptor);
        event_index += 1;
    }
    try expectEvent(&channel, event_index, .pow, &.{
        base_transcript.INTERACTION_POW_BITS,
        result.interaction_pow,
    });
    event_index += 1;
    try expectEvent(
        &channel,
        event_index,
        .mix_u64,
        &.{result.interaction_pow},
    );
    event_index += 1;
    try std.testing.expectEqual(Tag.draw_secure_felts, channel.events[event_index].tag);
    try std.testing.expectEqual(@as(u64, 24), channel.eventPayload(event_index)[0]);
    event_index += 1;
    try std.testing.expectEqual(Tag.draw_secure_felts, channel.events[event_index].tag);
    try std.testing.expectEqual(@as(u64, 2), channel.eventPayload(event_index)[0]);
    event_index += 1;
    try std.testing.expectEqual(interaction_claim_start, event_index);

    try expectFeltsEvent(
        &channel,
        event_index,
        &interaction_claim.claim.base.claimed_sums,
    );
    event_index += 1;
    try expectFeltsEvent(
        &channel,
        event_index,
        &interaction_claim.claim.extension_sums,
    );
    event_index += 1;
    const total_log_sizes = interaction_claim.log_sizes.len +
        components.caller_interaction_columns +
        components.provider_interaction_columns;
    try expectU32Event(
        &channel,
        event_index,
        .mix_u32s,
        &.{
            statement_mod.interaction_claim_geometry_domain_words[0],
            statement_mod.interaction_claim_geometry_domain_words[1],
            statement_mod.interaction_claim_geometry_domain_words[2],
            statement_mod.interaction_claim_geometry_domain_words[3],
            @intCast(interaction_claim.log_sizes.len),
            components.caller_interaction_columns,
            fixture.extension.components[0].log_size,
            components.provider_interaction_columns,
            fixture.extension.components[1].log_size,
            @intCast(total_log_sizes),
        },
    );
    event_index += 1;
    try expectU32Event(
        &channel,
        event_index,
        .mix_u32s,
        interaction_claim.log_sizes,
    );
    event_index += 1;

    const base_detail_count = try subject.detailedBaseClaimCount(&fixture.core);
    try expectU32Event(&channel, event_index, .mix_u32s, &.{
        subject.detailed_claim_domain_words[0],
        subject.detailed_claim_domain_words[1],
        subject.detailed_claim_domain_words[2],
        subject.detailed_claim_domain_words[3],
        @intCast(base_detail_count),
        components.caller_batch_count,
        components.provider_batch_count,
    });
    event_index += 1;
    for (fixture.core.component_descs[0..fixture.core.n_components], 0..) |
        descriptor,
        index,
    | {
        try expectFeltsEvent(
            &channel,
            event_index,
            try interaction_claim.base_detail.opcodeClaims(
                descriptor.family,
                index,
            ),
        );
        event_index += 1;
    }
    for (fixture.core.infra_descs[0..fixture.core.n_infra], 0..) |
        descriptor,
        index,
    | {
        try expectFeltsEvent(
            &channel,
            event_index,
            try interaction_claim.base_detail.infraClaims(
                descriptor.kind,
                index,
            ),
        );
        event_index += 1;
    }
    try expectFeltsEvent(&channel, event_index, &interaction_claim.caller);
    event_index += 1;
    try expectFeltsEvent(&channel, event_index, &interaction_claim.provider);
    event_index += 1;
    try expectEvent(&channel, event_index, .tree_2, &.{});
    event_index += 1;
    try std.testing.expectEqual(channel.events_len, event_index);
    try std.testing.expectEqual(
        2 + fixture.core.n_components + fixture.core.n_infra + 2,
        channel.count(.mix_felts),
    );
    try std.testing.expectEqual(@as(usize, 2), channel.count(.draw_secure_felts));
    // Mixing the first interaction-claim sum begins the Tree-2 phase and, as
    // in the production channel, resets the draw counter.
    try std.testing.expectEqual(@as(u32, 0), channel.inner.n_draws);
}

test "profile transcript prover and verifier are event-byte symmetric including zero calls" {
    try expectParity(0);
    try expectParity(2);
}

test "profile transcript binds valid dynamic geometry and rejects aggregate log mutation" {
    const one_call = try Fixture.init(1);
    const two_calls = try Fixture.init(2);
    var one_channel = RecordingChannel{};
    var two_channel = RecordingChannel{};
    try subject.mixProfileIdentity(
        &one_channel,
        &one_call.core,
        &one_call.extension,
        one_call.identity,
    );
    try subject.mixProfileIdentity(
        &two_channel,
        &two_calls.core,
        &two_calls.extension,
        two_calls.identity,
    );
    _ = try subject.proveToRelations(
        std.testing.allocator,
        &one_channel,
        &one_call.core,
        &one_call.extension,
    );
    _ = try subject.proveToRelations(
        std.testing.allocator,
        &two_channel,
        &two_calls.core,
        &two_calls.extension,
    );
    try std.testing.expect(!std.mem.eql(
        u64,
        one_channel.payload[0..one_channel.payload_len],
        two_channel.payload[0..two_channel.payload_len],
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &one_channel.digestBytes(),
        &two_channel.digestBytes(),
    ));

    var claim = try OwnedInteractionClaim.init(
        std.testing.allocator,
        &one_call.core,
        &one_call.extension,
    );
    defer claim.deinit(std.testing.allocator);
    claim.log_sizes[claim.log_sizes.len - 1] += 1;
    var rejected = RecordingChannel{};
    try std.testing.expectError(
        error.InvalidInteractionClaim,
        subject.mixInteractionClaim(
            &rejected,
            &one_call.core,
            &one_call.extension,
            &claim.claim,
            claim.detailed(),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), rejected.events_len);
    try expectPristineDigest(&rejected);
}

test "profile transcript rejects invalid artifacts before the Tree0 channel changes" {
    const fixture = try Fixture.init(1);

    var changed = fixture.identity;
    changed.profile_id = @intFromEnum(
        @import("../../isa/execution_profile.zig").ExecutionProfile.rv32im_zkvm_v1,
    );
    try expectArtifactRejected(error.ProfileMismatch, &fixture, changed);

    changed = fixture.identity;
    changed.total_components -= 1;
    try expectArtifactRejected(error.RegistryGeometryMismatch, &fixture, changed);

    changed = fixture.identity;
    changed.manifest_digest[0] ^= 1;
    try expectArtifactRejected(error.ManifestDigestMismatch, &fixture, changed);

    changed = fixture.identity;
    changed.statement_digest[31] ^= 1;
    try expectArtifactRejected(error.StatementDigestMismatch, &fixture, changed);
}

test "profile transcript invalid PoW stops before nonce mixing and relation draws" {
    const fixture = try Fixture.init(1);
    var prover = RecordingChannel{};
    try subject.mixProfileIdentity(
        &prover,
        &fixture.core,
        &fixture.extension,
        fixture.identity,
    );
    prover.boundary(.tree_0);
    prover.boundary(.tree_1);
    const result = try subject.proveToRelations(
        std.testing.allocator,
        &prover,
        &fixture.core,
        &fixture.extension,
    );
    try std.testing.expect(prover.has_pow_state);

    var invalid_nonce = result.interaction_pow +% 1;
    while (prover.pow_state.verifyPowNonce(
        base_transcript.INTERACTION_POW_BITS,
        invalid_nonce,
    )) invalid_nonce +%= 1;

    var verifier = RecordingChannel{};
    try subject.mixProfileIdentity(
        &verifier,
        &fixture.core,
        &fixture.extension,
        fixture.identity,
    );
    verifier.boundary(.tree_0);
    verifier.boundary(.tree_1);
    try std.testing.expectError(
        error.InvalidInteractionProofOfWork,
        subject.verifyToRelations(
            std.testing.allocator,
            &verifier,
            &fixture.core,
            &fixture.extension,
            invalid_nonce,
        ),
    );
    try std.testing.expect(verifier.has_pow_state);
    try std.testing.expectEqual(Tag.pow, verifier.events[verifier.events_len - 1].tag);
    try std.testing.expectEqual(@as(usize, 0), verifier.count(.draw_secure_felts));
    try std.testing.expectEqual(@as(u32, 0), verifier.inner.n_draws);
    try std.testing.expectEqual(
        verifier.pow_state.digestBytes(),
        verifier.digestBytes(),
    );
}

fn expectParity(n_guest: u32) !void {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(n_guest);
    var claim = try OwnedInteractionClaim.init(
        allocator,
        &fixture.core,
        &fixture.extension,
    );
    defer claim.deinit(allocator);

    var prover = RecordingChannel{};
    try subject.mixProfileIdentity(
        &prover,
        &fixture.core,
        &fixture.extension,
        fixture.identity,
    );
    prover.boundary(.tree_0);
    prover.boundary(.tree_1);
    const prover_result = try subject.proveToRelations(
        allocator,
        &prover,
        &fixture.core,
        &fixture.extension,
    );
    try subject.mixInteractionClaim(
        &prover,
        &fixture.core,
        &fixture.extension,
        &claim.claim,
        claim.detailed(),
    );
    prover.boundary(.tree_2);

    var verifier = RecordingChannel{};
    try subject.mixProfileIdentity(
        &verifier,
        &fixture.core,
        &fixture.extension,
        fixture.identity,
    );
    verifier.boundary(.tree_0);
    verifier.boundary(.tree_1);
    const verifier_relations = try subject.verifyToRelations(
        allocator,
        &verifier,
        &fixture.core,
        &fixture.extension,
        prover_result.interaction_pow,
    );
    try subject.mixInteractionClaim(
        &verifier,
        &fixture.core,
        &fixture.extension,
        &claim.claim,
        claim.detailed(),
    );
    verifier.boundary(.tree_2);

    try expectRecordersEqual(&prover, &verifier);
    try std.testing.expect(prover_result.relations.base.registers_state.z.eql(
        verifier_relations.base.registers_state.z,
    ));
    try std.testing.expect(prover_result.relations.base.range_check_m31.alpha.eql(
        verifier_relations.base.range_check_m31.alpha,
    ));
    try std.testing.expect(prover_result.relations.guest_poseidon2_io.z.eql(
        verifier_relations.guest_poseidon2_io.z,
    ));
    try std.testing.expect(prover_result.relations.guest_poseidon2_io.alpha.eql(
        verifier_relations.guest_poseidon2_io.alpha,
    ));
}

fn expectArtifactRejected(
    expected: anyerror,
    fixture: *const Fixture,
    identity: artifact.Identity,
) !void {
    var channel = RecordingChannel{};
    try std.testing.expectError(
        expected,
        subject.mixProfileIdentity(
            &channel,
            &fixture.core,
            &fixture.extension,
            identity,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), channel.events_len);
    try expectPristineDigest(&channel);
}

fn expectPristineDigest(channel: *const RecordingChannel) !void {
    const pristine = Blake2sChannel{};
    try std.testing.expectEqual(pristine.digestBytes(), channel.digestBytes());
    try std.testing.expectEqual(@as(u32, 0), channel.inner.n_draws);
}

fn expectRecordersEqual(
    expected: *const RecordingChannel,
    actual: *const RecordingChannel,
) !void {
    try std.testing.expectEqual(expected.events_len, actual.events_len);
    for (0..expected.events_len) |index|
        try expectEventEqual(actual, index, expected, index);
    try std.testing.expectEqualSlices(
        u64,
        expected.payload[0..expected.payload_len],
        actual.payload[0..actual.payload_len],
    );
    try std.testing.expectEqual(expected.digestBytes(), actual.digestBytes());
    try std.testing.expectEqual(expected.inner.n_draws, actual.inner.n_draws);
}

fn expectEvent(
    channel: *const RecordingChannel,
    index: usize,
    tag: Tag,
    expected: []const u64,
) !void {
    try std.testing.expectEqual(tag, channel.events[index].tag);
    try std.testing.expectEqualSlices(u64, expected, channel.eventPayload(index));
}

fn expectU32Event(
    channel: *const RecordingChannel,
    index: usize,
    tag: Tag,
    expected: []const u32,
) !void {
    try std.testing.expectEqual(tag, channel.events[index].tag);
    const actual = channel.eventPayload(index);
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got|
        try std.testing.expectEqual(@as(u64, want), got);
}

fn expectFeltsEvent(
    channel: *const RecordingChannel,
    index: usize,
    expected: []const QM31,
) !void {
    try std.testing.expectEqual(Tag.mix_felts, channel.events[index].tag);
    const actual = channel.eventPayload(index);
    try std.testing.expectEqual(expected.len * 4, actual.len);
    var cursor: usize = 0;
    for (expected) |value| {
        for (value.toM31Array()) |limb| {
            try std.testing.expectEqual(@as(u64, limb.toU32()), actual[cursor]);
            cursor += 1;
        }
    }
}

fn expectDescriptorEvent(
    channel: *const RecordingChannel,
    index: usize,
    descriptor: components.Descriptor,
) !void {
    try expectEvent(channel, index, .mix_u32s, &.{
        @intFromEnum(descriptor.slot),
        @intFromEnum(descriptor.kind),
        descriptor.version,
        descriptor.n_rows,
        descriptor.log_size,
        descriptor.preprocessed_columns,
        descriptor.main_columns,
        descriptor.interaction_columns,
    });
}

fn expectEventEqual(
    actual: *const RecordingChannel,
    actual_index: usize,
    expected: *const RecordingChannel,
    expected_index: usize,
) !void {
    try std.testing.expectEqual(
        expected.events[expected_index].tag,
        actual.events[actual_index].tag,
    );
    try std.testing.expectEqualSlices(
        u64,
        expected.eventPayload(expected_index),
        actual.eventPayload(actual_index),
    );
}

fn admittedCore(n_guest: u32) base_statement.RiscVStatement {
    var core = support.coreFixture(n_guest);
    core.public_data.completion = public_data.Completion.canonicalSelfLoop(
        core.final_pc,
    );
    const clock_update = core.infra_descs[2];
    core.infra_descs[2] = .{
        .kind = .merkle,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    core.infra_descs[3] = .{
        .kind = .poseidon2,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = poseidon2_air.N_MAIN_COLUMNS,
    };
    core.infra_descs[4] = clock_update;
    var index: usize = 5;
    for (component_order.lookupTables()) |kind| {
        core.infra_descs[index] = .{
            .kind = base_statement.infraKindForTable(kind),
            .log_size = lookup_table_schema.logSize(kind),
            .n_rows = @intCast(lookup_table_schema.size(kind)),
            .n_columns = 1,
        };
        index += 1;
    }
    core.n_infra = @intCast(index);
    return core;
}
