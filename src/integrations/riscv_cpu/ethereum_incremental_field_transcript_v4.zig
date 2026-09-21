//! Shared schema-4 Ethereum transcript framing. This module describes protocol
//! operations, not admission: callers must validate the native/profile owners.
//! Custody-only digests remain in those owners and never enter these frames.
//! The sink receives borrowed payloads synchronously; it must copy retained data.
const std = @import("std");
const core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;

pub const SCHEMA_VERSION: u16 = 4;
pub const Phase = enum { pre_tree0, post_tree1 };
pub const VerifierBinding = enum { pcs, statement, protocol, public_claim };

/// Each contiguous transcript group consumes its verifier control step once.
/// The post-Tree1 claim cannot reuse the pre-Tree0 statement step: those
/// groups are separated by two commitment steps in the native transcript.
pub fn verifierBinding(phase: Phase, kind: Kind) VerifierBinding {
    if (phase == .post_tree1) return .public_claim;
    return switch (kind) {
        .pcs => .pcs,
        .native_statement_header, .native_wire_id, .native_statement_words => .statement,
        else => .protocol,
    };
}
pub const Classification = enum {
    fixed_protocol,
    admitted_geometry,
    native_wire_id,
    native_statement,
    coordinate,
    role_io_header,
    role_input_words,
    role_output_word,
    completion,
};
pub const Kind = enum {
    pcs,
    native_statement_header,
    native_wire_id,
    native_statement_words,
    authority_header,
    coordinate,
    base_geometry,
    lookup_activation,
    protocol,
    ethereum_geometry,
    role_io_header,
    role_input_words,
    role_output_word,
    completion,
    bridge_geometry,
    canonical_main_claim,
    shard_manifest,
    fixed_program,
};
pub const Payload = union(enum) {
    u32_words: []const u32,
    canonical_m31: []const M31,
    secure_words: []const QM31,
    u64_value: u64,
};
pub const Frame = struct {
    phase: Phase,
    kind: Kind,
    /// Zero-based operation within a kind; output words use the output index.
    ordinal: u32,
    payload: Payload,

    pub fn classification(self: Frame) Classification {
        return switch (self.kind) {
            .pcs, .authority_header, .protocol => .fixed_protocol,
            .native_statement_header, .base_geometry, .lookup_activation, .ethereum_geometry, .bridge_geometry, .canonical_main_claim, .shard_manifest, .fixed_program => .admitted_geometry,
            .native_wire_id => .native_wire_id,
            .native_statement_words => .native_statement,
            .coordinate => .coordinate,
            .role_io_header => .role_io_header,
            .role_input_words => .role_input_words,
            .role_output_word => .role_output_word,
            .completion => .completion,
        };
    }

    /// Exact payload seen by RecordingPoseidonChannelV4 (not absorb padding).
    pub fn recordedWordCount(self: Frame) !usize {
        return switch (self.payload) {
            .u32_words => |words| std.math.mul(usize, words.len, 2),
            .canonical_m31 => |words| words.len,
            .secure_words => |words| std.math.mul(usize, words.len, 4),
            .u64_value => 4,
        };
    }

    /// Compare one recorded mix operation, whose hash input also contains the
    /// preceding channel digest. That digest is checked by ExecutionV4.validate;
    /// it is not part of this frame's semantic payload or routing metadata.
    pub fn validateRecordedOperation(self: Frame, execution: anytype, operation_index: usize) !void {
        const words = try recordedOperationPayload(execution, operation_index);
        if (words.len != try self.recordedWordCount()) return error.EthereumFieldTranscriptPayloadMismatch;
        for (words, 0..) |word, index| {
            if (word.toU32() != (try self.recordedWord(index)).toU32())
                return error.EthereumFieldTranscriptPayloadMismatch;
        }
    }

    pub fn recordedWord(self: Frame, index: usize) !M31 {
        if (index >= try self.recordedWordCount()) return error.InvalidEthereumTranscriptFrameIndex;
        return switch (self.payload) {
            .u32_words => |words| M31.fromCanonical((words[index / 2] >> @as(u5, @intCast(16 * (index % 2)))) & 0xffff),
            .canonical_m31 => |words| words[index],
            .secure_words => |words| words[index / 4].toM31Array()[index % 4],
            .u64_value => |value| M31.fromCanonical(@intCast((value >> @as(u6, @intCast(16 * index))) & 0xffff)),
        };
    }
};

/// Extract the payload of one mix operation after the recorder's RATE-word
/// previous-state prefix. Retained execution must have crossed its validation
/// boundary; this helper checks operation/frame geometry before borrowing it.
pub fn recordedOperationPayload(execution: anytype, operation_index: usize) ![]const M31 {
    const recording = frontend.recursion.recording_poseidon_channel_v4;
    if (operation_index >= execution.operations.len) return error.InvalidEthereumRecordedOperation;
    const operation = execution.operations[operation_index];
    if (operation.effect != .mix or operation.hash_count != 1 or
        operation.first_hash_id >= execution.hash_frames.len)
        return error.InvalidEthereumRecordedOperation;
    const frame = execution.hash_frames[operation.first_hash_id];
    if (frame.purpose != .mix or frame.words.len < recording.RATE)
        return error.InvalidEthereumRecordedOperation;
    return frame.words[recording.RATE..];
}

/// Adapter preserves each original channel operation and its encoding.
pub fn NativeSink(comptime Channel: type) type {
    return struct {
        channel: *Channel,
        pub fn frame(self: *@This(), value: Frame) !void {
            switch (value.payload) {
                .u32_words => |words| self.channel.mixU32s(words),
                .canonical_m31 => |words| self.channel.mixCanonicalM31Words(words),
                .secure_words => |words| self.channel.mixFelts(words),
                .u64_value => |word| self.channel.mixU64(word),
            }
        }
    };
}

pub fn mixPreTree0(profile: anytype, native: anytype, role_public: anytype, channel: anytype) !void {
    var sink = NativeSink(@TypeOf(channel.*)){ .channel = channel };
    try emitPreTree0(profile, native, role_public, &sink);
}
pub fn mixPostTree1(profile: anytype, native: anytype, channel: anytype) !void {
    var sink = NativeSink(@TypeOf(channel.*)){ .channel = channel };
    try emitPostTree1(profile, native, &sink);
}

/// Native and recursive consumers walk this same list. In particular, the raw
/// native statement is one canonical-M31 frame; per-word routing belongs to the
/// canonical V2 layout, not a second handwritten layout in this module.
pub fn emitPreTree0(profile: anytype, native: anytype, role_public: anytype, sink: anytype) !void {
    if (profile.schema_version != SCHEMA_VERSION and profile.schema_version != 5) return error.InvalidEthereumFieldTranscriptSchema;
    var channel = TaggedChannel(@TypeOf(sink.*)).init(sink, .pre_tree0, .pcs);
    (try profile.protocol.pcs.config()).mixInto(&channel);
    try channel.finish();
    const words = native.public_data.words();
    const count = std.math.cast(u32, words.len) orelse return error.EthereumTranscriptFrameTooLarge;
    const data_v2 = frontend.air.public_data_v2;
    try emitU32(sink, .pre_tree0, .native_statement_header, 0, &.{ data_v2.STATEMENT_TRANSCRIPT_DOMAIN, data_v2.STATEMENT_TRANSCRIPT_VERSION, data_v2.STATEMENT_TRANSCRIPT_SCHEMA_VERSION, count });
    try emitU32(sink, .pre_tree0, .native_wire_id, 0, &native.public_data.wireId());
    try sink.frame(.{ .phase = .pre_tree0, .kind = .native_statement_words, .ordinal = 0, .payload = .{ .canonical_m31 = words } });
    try emitAuthorityMetadata(profile, sink);
    if (profile.schema_version == 5) {
        const fixed = profile.fixed_program orelse return error.EthereumFixedProgramAdmissionRequired;
        const fixed_words = try fixed.canonicalWords();
        try emitU32(sink, .pre_tree0, .fixed_program, 0, &fixed_words);
    }
    channel = TaggedChannel(@TypeOf(sink.*)).init(sink, .pre_tree0, .lookup_activation);
    profile.base_geometry.lookup_activation.mixInto(&channel);
    try channel.finish();
    try emitProtocol(profile.protocol, sink);
    channel = TaggedChannel(@TypeOf(sink.*)).init(sink, .pre_tree0, .ethereum_geometry);
    try profile.ethereum.mixIntoV2WithCircuitProfileV1(native, &channel, profile.circuitProfile());
    try channel.finish();
    try emitRolePublic(role_public, sink);
    channel = TaggedChannel(@TypeOf(sink.*)).init(sink, .pre_tree0, .bridge_geometry);
    profile.bridge_geometry.mixFieldAuthority(&channel);
    try channel.finish();
}

pub fn emitPostTree1(profile: anytype, native: anytype, sink: anytype) !void {
    if (profile.schema_version != SCHEMA_VERSION and profile.schema_version != 5) return error.InvalidEthereumFieldTranscriptSchema;
    var channel = TaggedChannel(@TypeOf(sink.*)).init(sink, .post_tree1, .canonical_main_claim);
    const main = native.core.canonicalMainClaim();
    main.mixInto(&channel);
    try channel.finish();
    channel = TaggedChannel(@TypeOf(sink.*)).init(sink, .post_tree1, .shard_manifest);
    native.core.mixShardManifest(&channel);
    try channel.finish();
    channel = TaggedChannel(@TypeOf(sink.*)).init(sink, .post_tree1, .ethereum_geometry);
    try profile.ethereum.mixIntoV2WithCircuitProfileV1(native, &channel, profile.circuitProfile());
    try channel.finish();
    try emitU32(sink, .post_tree1, .authority_header, 0, &.{ 0x5749_5453, 0x3446_5242, profile.format_version, profile.schema_version });
    channel = TaggedChannel(@TypeOf(sink.*)).init(sink, .post_tree1, .bridge_geometry);
    profile.bridge_geometry.mixFieldAuthority(&channel);
    try channel.finish();
}

fn emitAuthorityMetadata(profile: anytype, sink: anytype) !void {
    try emitU32(sink, .pre_tree0, .authority_header, 0, &.{ 0x5749_5453, 0x3446_4c45, profile.format_version, profile.schema_version, @intFromEnum(profile.statement_family), @intFromEnum(profile.boundary_policy) });
    try emitU32(sink, .pre_tree0, .coordinate, 0, &.{ profile.coordinate.segment_index, profile.coordinate.segment_count, profile.continuation_roots.entry, profile.continuation_roots.exit });
    try emitU32(sink, .pre_tree0, .base_geometry, 0, &.{ profile.base_geometry.component_count, profile.base_geometry.infrastructure_count, profile.base_geometry.maximum_column_log_size });
    try emitU32(sink, .pre_tree0, .base_geometry, 1, &profile.base_geometry.compatibility_tree_columns);
    try emitU32(sink, .pre_tree0, .base_geometry, 2, &profile.base_geometry.physical_tree_columns);
}

fn emitProtocol(protocol: anytype, sink: anytype) !void {
    try emitU32(sink, .pre_tree0, .protocol, 0, &protocol.profile_words);
    try emitU32(sink, .pre_tree0, .protocol, 1, &protocol.protocol_id);
    try emitDigest(sink, 2, protocol.proof_security_identity_sha256);
    try emitU32(sink, .pre_tree0, .protocol, 3, &.{ protocol.pcs.pow_bits, protocol.pcs.log_blowup_factor, protocol.pcs.query_count, protocol.pcs.fold_step, protocol.pcs.log_last_layer_degree_bound, protocol.pcs.lifting_mode, protocol.pcs.configured_security_bits });
    try emitDigest(sink, 4, protocol.pcs.identity_sha256);
    try emitDigest(sink, 5, protocol.identity_sha256);
}

fn emitRolePublic(value: anytype, sink: anytype) !void {
    const io = value.io_entries;
    const inputs = std.math.cast(u32, io.input_words.len) orelse return error.EthereumTranscriptFrameTooLarge;
    const outputs = std.math.cast(u32, io.output_words.len) orelse return error.EthereumTranscriptFrameTooLarge;
    try emitU32(sink, .pre_tree0, .role_io_header, 0, &.{ io.input_start, io.input_len, inputs, io.output_len_addr, io.output_data_addr, io.output_len, outputs });
    try emitU32(sink, .pre_tree0, .role_input_words, 0, io.input_words);
    for (io.output_words, 0..) |word, index|
        try emitU32(sink, .pre_tree0, .role_output_word, @intCast(index), &.{ word.addr, word.value, word.clock });
    const completion = value.completion orelse return error.MissingCompletion;
    try emitU32(sink, .pre_tree0, .completion, 0, &.{ @intFromEnum(completion.kind), completion.address, completion.value, completion.clock });
}

fn emitU32(sink: anytype, phase: Phase, kind: Kind, ordinal: u32, words: []const u32) !void {
    try sink.frame(.{ .phase = phase, .kind = kind, .ordinal = ordinal, .payload = .{ .u32_words = words } });
}
fn emitDigest(sink: anytype, ordinal: u32, digest: [32]u8) !void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| word.* = std.mem.readInt(u32, digest[index * 4 ..][0..4], .little);
    try emitU32(sink, .pre_tree0, .protocol, ordinal, &words);
}

/// Existing geometry helpers have void channel methods. Preserve their API and
/// propagate the first sink failure at the end of each bounded helper call.
fn TaggedChannel(comptime Sink: type) type {
    const Return = @typeInfo(@TypeOf(Sink.frame)).@"fn".return_type.?;
    const Error = @typeInfo(Return).error_union.error_set || error{EthereumTranscriptFrameTooLarge};
    return struct {
        sink: *Sink,
        phase: Phase,
        kind: Kind,
        ordinal: u32 = 0,
        failure: ?Error = null,
        fn init(sink: *Sink, phase: Phase, kind: Kind) @This() {
            return .{ .sink = sink, .phase = phase, .kind = kind };
        }
        fn emit(self: *@This(), payload: Payload) void {
            if (self.failure != null) return;
            self.sink.frame(.{ .phase = self.phase, .kind = self.kind, .ordinal = self.ordinal, .payload = payload }) catch |err| {
                self.failure = err;
                return;
            };
            self.ordinal = std.math.add(u32, self.ordinal, 1) catch {
                self.failure = error.EthereumTranscriptFrameTooLarge;
                return;
            };
        }
        fn finish(self: @This()) !void {
            if (self.failure) |err| return err;
        }
        pub fn mixU32s(self: *@This(), words: []const u32) void {
            self.emit(.{ .u32_words = words });
        }
        pub fn mixU64(self: *@This(), value: u64) void {
            self.emit(.{ .u64_value = value });
        }
        pub fn mixFelts(self: *@This(), words: []const QM31) void {
            self.emit(.{ .secure_words = words });
        }
    };
}

const TestSink = struct {
    hash: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
    shape: std.crypto.hash.sha2.Sha256 = std.crypto.hash.sha2.Sha256.init(.{}),
    frame_count: usize = 0,
    fn digest(self: @This()) [32]u8 {
        var hash = self.hash;
        return hash.finalResult();
    }
    fn shapeDigest(self: @This()) [32]u8 {
        var hash = self.shape;
        return hash.finalResult();
    }
    pub fn frame(self: *@This(), value: Frame) !void {
        const header = [_]u32{ @intFromEnum(value.phase), @intFromEnum(value.kind), value.ordinal, @intFromEnum(value.classification()), @intCast(try value.recordedWordCount()) };
        for (header) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            self.hash.update(&bytes);
            self.shape.update(&bytes);
        }
        for (0..try value.recordedWordCount()) |index| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, (try value.recordedWord(index)).toU32(), .little);
            self.hash.update(&bytes);
            switch (value.classification()) {
                .fixed_protocol, .admitted_geometry => self.shape.update(&bytes),
                else => {},
            }
        }
        self.frame_count += 1;
    }
};

test "Ethereum schema4 frame payloads exactly match native recording encodings" {
    const recording = frontend.recursion.recording_poseidon_channel_v4;
    const u32_words = [_]u32{ 0x1234_abcd, 0xffff_ffff };
    const canonical = [_]M31{ M31.fromCanonical(0x1234_abcd), M31.one() };
    const secure = [_]QM31{QM31.fromU32Unchecked(3, 5, 7, 11)};
    const payloads = [_]Payload{ .{ .u32_words = &u32_words }, .{ .canonical_m31 = &canonical }, .{ .secure_words = &secure }, .{ .u64_value = 0x1234_abcd_5678_ef90 } };
    for (payloads) |payload| {
        var channel = recording.Channel.init(std.testing.allocator);
        defer channel.deinit();
        channel.setContextTag(1);
        var sink = NativeSink(recording.Channel){ .channel = &channel };
        const frame = Frame{ .phase = .pre_tree0, .kind = .protocol, .ordinal = 0, .payload = payload };
        try sink.frame(frame);
        var execution = try channel.finish();
        defer execution.deinit();
        try std.testing.expectEqual(@as(usize, 1), execution.operations.len);
        try std.testing.expectEqual(@as(usize, 1), execution.hash_frames.len);
        try execution.validate();
        const words = try recordedOperationPayload(&execution, 0);
        try std.testing.expectEqual(recording.RATE + words.len, execution.hash_frames[0].words.len);
        try frame.validateRecordedOperation(&execution, 0);
        try std.testing.expectError(error.InvalidEthereumTranscriptFrameIndex, frame.recordedWord(words.len));
        try std.testing.expectError(error.InvalidEthereumRecordedOperation, recordedOperationPayload(&execution, 1));
        const wrong = Frame{ .phase = frame.phase, .kind = frame.kind, .ordinal = 0, .payload = .{ .u32_words = &.{0} } };
        try std.testing.expectError(error.EthereumFieldTranscriptPayloadMismatch, wrong.validateRecordedOperation(&execution, 0));
    }
}

test "Ethereum schema4 metadata excludes custody digests and binds coordinate fields" {
    const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
    // Projection-only fixture: this does not mint a validated AuthorityV4.
    var profile: profile_mod.AuthorityV4 = undefined;
    profile.fixed_program = null;
    profile.format_version = 4;
    profile.statement_family = .segment_full_state_v4;
    profile.boundary_policy = .full_state_split_public_input_exit;
    profile.coordinate = .{ .segment_index = 1, .segment_count = 3 };
    profile.continuation_roots = .{ .entry = 13, .exit = 17 };
    profile.base_geometry.component_count = 2;
    profile.base_geometry.infrastructure_count = 3;
    profile.base_geometry.maximum_column_log_size = 12;
    profile.base_geometry.compatibility_tree_columns = .{ 1, 2, 3, 4 };
    profile.base_geometry.physical_tree_columns = .{ 5, 6, 7, 8 };
    var first = TestSink{};
    try emitAuthorityMetadata(&profile, &first);
    profile.boundary_artifact_content_sha256 = .{0xa5} ** 32;
    profile.base_geometry.identity_sha256 = .{0xb6} ** 32;
    profile.ethereum_identity_sha256 = .{0xc7} ** 32;
    profile.public_boundary_identity_sha256 = .{0xd8} ** 32;
    profile.identity_sha256 = .{0xe9} ** 32;
    profile.segment_public_wire_id = .{91} ** 8;
    profile.base_geometry.statement_authority_id = .{93} ** 8;
    var second = TestSink{};
    try emitAuthorityMetadata(&profile, &second);
    try std.testing.expectEqual(first.digest(), second.digest());
    try std.testing.expectEqual(@as(usize, 5), first.frame_count);
    const fields = [_]*u32{ &profile.coordinate.segment_index, &profile.coordinate.segment_count, &profile.continuation_roots.entry, &profile.continuation_roots.exit };
    for (fields) |field| {
        field.* += 1;
        var changed = TestSink{};
        try emitAuthorityMetadata(&profile, &changed);
        try std.testing.expect(!std.mem.eql(u8, &first.digest(), &changed.digest()));
        try std.testing.expectEqual(first.shapeDigest(), changed.shapeDigest());
        field.* -= 1;
    }
    profile.base_geometry.physical_tree_columns[0] += 1;
    var geometry = TestSink{};
    try emitAuthorityMetadata(&profile, &geometry);
    try std.testing.expect(!std.mem.eql(u8, &first.shapeDigest(), &geometry.shapeDigest()));
}

test "Ethereum schema4 explicit public IO and completion bind every data field" {
    const public_data = frontend.air.public_data;
    var inputs = [_]u32{ 0x1234_abcd, 0xdead_beef };
    var outputs = [_]public_data.OutputWord{.{ .addr = 0x1000, .value = 9, .clock = 7 }};
    // Framing fixture only; structural admission remains the caller's boundary.
    var value: public_data.PublicData = undefined;
    value.io_entries = .{ .input_start = 0x2000, .input_len = 8, .input_words = &inputs, .output_len_addr = 0x1000, .output_data_addr = 0x1004, .output_len = 0, .output_words = &outputs };
    value.completion = .{ .kind = .unretired_program_fetch, .address = 0x3000, .value = 0x0000006f, .clock = 0 };
    var first = TestSink{};
    try emitRolePublic(&value, &first);
    try std.testing.expectEqual(@as(usize, 4), first.frame_count);
    const fields = [_]*u32{ &value.io_entries.input_start, &value.io_entries.input_len, &value.io_entries.output_len_addr, &value.io_entries.output_data_addr, &value.io_entries.output_len, &inputs[0], &inputs[1], &outputs[0].addr, &outputs[0].value, &outputs[0].clock, &value.completion.?.address, &value.completion.?.value, &value.completion.?.clock };
    for (fields) |field| {
        field.* ^= 1;
        var changed = TestSink{};
        try emitRolePublic(&value, &changed);
        try std.testing.expect(!std.mem.eql(u8, &first.digest(), &changed.digest()));
        try std.testing.expectEqual(first.shapeDigest(), changed.shapeDigest());
        field.* ^= 1;
    }
    value.completion.?.kind = .unretired_self_loop;
    var kind_changed = TestSink{};
    try emitRolePublic(&value, &kind_changed);
    try std.testing.expect(!std.mem.eql(u8, &first.digest(), &kind_changed.digest()));
    value.completion = null;
    try std.testing.expectError(error.MissingCompletion, emitRolePublic(&value, &kind_changed));
}

test "Ethereum schema4 helper emission propagates sink failure" {
    const Failing = struct {
        calls: usize = 0,
        pub fn frame(self: *@This(), _: Frame) !void {
            self.calls += 1;
            return error.TestFrameRejected;
        }
    };
    var sink = Failing{};
    var channel = TaggedChannel(Failing).init(&sink, .pre_tree0, .protocol);
    channel.mixU32s(&.{1});
    channel.mixU64(2);
    try std.testing.expectError(error.TestFrameRejected, channel.finish());
    try std.testing.expectEqual(@as(usize, 1), sink.calls);
}
