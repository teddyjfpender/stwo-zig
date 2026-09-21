//! Value-independent program for the field-native recursive verifier transcript.
//!
//! Operation order comes from the protocol, manifest and verified proof shape,
//! never from the recorded operations. Payload sources name binding obligations
//! for the parent AIR. In particular, witness-dependent SHA seals are NOT
//! preprocessing constants; their hash computations still require constraints.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const recursion = frontend.recursion;
const recording = recursion.recording_poseidon_channel_v4;
const manifest_mod = recursion.air.universal_adapter_manifest;
const initial_manifest = recursion.air.ethereum_initial_input_manifest_v1;
const public_mod = @import("recursive_common_canonical_empty_field_public_v2.zig");
const ethereum_field = @import("ethereum_wrapper_field_transcript_v1.zig");
pub const EthereumFieldAdmissionV1 = ethereum_field.AdmissionV1;
const protocol_mod = @import("recursive_temporal_secure_parent_protocol_v1.zig");

const shared = recursion.pcs_transcript_program_v1;
pub const Context = shared.Context;
pub const Source = shared.Source;
pub const Draw = shared.Draw;
pub const Operation = shared.Operation;
pub const Error = shared.Error;
pub const PcsShape = shared.PcsShape;
pub const initPcsOperations = shared.initPcsOperations;
pub const appendPcsTranscript = shared.appendPcsTranscript;
const Writer = shared.Writer;
pub const Kind = enum(u8) { canonical_empty = 1, common_fold = 2, ethereum_incremental_field_v1 = 3 };

pub const Program = struct {
    allocator: std.mem.Allocator,
    kind: Kind,
    manifest_seal: [32]u8,
    operations: []Operation,
    identity: [32]u8,

    /// The capture must be admitted by the native verifier before this call.
    /// No capture VALUE enters program identity: only its immutable geometry.
    pub fn init(
        allocator: std.mem.Allocator,
        kind: Kind,
        manifest: *const manifest_mod.Manifest,
        capture: anytype,
    ) !Program {
        if (kind == .ethereum_incremental_field_v1)
            return error.InvalidRecursiveTranscriptProgram;
        return initAdmitted(false, allocator, kind, manifest, capture, null, null);
    }

    /// Explicit field profile; callers must independently admit the session,
    /// whole wrapper key, and geometry before providing this projection.
    pub fn initEthereumFieldV1(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        capture: anytype,
        admission: EthereumFieldAdmissionV1,
    ) !Program {
        return initEthereumFieldFieldsV1(allocator, manifest, capture, try admission.fieldProjection());
    }

    /// Uses only fixed field data from an independently admitted detached key.
    /// The session-based entry point delegates here and preserves its bytes.
    pub fn initEthereumFieldFieldsV1(
        allocator: std.mem.Allocator,
        manifest: *const manifest_mod.Manifest,
        capture: anytype,
        admission: ethereum_field.FieldAdmissionV1,
    ) !Program {
        try admission.validate();
        const ethereum_manifest = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
        var logs: ethereum_manifest.LogSizesV4 = undefined;
        for (manifest.placements, &logs) |placement, *log|
            log.* = (placement orelse return error.InvalidRecursiveTranscriptProgram).geometry.log_size;
        try ethereum_manifest.validateExact(manifest, logs);
        if (capture.commitments.len != 4 or !std.meta.eql(capture.commitments[0], admission.preprocessed_root))
            return error.InvalidRecursiveTranscriptProgram;
        var layout = try recursion.recursion_air_composition_circuit_v3.capture_layout_v3.CaptureLayoutV3.initEthereumWrapperV1(allocator, manifest, capture);
        defer layout.deinit();
        return initAdmitted(false, allocator, .ethereum_incremental_field_v1, manifest, capture, admission, null);
    }

    /// Explicit initial-input profile. The manifest authenticates the ordinary
    /// prefix and both appended typed AIRs; ordinary callers retain 36 claims.
    pub fn initEthereumInitialFieldFieldsV1(
        allocator: std.mem.Allocator,
        manifest: *const initial_manifest.Manifest,
        capture: anytype,
        admission: ethereum_field.FieldAdmissionV1,
    ) !Program {
        try admission.validate();
        try manifest.validate();
        if (capture.commitments.len != 4 or !std.meta.eql(capture.commitments[0], admission.preprocessed_root))
            return error.InvalidRecursiveTranscriptProgram;
        var layout = try recursion.recursion_air_composition_circuit_v3.capture_layout_v3.CaptureLayoutV3.initEthereumInitialWrapperV1(allocator, manifest, capture);
        defer layout.deinit();
        return initAdmitted(true, allocator, .ethereum_incremental_field_v1, manifest, capture, admission, null);
    }

    /// Explicit fixed-root namespace for a fold of admitted Ethereum children.
    /// This projection must come from an independently admitted complete key.
    pub fn initEthereumFoldKeyV1(allocator: std.mem.Allocator, key: *const @import("recursive_common_fold_detached_verifier_v2.zig").EthereumKeyV1, capture: anytype) !Program {
        const fields = try key.sessionFields();
        if (capture.commitments.len != 4 or !std.meta.eql(capture.commitments[0], key.key.preprocessed_root)) return error.InvalidRecursiveTranscriptProgram;
        return initAdmitted(false, allocator, .common_fold, &key.key.manifest, capture, null, fields);
    }

    fn initAdmitted(
        comptime initial: bool,
        allocator: std.mem.Allocator,
        kind: Kind,
        manifest: *const if (initial) initial_manifest.Manifest else manifest_mod.Manifest,
        capture: anytype,
        ethereum_admission: ?ethereum_field.FieldAdmissionV1,
        common_admission: ?ethereum_field.SessionFieldsV1,
    ) !Program {
        if (initial and kind != .ethereum_incremental_field_v1) return error.InvalidRecursiveTranscriptProgram;
        const ordinary_manifest = if (initial) &manifest.ordinary else manifest;
        if (common_admission != null and kind != .common_fold) return error.InvalidRecursiveTranscriptProgram;
        if ((kind == .ethereum_incremental_field_v1) != (ethereum_admission != null))
            return error.InvalidRecursiveTranscriptProgram;
        try manifest.validate();
        if (manifest.roster_count != (if (initial) initial_manifest.COMPONENT_COUNT else manifest_mod.COMPONENT_COUNT) or capture.commitments.len != 4 or
            capture.sampled_values.len == 0 or capture.fri.layers.len == 0 or
            capture.fri.layers.len > 30 or capture.last_layer_coefficients.len == 0 or
            capture.queries.raw.len != 193) return error.InvalidRecursiveTranscriptProgram;
        var list: std.ArrayList(Operation) = .empty;
        errdefer list.deinit(allocator);
        const writer = Writer{ .allocator = allocator, .list = &list };
        if (kind == .canonical_empty) {
            const root = @import("recursive_common_canonical_empty_universal_manifest_v2.zig").PREPROCESSED_ROOT;
            if (!std.meta.eql(capture.commitments[0], root)) return error.InvalidRecursiveTranscriptProgram;
            try writer.mixCanonicalWords(.tree0, .canonical_preprocessed_root, 0, &root);
        } else {
            // The capture is already verified against the admitted child key.
            // Bind that key in parent preprocessing, just as for canonical children.
            try writer.mixCanonicalWords(.tree0, .common_preprocessed_root, 0, &capture.commitments[0]);
        }
        try writer.mix(.tree1, .commitment, 1, 8);
        try writer.mixWords(.manifest, .manifest_header, 0, &manifest.transcriptHeader());
        try writer.mixDigest(.manifest, .manifest_seal, manifest.seal);
        try writer.mixDigest(.manifest, .registry_seal, recursion.air.universal_challenges.registryOrderDigest());
        try writer.mixWords(.authority, .authority_header, 0, if (kind == .canonical_empty)
            &@import("recursive_common_canonical_empty_universal_cohort_v2.zig").AUTHORITY_TRANSCRIPT_HEADER
        else if (kind == .ethereum_incremental_field_v1)
            &ethereum_field.AUTHORITY_HEADER
        else
            &@import("recursive_common_fold_secure_cohort_v2.zig").AUTHORITY_TRANSCRIPT_HEADER);
        try writer.mix(.authority, .statement, 0, 2 * public_mod.AIR_WORD_COUNT);
        const protocol = protocol_mod.AuthorityV1.secureParent();
        const session_mod = @import("recursive_temporal_secure_parent_artifact_v1.zig");
        const session_source: session_mod.SourceKindV1 = if (kind == .common_fold) .common_fold_field_v2 else .canonical_empty_wrapper_v1;
        try writer.mixWords(.session, .session_header, 0, if (kind == .ethereum_incremental_field_v1)
            &try ethereum_field.sessionHeader(protocol)
        else
            &try session_mod.fieldSessionTranscriptHeader(session_source, protocol));
        const keys = if (ethereum_admission) |admission| [_]recursion.poseidon2_channel.Digest{
            admission.session_fields.verification_key_id,
            admission.session_fields.next_parent_vk_id,
            admission.session_fields.air_program_id,
        } else if (common_admission) |admission| [_]recursion.poseidon2_channel.Digest{
            admission.verification_key_id, admission.next_parent_vk_id, admission.air_program_id,
        } else if (kind == .common_fold) blk: {
            const common_manifest = @import("recursive_common_fold_universal_manifest_v2.zig");
            var logs: common_manifest.LogSizes = undefined;
            for (manifest.placements[0..common_manifest.COMPONENT_COUNT], &logs) |placement, *log|
                log.* = (placement orelse return error.InvalidRecursiveTranscriptProgram).geometry.log_size;
            break :blk [_]recursion.poseidon2_channel.Digest{
                try common_manifest.verificationKeyIdForDerivedManifest(ordinary_manifest, logs),
                try common_manifest.nextParentVkIdForDerivedManifest(ordinary_manifest, logs),
                try common_manifest.airProgramIdForDerivedManifest(ordinary_manifest, logs),
            };
        } else blk: {
            const canonical_manifest = @import("recursive_common_canonical_empty_universal_manifest_v2.zig");
            try canonical_manifest.validateExact(ordinary_manifest);
            break :blk [_]recursion.poseidon2_channel.Digest{ try canonical_manifest.verificationKeyId(), try canonical_manifest.nextParentVkId(), try canonical_manifest.airProgramId() };
        };
        for (keys, 0..) |key, index| try writer.mixWords(.session, .session_key, @intCast(index), &key);
        try writer.pow(.interaction_pow, 0, protocol.interaction_pow_bits);
        for (0..recursion.air.universal_challenges.RELATION_COUNT) |i|
            try writer.draw(.relations, .relation, i, 8);
        try writer.mixWords(.claims, .claim_count, 0, &.{manifest.roster_count});
        for (manifest.roster_rows[0..manifest.roster_count]) |row| {
            const geometry = manifest.placements[row].?.geometry;
            try writer.mixWords(.claims, .claim_metadata, row, &.{ row, geometry.log_size, geometry.interaction_columns });
            try writer.mix(.claims, .claim_value, row, 4);
        }
        if (kind == .canonical_empty) {
            try writer.mixWords(.boundary, .canonical_boundary_header, 0, &@import("recursive_common_canonical_empty_universal_cohort_v2.zig").BOUNDARY_TRANSCRIPT_HEADER);
            try writer.mix(.boundary, .canonical_wire_boundary, recursion.recursion_air_composition_circuit_v3.COMPOSITION_CLAIM_INPUT_COUNT, 4);
        } else if (ethereum_admission) |admission| {
            try writer.mixWords(.boundary, .canonical_boundary_header, 0, &try ethereum_field.boundaryHeader(admission.wire_term_count));
            try writer.mix(.boundary, .canonical_wire_boundary, recursion.recursion_air_composition_circuit_v3.COMPOSITION_CLAIM_INPUT_COUNT, 4);
        }
        try writer.mix(.boundary, .provider_partial, recursion.recursion_air_composition_circuit_v3.POSEIDON_AUX_START, 8);
        try writer.mix(.tree2, .commitment, 2, 8);
        try appendPcsTranscript(writer, .{
            .sampled_value_count = capture.sampled_values.len,
            .fri_layer_count = capture.fri.layers.len,
            .last_layer_coefficient_count = capture.last_layer_coefficients.len,
            .query_count = protocol.fri_query_count,
            .pow_bits = protocol.pcs_pow_bits,
        });
        const operations = try list.toOwnedSlice(allocator);
        var result = Program{
            .allocator = allocator,
            .kind = kind,
            .manifest_seal = manifest.seal,
            .operations = operations,
            .identity = undefined,
        };
        result.identity = result.computeIdentity();
        return result;
    }

    pub fn deinit(self: *Program) void {
        self.allocator.free(self.operations);
        self.* = undefined;
    }

    /// Checks exact native frame geometry and draw-counter use. The recorder's
    /// own validation checks values/permutations; neither check substitutes
    /// for the parent AIR's payload, state, PoW and challenge relations.
    pub fn validateRecording(self: *const Program, execution: *const recording.ExecutionV4) !void {
        if (!std.mem.eql(u8, &self.identity, &self.computeIdentity()) or
            self.operations.len != execution.operations.len)
            return error.InvalidRecursiveTranscriptProgram;
        try execution.validate();
        var hash_at: usize = 0;
        var call_at: usize = 0;
        var draw_count: u32 = 0;
        var pow_at: usize = 0;
        for (self.operations, execution.operations) |expected, actual| {
            if (@intFromEnum(expected.context) != actual.context_tag or
                expected.effect != actual.effect or actual.first_hash_id != hash_at or
                actual.first_call_id != call_at)
                return error.InvalidRecursiveTranscriptProgram;
            const is_pow = expected.effect == .pow;
            const hash_count: usize = if (is_pow) 2 else 1;
            if (actual.hash_count != hash_count or hash_at + hash_count > execution.hash_frames.len)
                return error.InvalidRecursiveTranscriptProgram;
            for (0..hash_count) |part| {
                const is_draw = expected.effect == .draw or (is_pow and part == 1);
                const payload: usize = if (is_draw) 2 else expected.payload_words;
                const frame_words = recording.RATE + payload;
                const frame_calls = frame_words / recording.RATE + 1;
                const frame = execution.hash_frames[hash_at];
                if (frame.hash_id != hash_at or frame.first_call_id != call_at or
                    frame.call_count != frame_calls or frame.words.len != frame_words or
                    frame.purpose != @as(recording.HashPurpose, if (is_draw) .draw else .mix))
                    return error.InvalidRecursiveTranscriptProgram;
                if (expected.source.isConstantPayload()) {
                    if (payload > expected.constant_words.len) return error.InvalidRecursiveTranscriptProgram;
                    for (frame.words[recording.RATE..], expected.constant_words[0..payload]) |word, literal|
                        if (word.toU32() != literal) return error.InvalidRecursiveTranscriptProgram;
                }
                if (is_draw) {
                    if (frame.words[recording.RATE].toU32() != (if (is_pow) @as(u32, 0) else draw_count) or
                        frame.words[recording.RATE + 1].toU32() != recursion.poseidon2_channel.DRAW_TAG)
                        return error.InvalidRecursiveTranscriptProgram;
                    if (!is_pow) draw_count += 1;
                } else draw_count = 0;
                hash_at += 1;
                call_at += frame_calls;
            }
            if (is_pow) {
                if (actual.pow_check_index != @as(?u32, @intCast(pow_at)) or
                    pow_at >= execution.pow_checks.len or
                    execution.pow_checks[pow_at].bits != expected.pow_bits)
                    return error.InvalidRecursiveTranscriptProgram;
                pow_at += 1;
            } else if (actual.pow_check_index != null) return error.InvalidRecursiveTranscriptProgram;
        }
        if (hash_at != execution.hash_frames.len or call_at != execution.poseidon_calls.len or
            pow_at != execution.pow_checks.len or draw_count != execution.final_draw_count)
            return error.InvalidRecursiveTranscriptProgram;
    }

    fn computeIdentity(self: *const Program) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/recursive-secure-transcript-program/v1\x00");
        hash.update(&self.manifest_seal);
        hashInt(&hash, @intFromEnum(self.kind));
        hashInt(&hash, self.operations.len);
        for (self.operations) |op| {
            hashInt(&hash, @intFromEnum(op.context));
            hashInt(&hash, @intFromEnum(op.effect));
            hashInt(&hash, op.payload_words);
            hashInt(&hash, @intFromEnum(op.source));
            hashInt(&hash, op.item);
            hashInt(&hash, @intFromEnum(op.draw));
            hashInt(&hash, op.draw_word_count);
            hashInt(&hash, op.pow_bits);
            for (op.constant_words) |word| hashInt(&hash, word);
        }
        return hash.finalResult();
    }
};

fn hashInt(hash: anytype, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .little);
    hash.update(&bytes);
}

/// Genuine replay-gate check, invoked only after native verification has
/// admitted the caller's metadata. A legacy wrapper supplies real geometry and
/// keys here; this projection check does not turn it into a field-profile proof.
/// Keeping this helper with the program lets the retained-proof test exercise
/// its public constructor without copying a large proof fixture or its keys.
pub fn testEthereumFieldProgramFromVerifiedMetadata(
    allocator: std.mem.Allocator,
    manifest: *const manifest_mod.Manifest,
    capture: anytype,
    session: *const @import("recursive_temporal_secure_parent_artifact_v1.zig").SessionV1,
    wire_term_count: u32,
) !void {
    if (!@import("builtin").is_test)
        @compileError("Ethereum field program projection check is test-only");
    try std.testing.expectEqual(@as(usize, 4), capture.commitments.len);
    const admission = EthereumFieldAdmissionV1{
        .session = session,
        .preprocessed_root = capture.commitments[0],
        .wire_term_count = wire_term_count,
    };
    var program = try Program.initEthereumFieldV1(allocator, manifest, capture, admission);
    defer program.deinit();
    try std.testing.expectEqual(Kind.ethereum_incremental_field_v1, program.kind);

    // The independently admitted key must match Tree0. Change the admission,
    // never the retained capture's mutable nested storage.
    var wrong_root = admission;
    wrong_root.preprocessed_root[0] = (wrong_root.preprocessed_root[0] + 1) % @import("stwo_core").fields.m31.Modulus;
    try std.testing.expectError(error.InvalidRecursiveTranscriptProgram, Program.initEthereumFieldV1(
        allocator,
        manifest,
        capture,
        wrong_root,
    ));

    // A changed sample is not a newly verified proof. It is a shape-preserving
    // input to this constructor, whose identity must describe the circuit's
    // source obligations rather than the observed sample values.
    var changed_capture = capture.*;
    changed_capture.sampled_values = try allocator.dupe(@import("stwo_core").fields.qm31.QM31, capture.sampled_values);
    defer allocator.free(changed_capture.sampled_values);
    changed_capture.sampled_values[0] = changed_capture.sampled_values[0].add(@import("stwo_core").fields.qm31.QM31.one());
    var changed_program = try Program.initEthereumFieldV1(allocator, manifest, &changed_capture, admission);
    defer changed_program.deinit();
    try std.testing.expectEqualSlices(u8, &program.identity, &changed_program.identity);

    // Compare the actual public constructor's session schedule with the native
    // emitter. These four operations are selected, not independently authored.
    var session_operations: [4]Operation = undefined;
    var count: usize = 0;
    var has_sample_source = false;
    for (program.operations) |operation| {
        if (operation.source == .sampled_values) has_sample_source = true;
        try std.testing.expect(operation.source != .session_seal and operation.source != .claim_seal);
        if (operation.context != .session) continue;
        try std.testing.expect(count < session_operations.len);
        session_operations[count] = operation;
        count += 1;
    }
    try std.testing.expect(has_sample_source);
    try std.testing.expectEqual(session_operations.len, count);
    var session_program = Program{
        .allocator = allocator,
        .kind = program.kind,
        .manifest_seal = manifest.seal,
        .operations = &session_operations,
        .identity = undefined,
    };
    // Stack-borrowed operations: this scoped projection owns no allocation.
    session_program.identity = session_program.computeIdentity();
    var channel = recording.Channel.init(allocator);
    defer channel.deinit();
    channel.setContextTag(@intFromEnum(Context.session));
    try ethereum_field.mixSession(&channel, admission);
    var execution = try channel.finish();
    defer execution.deinit();
    try session_program.validateRecording(&execution);
    session_operations[1].constant_words[0] ^= 1;
    session_program.identity = session_program.computeIdentity();
    try std.testing.expectError(error.InvalidRecursiveTranscriptProgram, session_program.validateRecording(&execution));
}

test "Ethereum field transcript native emitters match explicit program frames" {
    const core = @import("stwo_core");
    const Q = core.fields.qm31.QM31;
    const allocator = std.testing.allocator;
    const session = try ethereumFieldTestSession();
    const admission = EthereumFieldAdmissionV1{ .session = &session, .preprocessed_root = [_]u32{7} ** 8, .wire_term_count = 11 };
    const ethereum_manifest = @import("recursive_common_ethereum_incremental_leaf_universal_manifest_v4.zig");
    var logs = [_]u32{4} ** 36;
    logs[34] = ethereum_manifest.MINIMUM_PROVIDER_LOG_SIZE;
    logs[35] = ethereum_manifest.RANGE_LOG_SIZE;
    const manifest = try ethereum_manifest.buildForDerivedLogSizes(logs);
    var claims = try manifest_mod.ClaimVector.init(&manifest);
    for (manifest.roster_rows[0..manifest.roster_count]) |row|
        try claims.bind(@enumFromInt(row), Q.fromBase(core.fields.m31.M31.fromCanonical(row + 1)));
    try claims.sealClaims(&manifest);
    const Audited = struct {
        wire_boundary: struct { tuple_count: u32, claimed_sum: Q },
        verifier_input_boundary: struct { tuple_count: u32, claimed_sum: Q },
        // This is a protocol encoding projection fixture, not a closure receipt.
        pub fn validate(_: *const @This()) !void {}
    };
    const audited = Audited{ .wire_boundary = .{ .tuple_count = 11, .claimed_sum = Q.one() }, .verifier_input_boundary = .{ .tuple_count = 0, .claimed_sum = Q.zero() } };
    const partials = [_]Q{ Q.fromU32Unchecked(2, 3, 4, 5), Q.fromU32Unchecked(6, 7, 8, 9) };
    const node_mod = @import("recursive_field_node_public_v2.zig");
    const coordinate = try @import("recursive_node_artifact_v1.zig").TaskCoordinateV1.init(0, 0);
    var body: [node_mod.STATEMENT_WORD_COUNT]u32 = undefined;
    for (&body, session.parent_statement_words) |*word, value| word.* = value.toU32();
    const node = try node_mod.NodePublicV2.initLeaf(coordinate, body, [_]u32{9} ** 8);
    const public_words = try node.canonicalAirWords();
    var channel = recording.Channel.init(allocator);
    defer channel.deinit();
    channel.setContextTag(@intFromEnum(Context.authority));
    try ethereum_field.mixAuthority(&channel, &public_words);
    channel.setContextTag(@intFromEnum(Context.session));
    try ethereum_field.mixSession(&channel, admission);
    channel.setContextTag(@intFromEnum(Context.claims));
    try ethereum_field.mixClaims(&channel, &manifest, &claims);
    channel.setContextTag(@intFromEnum(Context.boundary));
    try ethereum_field.mixBoundary(&channel, admission, &audited, &partials);
    var execution = try channel.finish();
    defer execution.deinit();

    var list: std.ArrayList(Operation) = .empty;
    defer list.deinit(allocator);
    const writer = Writer{ .allocator = allocator, .list = &list };
    try writer.mixWords(.authority, .authority_header, 0, &ethereum_field.AUTHORITY_HEADER);
    try writer.mix(.authority, .statement, 0, 2 * node_mod.AIR_WORD_COUNT);
    try writer.mixWords(.session, .session_header, 0, &try ethereum_field.sessionHeader(session.protocol));
    for ([_]recursion.poseidon2_channel.Digest{ session.verification_key_id, session.next_parent_vk_id, session.air_program_id }, 0..) |key, index|
        try writer.mixWords(.session, .session_key, index, &key);
    try writer.mixWords(.claims, .claim_count, 0, &.{manifest.roster_count});
    for (manifest.roster_rows[0..manifest.roster_count]) |row| {
        const geometry = manifest.placements[row].?.geometry;
        try writer.mixWords(.claims, .claim_metadata, row, &.{ row, geometry.log_size, geometry.interaction_columns });
        try writer.mix(.claims, .claim_value, row, 4);
    }
    try writer.mixWords(.boundary, .canonical_boundary_header, 0, &try ethereum_field.boundaryHeader(admission.wire_term_count));
    try writer.mix(.boundary, .canonical_wire_boundary, recursion.recursion_air_composition_circuit_v3.COMPOSITION_CLAIM_INPUT_COUNT, 4);
    try writer.mix(.boundary, .provider_partial, recursion.recursion_air_composition_circuit_v3.POSEIDON_AUX_START, 8);
    var program = Program{ .allocator = allocator, .kind = .ethereum_incremental_field_v1, .manifest_seal = manifest.seal, .operations = try list.toOwnedSlice(allocator), .identity = undefined };
    defer program.deinit();
    program.identity = program.computeIdentity();
    try program.validateRecording(&execution);
    const provider_operation = execution.operations[execution.operations.len - 1];
    const provider_words = execution.hash_frames[provider_operation.first_hash_id].words[recording.RATE..];
    try std.testing.expectEqual(@as(usize, 8), provider_words.len);
    for (partials, 0..) |partial, item| for (partial.toM31Array(), 0..) |word, limb| {
        try std.testing.expectEqual(word, provider_words[item * 4 + limb]);
    };
    const public_operation = execution.operations[1];
    const published_limbs = execution.hash_frames[public_operation.first_hash_id].words[recording.RATE..];
    for (public_words, 0..) |word, index| {
        try std.testing.expectEqual(word & 0xffff, published_limbs[2 * index].toU32());
        try std.testing.expectEqual(word >> 16, published_limbs[2 * index + 1].toU32());
    }
    for (program.operations) |operation| {
        try std.testing.expect(operation.source != .session_seal and operation.source != .claim_seal);
    }
    // Fixed key/header mismatches reject even if the caller reseals its local
    // program storage; they must match the actual native transcript words.
    program.operations[3].constant_words[0] ^= 1;
    program.identity = program.computeIdentity();
    try std.testing.expectError(error.InvalidRecursiveTranscriptProgram, program.validateRecording(&execution));
    var wrong = admission;
    wrong.wire_term_count += 1;
    try std.testing.expectError(error.InvalidEthereumFieldTranscriptAdmissionV1, ethereum_field.mixBoundary(&channel, wrong, &audited, &partials));
    var nonzero = audited;
    nonzero.verifier_input_boundary.claimed_sum = Q.one();
    try std.testing.expectError(error.InvalidEthereumFieldTranscriptAdmissionV1, ethereum_field.mixBoundary(&channel, admission, &nonzero, &partials));
}

test "Ethereum field transcript requires explicit admission and preserves legacy kind tags" {
    const session = try ethereumFieldTestSession();
    const admission = EthereumFieldAdmissionV1{ .session = &session, .preprocessed_root = [_]u32{7} ** 8, .wire_term_count = 11 };
    try admission.validate();
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(Kind.canonical_empty));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(Kind.common_fold));
    const capture = std.mem.zeroes(@import("recursive_common_wrapper_authority_v2.zig").ProofCapture);
    const manifest = std.mem.zeroes(manifest_mod.Manifest);
    try std.testing.expectError(error.InvalidRecursiveTranscriptProgram, Program.init(std.testing.allocator, .ethereum_incremental_field_v1, &manifest, &capture));
    var unsupported = admission;
    unsupported.wire_term_count = 0;
    try std.testing.expectError(error.InvalidEthereumFieldTranscriptAdmissionV1, Program.initEthereumFieldV1(std.testing.allocator, &manifest, &capture, unsupported));
    try std.testing.expect(!std.meta.eql(try ethereum_field.sessionHeader(session.protocol), @import("recursive_temporal_secure_parent_artifact_v1.zig").sessionTranscriptHeader(session.protocol)));
}

fn ethereumFieldTestSession() !@import("recursive_temporal_secure_parent_artifact_v1.zig").SessionV1 {
    const span = recursion.span_statement;
    const digest = [_]u32{1} ** 8;
    const initial = try span.MachineState.init(0, [_]u32{0} ** 32, digest, digest);
    const final = try span.MachineState.init(4, [_]u32{0} ** 32, digest, digest);
    const complete = try span.CompleteExecution.init(recursion.protocol.PROTOCOL_ID_WORDS, digest, initial, final, digest, digest, 8);
    const job = try span.JobContext.init(complete, 1);
    const executed = try span.ExecutedSpan.init(0, 1, 0, 8, initial, final, try span.EdgeClaim.present(digest), try span.EdgeClaim.present(digest));
    const statement = try span.SpanStatement.segmentLeaf(job, 0, executed);
    return @import("recursive_temporal_secure_parent_artifact_v1.zig").SessionV1.initEthereumIncrementalLeafWrapperV4(.{
        .ingress_identity_sha256 = [_]u8{1} ** 32,
        .parent_statement_words = try statement.canonicalWords(),
        .profile_identity_sha256 = [_]u8{2} ** 32,
        .child_composition_manifest_sha256 = [_]u8{3} ** 32,
        .parent_outer_manifest_sha256 = [_]u8{4} ** 32,
        .verification_key_id = [_]u32{5} ** 8,
        .next_parent_vk_id = [_]u32{6} ** 8,
        .air_program_id = [_]u32{7} ** 8,
    });
}
