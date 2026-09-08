//! Verifier-owned program for the role-0 Stage101 Poseidon replay.
//!
//! The ordinary SegmentV2 transcript program cannot describe the joined
//! Ethereum+incremental transcript. This owner reclassifies every operation
//! from the successful Stage101 cold verifier and binds it to the exact VM
//! verifier-plan step. Schema4 uses the shared emitter's exhaustive word
//! classifications: protocol/geometry in preprocessing, semantic source
//! comparisons in AIR, and auxiliary V2 provenance as private hash inputs.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4_support.zig");
const types =
    @import("recursive_common_ethereum_incremental_leaf_transcript_program_types_v4.zig");
const native_tree0 = @import("ethereum_native_tree0_admission_v1.zig");
const field_transcript = @import("ethereum_incremental_field_transcript_v4.zig");

const recording = frontend.recursion.recording_poseidon_channel_v4;
const schedule = frontend.recursion.air.verifier_schedule;

pub const FORMAT_VERSION = types.FORMAT_VERSION;
pub const SCHEMA_VERSION = types.SCHEMA_VERSION;
pub const FIELD_EXECUTION_PROFILE_VERSION = types.FIELD_EXECUTION_PROFILE_VERSION;
pub const RAW_V2_DOCUMENT_VALIDITY_PROVEN = types.RAW_V2_DOCUMENT_VALIDITY_PROVEN;
pub const EXTERNAL_SESSION_BINDINGS_ESTABLISHED = types.EXTERNAL_SESSION_BINDINGS_ESTABLISHED;
pub const CONTEXT_COUNT = types.CONTEXT_COUNT;
pub const BASE_STATEMENT_WIRE_OFFSET = types.BASE_STATEMENT_WIRE_OFFSET;
pub const BASE_STATEMENT_WORD_COUNT = types.BASE_STATEMENT_WORD_COUNT;
pub const TRANSCRIPT_CLAIM_COUNT = types.TRANSCRIPT_CLAIM_COUNT;
pub const RELATION_DRAW_COUNT = types.RELATION_DRAW_COUNT;
pub const RELATION_CHALLENGE_COUNT = types.RELATION_CHALLENGE_COUNT;
pub const QUERY_WORD_COUNT = types.QUERY_WORD_COUNT;
pub const PROGRAM_AUTHORITY_AVAILABLE = types.PROGRAM_AUTHORITY_AVAILABLE;
pub const DIGEST_ONLY_CONSTRUCTION = types.DIGEST_ONLY_CONSTRUCTION;
pub const PRODUCTION_ACTIVATION = types.PRODUCTION_ACTIVATION;
pub const Error = types.Error;
pub const InputKindV4 = types.InputKindV4;
pub const ContextRangeV4 = types.ContextRangeV4;
pub const StatementSpanV4 = types.StatementSpanV4;
pub const PayloadBindingV4 = types.PayloadBindingV4;
pub const DrawBindingV4 = types.DrawBindingV4;
pub const OperationV4 = types.OperationV4;
pub const PayloadMetadataV4 = types.PayloadMetadataV4;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-transcript-program/v4-schema9\x00";

/// Proof-entry policy checked after the enclosing materialized input has
/// passed validation. Legacy replay remains available for closure diagnostics;
/// it cannot satisfy admission for a new independently verified wrapper.
/// This policy check does not replace native profile or proof validation.
pub fn requireFieldBaseClaimAdmission(profile: *const @import("ethereum_incremental_full_leaf_profile_v4.zig").AuthorityV4) !void {
    _ = try profile.claimAdmission();
    if (!profile.usesFieldTranscript())
        return error.EthereumFieldBaseClaimAdmissionRequired;
}

/// Owned expansion with an immutable shared frame plan. `validateAgainst` reclassifies every native
/// operation from the live cold-verifier capture; its SHA identity is custody
/// evidence only and cannot mint this value.
pub const ProgramAuthorityV4 = struct {
    allocator: std.mem.Allocator,
    format_version: u16 = FORMAT_VERSION,
    schema_version: u16 = SCHEMA_VERSION,
    stage101_identity_sha256: [32]u8,
    replay_identity_sha256: [32]u8,
    vm_plan_identity: recording.Digest,
    recursion_plan_identity: recording.Digest,
    contexts: [CONTEXT_COUNT]ContextRangeV4,
    operations: []const OperationV4,
    field_plan: ?*support.field_frames.OwnedPlan = null,
    native_tree0_admission: ?*native_tree0.NativeTree0AdmissionV1 = null,
    identity_sha256: [32]u8,

    pub fn init(
        comptime Engine: type,
        allocator: std.mem.Allocator,
        captured: *const campaign_materializer
            .PreparedOwnedCampaignCaptureV4(Engine),
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) !ProgramAuthorityV4 {
        try captured.validate();
        const derived = try support.derive(
            Engine,
            allocator,
            captured,
            vm_plan,
            recursion_plan,
        );
        errdefer allocator.free(derived.operations);
        errdefer if (derived.field_plan) |plan| plan.deinit();
        const capture = &captured.base.input.stage101;
        const tree0: ?*native_tree0.NativeTree0AdmissionV1 = if (derived.field_plan != null)
            if (captured.base.input.fixed_program) |program|
                try native_tree0.NativeTree0AdmissionV1.createWithProgram(Engine, allocator, &capture.statement.core, &capture.profile.ethereum, &capture.profile.bridge_geometry, try capture.profile.pcsConfig(), program)
            else
                try native_tree0.NativeTree0AdmissionV1.create(Engine, allocator, &capture.statement.core, &capture.profile.ethereum, &capture.profile.bridge_geometry, try capture.profile.pcsConfig())
        else
            null;
        errdefer if (tree0) |admission| admission.deinit();
        var result = ProgramAuthorityV4{
            .allocator = allocator,
            .stage101_identity_sha256 = captured.base.input.stage101.identity_sha256,
            .replay_identity_sha256 = captured.base.transcript.identity_sha256,
            .vm_plan_identity = vm_plan.authority_digest,
            .recursion_plan_identity = recursion_plan.authority_digest,
            .contexts = derived.contexts,
            .operations = derived.operations,
            .field_plan = derived.field_plan,
            .native_tree0_admission = tree0,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity(&result);
        // Source admission and operation classification completed above. Finalize
        // these owned values without re-admitting the source and deriving the
        // same program again. The public validator still independently derives
        // and compares caller-supplied program state.
        try result.validateNativeTree0(Engine, captured);
        try result.validateDerived(
            captured.base.input.stage101.identity_sha256,
            captured.base.transcript.identity_sha256,
            vm_plan.authority_digest,
            recursion_plan.authority_digest,
            derived,
        );
        return result;
    }

    pub fn deinit(self: *ProgramAuthorityV4) void {
        if (self.native_tree0_admission) |admission| admission.deinit();
        if (self.field_plan) |plan| plan.deinit();
        self.allocator.free(self.operations);
        self.* = undefined;
    }

    pub fn validateAgainst(
        self: *const ProgramAuthorityV4,
        comptime Engine: type,
        captured: *const campaign_materializer
            .PreparedOwnedCampaignCaptureV4(Engine),
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) !void {
        try captured.validate();
        try self.validateAgainstPreparedSource(Engine, captured, vm_plan, recursion_plan);
    }

    /// Local classification check after the enclosing boundary has validated
    /// `captured`. This still replays and compares every operation, including
    /// the replay/input binding. It does not authenticate the campaign owner.
    pub fn validateAgainstPreparedSource(
        self: *const ProgramAuthorityV4,
        comptime Engine: type,
        captured: *const campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine),
        vm_plan: *const schedule.Plan,
        recursion_plan: *const schedule.Plan,
    ) !void {
        try self.validateNativeTree0(Engine, captured);
        const expected = try support.derive(
            Engine,
            self.allocator,
            captured,
            vm_plan,
            recursion_plan,
        );
        defer self.allocator.free(expected.operations);
        defer if (expected.field_plan) |plan| plan.deinit();
        try self.validateDerived(
            captured.base.input.stage101.identity_sha256,
            captured.base.transcript.identity_sha256,
            vm_plan.authority_digest,
            recursion_plan.authority_digest,
            expected,
        );
    }

    fn validateNativeTree0(
        self: *const ProgramAuthorityV4,
        comptime Engine: type,
        captured: *const campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine),
    ) !void {
        const capture = &captured.base.input.stage101;
        const field_profile = capture.profile.usesFieldTranscript();
        if (field_profile != (self.native_tree0_admission != null))
            return error.EthereumIncrementalTranscriptProgramMismatchV4;
        if (self.native_tree0_admission) |admission| {
            if (captured.base.input.fixed_program) |program|
                try admission.validateShapeWithProgram(&capture.statement.core, &capture.profile.ethereum, &capture.profile.bridge_geometry, try capture.profile.pcsConfig(), program)
            else
                try admission.validateShape(&capture.statement.core, &capture.profile.ethereum, &capture.profile.bridge_geometry, try capture.profile.pcsConfig());
            try validateRecordedTree0(self.operations, &captured.base.transcript.execution, admission.root());
        }
    }

    fn validateDerived(
        self: *const ProgramAuthorityV4,
        stage101_identity: [32]u8,
        replay_identity: [32]u8,
        vm_plan_identity: recording.Digest,
        recursion_plan_identity: recording.Digest,
        expected: support.DerivedV4,
    ) !void {
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.eql(
                u8,
                &self.stage101_identity_sha256,
                &stage101_identity,
            ) or !std.mem.eql(
            u8,
            &self.replay_identity_sha256,
            &replay_identity,
        ) or !std.meta.eql(self.vm_plan_identity, vm_plan_identity) or
            !std.meta.eql(
                self.recursion_plan_identity,
                recursion_plan_identity,
            ) or !std.meta.eql(self.contexts, expected.contexts) or
            !operationsEql(self.operations, expected.operations) or
            !fieldPlansEql(self.field_plan, expected.field_plan) or
            !std.mem.eql(u8, &self.identity_sha256, &identity(self)))
        {
            return error.EthereumIncrementalTranscriptProgramMismatchV4;
        }
    }

    pub fn payloadMetadata(
        self: *const ProgramAuthorityV4,
        operation_index: usize,
        payload_index: u32,
    ) Error!PayloadMetadataV4 {
        if (operation_index >= self.operations.len)
            return error.EthereumIncrementalTranscriptProgramMismatchV4;
        if (self.operations[operation_index].payload == .field_frame) {
            const plan = self.field_plan orelse return error.EthereumIncrementalTranscriptProgramMismatchV4;
            return support.fieldMetadata(plan, self.operations[operation_index].payload.field_frame, payload_index);
        }
        var metadata = try support.metadata(self.operations[operation_index], payload_index);
        if (self.native_tree0_admission) |admission| {
            if (metadata.source_kind == .commitment and metadata.item_index == 0)
                metadata = try fixedTree0Metadata(metadata, admission.root(), payload_index);
        }
        return metadata;
    }
};

fn fixedTree0Metadata(metadata: PayloadMetadataV4, root: *const [8]u32, payload_index: u32) Error!PayloadMetadataV4 {
    if (payload_index >= root.len) return error.EthereumIncrementalTranscriptProgramMismatchV4;
    var result = metadata;
    result.constant_mask = 1;
    result.expected_constant = root[payload_index];
    return result;
}

fn validateRecordedTree0(operations: []const OperationV4, execution: *const recording.ExecutionV4, root: *const [8]u32) !void {
    var found = false;
    for (operations, 0..) |operation, index| {
        if (operation.payload != .commitment or operation.payload.commitment != 0) continue;
        if (found) return error.EthereumIncrementalTranscriptProgramMismatchV4;
        found = true;
        const payload = try field_transcript.recordedOperationPayload(execution, index);
        if (payload.len != root.len) return error.EthereumIncrementalTranscriptProgramMismatchV4;
        for (payload, root) |actual, expected| if (actual.toU32() != expected)
            return error.EthereumIncrementalTranscriptProgramMismatchV4;
    }
    if (!found) return error.EthereumIncrementalTranscriptProgramMismatchV4;
}

fn fieldPlansEql(left: ?*const support.field_frames.OwnedPlan, right: ?*const support.field_frames.OwnedPlan) bool {
    if ((left == null) != (right == null)) return false;
    if (left) |lhs| return std.meta.eql(lhs.shapeIdentity(), right.?.shapeIdentity()) and
        std.meta.eql(lhs.custodyIdentity(), right.?.custodyIdentity());
    return true;
}

fn operationsEql(left: []const OperationV4, right: []const OperationV4) bool {
    if (left.len != right.len) return false;
    for (left, right) |lhs, rhs| if (!std.meta.eql(lhs, rhs)) return false;
    return true;
}

fn identity(value: *const ProgramAuthorityV4) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(IDENTITY_DOMAIN);
    hashInt(&hash, u16, value.format_version);
    hashInt(&hash, u16, value.schema_version);
    hash.update(&value.stage101_identity_sha256);
    hash.update(&value.replay_identity_sha256);
    for (value.vm_plan_identity) |word| hashInt(&hash, u32, word);
    for (value.recursion_plan_identity) |word| hashInt(&hash, u32, word);
    for (value.contexts) |range| {
        hashInt(&hash, u32, range.first);
        hashInt(&hash, u32, range.count);
    }
    hashInt(&hash, u32, value.operations.len);
    for (value.operations) |operation| hashOperation(&hash, operation);
    // Field plans add both immutable structure and witness custody; only the
    // former may enter verifier preprocessing.
    if (value.field_plan) |plan| {
        hashInt(&hash, u32, FIELD_EXECUTION_PROFILE_VERSION);
        hash.update(&plan.shapeIdentity());
        hash.update(&plan.custodyIdentity());
    }
    if (value.native_tree0_admission) |admission| {
        hash.update(&admission.shapeIdentity());
        for (admission.root()) |word| hashInt(&hash, u32, word);
    }
    return hash.finalResult();
}

fn hashOperation(hash: anytype, operation: OperationV4) void {
    hashInt(hash, u32, operation.recording_index);
    hashInt(hash, u32, @intFromEnum(operation.context));
    hashInt(hash, u32, operation.context_ordinal);
    hashInt(hash, u8, @intFromEnum(operation.effect));
    hashInt(hash, u32, operation.verifier_sequence);
    hashInt(hash, u32, operation.tag);
    for (operation.args) |arg| hashInt(hash, u32, arg);
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(operation.payload)));
    switch (operation.payload) {
        .none, .constant, .interaction_pow_nonce, .pcs_pow_nonce => {},
        .statement_span => |span| {
            hashInt(hash, u32, span.wire_offset);
            hashInt(hash, u32, span.word_count);
        },
        .native_publication => |field| hashInt(hash, u8, @intFromEnum(field)),
        .detailed_claims => |claims| {
            hashInt(hash, u32, claims.first_claim);
            hashInt(hash, u32, claims.claim_count);
        },
        .commitment,
        .transcript_claimed_sum,
        .sampled_values,
        .fri_commitment,
        .last_layer_coefficients,
        .field_frame,
        => |item| hashInt(hash, u32, item),
    }
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(operation.draw)));
    switch (operation.draw) {
        .none, .composition, .oods, .deep => {},
        .relation_challenge => |challenge| hashInt(hash, u32, challenge),
        .fri_alpha => |layer| hashInt(hash, u32, layer),
        .query_block => |draw| {
            hashInt(hash, u32, draw.block);
            hashInt(hash, u32, draw.first_word);
            hashInt(hash, u32, draw.word_count);
        },
    }
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

test "role0 secure wrapper policy requires field base claim admission" {
    const profile_mod = @import("ethereum_incremental_full_leaf_profile_v4.zig");
    // Policy reads only the already-validated profile's version. Full profile
    // and native proof validation remain mandatory at the enclosing boundary.
    var profile: profile_mod.AuthorityV4 = undefined;
    profile.schema_version = @intFromEnum(profile_mod.ClaimAdmissionV4.legacy_aggregate_v2);
    try std.testing.expectError(error.EthereumFieldBaseClaimAdmissionRequired, requireFieldBaseClaimAdmission(&profile));
    profile.schema_version = @intFromEnum(profile_mod.ClaimAdmissionV4.selected_detailed_v3);
    try std.testing.expectError(error.EthereumFieldBaseClaimAdmissionRequired, requireFieldBaseClaimAdmission(&profile));
    profile.schema_version = @intFromEnum(profile_mod.ClaimAdmissionV4.field_authority_v4);
    try requireFieldBaseClaimAdmission(&profile);
    profile.schema_version = @intFromEnum(profile_mod.ClaimAdmissionV4.fixed_program_narrow_v5);
    try requireFieldBaseClaimAdmission(&profile);
    profile.schema_version = 99;
    try std.testing.expectError(error.InvalidIncrementalEthereumLeafAuthorityV4, requireFieldBaseClaimAdmission(&profile));
}

test "Ethereum transcript prepared program keeps immutable operations and rejects resealed changes" {
    try std.testing.expect(@typeInfo(@FieldType(ProgramAuthorityV4, "operations")).pointer.is_const);
    const expected_operations = [_]OperationV4{.{
        .recording_index = 0,
        .context = .profile_pre_tree0,
        .context_ordinal = 0,
        .effect = .mix,
        .verifier_sequence = 1,
        .tag = 2,
        .args = .{ 3, 4, 5, 6 },
        .payload = .{ .statement_span = .{ .wire_offset = 60, .word_count = 412 } },
        .draw = .none,
    }};
    const operations = try std.testing.allocator.dupe(OperationV4, &expected_operations);
    const contexts = [_]ContextRangeV4{.{ .first = 0, .count = 1 }} ** CONTEXT_COUNT;
    var value: ProgramAuthorityV4 = .{
        .allocator = std.testing.allocator,
        .stage101_identity_sha256 = [_]u8{1} ** 32,
        .replay_identity_sha256 = [_]u8{2} ** 32,
        .vm_plan_identity = [_]u32{3} ** 8,
        .recursion_plan_identity = [_]u32{4} ** 8,
        .contexts = contexts,
        .operations = operations,
        .identity_sha256 = undefined,
    };
    defer value.deinit();
    value.identity_sha256 = identity(&value);
    // The mutable fixture copy is deliberately retained only in the test;
    // borrowed production views expose no mutable alias to this allocation.
    var expected_storage = expected_operations;
    const expected: support.DerivedV4 = .{ .contexts = contexts, .operations = &expected_storage };
    try value.validateDerived([_]u8{1} ** 32, [_]u8{2} ** 32, [_]u32{3} ** 8, [_]u32{4} ** 8, expected);
    const failure = error.EthereumIncrementalTranscriptProgramMismatchV4;
    operations[0].payload.statement_span.wire_offset += 1;
    value.identity_sha256 = identity(&value);
    try std.testing.expectError(failure, value.validateDerived([_]u8{1} ** 32, [_]u8{2} ** 32, [_]u32{3} ** 8, [_]u32{4} ** 8, expected));
    operations[0] = expected_operations[0];
    operations[0].verifier_sequence += 1;
    value.identity_sha256 = identity(&value);
    try std.testing.expectError(failure, value.validateDerived([_]u8{1} ** 32, [_]u8{2} ** 32, [_]u32{3} ** 8, [_]u32{4} ** 8, expected));
    operations[0] = expected_operations[0];
    value.identity_sha256 = identity(&value);
    try std.testing.expectError(failure, value.validateDerived([_]u8{9} ** 32, [_]u8{2} ** 32, [_]u32{3} ** 8, [_]u32{4} ** 8, expected));
    try std.testing.expectError(failure, value.validateDerived([_]u8{1} ** 32, [_]u8{9} ** 32, [_]u32{3} ** 8, [_]u32{4} ** 8, expected));
    try std.testing.expectError(failure, value.validateDerived([_]u8{1} ** 32, [_]u8{2} ** 32, [_]u32{9} ** 8, [_]u32{4} ** 8, expected));
    try std.testing.expectError(failure, value.validateDerived([_]u8{1} ** 32, [_]u8{2} ** 32, [_]u32{3} ** 8, [_]u32{9} ** 8, expected));
}

test "Ethereum native Tree0 transcript pin rejects changed commitments and preserves source uses" {
    const M31 = @import("stwo_core").fields.m31.M31;
    const root = [_]u32{ 11, 22, 33, 44, 55, 66, 77, 88 };
    const operation = OperationV4{
        .recording_index = 0,
        .context = .tree0_commitment,
        .context_ordinal = 0,
        .effect = .mix,
        .verifier_sequence = 0,
        .tag = 0,
        .args = .{ 0, 0, 0, 0 },
        .payload = .{ .commitment = 0 },
        .draw = .none,
    };
    var words: [8]M31 = undefined;
    for (&words, root) |*word, value| word.* = M31.fromCanonical(value);
    var channel = recording.Channel.init(std.testing.allocator);
    defer channel.deinit();
    channel.mixCanonicalM31Words(&words);
    var execution = try channel.finish();
    defer execution.deinit();
    try validateRecordedTree0(&.{operation}, &execution, &root);
    for (0..root.len) |index| {
        const dynamic = try support.metadata(operation, @intCast(index));
        const fixed = try fixedTree0Metadata(dynamic, &root, @intCast(index));
        try std.testing.expectEqual(@as(u32, 1), fixed.constant_mask);
        try std.testing.expectEqual(root[index], fixed.expected_constant.?);
        try std.testing.expectEqual(dynamic.source_kind, fixed.source_kind);
        try std.testing.expectEqual(dynamic.item_index, fixed.item_index);
        try std.testing.expectEqual(dynamic.limb_index, fixed.limb_index);
        try std.testing.expectEqual(dynamic.input_use_count, fixed.input_use_count);
        var changed = root;
        changed[index] += 1;
        try std.testing.expectError(error.EthereumIncrementalTranscriptProgramMismatchV4, validateRecordedTree0(&.{operation}, &execution, &changed));
    }
    try std.testing.expectError(error.EthereumIncrementalTranscriptProgramMismatchV4, validateRecordedTree0(&.{}, &execution, &root));
    try std.testing.expectError(error.EthereumIncrementalTranscriptProgramMismatchV4, fixedTree0Metadata(try support.metadata(operation, 0), &root, 8));
}
