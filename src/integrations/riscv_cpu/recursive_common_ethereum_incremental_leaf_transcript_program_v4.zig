//! Verifier-owned program for the role-0 Stage101 Poseidon replay.
//!
//! The ordinary SegmentV2 transcript program cannot describe the joined
//! Ethereum+incremental transcript. This owner reclassifies every operation
//! from the successful Stage101 cold verifier and binds it to the exact VM
//! verifier-plan step. Only values supplied by typed recursion rows remain
//! dynamic; all other verifier-derived words are committed preprocessing.

const std = @import("std");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4_support.zig");
const types =
    @import("recursive_common_ethereum_incremental_leaf_transcript_program_types_v4.zig");

const recording = frontend.recursion.recording_poseidon_channel_v4;
const schedule = frontend.recursion.air.verifier_schedule;

pub const FORMAT_VERSION = types.FORMAT_VERSION;
pub const SCHEMA_VERSION = types.SCHEMA_VERSION;
pub const CONTEXT_COUNT = types.CONTEXT_COUNT;
pub const BASE_STATEMENT_WIRE_OFFSET = types.BASE_STATEMENT_WIRE_OFFSET;
pub const BASE_STATEMENT_WORD_COUNT = types.BASE_STATEMENT_WORD_COUNT;
pub const TRANSCRIPT_CLAIM_COUNT = types.TRANSCRIPT_CLAIM_COUNT;
pub const RELATION_DRAW_COUNT = types.RELATION_DRAW_COUNT;
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
    "stwo-zig/common-ethereum-incremental-transcript-program/v4-schema3\x00";

/// Owned, pointer-free expansion. `validateAgainst` reclassifies every native
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
    operations: []OperationV4,
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
        var result = ProgramAuthorityV4{
            .allocator = allocator,
            .stage101_identity_sha256 = captured.base.input.stage101.identity_sha256,
            .replay_identity_sha256 = captured.base.transcript.identity_sha256,
            .vm_plan_identity = vm_plan.authority_digest,
            .recursion_plan_identity = recursion_plan.authority_digest,
            .contexts = derived.contexts,
            .operations = derived.operations,
            .identity_sha256 = undefined,
        };
        result.identity_sha256 = identity(&result);
        try result.validateAgainst(Engine, captured, vm_plan, recursion_plan);
        return result;
    }

    pub fn deinit(self: *ProgramAuthorityV4) void {
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
        const expected = try support.derive(
            Engine,
            self.allocator,
            captured,
            vm_plan,
            recursion_plan,
        );
        defer self.allocator.free(expected.operations);
        if (self.format_version != FORMAT_VERSION or
            self.schema_version != SCHEMA_VERSION or
            !std.mem.eql(
                u8,
                &self.stage101_identity_sha256,
                &captured.base.input.stage101.identity_sha256,
            ) or !std.mem.eql(
            u8,
            &self.replay_identity_sha256,
            &captured.base.transcript.identity_sha256,
        ) or !std.meta.eql(self.vm_plan_identity, vm_plan.authority_digest) or
            !std.meta.eql(
                self.recursion_plan_identity,
                recursion_plan.authority_digest,
            ) or !std.meta.eql(self.contexts, expected.contexts) or
            !operationsEql(self.operations, expected.operations) or
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
        return support.metadata(self.operations[operation_index], payload_index);
    }
};

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
        .commitment,
        .transcript_claimed_sum,
        .sampled_values,
        .fri_commitment,
        .last_layer_coefficients,
        => |item| hashInt(hash, u32, item),
    }
    hashInt(hash, u8, @intFromEnum(std.meta.activeTag(operation.draw)));
    switch (operation.draw) {
        .none, .composition, .oods, .deep => {},
        .relation_limb => |draw| {
            hashInt(hash, u32, draw.challenge);
            hashInt(hash, u32, draw.half);
        },
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
