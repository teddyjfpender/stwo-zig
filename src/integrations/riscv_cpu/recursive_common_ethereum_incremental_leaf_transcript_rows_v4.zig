//! Typed schema-3 source for universal role-0 transcript rows 0--9.
//!
//! Construction requires the live Stage101 cold-verifier replay, its exact
//! verifier plans, and the verifier-derived program authority. The returned
//! opaque owner retains canonical AIR witness rows; no digest or detached
//! producer count can construct it.

const std = @import("std");
const stwo_core = @import("stwo_core");
const frontend = @import("stwo_riscv_frontend");

const campaign_materializer =
    @import("recursive_common_ethereum_incremental_leaf_campaign_materializer_v4.zig");
const geometry_mod =
    @import("recursive_common_ethereum_incremental_leaf_transcript_geometry_v4.zig");
const program_mod =
    @import("recursive_common_ethereum_incremental_leaf_transcript_program_v4.zig");
const support =
    @import("recursive_common_ethereum_incremental_leaf_transcript_rows_v4_support.zig");

const M31 = stwo_core.fields.m31.M31;
const recursion = frontend.recursion;
const air = recursion.air;
const schedule = air.verifier_schedule;
const source_rows = recursion.segment_transcript_outer_source_v2;

pub const FORMAT_VERSION: u16 = 4;
pub const SCHEMA_VERSION: u16 = 3;
pub const ROW_COUNT: usize = 10;
pub const ROWS_PREPARED_FROM_FRESH_CAPTURE = true;
pub const DIGEST_ONLY_CONSTRUCTION = false;
pub const PRODUCTION_ACTIVATION = false;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-transcript-rows/v4-schema3\x00";

pub const Error = support.Error || error{
    ArithmeticOverflow,
    EthereumIncrementalTranscriptRowsMismatchV4,
};

pub const ViewsV4 = struct {
    control: *const air.control_witness.Preprocessed,
    transcript_air: []const source_rows.TranscriptAirRowV2,
    transcript_binding: []const source_rows.TranscriptBindingRowV2,
    transcript_state: []const source_rows.TranscriptStateRowV2,
    transcript_word: []const source_rows.TranscriptWordRowV2,
    transcript_payload: []const support.TranscriptPayloadRowV4,
    pow_check: []const source_rows.PowCheckRowV2,
    pow_frame: []const source_rows.PowFrameRowV2,
    relation_preprocessed: *const air.relation_challenge_witness.Preprocessed,
    relation_main: *const air.relation_challenge_witness.MainWitness,
    randomness_preprocessed: *const air.verifier_randomness_witness.Preprocessed,
    randomness_main: *const air.verifier_randomness_witness.MainWitness,
    provider_calls: []const source_rows.ProviderCall,
    log_sizes: [ROW_COUNT]u32,
    identity_sha256: [32]u8,
};

pub fn OwnerV4(comptime Engine: type) type {
    const Materialized =
        campaign_materializer.PreparedOwnedCampaignCaptureV4(Engine);

    return opaque {
        const Self = @This();

        pub fn init(
            allocator: std.mem.Allocator,
            captured: *const Materialized,
            program: *const program_mod.ProgramAuthorityV4,
            geometry: *const geometry_mod.AuthorityV4,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
        ) !*Self {
            try captured.validate();
            try program.validateAgainst(
                Engine,
                captured,
                vm_plan,
                recursion_plan,
            );
            try geometry.validateAgainst(
                &captured.base.transcript,
                vm_plan,
                recursion_plan,
            );

            var control = try air.control_witness.Preprocessed.init(
                allocator,
                vm_plan,
                recursion_plan,
            );
            errdefer control.deinit();
            var binding_preprocessed =
                try air.transcript_binding_witness.Preprocessed.init(
                    allocator,
                    vm_plan,
                    recursion_plan,
                );
            errdefer binding_preprocessed.deinit();
            var state_preprocessed =
                try air.transcript_state_witness.Preprocessed.init(
                    allocator,
                    &binding_preprocessed,
                );
            errdefer state_preprocessed.deinit();
            var word_preprocessed =
                try air.transcript_word_witness.Preprocessed.init(
                    allocator,
                    vm_plan,
                    recursion_plan,
                );
            errdefer word_preprocessed.deinit();
            var payload_preprocessed =
                try air.transcript_payload_witness.Preprocessed.init(
                    allocator,
                    vm_plan,
                    recursion_plan,
                );
            errdefer payload_preprocessed.deinit();
            var relation_preprocessed =
                try air.relation_challenge_witness.Preprocessed.init(
                    allocator,
                    vm_plan,
                    recursion_plan,
                );
            errdefer relation_preprocessed.deinit();
            const relation_draws = try support.relationDrawsAlloc(
                allocator,
                &captured.base.transcript.execution,
                program,
            );
            defer allocator.free(relation_draws);
            var relation_main =
                try air.relation_challenge_witness.MainWitness.init(
                    allocator,
                    &relation_preprocessed,
                    .{ .segment_leaf = relation_draws },
                );
            errdefer relation_main.deinit();
            var randomness_preprocessed =
                try air.verifier_randomness_witness.Preprocessed.init(
                    allocator,
                    vm_plan,
                    recursion_plan,
                );
            errdefer randomness_preprocessed.deinit();
            const randomness_draws = try support.randomnessDrawsAlloc(
                allocator,
                &captured.base.transcript.execution,
                program,
            );
            defer allocator.free(randomness_draws);
            var randomness_main =
                try air.verifier_randomness_witness.MainWitness.init(
                    allocator,
                    &randomness_preprocessed,
                    .{ .segment_leaf = randomness_draws },
                );
            errdefer randomness_main.deinit();

            const counts = geometry.counts;
            const transcript_air = try allocCount(
                source_rows.TranscriptAirRowV2,
                allocator,
                counts.transcript_air,
            );
            errdefer allocator.free(transcript_air);
            const transcript_binding = try allocCount(
                source_rows.TranscriptBindingRowV2,
                allocator,
                counts.transcript_binding,
            );
            errdefer allocator.free(transcript_binding);
            const transcript_state = try allocCount(
                source_rows.TranscriptStateRowV2,
                allocator,
                counts.transcript_state,
            );
            errdefer allocator.free(transcript_state);
            const transcript_word = try allocCount(
                source_rows.TranscriptWordRowV2,
                allocator,
                counts.transcript_word,
            );
            errdefer allocator.free(transcript_word);
            const transcript_payload = try allocCount(
                support.TranscriptPayloadRowV4,
                allocator,
                counts.transcript_payload,
            );
            errdefer allocator.free(transcript_payload);
            const pow_check = try allocCount(
                source_rows.PowCheckRowV2,
                allocator,
                counts.pow_check,
            );
            errdefer allocator.free(pow_check);
            const pow_frame = try allocCount(
                source_rows.PowFrameRowV2,
                allocator,
                counts.pow_frame,
            );
            errdefer allocator.free(pow_frame);
            const provider_calls = try allocCount(
                source_rows.ProviderCall,
                allocator,
                counts.transcript_air,
            );
            errdefer allocator.free(provider_calls);
            const buffers = support.BuffersV4{
                .transcript_air = transcript_air,
                .transcript_binding = transcript_binding,
                .transcript_state = transcript_state,
                .transcript_word = transcript_word,
                .transcript_payload = transcript_payload,
                .pow_check = pow_check,
                .pow_frame = pow_frame,
                .provider_calls = provider_calls,
            };
            try support.populateOrValidate(
                &captured.base.transcript.execution,
                program,
                vm_plan,
                recursion_plan,
                .{
                    .binding = &binding_preprocessed,
                    .state = &state_preprocessed,
                    .word = &word_preprocessed,
                    .payload = &payload_preprocessed,
                },
                buffers,
                false,
            );

            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);
            backing.* = .{
                .allocator = allocator,
                .captured = captured,
                .program = program,
                .geometry = geometry,
                .vm_plan = vm_plan,
                .recursion_plan = recursion_plan,
                .control = control,
                .binding_preprocessed = binding_preprocessed,
                .state_preprocessed = state_preprocessed,
                .word_preprocessed = word_preprocessed,
                .payload_preprocessed = payload_preprocessed,
                .relation_preprocessed = relation_preprocessed,
                .relation_main = relation_main,
                .randomness_preprocessed = randomness_preprocessed,
                .randomness_main = randomness_main,
                .buffers = buffers,
                .identity_sha256 = undefined,
            };
            backing.identity_sha256 = backing.computeIdentity();
            try backing.validate();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        pub fn views(self: *const Self) !ViewsV4 {
            try self.validate();
            return storageConst(self).viewsUnchecked();
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            captured: *const Materialized,
            program: *const program_mod.ProgramAuthorityV4,
            geometry: *const geometry_mod.AuthorityV4,
            vm_plan: *const schedule.Plan,
            recursion_plan: *const schedule.Plan,
            control: air.control_witness.Preprocessed,
            binding_preprocessed: air.transcript_binding_witness.Preprocessed,
            state_preprocessed: air.transcript_state_witness.Preprocessed,
            word_preprocessed: air.transcript_word_witness.Preprocessed,
            payload_preprocessed: air.transcript_payload_witness.Preprocessed,
            relation_preprocessed: air.relation_challenge_witness.Preprocessed,
            relation_main: air.relation_challenge_witness.MainWitness,
            randomness_preprocessed: air.verifier_randomness_witness.Preprocessed,
            randomness_main: air.verifier_randomness_witness.MainWitness,
            buffers: support.BuffersV4,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.captured.validate();
                try self.program.validateAgainst(
                    Engine,
                    self.captured,
                    self.vm_plan,
                    self.recursion_plan,
                );
                try self.geometry.validateAgainst(
                    &self.captured.base.transcript,
                    self.vm_plan,
                    self.recursion_plan,
                );
                try self.control.validateAgainst(
                    self.vm_plan,
                    self.recursion_plan,
                );
                try self.binding_preprocessed.validateAgainst(
                    self.vm_plan,
                    self.recursion_plan,
                );
                try self.state_preprocessed.validateAgainst(
                    &self.binding_preprocessed,
                );
                try self.word_preprocessed.validateAgainst(
                    self.vm_plan,
                    self.recursion_plan,
                );
                try self.payload_preprocessed.validateAgainst(
                    self.vm_plan,
                    self.recursion_plan,
                );
                try self.relation_preprocessed.validateAgainst(
                    self.vm_plan,
                    self.recursion_plan,
                );
                try self.relation_main.validateAgainst(
                    &self.relation_preprocessed,
                );
                try self.randomness_preprocessed.validateAgainst(
                    self.vm_plan,
                    self.recursion_plan,
                );
                try self.randomness_main.validateAgainst(
                    &self.randomness_preprocessed,
                );
                const counts = self.geometry.counts;
                if (self.control.rows.len != @as(usize, counts.control) or
                    self.control.log_size != self.geometry.log_sizes[0] or
                    self.buffers.transcript_air.len !=
                        @as(usize, counts.transcript_air) or
                    self.buffers.transcript_binding.len !=
                        @as(usize, counts.transcript_binding) or
                    self.buffers.transcript_state.len !=
                        @as(usize, counts.transcript_state) or
                    self.buffers.transcript_word.len !=
                        @as(usize, counts.transcript_word) or
                    self.buffers.transcript_payload.len !=
                        @as(usize, counts.transcript_payload) or
                    self.buffers.pow_check.len != @as(usize, counts.pow_check) or
                    self.buffers.pow_frame.len != @as(usize, counts.pow_frame) or
                    self.relation_preprocessed.rows.len !=
                        @as(usize, counts.relation_challenge) or
                    self.relation_preprocessed.log_size !=
                        self.geometry.log_sizes[8] or
                    self.randomness_preprocessed.rows.len !=
                        @as(usize, counts.verifier_randomness) or
                    self.randomness_preprocessed.log_size !=
                        self.geometry.log_sizes[9] or
                    self.buffers.provider_calls.len !=
                        @as(usize, counts.transcript_air))
                {
                    return mismatch();
                }
                try support.populateOrValidate(
                    &self.captured.base.transcript.execution,
                    self.program,
                    self.vm_plan,
                    self.recursion_plan,
                    .{
                        .binding = &self.binding_preprocessed,
                        .state = &self.state_preprocessed,
                        .word = &self.word_preprocessed,
                        .payload = &self.payload_preprocessed,
                    },
                    self.buffers,
                    true,
                );
                if (!std.mem.eql(
                    u8,
                    &self.identity_sha256,
                    &self.computeIdentity(),
                )) return mismatch();
            }

            fn viewsUnchecked(self: *const Storage) ViewsV4 {
                return .{
                    .control = &self.control,
                    .transcript_air = self.buffers.transcript_air,
                    .transcript_binding = self.buffers.transcript_binding,
                    .transcript_state = self.buffers.transcript_state,
                    .transcript_word = self.buffers.transcript_word,
                    .transcript_payload = self.buffers.transcript_payload,
                    .pow_check = self.buffers.pow_check,
                    .pow_frame = self.buffers.pow_frame,
                    .relation_preprocessed = &self.relation_preprocessed,
                    .relation_main = &self.relation_main,
                    .randomness_preprocessed = &self.randomness_preprocessed,
                    .randomness_main = &self.randomness_main,
                    .provider_calls = self.buffers.provider_calls,
                    .log_sizes = self.geometry.log_sizes,
                    .identity_sha256 = self.identity_sha256,
                };
            }

            fn computeIdentity(self: *const Storage) [32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(IDENTITY_DOMAIN);
                hashInt(&hash, u16, FORMAT_VERSION);
                hashInt(&hash, u16, SCHEMA_VERSION);
                hash.update(&self.captured.base.input.stage101.identity_sha256);
                hash.update(&self.program.identity_sha256);
                hash.update(&self.geometry.identity_sha256);
                for (self.geometry.log_sizes) |value|
                    hashInt(&hash, u32, value);
                for (self.vm_plan.authority_digest) |value|
                    hashInt(&hash, u32, value);
                for (self.recursion_plan.authority_digest) |value|
                    hashInt(&hash, u32, value);
                return hash.finalResult();
            }

            fn destroy(self: *Storage) void {
                const allocator = self.allocator;
                allocator.free(self.buffers.provider_calls);
                allocator.free(self.buffers.pow_frame);
                allocator.free(self.buffers.pow_check);
                allocator.free(self.buffers.transcript_payload);
                allocator.free(self.buffers.transcript_word);
                allocator.free(self.buffers.transcript_state);
                allocator.free(self.buffers.transcript_binding);
                allocator.free(self.buffers.transcript_air);
                self.randomness_main.deinit();
                self.randomness_preprocessed.deinit();
                self.relation_main.deinit();
                self.relation_preprocessed.deinit();
                self.payload_preprocessed.deinit();
                self.word_preprocessed.deinit();
                self.state_preprocessed.deinit();
                self.binding_preprocessed.deinit();
                self.control.deinit();
                self.* = undefined;
                allocator.destroy(self);
            }
        };

        fn handle(value: *Storage) *Self {
            return @ptrCast(value);
        }

        fn storage(value: *Self) *Storage {
            return @ptrCast(@alignCast(value));
        }

        fn storageConst(value: *const Self) *const Storage {
            return @ptrCast(@alignCast(value));
        }
    };
}

fn allocCount(
    comptime T: type,
    allocator: std.mem.Allocator,
    count: u32,
) ![]T {
    return allocator.alloc(T, @intCast(count));
}

fn hashInt(hash: anytype, comptime T: type, value: anytype) void {
    var encoded: [@sizeOf(T)]u8 = undefined;
    std.mem.writeInt(T, &encoded, @intCast(value), .little);
    hash.update(&encoded);
}

fn mismatch() Error {
    return error.EthereumIncrementalTranscriptRowsMismatchV4;
}

comptime {
    if (FORMAT_VERSION != 4 or SCHEMA_VERSION != 3 or ROW_COUNT != 10 or
        !ROWS_PREPARED_FROM_FRESH_CAPTURE or DIGEST_ONLY_CONSTRUCTION or
        PRODUCTION_ACTIVATION)
    {
        @compileError("Ethereum incremental transcript rows V4 drifted");
    }
}
