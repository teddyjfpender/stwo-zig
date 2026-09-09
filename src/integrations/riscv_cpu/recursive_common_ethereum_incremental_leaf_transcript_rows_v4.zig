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
pub const payloadLogicalRow = support.payloadLogicalRow;

const IDENTITY_DOMAIN =
    "stwo-zig/common-ethereum-incremental-transcript-rows/v4-schema3\x00";

pub const Error = support.Error || error{
    ArithmeticOverflow,
    EthereumIncrementalTranscriptRowsMismatchV4,
};

pub const ViewsV4 = struct {
    control: struct { rows: []const air.control_witness.Row },
    transcript_air: []const source_rows.TranscriptAirRowV2,
    transcript_binding: []const source_rows.TranscriptBindingRowV2,
    transcript_state: []const source_rows.TranscriptStateRowV2,
    transcript_word: []const source_rows.TranscriptWordRowV2,
    transcript_payload: []const support.TranscriptPayloadRowV4,
    pow_check: []const source_rows.PowCheckRowV2,
    pow_frame: []const source_rows.PowFrameRowV2,
    relation_preprocessed: struct { rows: []const air.relation_challenge_witness.PreprocessedRow },
    relation_main: struct { rows: []const air.relation_challenge_witness.MainRow },
    randomness_preprocessed: struct { rows: []const air.verifier_randomness_witness.PreprocessedRow },
    randomness_main: struct { rows: []const air.verifier_randomness_witness.MainRow },
    provider_calls: []const source_rows.ProviderCall,
    terminal_digest_hash_id: u32,
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
            // Program admission validates the capture and independently checks
            // its classification. Accept both at this single entry boundary.
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
                program.operations,
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

            const frames = captured.base.transcript.execution.hash_frames;
            if (frames.len == 0) return error.EthereumIncrementalTranscriptRowsMismatchV4;
            var owned_vm = try clonePlan(allocator, vm_plan);
            errdefer owned_vm.deinit();
            var owned_recursion = try clonePlan(allocator, recursion_plan);
            errdefer owned_recursion.deinit();
            const terminal = frames[frames.len - 1];
            if (terminal.words.len < 8) return mismatch();
            const backing = try allocator.create(Storage);
            errdefer allocator.destroy(backing);
            backing.* = .{
                .allocator = allocator,
                .captured = captured,
                .program = program,
                .geometry = geometry.*,
                .vm_plan = owned_vm,
                .recursion_plan = owned_recursion,
                .stage101_identity_sha256 = captured.base.input.stage101.identity_sha256,
                .program_identity_sha256 = program.identity_sha256,
                .terminal_words = terminal.words[0..8].*,
                .terminal_purpose = terminal.purpose,
                .final_digest = captured.base.transcript.final_digest,
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
                .terminal_digest_hash_id = frames[frames.len - 1].hash_id,
                .log_sizes = geometry.log_sizes,
                .identity_sha256 = undefined,
            };
            backing.identity_sha256 = backing.computeIdentity();
            // The source/program/geometry were accepted above. Finalization
            // checks every newly generated row and its custody locally; public
            // validate remains the full external-source admission boundary.
            try backing.validateLiveRows();
            try backing.validatePreparedRows();
            return handle(backing);
        }

        pub fn deinit(self: *Self) void {
            storage(self).destroy();
        }

        pub fn validate(self: *const Self) !void {
            try storageConst(self).validate();
        }

        /// Check constructor-owned operational rows and copied plans only.
        /// This does not read or replay the mutable source capture. External
        /// input/proof admission uses validate and re-derives the live source.
        pub fn validatePreparedRows(self: *const Self) !void {
            try storageConst(self).validatePreparedRows();
        }

        /// Reconstruct row values after the enclosing boundary has admitted
        /// the live program/replay. Kept separate to avoid deriving it twice.
        pub fn validateRowsAgainstLiveSource(self: *const Self) !void {
            try storageConst(self).validateLiveRows();
            try storageConst(self).validatePreparedRows();
        }

        /// Read privately owned, construction-admitted rows. No mutable slice
        /// escapes; only deinit changes their lifetime. Call validate explicitly
        /// when accepting/finalizing state or entering a proof boundary.
        pub fn views(self: *const Self) !ViewsV4 {
            return storageConst(self).viewsUnchecked();
        }

        const Storage = struct {
            allocator: std.mem.Allocator,
            // These borrowed pointers are used only by the cold/live auditor.
            captured: *const Materialized,
            program: *const program_mod.ProgramAuthorityV4,
            geometry: geometry_mod.AuthorityV4,
            vm_plan: schedule.Plan,
            recursion_plan: schedule.Plan,
            stage101_identity_sha256: [32]u8,
            program_identity_sha256: [32]u8,
            terminal_words: [8]M31,
            terminal_purpose: frontend.recursion.recording_poseidon_channel_v4.HashPurpose,
            final_digest: [8]u32,
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
            terminal_digest_hash_id: u32,
            log_sizes: [ROW_COUNT]u32,
            identity_sha256: [32]u8,

            fn validate(self: *const Storage) !void {
                try self.captured.validate();
                try self.program.validateAgainstPreparedSource(
                    Engine,
                    self.captured,
                    &self.vm_plan,
                    &self.recursion_plan,
                );
                try self.geometry.validateAgainst(
                    &self.captured.base.transcript,
                    &self.vm_plan,
                    &self.recursion_plan,
                );
                try self.validateLiveRows();
                try self.validatePreparedRows();
            }

            fn validatePreparedRows(self: *const Storage) !void {
                if (self.terminal_purpose != .draw or
                    !std.mem.eql(u32, &self.log_sizes, &self.geometry.log_sizes)) return mismatch();
                for (self.terminal_words, self.final_digest) |actual, expected|
                    if (actual.toU32() != expected) return mismatch();
                try self.control.validateAgainst(
                    &self.vm_plan,
                    &self.recursion_plan,
                );
                try self.binding_preprocessed.validateAgainst(
                    &self.vm_plan,
                    &self.recursion_plan,
                );
                try self.state_preprocessed.validateAgainst(
                    &self.binding_preprocessed,
                );
                try self.word_preprocessed.validateAgainst(
                    &self.vm_plan,
                    &self.recursion_plan,
                );
                try self.payload_preprocessed.validateAgainst(
                    &self.vm_plan,
                    &self.recursion_plan,
                );
                try self.relation_preprocessed.validateAgainst(
                    &self.vm_plan,
                    &self.recursion_plan,
                );
                try self.relation_main.validateAgainst(
                    &self.relation_preprocessed,
                );
                try self.randomness_preprocessed.validateAgainst(
                    &self.vm_plan,
                    &self.recursion_plan,
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
                if (!std.mem.eql(
                    u8,
                    &self.identity_sha256,
                    &self.computeIdentity(),
                )) return mismatch();
            }

            fn validateLiveRows(self: *const Storage) !void {
                const frames = self.captured.base.transcript.execution.hash_frames;
                if (frames.len == 0) return mismatch();
                const terminal = frames[frames.len - 1];
                if (terminal.words.len < 8 or terminal.hash_id != self.terminal_digest_hash_id or
                    terminal.purpose != self.terminal_purpose or
                    !std.meta.eql(terminal.words[0..8].*, self.terminal_words) or
                    !std.meta.eql(self.captured.base.transcript.final_digest, self.final_digest) or
                    !std.meta.eql(self.captured.base.input.stage101.identity_sha256, self.stage101_identity_sha256) or
                    !std.meta.eql(self.program.identity_sha256, self.program_identity_sha256)) return mismatch();
                try support.populateOrValidate(
                    &self.captured.base.transcript.execution,
                    self.program,
                    &self.vm_plan,
                    &self.recursion_plan,
                    .{
                        .binding = &self.binding_preprocessed,
                        .state = &self.state_preprocessed,
                        .word = &self.word_preprocessed,
                        .payload = &self.payload_preprocessed,
                    },
                    self.buffers,
                    true,
                );
            }

            fn viewsUnchecked(self: *const Storage) ViewsV4 {
                return .{
                    .control = .{ .rows = self.control.rows },
                    .transcript_air = self.buffers.transcript_air,
                    .transcript_binding = self.buffers.transcript_binding,
                    .transcript_state = self.buffers.transcript_state,
                    .transcript_word = self.buffers.transcript_word,
                    .transcript_payload = self.buffers.transcript_payload,
                    .pow_check = self.buffers.pow_check,
                    .pow_frame = self.buffers.pow_frame,
                    .relation_preprocessed = .{ .rows = self.relation_preprocessed.rows },
                    .relation_main = .{ .rows = self.relation_main.rows },
                    .randomness_preprocessed = .{ .rows = self.randomness_preprocessed.rows },
                    .randomness_main = .{ .rows = self.randomness_main.rows },
                    .provider_calls = self.buffers.provider_calls,
                    .terminal_digest_hash_id = self.terminal_digest_hash_id,
                    .log_sizes = self.log_sizes,
                    .identity_sha256 = self.identity_sha256,
                };
            }

            fn computeIdentity(self: *const Storage) [32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update(IDENTITY_DOMAIN);
                hashInt(&hash, u16, FORMAT_VERSION);
                hashInt(&hash, u16, SCHEMA_VERSION);
                hash.update(&self.stage101_identity_sha256);
                hash.update(&self.program_identity_sha256);
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
                self.vm_plan.deinit();
                self.recursion_plan.deinit();
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

test "Ethereum transcript prepared views expose deeply readonly rows and copied metadata" {
    const Audit = struct {
        fn readOnly(comptime T: type) bool {
            return switch (@typeInfo(T)) {
                .pointer => |pointer| pointer.is_const and readOnly(pointer.child),
                .array => |array| readOnly(array.child),
                .optional => |optional| readOnly(optional.child),
                .@"struct" => |structure| blk: {
                    for (structure.fields) |field| if (!readOnly(field.type)) break :blk false;
                    break :blk true;
                },
                .@"union" => |value| blk: {
                    for (value.fields) |field| if (!readOnly(field.type)) break :blk false;
                    break :blk true;
                },
                else => true,
            };
        }
    };
    try std.testing.expect(comptime Audit.readOnly(ViewsV4));
    // A const wrapper around a mutable slice is exactly the old leak.
    try std.testing.expect(comptime !Audit.readOnly(*const struct { rows: []air.control_witness.Row }));
    try std.testing.expect(@typeInfo(@FieldType(ViewsV4, "log_sizes")) == .array);
    try std.testing.expect(@FieldType(ViewsV4, "terminal_digest_hash_id") == u32);
    try testPlanCloneIsolation();
}

// VerifierStep owns no slices: cloning the single finalized step allocation
// copies the complete operational plan without retaining a source alias.
fn clonePlan(allocator: std.mem.Allocator, source: *const schedule.Plan) !schedule.Plan {
    comptime {
        assertPointerFree(schedule.VerifierStep);
        assertPointerFree(geometry_mod.AuthorityV4);
        for (@typeInfo(schedule.Plan).@"struct".fields) |field| {
            if (!std.mem.eql(u8, field.name, "allocator") and !std.mem.eql(u8, field.name, "steps"))
                assertPointerFree(field.type);
        }
    }
    try source.validate();
    var result = source.*;
    result.allocator = allocator;
    result.steps = try allocator.dupe(schedule.VerifierStep, source.steps);
    return result;
}

fn assertPointerFree(comptime T: type) void {
    switch (@typeInfo(T)) {
        .pointer => @compileError("transcript operational snapshot gained a shallow pointer"),
        .array => |array| assertPointerFree(array.child),
        .optional => |optional| assertPointerFree(optional.child),
        .@"struct" => |value| for (value.fields) |field| {
            assertPointerFree(field.type);
        },
        .@"union" => |value| for (value.fields) |field| {
            assertPointerFree(field.type);
        },
        else => {},
    }
}

fn exercisePlanCloneFailure(allocator: std.mem.Allocator, source: *const schedule.Plan) !void {
    var owned = try clonePlan(allocator, source);
    defer owned.deinit();
    try owned.validate();
    try std.testing.expect(owned.steps.ptr != source.steps.ptr);
    try std.testing.expectEqualDeep(source.steps, owned.steps);
}

fn testPlanCloneIsolation() !void {
    const allocator = std.testing.allocator;
    const shape = schedule.ScheduleShape{
        .protocol_id = [_]u32{1} ** 8,
        .shape_id = [_]u32{2} ** 8,
        .interaction_pow_bits = 0,
        .pcs_pow_bits = 0,
        .query_count = 1,
        .table_count = 4,
        .claimed_sum_count = 1,
        .sampled_value_count = 4,
        .tree_heights = .{ 25, 25, 25, 25 },
        .fri = try recursion.fixed_profile.FriSchedule.init(24, recursion.protocol.PCS_CONFIG.fri_config),
    };
    var source = try schedule.Plan.initShape(allocator, schedule.VM_PROGRAM_SPEC_V1, shape);
    defer source.deinit();
    var owned = try clonePlan(allocator, &source);
    defer owned.deinit();
    try std.testing.expect(owned.steps.ptr != source.steps.ptr);
    const first = source.steps[0];
    @constCast(source.steps)[0] = .complete;
    try owned.validate();
    try std.testing.expectEqualDeep(first, owned.steps[0]);
    try std.testing.expectError(error.ScheduleDigestMismatch, source.validate());
    @constCast(source.steps)[0] = first;
    try source.validate();
    try std.testing.checkAllAllocationFailures(allocator, exercisePlanCloneFailure, .{&source});
}
