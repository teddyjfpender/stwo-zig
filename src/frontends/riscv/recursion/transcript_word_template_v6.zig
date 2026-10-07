//! Fixed row-4 preprocessing rebuilt from the admitted native instruction list.
//! Only payload words are leaf-dependent; their values already occupy the V4
//! main column. Draw counters, draw tags and frame padding are shape constants.
const std = @import("std");
const channel = @import("poseidon2_channel.zig");
const transcript = @import("transcript_program_v2.zig");
const program = @import("transcript_program_v2_program.zig");
const source = @import("segment_transcript_outer_source_v2.zig");
const word = @import("air/transcript_word_witness.zig");
const frame = @import("segment_leaf_wrapper_frame_provider_direct_v4.zig");
const core = @import("stwo_core");
const M31 = core.fields.m31.M31;
const native_schedule = @import("air/verifier_schedule.zig");
const statement = @import("../air/statement.zig");
const instruction_template = @import("transcript_instruction_template_v6.zig");

pub const DOMAIN = "stwo-zig/riscv-transcript-row4-fixed-template/v6\x00";
pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const FixedRow = struct {
    preprocessing: word.Row,
    tree0_bridge: u32,
};

pub const Template = struct {
    allocator: std.mem.Allocator,
    rows: []FixedRow,
    tree0_hash_id: u32,
    schedule_id: [32]u8,

    /// Production-facing builder: descriptor and frame preprocessing is
    /// independently recompiled from the admitted native verifier shape.
    pub fn buildFromAdmittedShape(
        allocator: std.mem.Allocator,
        plan: *const native_schedule.Plan,
        wire_word_count: u32,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        lookup_enabled: bool,
    ) !Template {
        const instructions = try instruction_template.compileInstructions(
            allocator,
            plan,
            wire_word_count,
            component_descs,
            infra_descs,
            lookup_enabled,
        );
        defer allocator.free(instructions);
        return build(allocator, instructions);
    }

    pub fn build(allocator: std.mem.Allocator, instructions: []const transcript.Instruction) !Template {
        if (instructions.len == 0) return error.InvalidRow4Template;
        var rows: std.ArrayList(FixedRow) = .empty;
        defer rows.deinit(allocator);
        var hash_id: u32 = 0;
        var draw_count: u32 = 0;
        var tree0_hash_id: ?u32 = null;
        for (instructions, 0..) |instruction, sequence| {
            if (instruction.kind == .trace_commitment and instruction.args[0] == 0) {
                if (tree0_hash_id != null) return error.InvalidRow4Template;
                tree0_hash_id = hash_id;
            }
            switch (instruction.effect()) {
                .mix => {
                    try appendFrame(allocator, &rows, instruction, sequence, hash_id, true, try instruction.payloadWordCount(), 0);
                    hash_id = try std.math.add(u32, hash_id, 1);
                    draw_count = 0;
                },
                .draw => {
                    try appendFrame(allocator, &rows, instruction, sequence, hash_id, false, 2, draw_count);
                    hash_id = try std.math.add(u32, hash_id, 1);
                    draw_count = try std.math.add(u32, draw_count, 1);
                },
                .pow => {
                    try appendFrame(allocator, &rows, instruction, sequence, hash_id, true, try instruction.payloadWordCount(), 0);
                    hash_id = try std.math.add(u32, hash_id, 1);
                    try appendFrame(allocator, &rows, instruction, sequence, hash_id, false, 2, 0);
                    hash_id = try std.math.add(u32, hash_id, 1);
                    draw_count = 0;
                },
            }
        }
        const root_hash = tree0_hash_id orelse return error.InvalidRow4Template;
        var seen: u8 = 0;
        for (rows.items) |*row| {
            const pp = row.preprocessing;
            if (pp.hash_id == root_hash and pp.word_index >= frame.ROOT_START_INDEX and
                pp.word_index < frame.ROOT_START_INDEX + frame.ROOT_WORDS)
            {
                const limb: u3 = @intCast(pp.word_index - frame.ROOT_START_INDEX);
                const bit = @as(u8, 1) << limb;
                if (seen & bit != 0 or pp.is_payload != 1) return error.InvalidRow4Template;
                seen |= bit;
                row.tree0_bridge = 1;
            }
        }
        if (seen != 0xff) return error.InvalidRow4Template;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update(DOMAIN);
        for (rows.items) |row| {
            for (row.preprocessing.values()) |felt| hashU32(&hash, felt.toU32());
            hashU32(&hash, row.tree0_bridge);
        }
        return .{
            .allocator = allocator,
            .rows = try rows.toOwnedSlice(allocator),
            .tree0_hash_id = root_hash,
            .schedule_id = hash.finalResult(),
        };
    }

    pub fn deinit(self: *Template) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    /// Hashes the complete physical preprocessed table, including padded
    /// zero rows and the V4 Tree0 selector, in row-major canonical order.
    pub fn preprocessedId(self: *const Template, log_size: u32) ![32]u8 {
        if (log_size >= @bitSizeOf(usize)) return error.InvalidRow4Template;
        const capacity = @as(usize, 1) << @intCast(log_size);
        if (self.rows.len > capacity) return error.InvalidRow4Template;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/riscv-v6-row4-fixed-columns/v1\x00");
        hashU32(&hash, @intCast(capacity));
        for (0..capacity) |index| {
            if (index < self.rows.len) {
                const row = self.rows[index];
                for (row.preprocessing.values()) |felt| hashU32(&hash, felt.toU32());
                hashU32(&hash, row.tree0_bridge);
            } else {
                for (0..16) |_| hashU32(&hash, 0);
            }
        }
        return hash.finalResult();
    }

    /// Checks the old V2 witness against independently compiled fixed columns.
    /// It does not constrain payload values; V4 frame/payload lookup does that.
    pub fn validateSource(self: *const Template, source_rows: []const source.TranscriptWordRowV2) !void {
        if (source_rows.len != self.rows.len) return error.Row4TemplateMismatch;
        for (source_rows, self.rows) |actual, expected| {
            if (!std.meta.eql(actual.preprocessing, expected.preprocessing) or
                (actual.preprocessing.is_payload == 0 and !actual.value.isZero()))
                return error.Row4TemplateMismatch;
        }
    }
};

fn appendFrame(
    allocator: std.mem.Allocator,
    rows: *std.ArrayList(FixedRow),
    instruction: transcript.Instruction,
    sequence: usize,
    hash_id: u32,
    is_mix: bool,
    payload_count: usize,
    draw_count: u32,
) !void {
    const words = try std.math.add(usize, channel.RATE, payload_count);
    const calls = try program.frameCallCount(words);
    const padded = try std.math.mul(usize, calls, channel.RATE);
    for (channel.RATE..padded) |index| {
        const is_payload = is_mix and index < words;
        const constant_value: u32 = if (is_payload) 0 else if (index < words)
            if (index == channel.RATE) draw_count else channel.DRAW_TAG
        else if (index == words) 1 else 0;
        try rows.append(allocator, .{
            .preprocessing = .{
                .row_mask = 1,
                .segment_mask = 1,
                .binary_mask = 0,
                .verifier_id = 0,
                .sequence = @intCast(sequence),
                .tag = @import("segment_transcript_outer_source_v2_contract.zig").typedTag(instruction.kind),
                .args = instruction.args,
                .hash_id = hash_id,
                .word_index = @intCast(index),
                .is_payload = @intFromBool(is_payload),
                .payload_index = if (is_payload) @intCast(index - channel.RATE) else 0,
                .constant_value = constant_value,
            },
            .tree0_bridge = 0,
        });
    }
}

fn hashU32(hash: *std.crypto.hash.sha2.Sha256, value: u32) void {
    var encoded: [4]u8 = undefined;
    std.mem.writeInt(u32, &encoded, value, .little);
    hash.update(&encoded);
}

test "V6 row4 fixed columns are invariant across two distinct leaf payloads" {
    const allocator = std.testing.allocator;
    const instructions = [_]transcript.Instruction{
        .{ .kind = .statement_words, .verifier_sequence = 1, .sub_index = 0, .args = .{ 20, 0, 0, 0 } },
        .{ .kind = .trace_commitment, .verifier_sequence = 2, .sub_index = 0, .args = .{ 0, 0, 8, 0 } },
        .{ .kind = .relation_draw, .verifier_sequence = 3, .sub_index = 0 },
        .{ .kind = .pcs_pow, .verifier_sequence = 4, .sub_index = 0 },
    };
    var template = try Template.build(allocator, &instructions);
    defer template.deinit();
    const first = try allocator.alloc(source.TranscriptWordRowV2, template.rows.len);
    defer allocator.free(first);
    const second = try allocator.alloc(source.TranscriptWordRowV2, template.rows.len);
    defer allocator.free(second);
    for (template.rows, first, second) |fixed, *left, *right| {
        left.* = .{ .preprocessing = fixed.preprocessing, .value = M31.zero() };
        right.* = left.*;
        if (fixed.preprocessing.is_payload == 1) right.value = M31.fromCanonical(7);
    }
    try template.validateSource(first);
    try template.validateSource(second);
    try std.testing.expectEqualDeep(first[0].preprocessing, second[0].preprocessing);
    const capacity = try std.math.ceilPowerOfTwo(usize, template.rows.len);
    const fixed_id = try template.preprocessedId(std.math.log2_int(usize, capacity));
    for (template.rows) |*row| {
        if (row.tree0_bridge == 1) {
            row.tree0_bridge = 0;
            try std.testing.expect(!std.meta.eql(fixed_id, try template.preprocessedId(std.math.log2_int(usize, capacity))));
            row.tree0_bridge = 1;
            break;
        }
    }
    const mutated_index = template.rows.len - 1;
    second[mutated_index].preprocessing.constant_value +%= 1;
    try std.testing.expectError(error.Row4TemplateMismatch, template.validateSource(second));
    second[mutated_index].preprocessing = template.rows[mutated_index].preprocessing;
    second[mutated_index].preprocessing.hash_id +%= 1;
    try std.testing.expectError(error.Row4TemplateMismatch, template.validateSource(second));
    second[mutated_index].preprocessing = template.rows[mutated_index].preprocessing;
    second[mutated_index].value = M31.fromCanonical(1);
    try std.testing.expectError(error.Row4TemplateMismatch, template.validateSource(second));
}

test "V6 row4 admitted shape compiles the same fixed schedule without leaf values" {
    const allocator = std.testing.allocator;
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    var from_shape = try Template.buildFromAdmittedShape(
        allocator,
        &plans.vm,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    defer from_shape.deinit();
    const independently_compiled = try instruction_template.compileInstructions(
        allocator,
        &plans.vm,
        128,
        &child_fixture.components,
        &child_fixture.infra,
        false,
    );
    defer allocator.free(independently_compiled);
    var from_instructions = try Template.build(allocator, independently_compiled);
    defer from_instructions.deinit();
    try std.testing.expectEqualDeep(from_shape.schedule_id, from_instructions.schedule_id);
    try std.testing.expectEqualDeep(from_shape.rows, from_instructions.rows);
    try std.testing.expect(from_shape.tree0_hash_id < independently_compiled.len);
}

test "V6 row4 template matches two executed native transcripts" {
    const allocator = std.testing.allocator;
    const fixture_support = @import("segment_transcript_outer_source_v2_test_support.zig");
    const source_contract = @import("segment_transcript_outer_source_v2_contract.zig");
    const source_writer = @import("segment_transcript_outer_source_v2_write_rows_assume_valid.zig");
    var fixture = try fixture_support.Fixture.init(allocator);
    defer fixture.deinit();
    var changed_commitments = fixture.trace_commitments;
    changed_commitments[0][0] +%= 1;
    var second_execution = try transcript.execute(allocator, &fixture.program, &fixture.data, .{
        .trace_commitments = &changed_commitments,
        .interaction_pow = 0,
        .claimed_sums = &fixture.claimed_sums,
        .sampled_values = &fixture.sampled_values,
        .fri_commitments = &fixture.fri_commitments,
        .last_layer_coefficients = &fixture.last_layer_coefficients,
        .pcs_pow = 0,
    });
    defer second_execution.deinit();
    const first_counts = try source_contract.deriveCounts(&fixture.program, &fixture.execution, &fixture.plan);
    const second_counts = try source_contract.deriveCounts(&fixture.program, &second_execution, &fixture.plan);
    try std.testing.expectEqualDeep(first_counts, second_counts);
    var first = try fixture_support.OwnedDestinations.init(allocator, first_counts);
    defer first.deinit();
    var second = try fixture_support.OwnedDestinations.init(allocator, second_counts);
    defer second.deinit();
    source_writer.writeRowsAssumeValid(first.view(), &fixture.program, &fixture.execution, &fixture.plan);
    source_writer.writeRowsAssumeValid(second.view(), &fixture.program, &second_execution, &fixture.plan);
    var template = try Template.build(allocator, fixture.program.instructions);
    defer template.deinit();
    try template.validateSource(first.transcript_word);
    try template.validateSource(second.transcript_word);
    var differing_payloads: usize = 0;
    for (first.transcript_word, second.transcript_word) |left, right| {
        try std.testing.expectEqualDeep(left.preprocessing, right.preprocessing);
        if (left.value.toU32() != right.value.toU32()) differing_payloads += 1;
    }
    try std.testing.expect(differing_payloads > 0);
}
