//! Verifier-owned row-5 fixed schedule for the V7 native half-word bridge.
//! It recompiles transcript payload metadata from the admitted instruction
//! sequence; no native payload value or child proof enters the fixed columns.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const instruction = @import("transcript_instruction_template_v6.zig");
const transcript = @import("transcript_program_v2.zig");
const source = @import("segment_transcript_outer_source_v2_prepared_v2.zig");
const components = @import("segment_transcript_outer_components_v2_source.zig");
const frame_template = @import("transcript_word_template_v6.zig");
const payload_relation = @import("air/transcript_payload_relation.zig");
const direct = @import("air/transcript_payload_direct_v7.zig");
const fanout = @import("segment_leaf_wrapper_row5_fanout_v6.zig");
const halves = @import("segment_leaf_wrapper_row5_halves_v7.zig");
const link = @import("ethereum_leaf_link_program_v3.zig");
const plan = @import("air/verifier_schedule.zig");
const statement = @import("../air/statement.zig");
const framework = @import("air/framework_interaction.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const DOMAIN = "stwo-zig/riscv-v7-row5-fixed-columns/v1\x00";

pub const Template = struct {
    allocator: std.mem.Allocator,
    rows: []direct.Row,
    id: [32]u8,

    pub fn initFromShape(
        allocator: std.mem.Allocator,
        native_plan: *const plan.Plan,
        wire_word_count: u32,
        component_descs: []const statement.FamilyComponentDesc,
        infra_descs: []const statement.InfraComponentDesc,
        lookup_enabled: bool,
        link_program: *const link.ProgramV3,
    ) !Template {
        const instructions = try instruction.compileInstructions(allocator, native_plan, wire_word_count, component_descs, infra_descs, lookup_enabled);
        defer allocator.free(instructions);
        return init(allocator, instructions, link_program);
    }

    pub fn init(allocator: std.mem.Allocator, instructions: []const transcript.Instruction, link_program: *const link.ProgramV3) !Template {
        var frames = try frame_template.Template.build(allocator, instructions);
        defer frames.deinit();
        var original: std.ArrayList(payload_relation.Row) = .empty;
        defer original.deinit(allocator);
        for (frames.rows) |frame| {
            const fixed = frame.preprocessing;
            if (fixed.is_payload == 0) continue;
            if (fixed.sequence >= instructions.len) return error.InvalidV7PayloadTemplate;
            const value = M31.fromCanonical(fixed.constant_value);
            const item = source.payloadRow(
                instructions[fixed.sequence],
                fixed.sequence,
                fixed.hash_id,
                fixed.payload_index,
                fixed.word_index,
                value,
            );
            try original.append(allocator, components.payloadLogicalRow(item));
        }
        var selected = try fanout.Schedule.init(allocator, link_program, original.items);
        defer selected.deinit();
        const zero_words = [_]M31{M31.zero()} ** halves.WIRE_WORD_COUNT;
        const wire = try halves.Schedule.init(allocator, selected.rows, &zero_words);
        const rows = wire.rows;
        return .{ .allocator = allocator, .rows = rows, .id = fixedDigest(rows) };
    }

    pub fn deinit(self: *Template) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateSource(
        self: *const Template,
        allocator: std.mem.Allocator,
        link_program: *const link.ProgramV3,
        native_rows: []const payload_relation.Row,
        wire_words: []const M31,
    ) !void {
        if (!std.meta.eql(self.id, fixedDigest(self.rows)))
            return error.InvalidV7PayloadFixedSchedule;
        var selected = try fanout.Schedule.init(allocator, link_program, native_rows);
        defer selected.deinit();
        var wire = try halves.Schedule.init(allocator, selected.rows, wire_words);
        defer wire.deinit();
        if (wire.rows.len != self.rows.len) return error.V7PayloadFixedSourceMismatch;
        for (wire.rows, self.rows) |actual, expected| {
            const start = direct.PHYSICAL_MAIN_COLUMN_COUNT;
            if (!std.mem.eql(M31, actual[start..][0..direct.PREPROCESSED_COLUMN_COUNT], expected[start..][0..direct.PREPROCESSED_COLUMN_COUNT]))
                return error.V7PayloadFixedSourceMismatch;
        }
    }

    pub fn writeInto(self: *const Template, log_size: u32, columns: [][]M31) !void {
        if (log_size >= @bitSizeOf(usize) or columns.len != direct.PREPROCESSED_COLUMN_COUNT)
            return error.InvalidV7PayloadFixedGeometry;
        const capacity = @as(usize, 1) << @intCast(log_size);
        if (self.rows.len > capacity or !std.meta.eql(self.id, fixedDigest(self.rows)))
            return error.InvalidV7PayloadFixedSchedule;
        for (columns) |column| {
            if (column.len != capacity) return error.InvalidV7PayloadFixedGeometry;
            for (column) |value| if (!value.isZero()) return error.V7PayloadFixedDestinationNotFresh;
        }
        for (self.rows, 0..) |row, logical| {
            const committed = framework.committedRow(logical, log_size);
            for (row[direct.PHYSICAL_MAIN_COLUMN_COUNT..][0..direct.PREPROCESSED_COLUMN_COUNT], columns) |value, column|
                column[committed] = value;
        }
    }
};

fn fixedDigest(rows: []const direct.Row) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(DOMAIN);
    hash.update(&direct.SEMANTIC_DIGEST);
    var count: [8]u8 = undefined;
    std.mem.writeInt(u64, &count, rows.len, .little);
    hash.update(&count);
    for (rows) |row| for (row[direct.PHYSICAL_MAIN_COLUMN_COUNT..][0..direct.PREPROCESSED_COLUMN_COUNT]) |value| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, value.toU32(), .little);
        hash.update(&bytes);
    };
    return hash.finalResult();
}

test "V7 row5 fixed schedule comes from admitted transcript shape" {
    const allocator = std.testing.allocator;
    const child_fixture = @import("tests/ethereum_leaf_child_field_test.zig");
    var plans = try @import("segment_profile.zig").initPlans(allocator, 16, 16);
    defer plans.vm.deinit();
    defer plans.recursion.deinit();
    var link_program = try link.ProgramV3.init(allocator);
    defer link_program.deinit();
    var fixed = try Template.initFromShape(allocator, &plans.vm, 128, &child_fixture.components, &child_fixture.infra, false, &link_program);
    defer fixed.deinit();
    const log_size: u32 = @intCast(std.math.log2_int_ceil(usize, @max(fixed.rows.len, 16)));
    const capacity = @as(usize, 1) << @intCast(log_size);
    const columns = try allocator.alloc([]M31, direct.PREPROCESSED_COLUMN_COUNT);
    defer allocator.free(columns);
    for (columns) |*column| {
        column.* = try allocator.alloc(M31, capacity);
        @memset(column.*, M31.zero());
    }
    defer for (columns) |column| allocator.free(column);
    try fixed.writeInto(log_size, columns);
    for (fixed.rows, 0..) |row, logical| {
        const committed = framework.committedRow(logical, log_size);
        for (row[direct.PHYSICAL_MAIN_COLUMN_COUNT..][0..direct.PREPROCESSED_COLUMN_COUNT], columns) |value, column|
            try std.testing.expectEqual(value.toU32(), column[committed].toU32());
    }
    try std.testing.expectError(error.V7PayloadFixedDestinationNotFresh, fixed.writeInto(log_size, columns));
    fixed.rows[0][direct.PHYSICAL_MAIN_COLUMN_COUNT] = M31.zero();
    try std.testing.expectError(error.InvalidV7PayloadFixedSchedule, fixed.writeInto(log_size, columns));
}
