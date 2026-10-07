//! Exact V6 row-5 NPV2 wire-ID export from the native Fiat–Shamir payload.
//! This owns only a diagnostic schedule until row 5's physical columns and
//! the complete fixed-key root are independently rebuilt and committed.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const base_air = @import("air/transcript_payload.zig");
const base = @import("air/transcript_payload_relation.zig");
const direct = @import("air/transcript_payload_direct_v6.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const WIRE_WORD_COUNT: usize = base_air.NPV2_WIRE_WORD_COUNT;

pub const Schedule = struct {
    allocator: std.mem.Allocator,
    rows: []direct.Row,
    wire_positions: [WIRE_WORD_COUNT]usize,

    pub fn init(
        allocator: std.mem.Allocator,
        native_rows: []const base.Row,
        expected_wire_words: []const M31,
    ) !Schedule {
        if (expected_wire_words.len != WIRE_WORD_COUNT or native_rows.len == 0)
            return error.InvalidDirectWireWordCount;
        const rows = try allocator.alloc(direct.Row, native_rows.len);
        errdefer allocator.free(rows);
        var positions = [_]usize{std.math.maxInt(usize)} ** WIRE_WORD_COUNT;
        var seen: usize = 0;
        for (native_rows, rows, 0..) |native, *destination, index| {
            const source = native[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 11].toU32();
            const item = native[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 12].toU32();
            const limb = native[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 13].toU32();
            const is_wire = source == @intFromEnum(base_air.VerifierInputKind.statement) and item == 1;
            if (is_wire) {
                if (limb >= WIRE_WORD_COUNT or positions[limb] != std.math.maxInt(usize) or
                    !native[1].eql(expected_wire_words[limb]))
                    return error.InvalidDirectWireSource;
                positions[limb] = index;
                seen += 1;
            }
            destination.* = try direct.logicalRow(native, is_wire);
        }
        if (seen != WIRE_WORD_COUNT) return error.IncompleteDirectWireSource;
        return .{ .allocator = allocator, .rows = rows, .wire_positions = positions };
    }

    pub fn deinit(self: *Schedule) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Schedule, native_rows: []const base.Row, expected_wire_words: []const M31) !void {
        var wanted = try init(self.allocator, native_rows, expected_wire_words);
        defer wanted.deinit();
        if (!std.meta.eql(self.wire_positions, wanted.wire_positions) or
            self.rows.len != wanted.rows.len)
            return error.InvalidDirectWireSchedule;
        for (self.rows, wanted.rows) |actual, expected| if (!std.meta.eql(actual, expected))
            return error.InvalidDirectWireSchedule;
    }
};

test "V6 row5 exports exactly the eight transcript-bound wire IDs" {
    const allocator = std.testing.allocator;
    var original = [_]base.Row{[_]M31{M31.zero()} ** base_air.LOGICAL_INPUT_COUNT} ** WIRE_WORD_COUNT;
    var words: [WIRE_WORD_COUNT]M31 = undefined;
    for (&original, &words, 0..) |*row, *word, limb| {
        word.* = M31.fromCanonical(@intCast(100 + limb));
        row[0] = M31.one();
        row[1] = word.*;
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT] = M31.one();
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 1] = M31.one();
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 11] = M31.fromCanonical(@intFromEnum(base_air.VerifierInputKind.statement));
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 12] = M31.one();
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 13] = M31.fromCanonical(@intCast(limb));
        row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 15] = M31.one();
        row[base_air.LOGICAL_INPUT_COUNT - 2] = M31.one();
    }
    var schedule = try Schedule.init(allocator, &original, &words);
    defer schedule.deinit();
    try schedule.validateAgainst(&original, &words);
    for (schedule.rows, 0..) |row, limb| {
        try std.testing.expectEqual(@as(u32, 1), row[base_air.PHYSICAL_MAIN_COLUMN_COUNT + base_air.PREPROCESSED_COLUMN_COUNT].toU32());
        try std.testing.expect(row[1].eql(words[limb]));
    }
    var changed = words;
    changed[0] = changed[0].add(M31.one());
    try std.testing.expectError(error.InvalidDirectWireSource, Schedule.init(allocator, &original, &changed));
    original[0][base_air.PHYSICAL_MAIN_COLUMN_COUNT + 15] = M31.zero();
    try std.testing.expectError(error.InvalidDirectNpv2WireRow, Schedule.init(allocator, &original, &words));
}

test "V6 authority export materializes a validated local witness" {
    const allocator = std.testing.allocator;
    const fixture_mod = @import("tests/ethereum_leaf_child_field_test.zig");
    const program_mod = @import("ethereum_leaf_child_field_program_v1.zig");
    const witness_mod = @import("ethereum_leaf_child_field_witness_v1.zig");
    const local = @import("segment_leaf_wrapper_local_identity_v5.zig");
    var fixture = try fixture_mod.Fixture.init(allocator);
    defer fixture.deinit();
    var program = try program_mod.ProgramV1.initWithNativeProgramBridge(allocator, &fixture_mod.components, &fixture_mod.infra);
    defer program.deinit();
    const inputs = fixture.input();
    var witness = try witness_mod.WitnessV1.init(allocator, &program, inputs);
    defer witness.deinit();
    const rows = try local.Rows.init(allocator, &program, &witness, inputs);
    try std.testing.expectEqual(program.router_rows.len, witness.router_rows.len);
    try std.testing.expectEqualDeep(try local.directScheduleId(&program), rows.schedule_id);
}
