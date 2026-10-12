//! Exact V7 row-5 NPH2 half-word export from the native transcript payload.
//! Every wire digest word is two u16 payloads, in little-endian order.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const base_air = @import("air/transcript_payload.zig");
const base = @import("air/transcript_payload_relation.zig");
const direct = @import("air/transcript_payload_direct_v7.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const WIRE_WORD_COUNT: usize = base_air.NPV2_WIRE_WORD_COUNT;
pub const HALF_COUNT: usize = 2 * WIRE_WORD_COUNT;

pub const Schedule = struct {
    allocator: std.mem.Allocator,
    rows: []direct.Row,
    half_positions: [HALF_COUNT]usize,

    pub fn init(
        allocator: std.mem.Allocator,
        native_rows: []const base.Row,
        expected_wire_words: []const M31,
    ) !Schedule {
        if (expected_wire_words.len != WIRE_WORD_COUNT or native_rows.len == 0)
            return error.InvalidDirectWireWordCount;
        const rows = try allocator.alloc(direct.Row, native_rows.len);
        errdefer allocator.free(rows);
        var positions = [_]usize{std.math.maxInt(usize)} ** HALF_COUNT;
        var seen: usize = 0;
        for (native_rows, rows, 0..) |native, *destination, index| {
            const source = native[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 11].toU32();
            const item = native[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 12].toU32();
            const limb = native[base_air.PHYSICAL_MAIN_COLUMN_COUNT + 13].toU32();
            const is_half = source == @intFromEnum(base_air.VerifierInputKind.statement) and item == 1;
            if (is_half) {
                if (limb >= HALF_COUNT or positions[limb] != std.math.maxInt(usize))
                    return error.InvalidDirectWireHalfSource;
                const word = expected_wire_words[limb / 2].toU32();
                const expected_half: u32 = if (limb % 2 == 0) word & 0xffff else word >> 16;
                if (native[1].toU32() != expected_half) return error.InvalidDirectWireHalfSource;
                positions[limb] = index;
                seen += 1;
            }
            destination.* = try direct.logicalRow(native, is_half);
        }
        if (seen != HALF_COUNT) return error.IncompleteDirectWireHalfSource;
        return .{ .allocator = allocator, .rows = rows, .half_positions = positions };
    }

    pub fn deinit(self: *Schedule) void {
        self.allocator.free(self.rows);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Schedule, native_rows: []const base.Row, expected_wire_words: []const M31) !void {
        var wanted = try init(self.allocator, native_rows, expected_wire_words);
        defer wanted.deinit();
        if (!std.meta.eql(self.half_positions, wanted.half_positions) or
            self.rows.len != wanted.rows.len)
            return error.InvalidDirectWireHalfSchedule;
        for (self.rows, wanted.rows) |actual, expected| if (!std.meta.eql(actual, expected))
            return error.InvalidDirectWireHalfSchedule;
    }
};

test "V7 row5 exports sixteen transcript-bound u16 halves" {
    const allocator = std.testing.allocator;
    var original = [_]base.Row{[_]M31{M31.zero()} ** base_air.LOGICAL_INPUT_COUNT} ** HALF_COUNT;
    var words: [WIRE_WORD_COUNT]M31 = undefined;
    for (&words, 0..) |*word, index| word.* = M31.fromCanonical(@intCast(0x12340000 + index * 101));
    for (&original, 0..) |*row, limb| {
        const word = words[limb / 2].toU32();
        const half: u32 = if (limb % 2 == 0) word & 0xffff else word >> 16;
        row[0] = M31.one();
        row[1] = M31.fromCanonical(half);
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
        try std.testing.expect(row[1].eql(original[limb][1]));
    }
    var changed = words;
    changed[0] = changed[0].add(M31.one());
    try std.testing.expectError(error.InvalidDirectWireHalfSource, Schedule.init(allocator, &original, &changed));
    original[0][base_air.PHYSICAL_MAIN_COLUMN_COUNT + 15] = M31.zero();
    try std.testing.expectError(error.InvalidDirectWireHalfRow, Schedule.init(allocator, &original, &words));
    original[0][base_air.PHYSICAL_MAIN_COLUMN_COUNT + 15] = M31.one();
    original[1][base_air.PHYSICAL_MAIN_COLUMN_COUNT + 13] = M31.zero();
    try std.testing.expectError(error.InvalidDirectWireHalfSource, Schedule.init(allocator, &original, &words));
}
