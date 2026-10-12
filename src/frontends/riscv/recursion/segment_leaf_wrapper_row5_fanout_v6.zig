//! Exact diagnostic fan-out for the 112 native transcript-claim words read by
//! direct row39. It changes only row5's key-owned input-use count; the row5
//! AIR and the committed main value remain the native verifier's originals.
//! A V6 Tree0/key and physical row5 writer are required before proof use.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const payload = @import("air/transcript_payload.zig");
const PayloadRow = @import("air/transcript_payload_relation.zig").Row;
const link_program = @import("ethereum_leaf_link_program_v3.zig");
const old_program = @import("ethereum_leaf_link_program_v1.zig");
const source_air = @import("air/ethereum_leaf_link_source_v1.zig");

pub const PRODUCTION_PROOF_ACTIVATION = false;
pub const EXPECTED_NATIVE_CLAIM_WORDS: usize = link_program.TRANSCRIPT_CLAIM_COUNT * old_program.SECURE_VALUE_WORD_COUNT;
pub const ROW5_INPUT_USE_COUNT_COLUMN: usize = payload.PHYSICAL_MAIN_COLUMN_COUNT + 15;
pub const ROW5_CONSTANT_MASK_COLUMN: usize = payload.PHYSICAL_MAIN_COLUMN_COUNT + 14;
pub const ROW5_CONSTANT_VALUE_COLUMN: usize = payload.PHYSICAL_MAIN_COLUMN_COUNT + 16;

pub const Schedule = struct {
    allocator: std.mem.Allocator,
    rows: []PayloadRow,
    selected: []bool,
    id: [32]u8,
    selected_count: usize,

    pub fn init(allocator: std.mem.Allocator, program: *const link_program.ProgramV3, native_rows: []const PayloadRow) !Schedule {
        try program.validate();
        const rows = try allocator.dupe(PayloadRow, native_rows);
        errdefer allocator.free(rows);
        const selected = try allocator.alloc(bool, native_rows.len);
        errdefer allocator.free(selected);
        @memset(selected, false);
        var count: usize = 0;
        for (program.source_rows) |source| {
            if (source.transcript_mask == 0) continue;
            if (source.active != 1 or source.transcript_mask != 1 or source.verifier_mask != 0 or
                source.kind != source_air.TRANSCRIPT_CLAIM_KIND or source.use_count != 1)
                return error.InvalidDirectRow5FanoutSource;
            var found: ?usize = null;
            for (native_rows, 0..) |row, index| {
                if (row[payload.PHYSICAL_MAIN_COLUMN_COUNT + 3].toU32() != source_air.VERIFIER_ID or
                    row[payload.PHYSICAL_MAIN_COLUMN_COUNT + 11].toU32() != source.kind or
                    row[payload.PHYSICAL_MAIN_COLUMN_COUNT + 12].toU32() != source.index_0 or
                    row[payload.PHYSICAL_MAIN_COLUMN_COUNT + 13].toU32() != source.index_1 or
                    row[ROW5_INPUT_USE_COUNT_COLUMN].toU32() != 1)
                    continue;
                if (found != null) return error.DuplicateDirectRow5FanoutSource;
                found = index;
            }
            const index = found orelse return error.MissingDirectRow5FanoutSource;
            if (selected[index] or native_rows[index][ROW5_CONSTANT_MASK_COLUMN].toU32() != 0 or
                native_rows[index][ROW5_CONSTANT_VALUE_COLUMN].toU32() != 0)
                return error.InvalidDirectRow5FanoutSource;
            selected[index] = true;
            rows[index][ROW5_INPUT_USE_COUNT_COLUMN] = M31.fromCanonical(2);
            count += 1;
        }
        if (count != EXPECTED_NATIVE_CLAIM_WORDS) return error.IncompleteDirectRow5Fanout;
        var result = Schedule{ .allocator = allocator, .rows = rows, .selected = selected, .id = undefined, .selected_count = count };
        result.id = result.scheduleId(program);
        return result;
    }

    pub fn deinit(self: *Schedule) void {
        self.allocator.free(self.rows);
        self.allocator.free(self.selected);
        self.* = undefined;
    }

    pub fn validateAgainst(self: *const Schedule, program: *const link_program.ProgramV3, native_rows: []const PayloadRow) !void {
        var wanted = try init(self.allocator, program, native_rows);
        defer wanted.deinit();
        if (self.rows.len != wanted.rows.len or self.selected_count != wanted.selected_count or
            !std.meta.eql(self.id, wanted.id) or !std.mem.eql(bool, self.selected, wanted.selected))
            return error.InvalidDirectRow5Fanout;
        for (self.rows, wanted.rows) |actual, expected|
            if (!std.meta.eql(actual, expected)) return error.InvalidDirectRow5Fanout;
    }

    fn scheduleId(self: *const Schedule, program: *const link_program.ProgramV3) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo-zig/riscv-direct-row5-fanout/v6\x00");
        hash.update(&program.schedule_id);
        for (self.rows) |row| for (row[payload.PHYSICAL_MAIN_COLUMN_COUNT .. payload.PHYSICAL_MAIN_COLUMN_COUNT + payload.PREPROCESSED_COLUMN_COUNT]) |word| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word.toU32(), .little);
            hash.update(&bytes);
        };
        return hash.finalResult();
    }
};

test "row5 V6 fan-out selects exactly the native transcript claims" {
    const allocator = std.testing.allocator;
    var program = try link_program.ProgramV3.init(allocator);
    defer program.deinit();
    const native_rows = try allocator.alloc(PayloadRow, EXPECTED_NATIVE_CLAIM_WORDS);
    defer allocator.free(native_rows);
    var at: usize = 0;
    for (program.source_rows) |source| {
        if (source.transcript_mask == 0) continue;
        var row = [_]M31{M31.zero()} ** payload.LOGICAL_INPUT_COUNT;
        row[0] = M31.one();
        row[1] = M31.fromCanonical(@intCast(at + 1));
        row[payload.PHYSICAL_MAIN_COLUMN_COUNT + 3] = M31.fromCanonical(source_air.VERIFIER_ID);
        row[payload.PHYSICAL_MAIN_COLUMN_COUNT + 11] = M31.fromCanonical(source.kind);
        row[payload.PHYSICAL_MAIN_COLUMN_COUNT + 12] = M31.fromCanonical(source.index_0);
        row[payload.PHYSICAL_MAIN_COLUMN_COUNT + 13] = M31.fromCanonical(source.index_1);
        row[ROW5_INPUT_USE_COUNT_COLUMN] = M31.one();
        native_rows[at] = row;
        at += 1;
    }
    try std.testing.expectEqual(EXPECTED_NATIVE_CLAIM_WORDS, at);
    var schedule = try Schedule.init(allocator, &program, native_rows);
    defer schedule.deinit();
    try schedule.validateAgainst(&program, native_rows);
    try std.testing.expectEqual(EXPECTED_NATIVE_CLAIM_WORDS, schedule.selected_count);
    schedule.rows[0][ROW5_INPUT_USE_COUNT_COLUMN] = M31.one();
    try std.testing.expectError(error.InvalidDirectRow5Fanout, schedule.validateAgainst(&program, native_rows));
    schedule.rows[0][ROW5_INPUT_USE_COUNT_COLUMN] = M31.fromCanonical(2);
    native_rows[0][ROW5_CONSTANT_MASK_COLUMN] = M31.one();
    try std.testing.expectError(error.InvalidDirectRow5FanoutSource, Schedule.init(allocator, &program, native_rows));
}
