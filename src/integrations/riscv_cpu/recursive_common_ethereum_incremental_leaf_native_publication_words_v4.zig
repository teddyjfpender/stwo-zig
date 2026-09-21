//! Join authenticated native transcript inputs into schema-3 source hash words.
//! The raw bus comes from row5 payloads and row3 terminal digest inputs. Values
//! are witnesses; the AIR consumes the raw words and constrains every join.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const air = @import("stwo_riscv_frontend").recursion.air.ethereum_publication_control_v1;
const hashes = @import("recursive_common_ethereum_incremental_leaf_publication_hash_v4.zig");
pub const RAW_ROW_COUNT: usize = 71;
pub const ROW_COUNT: usize = RAW_ROW_COUNT + 1;
pub const FIELD_ROW_COUNT: usize = ROW_COUNT - 16;
pub const SOURCE_INDICES: [RAW_ROW_COUNT]u32 = blk: {
    var result: [RAW_ROW_COUNT]u32 = undefined;
    var at = 0;
    for (16..94) |index| {
        if (index == 40 or (index >= 48 and index <= 52) or index == 61) continue;
        result[at] = index;
        at += 1;
    }
    if (at != RAW_ROW_COUNT) @compileError("native publication route count drifted");
    break :blk result;
};

pub fn write(schedule: anytype, execution: anytype, destination: []air.Relation.Row) !void {
    return writeProfile(schedule, execution, null, destination);
}

pub fn writeFieldProfile(schedule: anytype, execution: anytype, protocol_id: [8]u32, destination: []air.Relation.Row) !void {
    return writeProfile(schedule, execution, protocol_id, destination);
}

fn writeProfile(schedule: anytype, execution: anytype, field_protocol: ?[8]u32, destination: []air.Relation.Row) !void {
    if (destination.len != (if (field_protocol != null) FIELD_ROW_COUNT else ROW_COUNT)) return error.InvalidNativePublicationRows;
    const preimage = try schedule.source.preimage();
    var row_at: usize = 0;
    for (SOURCE_INDICES) |index| {
        if (field_protocol != null and index < 32) continue; // Actual native hash outputs supply16..31.
        const row = &destination[row_at];
        row_at += 1;
        const value = preimage[index];
        const joined = index < 40 or index == 41;
        const low = if (joined) value & 0xffff else value;
        const high = if (joined) value >> 16 else 0;
        var pp = [_]u32{0} ** air.PREPROCESSED_COLUMN_COUNT;
        pp[9] = 1;
        pp[13] = 1;
        pp[14] = hashes.hashScope(.source);
        pp[15] = index;
        if (field_protocol) |protocol_id| if (index >= 32 and index < 40) {
            if (value != protocol_id[index - 32]) return error.InvalidNativePublicationRows;
            pp[30] = 1;
            pp[31] = protocol_id[index - 32];
            row.* = air.wordRow(M31.fromCanonical(value), pp);
            continue;
        };
        if (index >= 41 and index <= 47) {
            pp[16] = 1;
            pp[17] = 1115;
            pp[18] = index;
        }
        row.* = try air.rawWordRow(M31.fromCanonical(value), M31.fromCanonical(low), M31.fromCanonical(high), joined, index * 2, pp);
    }
    const count = try finalDrawCount(execution.operations);
    if (count != execution.final_draw_count or count != preimage[61]) return error.InvalidNativePublicationRows;
    var pp = [_]u32{0} ** air.PREPROCESSED_COLUMN_COUNT;
    pp[9] = 1;
    pp[13] = 1;
    pp[14] = hashes.hashScope(.source);
    pp[15] = 61;
    pp[30] = 1;
    pp[31] = count;
    if (row_at + 1 != destination.len) return error.InvalidNativePublicationRows;
    destination[row_at] = air.wordRow(M31.fromCanonical(count), pp);
}

pub fn finalDrawCount(operations: anytype) !u32 {
    var count: u32 = 0;
    for (operations) |operation| switch (operation.effect) {
        .mix, .pow => count = 0,
        .draw => count = try std.math.add(u32, count, 1),
    };
    if (count >= @import("stwo_core").fields.m31.Modulus) return error.InvalidNativePublicationRows;
    return count;
}

test "Ethereum native publication count derives from operation effects including pow reset" {
    const Effect = @import("stwo_riscv_frontend").recursion.recording_poseidon_channel_v4.Effect;
    const Op = struct { effect: Effect };
    const operations = [_]Op{ .{ .effect = .draw }, .{ .effect = .mix }, .{ .effect = .draw }, .{ .effect = .draw }, .{ .effect = .pow }, .{ .effect = .draw }, .{ .effect = .draw }, .{ .effect = .draw } };
    try std.testing.expectEqual(@as(u32, 0), try finalDrawCount(operations[0..0]));
    try std.testing.expectEqual(@as(u32, 2), try finalDrawCount(operations[0..4]));
    try std.testing.expectEqual(@as(u32, 0), try finalDrawCount(operations[0..5]));
    try std.testing.expectEqual(@as(u32, 3), try finalDrawCount(&operations));
}

test "ethereum native publication coordinates retain unresolved source obligations" {
    try std.testing.expectEqual(@as(usize, 71), SOURCE_INDICES.len);
    for (SOURCE_INDICES) |index|
        try std.testing.expect(index >= 16 and index < 94 and index != 40 and
            index != 61 and !(index >= 48 and index <= 52));
}

test "Ethereum completion policy publication relays the same native fields" {
    const Source = struct {
        words: [104]u32 = .{0} ** 104,
        pub fn preimage(self: *const @This()) ![104]u32 {
            return self.words;
        }
    };
    var schedule = struct { source: Source }{ .source = .{} };
    schedule.source.words[41] = 3;
    schedule.source.words[61] = 2;
    const Op = struct { effect: @import("stwo_riscv_frontend").recursion.recording_poseidon_channel_v4.Effect };
    const operations = [_]Op{ .{ .effect = .draw }, .{ .effect = .draw } };
    const execution = .{ .operations = &operations, .final_draw_count = @as(u32, 2) };
    var rows: [ROW_COUNT]air.Relation.Row = undefined;
    try write(&schedule, &execution, &rows);
    const pp = air.PHYSICAL_MAIN_COLUMN_COUNT;
    var relays: usize = 0;
    for (rows[0..RAW_ROW_COUNT], SOURCE_INDICES) |row, source_index| {
        const has_relay = source_index >= 41 and source_index <= 47;
        try std.testing.expectEqual(@as(u32, @intFromBool(has_relay)), row[pp + 16].toU32());
        if (has_relay) {
            relays += 1;
            try std.testing.expectEqual(@as(u32, 1115), row[pp + 17].toU32());
            try std.testing.expectEqual(source_index, row[pp + 18].toU32());
            try std.testing.expectEqual(schedule.source.words[source_index], row[0].toU32());
        }
    }
    try std.testing.expectEqual(@as(usize, 7), relays);
}
