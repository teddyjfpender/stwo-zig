//! Diagnostic relations for the non-production analyze_legacy candidate.
//!
//! Scan rows request `(call_index, source_cursor)` exactly when the scanned
//! opcode is JUMPDEST. Bitmap rows supply the same tuple for every decomposed
//! set bit. This file exposes field-generic interaction fractions and a host
//! multiset validator; no production relation ID, transcript slot, or
//! interaction component is registered.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const candidate = @import("analyze_legacy_candidate_v1.zig");
const scan = @import("analyze_legacy_scan_candidate_v1.zig");
const bitmap = @import("analyze_legacy_bitmap_candidate_v1.zig");

pub const production_active = false;
pub const relation_registered = false;
pub const interaction_component_ready = false;
pub const relation_name = "stwo.riscv.analyze-legacy-jumpdest.v1";
pub const relation_version: u16 = 1;
pub const relation_arity: usize = 2;

pub const Error = error{
    DescriptorMismatch,
    JumpdestMultiplicityMismatch,
    OutOfMemory,
};

pub const JumpEvent = struct {
    call_index: u32,
    cursor: u32,
};

pub fn Elements(comptime S: type) type {
    return struct {
        z: S,
        alpha: S,

        pub fn combine(self: @This(), tuple: [relation_arity]S) S {
            return self.z.add(tuple[0]).add(self.alpha.mul(tuple[1]));
        }
    };
}

pub fn Fraction(comptime S: type) type {
    return struct {
        numerator: S,
        denominator: S,
    };
}

pub fn scanTuple(
    comptime S: type,
    row: *const scan.Row(S),
) [relation_arity]S {
    return .{ row.call_index, row.cursor };
}

pub fn scanInteraction(
    comptime S: type,
    row: *const scan.Row(S),
    elements: Elements(S),
) Fraction(S) {
    const tuple = scanTuple(S, row);
    return .{
        .numerator = S.zero().sub(row.active.mul(row.is_jumpdest)),
        .denominator = elements.combine(tuple),
    };
}

pub fn bitmapInteraction(
    comptime S: type,
    row: *const bitmap.Row(S),
    bit: usize,
    elements: Elements(S),
) Fraction(S) {
    const tuple = bitmap.jumpdestTuple(S, row, bit);
    return .{
        .numerator = bitmap.bitmapWeight(S, row, bit),
        .denominator = elements.combine(tuple),
    };
}

pub fn validateStatement(
    descriptor: candidate.DescriptorV1,
    scan_rows: []const scan.Row(M31),
    bitmap_rows: []const bitmap.Row(M31),
) Error!void {
    if (scan_rows.len != descriptor.summary.scan_iterations or
        bitmap_rows.len != descriptor.bitmapWordRows() or
        scan_rows.len == 0 or
        bitmap_rows.len == 0)
    {
        return error.DescriptorMismatch;
    }
    const first_scan = scan_rows[0];
    const last_scan = scan_rows[scan_rows.len - 1];
    const first_bitmap = bitmap_rows[0];
    const last_bitmap = bitmap_rows[bitmap_rows.len - 1];
    if (first_scan.active.toU32() != 1 or
        first_scan.is_first.toU32() != 1 or
        last_scan.is_last.toU32() != 1 or
        first_bitmap.active.toU32() != 1 or
        first_bitmap.is_first.toU32() != 1 or
        last_bitmap.is_last.toU32() != 1 or
        first_scan.call_index.toU32() != descriptor.call_index or
        first_scan.source_pointer.toU32() != descriptor.source_pointer or
        first_scan.source_length.toU32() != descriptor.source_length or
        first_scan.bitmap_bytes.toU32() != descriptor.summary.bitmap_bytes or
        first_scan.expected_scan_iterations.toU32() !=
            descriptor.summary.scan_iterations or
        first_scan.expected_push_count.toU32() != descriptor.summary.push_count or
        first_scan.expected_jumpdest_count.toU32() !=
            descriptor.summary.jumpdest_count or
        last_scan.push_overflow.toU32() != descriptor.summary.push_overflow or
        last_scan.eof_immediate_padding.toU32() !=
            descriptor.summary.eof_immediate_padding or
        last_scan.total_padding.toU32() != descriptor.summary.total_padding or
        first_bitmap.call_index.toU32() != descriptor.call_index or
        first_bitmap.source_length.toU32() != descriptor.source_length or
        first_bitmap.bitmap_bytes.toU32() != descriptor.summary.bitmap_bytes or
        first_bitmap.expected_jumpdest_count.toU32() !=
            descriptor.summary.jumpdest_count)
    {
        return error.DescriptorMismatch;
    }
    try validateExactJumpdestClosure(scan_rows, bitmap_rows);
}

pub fn validateExactJumpdestClosure(
    scan_rows: []const scan.Row(M31),
    bitmap_rows: []const bitmap.Row(M31),
) Error!void {
    var requests = std.AutoHashMap(JumpEvent, i64).init(std.heap.page_allocator);
    defer requests.deinit();
    for (scan_rows) |row| {
        if (row.active.toU32() == 1 and row.is_jumpdest.toU32() == 1) {
            const event = JumpEvent{
                .call_index = row.call_index.toU32(),
                .cursor = row.cursor.toU32(),
            };
            const result = requests.getOrPut(event) catch return error.OutOfMemory;
            if (!result.found_existing) result.value_ptr.* = 0;
            result.value_ptr.* -= 1;
        }
    }
    for (bitmap_rows) |row| {
        if (row.active.toU32() != 1) continue;
        for (row.bitmap_bits, 0..) |bit_value, bit| {
            if (bit_value.toU32() != 1) continue;
            const event = JumpEvent{
                .call_index = row.call_index.toU32(),
                .cursor = row.word_index.toU32() * bitmap.bits_per_word +
                    @as(u32, @intCast(bit)),
            };
            const result = requests.getOrPut(event) catch return error.OutOfMemory;
            if (!result.found_existing) result.value_ptr.* = 0;
            result.value_ptr.* += 1;
        }
    }
    var iterator = requests.valueIterator();
    while (iterator.next()) |multiplicity| {
        if (multiplicity.* != 0) return error.JumpdestMultiplicityMismatch;
    }
}

pub fn relationIdentity() [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update(relation_name);
    hash.update(&u16Bytes(relation_version));
    hash.update(&u16Bytes(relation_arity));
    const program = candidate.verifierProgramIdentity();
    hash.update(&program);
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn u16Bytes(value: anytype) [2]u8 {
    var result: [2]u8 = undefined;
    std.mem.writeInt(u16, &result, @intCast(value), .little);
    return result;
}

comptime {
    if (production_active or
        relation_registered or
        interaction_component_ready or
        relation_arity != bitmap.jumpdest_relation_arity)
    {
        @compileError("analyze_legacy JUMPDEST relation drifted");
    }
}
