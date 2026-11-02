//! Canonical fixed rows from verifier program/path, and byte witness utilities.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const L = @import("layout.zig");
const op = @import("operations.zig");
const isa = @import("../decode.zig");
const statement = @import("statement.zig");
pub const Fixed = [L.fixed.COUNT]M;
pub const Main = [L.MAIN]M;

pub fn fixedRow(public: statement.Statement, metadata: statement.Metadata, index: usize, domain_size: usize) !Fixed {
    var row: Fixed = @splat(M.zero());
    row[L.fixed.first] = scalar(@intFromBool(index == 0));
    row[L.fixed.last] = scalar(@intFromBool(index + 1 == domain_size));
    if (index >= public.steps) return row;
    const pc = metadata.path[index];
    const instruction = try public.instruction(pc);
    const effects = isa.effects(instruction.opcode);
    const slots = [4]bool{ effects.reads_rs1 and instruction.rs1 != 0, effects.reads_rs2 and instruction.rs2 != 0, effects.writes_rd and instruction.rd != 0, effects.memory_width != 0 };
    row[L.fixed.active] = M.one();
    row[L.fixed.opcode_start + @intFromEnum(instruction.opcode)] = M.one();
    row[L.fixed.rs1] = scalar(if (slots[0]) instruction.rs1 else 0);
    row[L.fixed.rs2] = scalar(if (slots[1]) instruction.rs2 else 0);
    row[L.fixed.rd] = scalar(if (slots[2]) instruction.rd else 0);
    for (slots, 0..) |enabled, slot| {
        row[L.fixed.slot_start + slot] = scalar(@intFromBool(enabled));
        row[L.fixed.tick_start + slot] = scalar(@intCast(if (enabled) 4 * index + slot + 1 else 0));
    }
    fixedWord(&row, L.fixed.immediate, @bitCast(instruction.imm));
    fixedWord(&row, L.fixed.pc, pc);
    fixedWord(&row, L.fixed.next_pc, if (index + 1 < public.steps) metadata.path[index + 1] else public.final_pc);
    fixedWord(&row, L.fixed.increment, pc +% 4);
    fixedWord(&row, L.fixed.target, pc +% @as(u64, @bitCast(instruction.imm)));
    for (0..L.WORDS) |i| row[L.fixed.word_start + i] = scalar(@intFromBool(op.wordActive(@enumFromInt(i), instruction.opcode, slots)));
    for (0..L.CARRIES) |i| row[L.fixed.carry_start + i] = scalar(@intFromBool(op.carryActive(@enumFromInt(i / 8), i % 8, instruction.opcode)));
    return row;
}

pub fn putWord(row: *Main, which: L.Word, value: u64) void {
    for (0..8) |i| row[L.byte(which, i)] = scalar(@intCast((value >> @as(u6, @intCast(i * 8))) & 255));
    for (0..64) |i| row[L.bit(which, i)] = scalar(@intCast((value >> @as(u6, @intCast(i))) & 1));
}
pub fn getWord(row: *const Main, which: L.Word) u64 {
    var value: u64 = 0;
    for (0..8) |i| value |= @as(u64, row[L.byte(which, i)].toU32()) << @as(u6, @intCast(i * 8));
    return value;
}
pub fn putBounded(row: *Main, start: usize, bits: usize, value: u32) void {
    row[start] = scalar(value);
    for (0..bits) |i| row[start + 1 + i] = scalar((value >> @as(u5, @intCast(i))) & 1);
}
pub fn scalar(value: u32) M {
    return M.fromCanonical(value);
}
fn fixedWord(row: *Fixed, start: usize, value: u64) void {
    for (0..8) |i| row[start + i] = scalar(@intCast((value >> @as(u6, @intCast(i * 8))) & 255));
}

pub fn carryAdd(row: *Main, kind: L.Carry, a: u64, b: u64, width: usize, subtract: bool) void {
    var carry: u32 = @intFromBool(subtract);
    for (0..width) |i| {
        const aa: u32 = @intCast((a >> @as(u6, @intCast(8 * i))) & 255);
        const bb: u32 = @intCast((b >> @as(u6, @intCast(8 * i))) & 255);
        carry = (aa + (if (subtract) 255 - bb else bb) + carry) >> 8;
        row[L.carry(kind, i)] = scalar(carry);
    }
}
pub fn carryNegate(row: *Main, kind: L.Carry, a: u64, negated: u64, width: usize) void {
    var carry: u32 = 0;
    for (0..width) |i| {
        carry = (@as(u32, @intCast((a >> @as(u6, @intCast(8 * i))) & 255)) + @as(u32, @intCast((negated >> @as(u6, @intCast(8 * i))) & 255)) + carry) >> 8;
        row[L.carry(kind, i)] = scalar(carry);
    }
}
