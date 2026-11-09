//! Separate bounded OP event. Legacy curve calls retain their24-word layout.
const std = @import("std");
const machine = @import("../machine.zig");
const memory = @import("../memory.zig");
const profile = @import("../execution_profile.zig");
const Word = @import("../word.zig").Word;
pub const math = @import("bn254_tower.zig");

comptime {
    if (math.TAG != profile.OP_TOWER_TAG) @compileError("OP tower packet tag differs from execution ABI");
}

pub const Call = struct {
    op: math.Kind = .mul034,
    call_id: u64,
    clock: u64,
    pc: u64,
    pointer: u64,
    before: [math.WORDS]u64,
    output: [math.WRITTEN_WORDS]u64,

    pub fn wordAfter(self: *const Call, index: usize) u64 {
        std.debug.assert(index < math.WORDS);
        return if (index < math.WRITTEN_WORDS) self.output[index] else self.before[index];
    }
    pub fn retirement(self: *const Call) machine.Retirement {
        return .{ .clock = self.clock, .pc = Word.fromInt(self.pc), .next_pc = Word.fromInt(self.pc +% 4), .immediate = Word.fromInt(0), .instruction = 0x73, .opcode = .ECALL, .rs1 = profile.POINTER_REGISTER, .rs2 = profile.TAG_REGISTER, .lhs = Word.fromInt(self.pointer), .rhs = Word.fromInt(profile.OP_TOWER_TAG), .rd = 0, .previous_rd = Word.fromInt(0), .result = Word.fromInt(0), .writes_rd = false, .branch_taken = false, .memory = null };
    }
};

/// Rights, shape, computation and atomic store all precede CPU/counter changes.
pub fn execute(cpu: *machine.Cpu, mem: *memory.Memory, count: *u64) !Call {
    if (count.* == std.math.maxInt(u64)) return error.ServiceCounterOverflow;
    const next_clock = std.math.add(u64, cpu.retired, 1) catch return error.ServiceCounterOverflow;
    const pointer = cpu.read(profile.POINTER_REGISTER);
    if (pointer & 31 != 0) return error.MisalignedAddress;
    _ = try memory.endAddress(pointer, math.PACKET_BYTES);
    try mem.mappings.check(pointer, math.PACKET_BYTES, .read);
    try mem.mappings.check(pointer, math.WRITTEN_BYTES, .write);
    var before: [math.WORDS]u64 = undefined;
    for (&before, 0..) |*word, i| word.* = try mem.load(pointer + 8 * i, 8);
    const after = try math.execute(&before);
    try mem.storeWords(pointer, after[0..math.WRITTEN_WORDS]);
    const result = Call{ .call_id = count.* + 1, .clock = next_clock, .pc = cpu.pc, .pointer = pointer, .before = before, .output = after[0..math.WRITTEN_WORDS].* };
    cpu.pc +%= 4;
    cpu.retired = next_clock;
    count.* += 1;
    return result;
}
