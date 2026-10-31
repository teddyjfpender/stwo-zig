//! Exact semantic-family census from immutable ROM and captured PC advice.
//! This is transport/planning metadata, never a substitute for physical buses.
const std = @import("std");
const rv = @import("stwo_riscv_frontend").rv64;
const Program = @import("program.zig").Program;
pub const Counts = struct {
    alu: u32 = 0,
    binary: u32 = 0,
    shift: u32 = 0,
    jalr: u32 = 0,
    division: u32 = 0,
    multiplication: u32 = 0,
    memory: u32 = 0,
    service: u32 = 0,
    pub fn fromTape(program: *const Program, tape: *const rv.compact_tape.Tape) !Counts {
        if (tape.len == 0 or tape.len > tape.storage.len or tape.execution_profile != program.profile) return error.InvalidExecutionTape;
        var result: Counts = .{};
        var pc = tape.initial_pc;
        for (tape.storage[0..tape.len]) |step| {
            const entry = program.entries[try program.lookup(pc)];
            if (entry.function) switch (entry.operation) {
                0...9 => result.alu += 1,
                10 => {
                    result.jalr += 1;
                    result.alu += 1;
                    result.binary += 1;
                },
                16...18 => result.binary += 1,
                32...37 => result.shift += 1,
                49...52, 57 => result.multiplication += 1,
                53...56, 58...61 => result.division += 1,
                else => return error.UnsupportedExecutionFunction,
            };
            switch (entry.instruction.opcode) {
                .LB, .LH, .LW, .LD, .LBU, .LHU, .LWU, .SB, .SH, .SW, .SD => result.memory += 1,
                .ECALL => result.service += 1,
                else => {},
            }
            pc = step.next_pc;
        }
        return result;
    }
};
pub fn minimalLog(count: u32) !u32 {
    if (count > 1 << 22) return error.ExecutionCapacityExceeded;
    return @intCast(@max(5, std.math.log2_int_ceil(u32, @max(1, count))));
}
/// Prefix authorities require at least one inactive row; pure truth-fact
/// providers instead admit a completely occupied capacity via minimalLog.
pub fn minimalPrefixLog(count: u32) !u32 {
    if (count >= 1 << 22) return error.ExecutionCapacityExceeded;
    return minimalLog(count + 1);
}

/// Planning only: exact unique aligned words from captured addresses, without
/// restoring instructions, constructing state transitions or running the VM.
pub fn memoryWords(a: std.mem.Allocator, program: *const Program, tape: *const rv.compact_tape.Tape) !u32 {
    if (tape.len == 0 or tape.len > tape.storage.len or tape.execution_profile != program.profile) return error.InvalidExecutionTape;
    var words: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer words.deinit(a);
    var pc = tape.initial_pc;
    for (tape.storage[0..tape.len]) |step| {
        const entry = program.entries[try program.lookup(pc)];
        if (rv.decode.effects(entry.instruction.opcode).memory_width != 0) {
            const address = step.lhs +% @as(u64, @bitCast(entry.instruction.imm));
            try words.put(a, address & ~@as(u64, 7), {});
        }
        pc = step.next_pc;
    }
    return @intCast(words.count());
}
