//! Verifier-owned public statement; no execution or witness generation here.
const std = @import("std");
const isa = @import("../decode.zig");
pub const MAX_STEPS = 256;
pub const MAX_PROGRAM_WORDS = 4096;
pub const MAX_CELLS = 128;
pub const Cell = struct { address: u64, initial: u64, final: u64, readable: bool = true, writable: bool = true };
pub const Statement = struct {
    program_base: u64,
    program: []const u32,
    /// Empty for dense v2; sorted exact PCs for sparse v3.
    program_addresses: []const u64 = &.{},
    initial_pc: u64,
    final_pc: u64,
    initial_registers: [32]u64,
    final_registers: [32]u64,
    memory: []const Cell,
    steps: u32,

    pub fn validate(self: Statement) !void {
        if (self.steps == 0 or self.steps > MAX_STEPS or self.program.len == 0 or self.program.len > MAX_PROGRAM_WORDS or self.memory.len > MAX_CELLS) return error.InvalidRv64StatementSize;
        if (self.program_base & 3 != 0 or self.initial_pc & 3 != 0 or self.final_pc & 3 != 0) return error.InvalidRv64Pc;
        if (self.program_addresses.len != 0) {
            if (self.program_addresses.len != self.program.len or self.program_addresses[0] != self.program_base) return error.InvalidRv64Program;
            for (self.program_addresses, 0..) |pc, i| {
                if (pc & 3 != 0 or (i != 0 and self.program_addresses[i - 1] >= pc)) return error.InvalidRv64Program;
            }
        } else {
            _ = std.math.add(u64, self.program_base, @as(u64, @intCast(self.program.len * 4 - 1))) catch return error.InvalidRv64Program;
        }
        _ = try self.instruction(self.initial_pc);
        if (self.initial_registers[0] != 0 or self.final_registers[0] != 0) return error.InvalidRv64ZeroRegister;
        for (self.memory, 0..) |cell, i| {
            if (cell.address & 7 != 0 or cell.address > std.math.maxInt(u64) - 7) return error.InvalidRv64Cell;
            if (i != 0 and self.memory[i - 1].address >= cell.address) return error.InvalidRv64CellOrder;
            if (self.program_addresses.len == 0) {
                const last = self.program_base + (self.program.len * 4 - 1);
                if (cell.address <= last and cell.address + 7 >= self.program_base) return error.Rv64ProgramMemoryOverlap;
            } else {
                const index = self.lowerBound(cell.address);
                if (index < self.program_addresses.len and self.program_addresses[index] <= cell.address + 7) return error.Rv64ProgramMemoryOverlap;
            }
            if (!cell.writable and cell.initial != cell.final) return error.InvalidRv64ReadOnlyFinal;
        }
    }

    pub fn programPc(self: Statement, index: usize) u64 {
        return if (self.program_addresses.len == 0) self.program_base + 4 * index else self.program_addresses[index];
    }
    fn lowerBound(self: Statement, pc: u64) usize {
        var low: usize = 0;
        var high = self.program_addresses.len;
        while (low < high) {
            const mid = low + (high - low) / 2;
            if (self.program_addresses[mid] < pc) low = mid + 1 else high = mid;
        }
        return low;
    }

    pub fn instruction(self: Statement, pc: u64) !isa.Instruction {
        if (pc < self.program_base or pc & 3 != 0) return error.InvalidRv64Pc;
        const offset = if (self.program_addresses.len != 0) blk: {
            const index = self.lowerBound(pc);
            if (index >= self.program_addresses.len or self.program_addresses[index] != pc) return error.InvalidRv64Pc;
            break :blk index;
        } else (pc - self.program_base) / 4;
        if (offset >= self.program.len) return error.InvalidRv64Pc;
        const instruction_value = try isa.Instruction.decode(self.program[@intCast(offset)]);
        if (instruction_value.opcode == .ECALL or instruction_value.opcode == .EBREAK) return error.UnsupportedRv64ProofOpcode;
        return instruction_value;
    }
};

pub const Metadata = struct {
    path: []u64,
    register_clocks: [32]u16,
    memory_clocks: []u16,

    pub fn validate(self: Metadata, statement: Statement) !void {
        try statement.validate();
        if (self.path.len != statement.steps or self.memory_clocks.len != statement.memory.len or self.register_clocks[0] != 0) return error.InvalidRv64Metadata;
        if (self.path[0] != statement.initial_pc) return error.InvalidRv64Metadata;
        for (self.path) |pc| _ = try statement.instruction(pc);
        for (self.register_clocks) |clock| if (clock > 4 * statement.steps) return error.InvalidRv64Clock;
        for (self.memory_clocks) |clock| if (clock > 4 * statement.steps) return error.InvalidRv64Clock;
    }
    pub fn deinit(self: *Metadata, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.memory_clocks);
        self.* = undefined;
    }
};
