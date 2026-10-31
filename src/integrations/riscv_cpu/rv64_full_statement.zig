//! Request identity and state closure for one full execution. No execution path
//! is public setup; immutable ROM identity is supplied by the receiver.
const std = @import("std");
const core = @import("stwo_core");
const rv = @import("stwo_riscv_frontend").rv64_air;
const Q = core.fields.qm31.QM31;
const execution_profile = @import("stwo_riscv_frontend").rv64.execution_profile;
pub const Cell = rv.statement.Cell;
pub const Statement = struct {
    program: rv.program.setup.Program,
    steps: u32,
    initial_pc: u64,
    final_pc: u64,
    initial_registers: [32]u64,
    final_registers: [32]u64,
    cells: []const Cell,
    register_clocks: [32]u32,
    memory_clocks: []const u32,
    opcodes: [65]bool,

    pub fn logSize(self: Statement) u32 {
        return @max(5, std.math.log2_int_ceil(u32, self.steps));
    }
    pub fn validate(self: Statement) !void {
        return self.validateWithProfile(.rv64im);
    }
    pub fn validateWithProfile(self: Statement, profile: execution_profile.Profile) !void {
        try self.program.validate();
        if (self.steps == 0 or self.steps >= 1 << 22 or self.initial_pc & 3 != 0 or self.final_pc & 3 != 0 or
            self.initial_registers[0] != 0 or self.final_registers[0] != 0 or self.register_clocks[0] != 0 or
            self.cells.len != self.memory_clocks.len or self.cells.len > 1 << 24) return error.InvalidRv64FullStatement;
        var any = false;
        for (self.opcodes, 0..) |enabled, op| {
            if (!enabled) continue;
            // ECALL/EBREAK are terminal traps, not authenticated retirements.
            const decoded: @import("stwo_riscv_frontend").rv64.decode.Opcode = @enumFromInt(op);
            if (!execution_profile.admitted(profile, decoded)) return error.InvalidRv64FullStatement;
            any = true;
        }
        if (!any) return error.InvalidRv64FullStatement;
        const max_clock = 4 * self.steps;
        for (self.register_clocks, 0..) |clock, reg| {
            if (clock > max_clock or (clock != 0 and (clock & 3 == 0)) or
                (clock == 0 and self.initial_registers[reg] != self.final_registers[reg])) return error.InvalidRv64FullClock;
        }
        for (self.cells, self.memory_clocks, 0..) |cell, clock, i| {
            if (cell.address & 7 != 0 or cell.address > std.math.maxInt(u64) - 7 or
                (i != 0 and self.cells[i - 1].address >= cell.address) or (!cell.readable and !cell.writable) or
                clock > max_clock or clock == 0 or clock & 3 != 0) return error.InvalidRv64FullStatement;
        }
        // Fetches use immutable ROM. RAM reads overlapping code must describe
        // precisely those same bytes, and code cannot acquire write permission.
        var instruction_index: usize = 0;
        for (self.cells) |cell| {
            while (instruction_index < self.program.words.len and self.program.pc(instruction_index) + 3 < cell.address) : (instruction_index += 1) {}
            var j = instruction_index;
            while (j < self.program.words.len and self.program.pc(j) <= cell.address + 7) : (j += 1) {
                if (cell.writable or cell.initial != cell.final) return error.Rv64MutableProgramMemory;
                const pc = self.program.pc(j);
                for (0..4) |b| {
                    const address = pc + b;
                    if (address < cell.address or address > cell.address + 7) continue;
                    const offset: u6 = @intCast((address - cell.address) * 8);
                    const shift: u5 = @intCast(b * 8);
                    if ((cell.initial >> offset) & 255 != (self.program.words[j] >> shift) & 255) return error.Rv64ProgramMemoryMismatch;
                }
            }
        }
    }
    /// Bind the request before any commitment/challenge. The caller's expected
    /// ELF/input/terminal output determines these fields independently.
    pub fn mix(self: Statement, channel: *rv.protocol.Channel, program_identity: [32]u8) !void {
        return self.mixWithProfile(channel, program_identity, .rv64im);
    }
    pub fn mixWithProfile(self: Statement, channel: *rv.protocol.Channel, program_identity: [32]u8, profile: execution_profile.Profile) !void {
        try self.validateWithProfile(profile);
        if (profile != .rv64im) channel.mixU32s(&.{ 0x52565052, 1, @intFromEnum(profile) });
        channel.mixU32s(&.{ 0x52563634, 0x46554c4c, 1, self.steps, self.logSize() });
        rv.protocol.config().mixInto(channel);
        for (program_identity) |byte| channel.mixU32s(&.{byte});
        channel.mixU64(self.initial_pc);
        channel.mixU64(self.final_pc);
        for (self.initial_registers) |value| channel.mixU64(value);
        for (self.final_registers) |value| channel.mixU64(value);
        for (self.register_clocks) |clock| channel.mixU32s(&.{clock});
        for (self.opcodes) |enabled| channel.mixU32s(&.{@intFromBool(enabled)});
        channel.mixU64(self.cells.len);
        for (self.cells, self.memory_clocks) |cell, clock| {
            channel.mixU64(cell.address);
            channel.mixU64(cell.initial);
            channel.mixU64(cell.final);
            channel.mixU32s(&.{ @intFromBool(cell.readable), @intFromBool(cell.writable), clock });
        }
    }
    pub fn expectedState(self: Statement, challenges: rv.relations.Challenges) !Q {
        return self.expectedStateWithProfile(challenges, .rv64im);
    }
    pub fn expectedStateWithProfile(self: Statement, challenges: rv.relations.Challenges, profile: execution_profile.Profile) !Q {
        try self.validateWithProfile(profile);
        var target = Q.zero();
        for (1..32) |reg| {
            target = target.add(try challenges.denominator(rv.relations.boundaryTuple(0, reg, 0, self.initial_registers[reg], true, true)).inv());
            target = target.sub(try challenges.denominator(rv.relations.boundaryTuple(0, reg, self.register_clocks[reg], self.final_registers[reg], true, true)).inv());
        }
        for (self.cells, self.memory_clocks) |cell, clock| {
            target = target.add(try challenges.denominator(rv.relations.boundaryTuple(1, cell.address, 0, cell.initial, cell.readable, cell.writable)).inv());
            target = target.sub(try challenges.denominator(rv.relations.boundaryTuple(1, cell.address, clock, cell.final, cell.readable, cell.writable)).inv());
        }
        return target;
    }
};

/// Canonical full-width RAM word lookup shared by ordinary and service journals.
pub fn cellIndex(cells: []const Cell, address: u64) !usize {
    var low: usize = 0;
    var high = cells.len;
    while (low < high) {
        const mid = low + (high - low) / 2;
        if (cells[mid].address < address) low = mid + 1 else high = mid;
    }
    if (low == cells.len or cells[low].address != address) return error.InvalidRv64FullMemoryCell;
    return low;
}
