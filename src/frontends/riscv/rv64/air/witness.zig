//! Execution-side witness ownership. No function here is verifier authority.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const core = @import("stwo_core");
const public = @import("statement.zig");
const R = @import("rows.zig");
const L = @import("layout.zig");
const hints = @import("witness_hints.zig");
const isa = @import("../decode.zig");
const execution = @import("../machine.zig");
const memory_mod = @import("../memory.zig");

pub const Witness = struct {
    allocator: std.mem.Allocator,
    metadata: public.Metadata,
    rows: []R.Main,

    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.rows);
        self.metadata.deinit(self.allocator);
        self.* = undefined;
    }

    pub fn build(a: std.mem.Allocator, statement: public.Statement) !Witness {
        try statement.validate();
        const rows = try a.alloc(R.Main, statement.steps);
        errdefer a.free(rows);
        const path = try a.alloc(u64, statement.steps);
        errdefer a.free(path);
        const clocks = try a.alloc(u16, statement.memory.len);
        errdefer a.free(clocks);
        @memset(clocks, 0);
        var result = Witness{ .allocator = a, .rows = rows, .metadata = .{ .path = path, .register_clocks = @splat(0), .memory_clocks = clocks } };
        var memory = memory_mod.Memory.init(a, .{ .max_regions = public.MAX_CELLS + public.MAX_PROGRAM_WORDS + 1 });
        defer memory.deinit();
        var first: usize = 0;
        while (first < statement.program.len) {
            var end = first + 1;
            while (end < statement.program.len and statement.programPc(end) - statement.programPc(end - 1) == 4) : (end += 1) {}
            try memory.map(.{ .start = statement.programPc(first), .size = (end - first) * 4, .permissions = .{ .read = true, .execute = true } });
            first = end;
        }
        for (statement.program, 0..) |word, i| {
            var bytes: [4]u8 = undefined;
            std.mem.writeInt(u32, &bytes, word, .little);
            try memory.initialize(statement.programPc(i), &bytes);
        }
        for (statement.memory) |cell| {
            try memory.map(.{ .start = cell.address, .size = 8, .permissions = .{ .read = cell.readable, .write = cell.writable } });
            if (cell.initial != 0) {
                var bytes: [8]u8 = undefined;
                std.mem.writeInt(u64, &bytes, cell.initial, .little);
                try memory.initialize(cell.address, &bytes);
            }
        }
        var cpu = execution.Cpu.init(statement.initial_pc, 0);
        cpu.regs = statement.initial_registers;
        for (rows, path, 0..) |*row, *pc, i| {
            pc.* = cpu.pc;
            const instruction = try statement.instruction(cpu.pc);
            const record = try cpu.step(&memory);
            const effects = isa.effects(instruction.opcode);
            var predecessors: [4]u16 = @splat(0);
            if (effects.reads_rs1 and instruction.rs1 != 0) {
                predecessors[0] = result.metadata.register_clocks[instruction.rs1];
                result.metadata.register_clocks[instruction.rs1] = @intCast(4 * i + 1);
            }
            if (effects.reads_rs2 and instruction.rs2 != 0) {
                predecessors[1] = result.metadata.register_clocks[instruction.rs2];
                result.metadata.register_clocks[instruction.rs2] = @intCast(4 * i + 2);
            }
            if (effects.writes_rd and instruction.rd != 0) {
                predecessors[2] = result.metadata.register_clocks[instruction.rd];
                result.metadata.register_clocks[instruction.rd] = @intCast(4 * i + 3);
            }
            var rights = memory_mod.Permissions{};
            if (record.memory) |event| {
                const index = try memoryIndex(statement, event.address.toInt() & ~@as(u64, 7));
                predecessors[3] = clocks[index];
                clocks[index] = @intCast(4 * i + 4);
                rights = .{ .read = statement.memory[index].readable, .write = statement.memory[index].writable };
            }
            row.* = try fromRetirement(record, instruction, predecessors, rights);
        }
        if (cpu.pc != statement.final_pc or !std.mem.eql(u64, &cpu.regs, &statement.final_registers)) return error.Rv64ExpectedFinalMismatch;
        for (statement.memory) |cell| if (memory.backing.load(cell.address, 8).value != cell.final) return error.Rv64ExpectedFinalMismatch;
        try result.metadata.validate(statement);
        return result;
    }
};

pub fn fromRetirement(record: execution.Retirement, instruction: isa.Instruction, previous: [4]u16, rights: memory_mod.Permissions) !R.Main {
    var row = try fromRetirementValues(record, instruction, rights);
    const effects = isa.effects(instruction.opcode);
    const enabled = [4]bool{ effects.reads_rs1 and instruction.rs1 != 0, effects.reads_rs2 and instruction.rs2 != 0, effects.writes_rd and instruction.rd != 0, effects.memory_width != 0 };
    for (enabled, previous, 0..) |active, before, slot| {
        if (!active) continue;
        const clock = 4 * (record.clock - 1) + slot + 1;
        if (before >= clock or clock >= 1 << L.CLOCK_BITS) return error.InvalidRv64WitnessClock;
        R.putBounded(&row, L.previousClock(slot), L.CLOCK_BITS, before);
        R.putBounded(&row, L.gap(slot), L.CLOCK_BITS, @intCast(clock - before - 1));
    }
    return row;
}

/// Constructs operand and arithmetic advice once, without imposing a clock profile.
/// The caller must encode and constrain predecessor clocks for its own profile.
pub fn fromRetirementValues(record: execution.Retirement, instruction: isa.Instruction, rights: memory_mod.Permissions) !R.Main {
    var row: R.Main = @splat(M.zero());
    R.putWord(&row, .a, record.lhs.toInt());
    R.putWord(&row, .b, record.rhs.toInt());
    R.putWord(&row, .result, record.result.toInt());
    R.putWord(&row, .previous_rd, record.previous_rd.toInt());
    row[L.taken] = R.scalar(@intFromBool(record.branch_taken));
    if (record.memory) |event| {
        R.putWord(&row, .memory_before, event.before_word.toInt());
        R.putWord(&row, .memory_after, event.after_word.toInt());
        row[L.offset_start + @as(usize, @intCast(event.address.toInt() & 7))] = M.one();
        row[L.readable] = R.scalar(@intFromBool(rights.read));
        row[L.writable] = R.scalar(@intFromBool(rights.write));
    }
    hints.fill(&row, instruction.opcode, @bitCast(instruction.imm));
    return row;
}

pub fn memoryIndex(statement: public.Statement, address: u64) !usize {
    for (statement.memory, 0..) |cell, i| if (cell.address == address) return i;
    return error.Rv64UnlistedMemoryCell;
}

pub fn physical(logical: usize, log_size: u32) usize {
    return core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, log_size), log_size);
}
