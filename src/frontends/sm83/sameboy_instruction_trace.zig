//! Parser and comparator for the pinned SameBoy instruction oracle.
//!
//! The compact record is captured at SameBoy's execution callback, after the
//! opcode fetch and delayed-IME promotion but before instruction semantics.
//! It is an equivalence oracle, not a proving witness: the frontend still
//! generates and authenticates its own ordered bus and device events.

const std = @import("std");
const runner = @import("runner/mod.zig");
const machine = @import("runner/machine.zig");

pub const RECORD_SIZE: usize = 29;
pub const TICKS_PER_MCYCLE: u64 = 8;

pub const Error = error{
    EmptyTrace,
    InvalidTraceLength,
    RecordIndexOutOfBounds,
    InvalidBoolean,
    InvalidFlags,
    InvalidTickAlignment,
    MachineClockOverflow,
    NonIncreasingTicks,
    NotInstruction,
    CpuMismatch,
    OpcodeMismatch,
    InterruptEnableMismatch,
    InterruptFlagsMismatch,
    RomBankMismatch,
    OracleExhausted,
    TimingMismatch,
    InstructionCountMismatch,
};

pub const Record = struct {
    ticks_8mhz: u64,
    pc: u16,
    sp: u16,
    af: u16,
    bc: u16,
    de: u16,
    hl: u16,
    rom_bank: u16,
    opcode: u8,
    ime: u8,
    ime_toggle: u8,
    halted: u8,
    stopped: u8,
    interrupt_enable: u8,
    interrupt_flags: u8,

    pub fn decode(bytes: []const u8) Error!Record {
        if (bytes.len != RECORD_SIZE) return error.InvalidTraceLength;
        const record = Record{
            .ticks_8mhz = std.mem.readInt(u64, bytes[0..8], .little),
            .pc = std.mem.readInt(u16, bytes[8..10], .little),
            .sp = std.mem.readInt(u16, bytes[10..12], .little),
            .af = std.mem.readInt(u16, bytes[12..14], .little),
            .bc = std.mem.readInt(u16, bytes[14..16], .little),
            .de = std.mem.readInt(u16, bytes[16..18], .little),
            .hl = std.mem.readInt(u16, bytes[18..20], .little),
            .rom_bank = std.mem.readInt(u16, bytes[20..22], .little),
            .opcode = bytes[22],
            .ime = bytes[23],
            .ime_toggle = bytes[24],
            .halted = bytes[25],
            .stopped = bytes[26],
            .interrupt_enable = bytes[27],
            .interrupt_flags = bytes[28],
        };
        try record.validate();
        return record;
    }

    pub fn validate(self: Record) Error!void {
        inline for (.{
            self.ime,
            self.ime_toggle,
            self.halted,
            self.stopped,
        }) |value| if (value > 1) return error.InvalidBoolean;
        if (self.af & 0x000f != 0) return error.InvalidFlags;
        _ = try self.callbackMcycle();
    }

    /// SameBoy invokes the callback after reading the opcode but before
    /// advancing that fetch's pending clock, so this is the instruction-start
    /// M-cycle used by callback-to-callback timing.
    pub fn callbackMcycle(self: Record) Error!u32 {
        if (self.ticks_8mhz % TICKS_PER_MCYCLE != 0)
            return error.InvalidTickAlignment;
        return std.math.cast(
            u32,
            self.ticks_8mhz / TICKS_PER_MCYCLE,
        ) orelse error.MachineClockOverflow;
    }

    pub fn cpu(self: Record) Error!runner.Cpu {
        try self.validate();
        return .{
            .a = @truncate(self.af >> 8),
            .f = @truncate(self.af),
            .b = @truncate(self.bc >> 8),
            .c = @truncate(self.bc),
            .d = @truncate(self.de >> 8),
            .e = @truncate(self.de),
            .h = @truncate(self.hl >> 8),
            .l = @truncate(self.hl),
            .sp = self.sp,
            .pc = self.pc,
            .ime = self.ime == 1,
            .ime_enable_pending = self.ime_toggle == 1,
            .halted = self.halted == 1,
            .stopped = self.stopped == 1,
        };
    }
};

pub const Trace = struct {
    bytes: []const u8,

    pub fn init(bytes: []const u8) Error!Trace {
        if (bytes.len == 0) return error.EmptyTrace;
        if (bytes.len % RECORD_SIZE != 0)
            return error.InvalidTraceLength;
        return .{ .bytes = bytes };
    }

    pub fn count(self: Trace) usize {
        return self.bytes.len / RECORD_SIZE;
    }

    pub fn record(self: Trace, index: usize) Error!Record {
        if (index >= self.count()) return error.RecordIndexOutOfBounds;
        const start = index * RECORD_SIZE;
        return Record.decode(self.bytes[start..][0..RECORD_SIZE]);
    }

    pub fn validateAll(self: Trace) Error!void {
        var previous_tick: ?u64 = null;
        for (0..self.count()) |index| {
            const current = try self.record(index);
            if (previous_tick) |previous|
                if (current.ticks_8mhz <= previous)
                    return error.NonIncreasingTicks;
            previous_tick = current.ticks_8mhz;
        }
    }
};

/// Streams scheduler events against callback records without materializing a
/// second trace. Callback-to-callback timing includes the previous
/// instruction plus every intervening HALT or interrupt-service M-cycle.
pub const Comparator = struct {
    trace: Trace,
    /// Absolute M-cycle at the restored machine boundary. When present, the
    /// first SameBoy callback must occur after intervening scheduler rows plus
    /// exactly one opcode-fetch M-cycle.
    initial_boundary_mcycle: ?u32 = null,
    next_record: usize = 0,
    previous_callback_mcycle: ?u32 = null,
    elapsed_since_callback: u64 = 0,

    pub fn observe(
        self: *Comparator,
        actual: machine.CartridgeStepResult,
    ) Error!void {
        if (actual.event != .instruction) {
            if (self.previous_callback_mcycle != null or
                self.initial_boundary_mcycle != null)
            {
                self.elapsed_since_callback = std.math.add(
                    u64,
                    self.elapsed_since_callback,
                    actual.m_cycles,
                ) catch return error.MachineClockOverflow;
            }
            return;
        }
        if (self.next_record >= self.trace.count())
            return error.OracleExhausted;

        const expected = try self.trace.record(self.next_record);
        const callback_mcycle = try expected.callbackMcycle();
        if (self.previous_callback_mcycle) |previous| {
            if (callback_mcycle <= previous)
                return error.NonIncreasingTicks;
            const oracle_delta = callback_mcycle - previous;
            if (self.elapsed_since_callback != oracle_delta)
                return error.TimingMismatch;
        } else if (self.initial_boundary_mcycle) |initial| {
            if (callback_mcycle < initial)
                return error.TimingMismatch;
            if (self.elapsed_since_callback != callback_mcycle - initial)
                return error.TimingMismatch;
        }
        try expectInstruction(expected, actual);
        self.previous_callback_mcycle = callback_mcycle;
        self.elapsed_since_callback = actual.m_cycles;
        self.next_record += 1;
    }

    pub fn expectConsumed(
        self: Comparator,
        expected_records: usize,
    ) Error!void {
        if (self.trace.count() != expected_records or
            self.next_record != expected_records)
        {
            return error.InstructionCountMismatch;
        }
    }
};

/// Compares one frontend instruction event with SameBoy's callback state.
///
/// SameBoy promotes delayed IME before its callback. The frontend retains that
/// promotion as part of the instruction row, so only this callback projection
/// normalizes the pending bit before comparing.
pub fn expectInstruction(
    expected: Record,
    actual: machine.CartridgeStepResult,
) Error!void {
    if (actual.event != .instruction or actual.instruction == null)
        return error.NotInstruction;
    try expected.validate();

    var callback_cpu = actual.before.cpu;
    if (callback_cpu.ime_enable_pending) {
        callback_cpu.ime = true;
        callback_cpu.ime_enable_pending = false;
    }
    if (!std.meta.eql(try expected.cpu(), callback_cpu))
        return error.CpuMismatch;

    const raw_opcode = actual.instruction.?.instruction.decoded.raw_opcode;
    const first_opcode: u8 = if (raw_opcode > 0xff)
        @truncate(raw_opcode >> 8)
    else
        @truncate(raw_opcode);
    if (first_opcode != expected.opcode) return error.OpcodeMismatch;
    if (actual.before.interrupt_enable != expected.interrupt_enable)
        return error.InterruptEnableMismatch;
    if (actual.before.interrupt_flags != expected.interrupt_flags)
        return error.InterruptFlagsMismatch;

    if (expected.pc < 0x8000) {
        const actual_bank: u16 = if (expected.pc < 0x4000)
            0
        else
            actual.mapper_before.selectedRomBank();
        if (actual_bank != expected.rom_bank)
            return error.RomBankMismatch;
    }
}

fn encode(record: Record) [RECORD_SIZE]u8 {
    var out: [RECORD_SIZE]u8 = undefined;
    std.mem.writeInt(u64, out[0..8], record.ticks_8mhz, .little);
    std.mem.writeInt(u16, out[8..10], record.pc, .little);
    std.mem.writeInt(u16, out[10..12], record.sp, .little);
    std.mem.writeInt(u16, out[12..14], record.af, .little);
    std.mem.writeInt(u16, out[14..16], record.bc, .little);
    std.mem.writeInt(u16, out[16..18], record.de, .little);
    std.mem.writeInt(u16, out[18..20], record.hl, .little);
    std.mem.writeInt(u16, out[20..22], record.rom_bank, .little);
    out[22] = record.opcode;
    out[23] = record.ime;
    out[24] = record.ime_toggle;
    out[25] = record.halted;
    out[26] = record.stopped;
    out[27] = record.interrupt_enable;
    out[28] = record.interrupt_flags;
    return out;
}

fn testRecord(ticks: u64) Record {
    return .{
        .ticks_8mhz = ticks,
        .pc = 0x4567,
        .sp = 0xfffe,
        .af = 0x12b0,
        .bc = 0x3456,
        .de = 0x789a,
        .hl = 0xbcde,
        .rom_bank = 3,
        .opcode = 0xcb,
        .ime = 1,
        .ime_toggle = 0,
        .halted = 0,
        .stopped = 0,
        .interrupt_enable = 0x0d,
        .interrupt_flags = 0x10,
    };
}

test "SameBoy compact records decode exact CPU and callback clock" {
    const bytes = encode(testRecord(80));
    const record = try Record.decode(&bytes);
    try std.testing.expectEqual(@as(u32, 10), try record.callbackMcycle());
    try std.testing.expectEqual(runner.Cpu{
        .a = 0x12,
        .f = 0xb0,
        .b = 0x34,
        .c = 0x56,
        .d = 0x78,
        .e = 0x9a,
        .h = 0xbc,
        .l = 0xde,
        .sp = 0xfffe,
        .pc = 0x4567,
        .ime = true,
    }, try record.cpu());
}

test "SameBoy trace validation rejects shape clock and field mutations" {
    const first = encode(testRecord(80));
    var second = encode(testRecord(88));
    var bytes = first ++ second;
    const trace = try Trace.init(&bytes);
    try trace.validateAll();
    try std.testing.expectEqual(@as(usize, 2), trace.count());
    try std.testing.expectError(
        error.RecordIndexOutOfBounds,
        trace.record(2),
    );
    try std.testing.expectError(error.EmptyTrace, Trace.init(""));
    try std.testing.expectError(
        error.InvalidTraceLength,
        Trace.init(bytes[0 .. bytes.len - 1]),
    );

    second[23] = 2;
    try std.testing.expectError(error.InvalidBoolean, Record.decode(&second));
    second = encode(testRecord(88));
    second[12] |= 1;
    try std.testing.expectError(error.InvalidFlags, Record.decode(&second));
    second = encode(testRecord(89));
    try std.testing.expectError(
        error.InvalidTickAlignment,
        Record.decode(&second),
    );

    second = encode(testRecord(80));
    bytes = first ++ second;
    try std.testing.expectError(
        error.NonIncreasingTicks,
        (try Trace.init(&bytes)).validateAll(),
    );
}

test "SameBoy comparator binds CPU opcode interrupts bank and delayed IME" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0);
    var cpu = runner.Cpu{
        .a = 0x12,
        .f = 0xb0,
        .b = 0x34,
        .c = 0x56,
        .d = 0x78,
        .e = 0x9a,
        .h = 0xbc,
        .l = 0xde,
        .sp = 0xfffe,
        .pc = 0,
        .ime_enable_pending = true,
    };
    const instruction = try runner.step(&cpu, &memory);
    var result = machine.CartridgeStepResult{
        .before = .{
            .cpu = instruction.before,
            .halt_bug = false,
            .div_counter = 0,
            .tima = 0,
            .tma = 0,
            .tac = 0,
            .timer_reload = .running,
            .interrupt_flags = 0x10,
            .interrupt_enable = 0x0d,
        },
        .after = .{
            .cpu = instruction.after,
            .halt_bug = false,
            .div_counter = 0,
            .tima = 0,
            .tma = 0,
            .tac = 0,
            .timer_reload = .running,
            .interrupt_flags = 0x10,
            .interrupt_enable = 0x0d,
        },
        .event = .instruction,
        .m_cycles = instruction.cycle_count,
        .instruction = .{
            .instruction = instruction,
            .accesses = [_]?runner.cartridge_memory.Access{null} **
                runner.MAX_BUS_CYCLES,
        },
        .mapper_before = .{},
        .mapper_after = .{},
    };
    var expected = testRecord(80);
    expected.pc = 0;
    expected.rom_bank = 0;
    expected.opcode = 0;
    try expectInstruction(expected, result);

    result.before.cpu.a ^= 1;
    try std.testing.expectError(
        error.CpuMismatch,
        expectInstruction(expected, result),
    );
    result.before.cpu.a ^= 1;
    expected.opcode = 1;
    try std.testing.expectError(
        error.OpcodeMismatch,
        expectInstruction(expected, result),
    );
    expected.opcode = 0;
    result.before.interrupt_enable ^= 1;
    try std.testing.expectError(
        error.InterruptEnableMismatch,
        expectInstruction(expected, result),
    );
    result.before.interrupt_enable ^= 1;
    result.before.interrupt_flags ^= 1;
    try std.testing.expectError(
        error.InterruptFlagsMismatch,
        expectInstruction(expected, result),
    );
    result.before.interrupt_flags ^= 1;

    expected.pc = 0x4000;
    expected.rom_bank = 2;
    result.before.cpu.pc = expected.pc;
    try std.testing.expectError(
        error.RomBankMismatch,
        expectInstruction(expected, result),
    );
}

test "SameBoy streaming comparator binds callback timing across idle rows" {
    var memory = try runner.Memory.init(std.testing.allocator);
    defer memory.deinit();
    memory.write(0, 0);
    var cpu = runner.Cpu{ .pc = 0 };
    const instruction = try runner.step(&cpu, &memory);
    const result = machine.CartridgeStepResult{
        .before = .{
            .cpu = instruction.before,
            .halt_bug = false,
            .div_counter = 0,
            .tima = 0,
            .tma = 0,
            .tac = 0,
            .timer_reload = .running,
            .interrupt_flags = 0,
            .interrupt_enable = 0,
        },
        .after = .{
            .cpu = instruction.after,
            .halt_bug = false,
            .div_counter = 0,
            .tima = 0,
            .tma = 0,
            .tac = 0,
            .timer_reload = .running,
            .interrupt_flags = 0,
            .interrupt_enable = 0,
        },
        .event = .instruction,
        .m_cycles = 1,
        .instruction = .{
            .instruction = instruction,
            .accesses = [_]?runner.cartridge_memory.Access{null} **
                runner.MAX_BUS_CYCLES,
        },
        .mapper_before = .{},
        .mapper_after = .{},
    };
    var first = testRecord(80);
    first.pc = 0;
    first.af = 0;
    first.bc = 0;
    first.de = 0;
    first.hl = 0;
    first.sp = 0;
    first.rom_bank = 0;
    first.opcode = 0;
    first.ime = 0;
    first.interrupt_enable = 0;
    first.interrupt_flags = 0;
    var second = first;
    second.ticks_8mhz = 96;
    const bytes = encode(first) ++ encode(second);
    var comparator = Comparator{ .trace = try Trace.init(&bytes) };
    try comparator.observe(result);

    var idle = result;
    idle.event = .halt_idle;
    idle.instruction = null;
    try comparator.observe(idle);
    try comparator.observe(result);
    try comparator.expectConsumed(2);

    var incomplete = Comparator{ .trace = try Trace.init(&bytes) };
    try incomplete.observe(result);
    try std.testing.expectError(
        error.InstructionCountMismatch,
        incomplete.expectConsumed(1),
    );

    var unanchored_prefix = Comparator{
        .trace = try Trace.init(&bytes),
        .initial_boundary_mcycle = 8,
    };
    try std.testing.expectError(
        error.TimingMismatch,
        unanchored_prefix.observe(result),
    );

    second.ticks_8mhz = 88;
    const forged_bytes = encode(first) ++ encode(second);
    var forged = Comparator{ .trace = try Trace.init(&forged_bytes) };
    try forged.observe(result);
    try forged.observe(idle);
    try std.testing.expectError(
        error.TimingMismatch,
        forged.observe(result),
    );
    try std.testing.expectError(
        error.InstructionCountMismatch,
        forged.expectConsumed(2),
    );
}
