//! One native pass into compact advice; no retirement array or logical AIR rows.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const Image = @import("csp_image.zig");
pub const Capture = struct {
    tape: rv.compact_tape.Tape,
    tape_live: bool = true,
    boundary: front.rv64_air.word16_execution.types.Boundary,
    histogram: [65]u64,
    pub fn run(a: std.mem.Allocator, image: *const Image.Owner) !Capture {
        const config = image.config;
        var loaded = try rv.csp_contract.load(a, config.guest, image.elf, image.input);
        defer loaded.deinit();
        var session = try rv.Session.init(a, rv.machine.Cpu.init(loaded.info.entry, config.guest.symbols.stack_top), &loaded.memory, .{ .max_retirements = config.expected_steps });
        defer session.deinit();
        var tape = try rv.compact_tape.Tape.init(a, config.expected_steps, session.cpu.pc, 0, .rv64im);
        errdefer tape.deinit();
        var clocks: [32]u32 = @splat(0);
        var histogram: [65]u64 = @splat(0);
        var complete = false;
        for (0..config.expected_steps) |i| {
            const record = try session.step();
            try tape.append(record);
            histogram[@intFromEnum(record.opcode)] += 1;
            const effect = rv.decode.effects(record.opcode);
            const tick: u32 = @intCast(4 * i);
            if (effect.reads_rs1 and record.rs1 != 0) clocks[record.rs1] = tick + 1;
            if (effect.reads_rs2 and record.rs2 != 0) clocks[record.rs2] = tick + 2;
            if (effect.writes_rd and record.rd != 0) clocks[record.rd] = tick + 3;
            if (record.memory) |event| {
                if (event.write and event.address.toInt() <= config.guest.symbols.halt_flag + 3 and try rv.memory.endAddress(event.address.toInt(), event.width) >= config.guest.symbols.halt_flag) {
                    const flag = try loaded.memory.load(config.guest.symbols.halt_flag, 4);
                    if (flag > 1) return error.InvalidCspHalt;
                    complete = flag == 1;
                }
            }
            if (complete) break;
        }
        if (!complete or tape.len != config.expected_steps) return error.IncompleteCspExecution;
        if (try loaded.memory.load(config.guest.symbols.output_len, 4) != 32) return error.InvalidCspOutputLength;
        for (image.expected, 0..) |byte, i| if (try loaded.memory.load(config.guest.symbols.output_data + i, 1) != byte) return error.CspNativeOutputMismatch;
        return .{ .tape = tape, .histogram = histogram, .boundary = .{ .steps = @intCast(tape.len), .initial_pc = image.loaded.info.entry, .final_pc = session.cpu.pc, .initial_registers = image.initial_registers, .final_registers = session.cpu.regs, .register_clocks = clocks } };
    }
    pub fn deinit(self: *Capture) void {
        self.releaseTape();
        self.* = undefined;
    }
    /// Prepared owns the narrow restored metadata after capture. Retire the
    /// compact journal before any wide CPU/provider allocation, keeping only
    /// the public boundary and census used by the qualification report.
    pub fn releaseTape(self: *Capture) void {
        if (self.tape_live) {
            self.tape.deinit();
            self.tape_live = false;
        }
    }
};
