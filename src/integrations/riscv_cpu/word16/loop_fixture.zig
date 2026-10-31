//! Measured ALU/BINARY/branch workload, independently derived public endpoints.
//! No RAM, services, Ethereum or whole-ISA coverage is claimed by this study.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const CPU = @import("cpu.zig");
const Full = @import("../rv64_full.zig");
pub const BASE: u64 = 4096;
pub const MASK: u64 = 0x123456789abcdef0;
pub const WORDS = [_]u32{ 0x00108093, 0x0030f133, 0x00320213, 0xfe50eae3 };
pub fn expected(iterations: u32) !CPU.Public {
    if (iterations == 0 or iterations > 1048575) return error.InvalidLoopIterations;
    var initial: [32]u64 = @splat(0);
    initial[3] = MASK;
    initial[5] = iterations;
    var final = initial;
    final[1] = iterations;
    final[2] = iterations & MASK;
    final[4] = 3 * @as(u64, iterations);
    var clocks: [32]u32 = @splat(0);
    const end = 16 * iterations;
    clocks[1] = end - 3;
    clocks[2] = end - 9;
    clocks[3] = end - 10;
    clocks[4] = end - 5;
    clocks[5] = end - 2;
    return .{ .steps = 4 * iterations, .initial_pc = BASE, .final_pc = BASE + 16, .initial_registers = initial, .final_registers = final, .register_clocks = clocks };
}
pub fn geometry(public: CPU.Public) CPU.Geometry {
    const iterations = public.steps / 4;
    return .{
        .profile = .alu_binary_v2,
        .cpu_log = @max(5, std.math.log2_int_ceil(u32, public.steps + 1)),
        .alu_log = @max(5, std.math.log2_int_ceil(u32, 3 * iterations)),
        .binary_log = @max(5, std.math.log2_int_ceil(u32, iterations)),
    };
}
pub fn statement(public: CPU.Public) Full.Statement {
    var opcodes: [65]bool = @splat(false);
    for ([_]front.rv64.decode.Opcode{ .ADDI, .AND, .BLTU }) |op| opcodes[@intFromEnum(op)] = true;
    return .{ .program = .{ .base = BASE, .words = &WORDS }, .steps = public.steps, .initial_pc = public.initial_pc, .final_pc = public.final_pc, .initial_registers = public.initial_registers, .final_registers = public.final_registers, .register_clocks = public.register_clocks, .cells = &.{}, .memory_clocks = &.{}, .opcodes = opcodes };
}
/// Construct actual native retirements once. Expected state never depends on
/// this capture, and the receiving process calls expected() without executing.
pub fn capture(a: std.mem.Allocator, public: CPU.Public) ![]front.rv64.machine.Retirement {
    var memory = front.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = BASE, .size = 16, .permissions = .{ .read = true, .execute = true } });
    for (WORDS, 0..) |word, i| {
        var bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &bytes, word, .little);
        try memory.initialize(BASE + 4 * i, &bytes);
    }
    const records = try a.alloc(front.rv64.machine.Retirement, public.steps);
    errdefer a.free(records);
    var cpu = front.rv64.machine.Cpu.init(BASE, 0);
    cpu.regs = public.initial_registers;
    var clocks: [32]u32 = @splat(0);
    for (records, 0..) |*record, i| {
        record.* = try cpu.step(&memory);
        for ([_]u5{ record.rs1, record.rs2, record.rd }, 0..) |id, slot| if (id != 0) {
            clocks[id] = @intCast(4 * i + slot + 1);
        };
    }
    if (cpu.pc != public.final_pc or !std.mem.eql(u64, &cpu.regs, &public.final_registers) or !std.mem.eql(u32, &clocks, &public.register_clocks)) return error.LoopNativeDisagreement;
    return records;
}
