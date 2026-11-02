//! Independently expected native BEQ x0,x0,0 prefix for weighted ALU qualification.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const CPU = @import("cpu.zig");
pub const BASE: u64 = 4096;
pub const WORDS = [_]u32{0x00000063};
pub fn expected(cpu_log: u32) !CPU.Public {
    if (cpu_log < 5 or cpu_log > 22) return error.InvalidWeightedAluFixtureGeometry;
    return .{ .steps = (@as(u32, 1) << @intCast(cpu_log)) - 1, .initial_pc = BASE, .final_pc = BASE, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
}
pub fn geometry(cpu_log: u32, alu_log: u32) CPU.Geometry {
    return .{ .cpu_log = cpu_log, .alu_log = alu_log, .binary_log = 5, .profile = .alu_binary_v2 };
}
pub fn capture(a: std.mem.Allocator, public: CPU.Public) ![]front.rv64.machine.Retirement {
    var memory = front.rv64.memory.Memory.init(a, .{});
    defer memory.deinit();
    try memory.map(.{ .start = BASE, .size = 4, .permissions = .{ .read = true, .execute = true } });
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, WORDS[0], .little);
    try memory.initialize(BASE, &bytes);
    var cpu = front.rv64.machine.Cpu.init(BASE, 0);
    const records = try a.alloc(front.rv64.machine.Retirement, public.steps);
    errdefer a.free(records);
    for (records) |*record| record.* = try cpu.step(&memory);
    if (cpu.pc != public.final_pc or !std.mem.eql(u64, &cpu.regs, &public.final_registers)) return error.WeightedAluFixtureBoundaryMismatch;
    return records;
}
