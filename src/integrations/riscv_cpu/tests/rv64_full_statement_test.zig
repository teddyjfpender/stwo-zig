const std = @import("std");
const S = @import("../rv64_full_statement.zig");
const rv = @import("stwo_riscv_frontend");
fn example() S.Statement {
    var result = S.Statement{ .program = .{ .base = 0x1000, .words = &.{0x00100093} }, .steps = 1, .initial_pc = 0x1000, .final_pc = 0x1004, .initial_registers = @splat(0), .final_registers = @splat(0), .cells = &.{}, .register_clocks = @splat(0), .memory_clocks = &.{}, .opcodes = @splat(false) };
    result.opcodes[@intFromEnum(rv.rv64.decode.Opcode.ADDI)] = true;
    result.final_registers[1] = 1;
    result.register_clocks[1] = 3;
    return result;
}
test "full request binds output and clocks without a public execution path" {
    const public = example();
    try public.validate();
    var first = rv.rv64_air.protocol.Channel{};
    try public.mix(&first, @splat(0));
    const digest = first.drawSecureFelt();
    var changed = public;
    changed.final_registers[1] = 2;
    var second = rv.rv64_air.protocol.Channel{};
    try changed.mix(&second, @splat(0));
    try std.testing.expect(!digest.eql(second.drawSecureFelt()));
    changed = public;
    changed.register_clocks[1] = 1;
    second = .{};
    try changed.mix(&second, @splat(0));
    try std.testing.expect(!digest.eql(second.drawSecureFelt()));
}
test "full request rejects invalid clocks and unsupported retirement opcodes" {
    var public = example();
    public.register_clocks[1] = 4;
    try std.testing.expectError(error.InvalidRv64FullClock, public.validate());
    public = example();
    public.opcodes[@intFromEnum(rv.rv64.decode.Opcode.EBREAK)] = true;
    try std.testing.expectError(error.InvalidRv64FullStatement, public.validate());
    public = example();
    public.register_clocks[1] = 0;
    try std.testing.expectError(error.InvalidRv64FullClock, public.validate());
}
test "full request represents CSP ECDSA clocks beyond u16" {
    var public = example();
    public.steps = 1625938;
    public.register_clocks[1] = 6503751;
    try public.validate();
    try std.testing.expectEqual(@as(u32, 21), public.logSize());
    public.register_clocks[1] = 6503753;
    try std.testing.expectError(error.InvalidRv64FullClock, public.validate());
}
test "full RAM cannot mutate ROM or substitute bytes on code reads" {
    var public = example();
    const clocks = [_]u32{4};
    var cells = [_]S.Cell{.{ .address = 0x1000, .initial = 0x00100093, .final = 0x00100093, .readable = true, .writable = true }};
    public.cells = &cells;
    public.memory_clocks = &clocks;
    try std.testing.expectError(error.Rv64MutableProgramMemory, public.validate());
    cells[0].writable = false;
    try public.validate();
    cells[0].initial ^= 1;
    cells[0].final = cells[0].initial;
    try std.testing.expectError(error.Rv64ProgramMemoryMismatch, public.validate());
}
