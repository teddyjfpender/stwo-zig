const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const Capture = @import("../word16_qualification/sail_capture.zig");
const Image = @import("../word16_qualification/sail_image.zig");
const Cell = front.rv64_air.memory.closed_ram.types.Cell;
fn put(raw: *[88]u8, offset: usize, value: u64) void {
    std.mem.writeInt(u64, raw[offset..][0..8], value, .little);
}
fn loadRecord() rv.machine.Retirement {
    const W = rv.Word;
    return .{ .clock = 1, .pc = W.fromInt(0x80000000), .next_pc = W.fromInt(0x80000004), .immediate = W.fromInt(0), .instruction = 0x00008183, .opcode = .LB, .rs1 = 1, .rs2 = 0, .lhs = W.fromInt(0x100004000), .rhs = W.fromInt(0), .rd = 3, .previous_rd = W.fromInt(0), .result = W.fromInt(0xffffffffffffff80), .writes_rd = true, .branch_taken = false, .memory = .{ .address = W.fromInt(0x100004000), .width = 1, .value = W.fromInt(0x80), .before_word = W.fromInt(0x80), .after_word = W.fromInt(0x80), .write = false } };
}
fn loadRvfi() [88]u8 {
    var raw: [88]u8 = @splat(0);
    put(&raw, 8, 0x80000000);
    put(&raw, 16, 0x80000004);
    put(&raw, 24, 0x00008183);
    put(&raw, 32, 0x100004000);
    put(&raw, 48, 0xffffffffffffff80);
    put(&raw, 56, 0x100004000);
    put(&raw, 64, 0x80);
    raw[80] = 1;
    raw[82] = 1;
    raw[84] = 3;
    return raw;
}
fn registers() [32]u64 {
    var result: [32]u64 = @splat(0);
    result[1] = 0x100004000;
    return result;
}
test "Sail retirement comparator rejects detached PC trap operands and register results" {
    const record = loadRecord();
    const good = loadRvfi();
    try Capture.compare(record, good, registers());
    var no_input_extension = good;
    no_input_extension[82] = 0;
    put(&no_input_extension, 32, 0);
    try Capture.compare(record, no_input_extension, registers());
    var wrong_prestate = registers();
    wrong_prestate[1] ^= 1;
    try std.testing.expectError(error.SailOperandMismatch, Capture.compare(record, no_input_extension, wrong_prestate));
    for ([_]usize{ 8, 16, 24, 85, 86, 87 }) |offset| {
        var bad = good;
        bad[offset] ^= 1;
        try std.testing.expectError(error.SailRetirementIdentityMismatch, Capture.compare(record, bad, registers()));
    }
    for ([_]usize{ 32, 82 }) |offset| {
        var bad = good;
        bad[offset] ^= 3;
        try std.testing.expectError(error.SailOperandMismatch, Capture.compare(record, bad, registers()));
    }
    for ([_]usize{ 48, 55, 84 }) |offset| {
        var bad = good;
        bad[offset] ^= 1;
        try std.testing.expectError(error.SailRegisterMismatch, Capture.compare(record, bad, registers()));
    }
}
test "Sail RVFI comparison binds masks address raw load bytes and x0 nonwrite semantics" {
    const good = loadRvfi();
    for ([_]usize{ 56, 64, 80, 81 }) |offset| {
        var bad = good;
        bad[offset] ^= 1;
        try std.testing.expectError(error.SailMemoryEffectMismatch, Capture.compare(loadRecord(), bad, registers()));
    }
    var record = loadRecord();
    var raw = good;
    record.rd = 0;
    record.writes_rd = false;
    raw[84] = 0;
    // A load into x0 still authenticates the RAM read and clock event. Its
    // discarded computed result is not an architectural register write.
    put(&raw, 48, 0);
    try Capture.compare(record, raw, registers());
    raw[80] = 0;
    try std.testing.expectError(error.SailMemoryEffectMismatch, Capture.compare(record, raw, registers()));
}
test "Sail receiver binds independently expected complete CPU and both terminal words" {
    const oracle = Image.Oracle{ .schema = 1, .steps = 1, .initial_pc = 0x80000000, .final_pc = 0x80000004, .final_registers = @splat(0), .data_address = 0x100004000, .data_initial = @splat(0), .data_final = @splat(0), .target_cases = 1, .sail_revision = "unused", .elf_sha256 = "unused", .rvfi_sha256 = "unused" };
    var cpu = front.rv64_air.word16_execution.types.Boundary{ .steps = 1, .initial_pc = oracle.initial_pc, .final_pc = oracle.final_pc, .initial_registers = @splat(0), .final_registers = @splat(0), .register_clocks = @splat(0) };
    var cells = [_]Cell{ .{ .address = oracle.data_address, .state = .{ .value = 0, .rights = 3 } }, .{ .address = oracle.data_address + 8, .state = .{ .value = 0, .rights = 3 } } };
    try Image.validateExpected(oracle, cpu, &cells);
    cpu.final_registers[31] = 1;
    try std.testing.expectError(error.SailCpuEndpointMismatch, Image.validateExpected(oracle, cpu, &cells));
    cpu.final_registers[31] = 0;
    cpu.final_pc += 4;
    try std.testing.expectError(error.SailCpuEndpointMismatch, Image.validateExpected(oracle, cpu, &cells));
    cpu.final_pc -= 4;
    cells[1].state.value = 1;
    try std.testing.expectError(error.SailMemoryEndpointMismatch, Image.validateExpected(oracle, cpu, &cells));
    try std.testing.expectError(error.MissingSailTerminalWord, Image.validateExpected(oracle, cpu, cells[0..1]));
}
