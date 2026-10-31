const std = @import("std");
const Full = @import("../rv64_full.zig");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64_air;
const a = std.testing.allocator;
const words = [_]u32{ 0x00100093, 0x0070f113, 0x00311193 }; // ADDI, ANDI, SLLI
fn statement(authority: *const Full.ProgramAuthority, steps: u32) Full.Statement {
    return .{ .program = authority.expectedProgram(), .steps = steps, .initial_pc = 4096, .final_pc = 4100, .initial_registers = @splat(0), .final_registers = @splat(0), .cells = &.{}, .register_clocks = @splat(0), .memory_clocks = &.{}, .opcodes = authority.opcodes };
}
test "program authority shares immutable ROM and fixed providers across batch geometries" {
    var source = words;
    var authority = try Full.ProgramAuthority.init(a, .{ .base = 4096, .words = &source }, .keccak_service_v1);
    defer authority.deinit();
    source[0] ^= 1 << 20;
    try std.testing.expectEqualSlices(u32, &words, authority.words);
    try std.testing.expectEqualDeep(try rv.program.opcode_policy.derive(authority.expectedProgram(), .keccak_service_v1), authority.opcodes);
    const public = statement(&authority, 1);
    var shared = try Full.PreparedMaterials.initWithAuthority(a, public, .division_service_v2, .cyclic_v2, &authority);
    defer shared.deinit();
    var larger = try Full.PreparedMaterials.initWithAuthority(a, statement(&authority, 33), .division_multiplication_services_v3, .cyclic_v2, &authority);
    defer larger.deinit();
    try std.testing.expect(shared.borrows_immutable and larger.borrows_immutable);
    try std.testing.expectEqual(authority.program.rows.ptr, shared.program.rows.ptr);
    try std.testing.expectEqual(shared.program.decoded.ptr, larger.program.decoded.ptr);
    try std.testing.expectEqual(shared.rom_fixed.ptr, larger.rom_fixed.ptr);
    try std.testing.expectEqual(shared.and_table.?.fixed.ptr, larger.and_table.?.fixed.ptr);
    try std.testing.expectEqual(shared.shift_table.?.fixed.ptr, larger.shift_table.?.fixed.ptr);
    try std.testing.expect(shared.cpu_fixed.len != larger.cpu_fixed.len);
    var control = try Full.PreparedMaterials.initWithStatePolicy(a, public, .division_service_v2, .keccak_service_v1, .cyclic_v2);
    defer control.deinit();
    const first = try shared.fixedColumns(a);
    defer a.free(first);
    const second = try control.fixedColumns(a);
    defer a.free(second);
    try std.testing.expectEqual(first.len, second.len);
    for (first, second) |left, right| {
        try std.testing.expectEqual(left.log_size, right.log_size);
        try std.testing.expectEqualSlices(@import("stwo_core").fields.m31.M31, left.values, right.values);
    }
    var wrong = public;
    wrong.opcodes[@intFromEnum(frontend.rv64.decode.Opcode.ANDI)] = false;
    try std.testing.expectError(error.Rv64FullSetupMismatch, Full.PreparedMaterials.initWithAuthority(a, wrong, .division_service_v2, .cyclic_v2, &authority));
}
fn allocationCase(allocator: std.mem.Allocator) !void {
    var authority = try Full.ProgramAuthority.init(allocator, .{ .base = 4096, .words = &words }, .keccak_service_v1);
    defer authority.deinit();
    var first = try Full.PreparedMaterials.initWithAuthority(allocator, statement(&authority, 1), .division_service_v2, .cyclic_v2, &authority);
    defer first.deinit();
    var second = try Full.PreparedMaterials.initWithAuthority(allocator, statement(&authority, 33), .division_multiplication_services_v3, .cyclic_v2, &authority);
    defer second.deinit();
}
test "program authority ownership remains singular across all allocation failures" {
    try std.testing.checkAllAllocationFailures(a, allocationCase, .{});
}
