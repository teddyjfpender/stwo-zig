//! Explicit compact CPU public boundary. Program/opcodes come ONLY from the
//! receiver's expected immutable authority; private cells have another section.
const std = @import("std");
const CPU = @import("rv64_keccak_cpu.zig");
const Full = @import("rv64_full.zig");
pub const BYTES = 768;
pub fn encode(value: CPU.Public) ![BYTES]u8 {
    if (value.statement.cells.len != 0 or value.statement.memory_clocks.len != 0) return error.InvalidWorkPacketPublic;
    var out: [BYTES]u8 = undefined;
    var at: usize = 0;
    const words = [_]u32{
        @intFromEnum(value.control_policy),  @intFromEnum(value.execution_profile),     @intFromEnum(value.arithmetic_policy),
        @intFromEnum(value.division_roster), @intFromEnum(value.multiplication_roster), value.multiplication_requests,
        value.multiplication_log,            @intFromEnum(value.roster),                @intFromEnum(value.state_policy),
        value.division_requests,             value.keccak_calls,                        value.first_call_id,
        value.division_log,                  value.keccak_log,                          value.bridge_log,
    };
    for (words) |word| put32(&out, &at, word);
    for (value.secp.groups()) |group| for ([_]u32{ @intFromEnum(group.roster), group.calls, group.first_id, group.geometry.product_log, group.geometry.linear_log, group.geometry.bridge_log }) |word| put32(&out, &at, word);
    put32(&out, &at, value.statement.steps);
    put64(&out, &at, value.statement.initial_pc);
    put64(&out, &at, value.statement.final_pc);
    for (value.statement.initial_registers) |word| put64(&out, &at, word);
    for (value.statement.final_registers) |word| put64(&out, &at, word);
    for (value.statement.register_clocks) |word| put32(&out, &at, word);
    std.debug.assert(at == BYTES);
    return out;
}
pub fn decode(raw: *const [BYTES]u8, authority: *const Full.ProgramAuthority) !CPU.Public {
    var at: usize = 0;
    var result = CPU.Public{ .division_requests = 0, .keccak_calls = 0, .statement = .{
        .program = authority.expectedProgram(),
        .steps = 0,
        .initial_pc = 0,
        .final_pc = 0,
        .initial_registers = @splat(0),
        .final_registers = @splat(0),
        .register_clocks = @splat(0),
        .cells = &.{},
        .memory_clocks = &.{},
        .opcodes = authority.opcodes,
    } };
    result.control_policy = try readEnum(@TypeOf(result.control_policy), raw, &at);
    result.execution_profile = try readEnum(@TypeOf(result.execution_profile), raw, &at);
    result.arithmetic_policy = try readEnum(@TypeOf(result.arithmetic_policy), raw, &at);
    result.division_roster = try readEnum(@TypeOf(result.division_roster), raw, &at);
    result.multiplication_roster = try readEnum(@TypeOf(result.multiplication_roster), raw, &at);
    result.multiplication_requests = get32(raw, &at);
    result.multiplication_log = get32(raw, &at);
    result.roster = try readEnum(@TypeOf(result.roster), raw, &at);
    result.state_policy = try readEnum(@TypeOf(result.state_policy), raw, &at);
    result.division_requests = get32(raw, &at);
    result.keccak_calls = get32(raw, &at);
    result.first_call_id = get32(raw, &at);
    result.division_log = get32(raw, &at);
    result.keccak_log = get32(raw, &at);
    result.bridge_log = get32(raw, &at);
    var groups = result.secp.groups();
    for (&groups) |*group| {
        group.roster = try readEnum(@TypeOf(group.roster), raw, &at);
        group.calls = get32(raw, &at);
        group.first_id = get32(raw, &at);
        group.geometry = .{ .product_log = get32(raw, &at), .linear_log = get32(raw, &at), .bridge_log = get32(raw, &at) };
    }
    result.secp = .{ .add = groups[0], .double = groups[1] };
    result.statement.steps = get32(raw, &at);
    result.statement.initial_pc = get64(raw, &at);
    result.statement.final_pc = get64(raw, &at);
    for (&result.statement.initial_registers) |*word| word.* = get64(raw, &at);
    for (&result.statement.final_registers) |*word| word.* = get64(raw, &at);
    for (&result.statement.register_clocks) |*word| word.* = get32(raw, &at);
    std.debug.assert(at == BYTES);
    if (result.control_policy != authority.control_policy or result.execution_profile != authority.profile) return error.WorkPacketAuthorityMismatch;
    try result.validateWithAdmittedOpcodes(&authority.opcodes);
    return result;
}
fn readEnum(comptime T: type, raw: *const [BYTES]u8, at: *usize) !T {
    return std.meta.intToEnum(T, get32(raw, at)) catch error.InvalidWorkPacketPublic;
}
fn put32(raw: *[BYTES]u8, at: *usize, value: u32) void {
    std.mem.writeInt(u32, raw[at.*..][0..4], value, .little);
    at.* += 4;
}
fn put64(raw: *[BYTES]u8, at: *usize, value: u64) void {
    std.mem.writeInt(u64, raw[at.*..][0..8], value, .little);
    at.* += 8;
}
fn get32(raw: *const [BYTES]u8, at: *usize) u32 {
    const value = std.mem.readInt(u32, raw[at.*..][0..4], .little);
    at.* += 4;
    return value;
}
fn get64(raw: *const [BYTES]u8, at: *usize) u64 {
    const value = std.mem.readInt(u64, raw[at.*..][0..8], .little);
    at.* += 8;
    return value;
}
