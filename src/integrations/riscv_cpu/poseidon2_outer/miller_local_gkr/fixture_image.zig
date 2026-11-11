//! Test-only, independently pinned ECALL image for full CPU/Miller/root gates.
//! This is a synthetic native program, not a Kona ELF or Ethereum guest ABI.
//! Production image admission continues to require Owner.initForOp.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const Service = front.rv64_air.crypto.bn254_tower.execution;
const Image = @import("../../word16_execution/expected_image.zig");
const Full = @import("../../rv64_full.zig");
pub const WORDS = [_]u32{ 0x73, 0x6f };
pub const PC: u64 = 4096;
pub const TERMINAL_PC: u64 = PC + 4;
pub const ADDRESS: u64 = 0x8000000000000fe0;

pub fn beforeWords() [Service.WORDS]u64 {
    var words: [Service.WORDS]u64 = @splat(0);
    for (0..20) |i| words[4 * i] = 1 + 2 * i;
    words[78] = 1;
    words[79] = 43;
    return words;
}
pub fn registers() [32]u64 {
    var out: [32]u64 = @splat(0);
    out[10] = ADDRESS;
    out[17] = Service.TAG;
    return out;
}
fn hashWord(hash: *std.crypto.hash.sha2.Sha256, value: u64) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    hash.update(&bytes);
}
pub fn init(a: std.mem.Allocator) !Image.Owner {
    if (!@import("builtin").is_test) return error.OpMillerImageFixtureOnly;
    var memory = rv.memory.Memory.init(a, .{ .max_pages = 4, .max_regions = 3 });
    errdefer memory.deinit();
    try memory.map(.{ .start = PC, .size = WORDS.len * 4, .permissions = .{ .read = true, .execute = true } });
    try memory.map(.{ .start = ADDRESS, .size = Service.WRITTEN_BYTES, .permissions = .{ .read = true, .write = true } });
    try memory.map(.{ .start = ADDRESS + Service.WRITTEN_BYTES, .size = Service.PACKET_BYTES - Service.WRITTEN_BYTES, .permissions = .{ .read = true } });
    var code: [WORDS.len * 4]u8 = undefined;
    for (WORDS, 0..) |word, i| std.mem.writeInt(u32, code[4 * i ..][0..4], word, .little);
    try memory.initialize(PC, &code);
    const before = beforeWords();
    var packet: [Service.PACKET_BYTES]u8 = undefined;
    for (before, 0..) |word, i| std.mem.writeInt(u64, packet[8 * i ..][0..8], word, .little);
    try memory.initialize(ADDRESS, &packet);
    if (try memory.fetch(TERMINAL_PC) != 0x6f) return error.InvalidEthereumTerminalPc;
    var authority = try Full.ProgramAuthority.initForOpWord16(a, .{ .base = PC, .words = &WORDS }, .bytes_v1);
    errdefer authority.deinit();
    _ = try authority.program.lookup(PC);
    _ = try authority.program.lookup(TERMINAL_PC);
    var policy = try front.rv64_air.memory.policy.Policy.fromMemory(a, &memory);
    errdefer policy.deinit();
    try policy.validateImmutableExecution();
    const after = try Service.execute(&before);
    var result: [Service.WRITTEN_BYTES]u8 = undefined;
    for (after[0..Service.WRITTEN_WORDS], 0..) |word, i| std.mem.writeInt(u64, result[8 * i ..][0..8], word, .little);
    var symbols = std.mem.zeroes(rv.ethereum_contract.Symbols);
    symbols.input_start = ADDRESS;
    symbols.input_end = ADDRESS + Service.PACKET_BYTES;
    symbols.halt_flag = ADDRESS + 78 * 8;
    symbols.output_len = ADDRESS + 79 * 8;
    symbols.output_data = ADDRESS;
    symbols.output_end = ADDRESS + 43;
    const regs = registers();
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("op-test-only-miller-image/v1\x00");
    hash.update(&code);
    hash.update(&packet);
    hash.update(&authority.program.identity);
    hash.update(&policy.identity);
    hash.update(result[0..43]);
    hashWord(&hash, @intFromEnum(authority.profile));
    hashWord(&hash, @intFromEnum(authority.rom_profile));
    hashWord(&hash, @intFromEnum(authority.control_policy));
    inline for (std.meta.fields(rv.ethereum_contract.Symbols)) |field| hashWord(&hash, @field(symbols, field.name));
    for (regs) |reg| hashWord(&hash, reg);
    for ([_]u64{ PC, TERMINAL_PC, 1 }) |word| hashWord(&hash, word);
    return .{ .loaded = .{ .info = .{ .entry = PC, .load_segments = 0, .mapped_bytes = code.len + packet.len, .file_bytes = 0, .initial_pages = memory.pageCount() }, .memory = memory }, .authority = authority, .policy = policy, .expected_output = result[0..43].*, .symbols = symbols, .terminal_pc = TERMINAL_PC, .identity = hash.finalResult(), .max_prefix_steps = 1, .initial_pc = PC, .initial_registers = regs };
}

test "OP Miller toy image pins immutable ROM packet rights and terminal authority" {
    var image = try init(std.testing.allocator);
    defer image.deinit();
    var fresh = try init(std.testing.allocator);
    defer fresh.deinit();
    try std.testing.expectEqualSlices(u8, &image.identity, &fresh.identity);
    try std.testing.expectEqualSlices(u8, &image.policy.identity, &fresh.policy.identity);
    try std.testing.expectEqual(@as(u32, 0x6f), try image.loaded.memory.fetch(image.terminal_pc));
    try std.testing.expectEqual(@as(u64, 1), try image.initialWord(image.symbols.halt_flag));
    try std.testing.expectEqual(@as(u64, 43), try image.initialWord(image.symbols.output_len));
    try std.testing.expectError(error.AccessDenied, image.loaded.memory.store(image.symbols.halt_flag, 8, 2));
    try std.testing.expectError(error.AccessDenied, image.loaded.memory.store(PC, 4, 0));
    try std.testing.expectEqualSlices(u64, &registers(), &image.initial_registers);
    const Cell = front.rv64_air.memory.closed_ram.types.Cell;
    const before = beforeWords();
    const after = try Service.execute(&before);
    var cells: [Service.WORDS]Cell = undefined;
    for (&cells, 0..) |*cell, i| cell.* = .{
        .address = ADDRESS + 8 * i,
        .state = .{ .value = if (i < Service.WRITTEN_WORDS) after[i] else before[i], .rights = if (i < Service.WRITTEN_WORDS) 3 else 1 },
    };
    var final = front.rv64_air.word16_execution.types.Boundary{ .steps = 1, .initial_pc = PC, .final_pc = TERMINAL_PC, .initial_registers = registers(), .final_registers = registers(), .register_clocks = @splat(0) };
    const Terminal = @import("../../word16_global_execution/ethereum/terminal.zig");
    try std.testing.expectEqualSlices(u8, &image.expected_output, &try Terminal.require(&image, final, &cells));
    final.final_pc = PC;
    try std.testing.expectError(error.EthereumTerminalPcMismatch, Terminal.require(&image, final, &cells));
    final.final_pc = TERMINAL_PC;
    cells[78].state.value = 0;
    try std.testing.expectError(error.EthereumHaltNotSet, Terminal.require(&image, final, &cells));
    cells[78].state.value = 1;
    cells[79].state.value = 42;
    try std.testing.expectError(error.EthereumOutputLengthMismatch, Terminal.require(&image, final, &cells));
    cells[79].state.value = 43;
    cells[0].state.value ^= 1;
    try std.testing.expectError(error.EthereumOutputMismatch, Terminal.require(&image, final, &cells));
}
