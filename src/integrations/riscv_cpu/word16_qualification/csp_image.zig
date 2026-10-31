//! Receiver-owned software CSP image. This is the 32-byte CSP ABI, not the
//! Ethereum ABI; serialized execution advice never supplies image authority.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const E = @import("../word16_execution/execution.zig");
const Memory = @import("../word16_execution/memory/statement.zig");
const Request = @import("../rv64_ethereum_request.zig");
pub const Config = struct {
    guest: rv.csp_contract.Config,
    elf_sha256: []const u8,
    input_sha256: []const u8,
    expected_steps: u32,
    workers: usize = 8,
    ls_ladder: bool = false,
};
pub const Owner = struct {
    allocator: std.mem.Allocator,
    config: Config,
    elf: []u8,
    input: []u8,
    loaded: rv.elf.LoadedImage,
    identity: [32]u8,
    expected: [32]u8,
    initial_registers: [32]u64,
    pub fn init(a: std.mem.Allocator, config: Config) !Owner {
        if (config.expected_steps == 0 or config.expected_steps >= 1 << 22 or config.expected_steps > config.guest.max_steps or config.workers == 0 or config.workers > 64) return error.InvalidCspQualificationBudget;
        const elf = try std.fs.cwd().readFileAlloc(a, config.guest.elf, 64 * 1024 * 1024);
        errdefer a.free(elf);
        const input = try std.fs.cwd().readFileAlloc(a, config.guest.input, 4096);
        errdefer a.free(input);
        try Request.pin(elf, config.elf_sha256);
        try Request.pin(input, config.input_sha256);
        var expected: [32]u8 = undefined;
        if (config.guest.expected_digest.len != 64) return error.InvalidCspDigest;
        _ = try std.fmt.hexToBytes(&expected, config.guest.expected_digest);
        var loaded = try rv.csp_contract.load(a, config.guest, elf, input);
        errdefer loaded.deinit();
        for (loaded.memory.mappings.entries.items) |region| if (region.permissions.execute and region.permissions.write) return error.MutableCspInstructions;
        if (try loaded.memory.load(config.guest.symbols.halt_flag, 4) != 0 or try loaded.memory.load(config.guest.symbols.output_len, 4) != 0) return error.InvalidCspInitialCompletion;
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("RV64/word16/software-CSP32/expected-image/v1\x00");
        h.update(&Request.sha(elf));
        h.update(&Request.sha(input));
        h.update(&expected);
        var bytes: [8]u8 = undefined;
        inline for (std.meta.fields(rv.csp_contract.Symbols)) |field| {
            std.mem.writeInt(u64, &bytes, @field(config.guest.symbols, field.name), .little);
            h.update(&bytes);
        }
        std.mem.writeInt(u64, &bytes, config.expected_steps, .little);
        h.update(&bytes);
        const initial = rv.machine.Cpu.init(loaded.info.entry, config.guest.symbols.stack_top);
        return .{ .allocator = a, .config = config, .elf = elf, .input = input, .loaded = loaded, .identity = h.finalResult(), .expected = expected, .initial_registers = initial.regs };
    }
    pub fn admission(self: *const Owner) E.Admission {
        return .{ .image = .{ .context = self, .initial_word = word, .rights_at = rights }, .image_identity = self.identity, .initial_pc = self.loaded.info.entry, .initial_registers = self.initial_registers, .max_prefix_steps = self.config.expected_steps };
    }
    fn word(ctx: *const anyopaque, address: u64) !u64 {
        const self: *const Owner = @ptrCast(@alignCast(ctx));
        if (address & 7 != 0) return error.MisalignedCspWord;
        _ = try std.math.add(u64, address, 7);
        const page = self.loaded.memory.backing.table.get(address / rv.memory.PAGE_SIZE) orelse return 0;
        const offset: usize = @intCast(address % rv.memory.PAGE_SIZE);
        return std.mem.readInt(u64, page[offset..][0..8], .little);
    }
    fn rights(ctx: *const anyopaque, address: u64) !u2 {
        const self: *const Owner = @ptrCast(@alignCast(ctx));
        for (self.loaded.memory.mappings.entries.items) |region| if (region.first <= address and address <= region.last) {
            return @as(u2, @intFromBool(region.permissions.read)) | (@as(u2, @intFromBool(region.permissions.write)) << 1);
        };
        return 0;
    }
    pub fn validateTerminal(self: *const Owner, steps: u32, terminal: []const Memory.Cell) !void {
        if (steps != self.config.expected_steps) return error.IncompleteCspExecution;
        try validateOutput(self.config.guest.symbols, self.expected, terminal);
    }
    pub fn deinit(self: *Owner) void {
        self.loaded.deinit();
        self.allocator.free(self.input);
        self.allocator.free(self.elf);
        self.* = undefined;
    }
};
/// Checks the values authenticated by the terminal RAM claim. Native output
/// reads are only capture diagnostics and cannot replace this receiver check.
pub fn validateOutput(symbols: rv.csp_contract.Symbols, expected: [32]u8, terminal: []const Memory.Cell) !void {
    const completion: [8]u8 = .{ 1, 0, 0, 0, 32, 0, 0, 0 };
    for (completion, 0..) |byte, i| if (try terminalByte(terminal, symbols.halt_flag + i) != byte) return error.UntrustedCspCompletion;
    for (expected, 0..) |byte, i| if (try terminalByte(terminal, symbols.output_data + i) != byte) return error.UntrustedCspOutput;
}
fn terminalByte(cells: []const Memory.Cell, address: u64) !u8 {
    const aligned = address & ~@as(u64, 7);
    var lo: usize = 0;
    var hi = cells.len;
    while (lo < hi) {
        const mid = lo + (hi - lo) / 2;
        if (cells[mid].address < aligned) lo = mid + 1 else hi = mid;
    }
    if (lo == cells.len or cells[lo].address != aligned) return error.MissingCspTerminalWord;
    return @truncate(cells[lo].state.value >> @as(u6, @intCast(8 * (address & 7))));
}
