//! Independently expected Sail workload, pinned separately from prover advice.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const E = @import("../word16_execution/execution.zig");
const Memory = @import("../word16_execution/memory/statement.zig");
const Request = @import("../rv64_ethereum_request.zig");
pub const Config = struct { elf: []const u8, elf_sha256: []const u8, oracle: []const u8, oracle_sha256: []const u8, rvfi: []const u8, workers: usize = 8, ls_ladder: bool = false };
pub const Oracle = struct {
    schema: u32,
    steps: u32,
    initial_pc: u64,
    final_pc: u64,
    final_registers: [32]u64,
    data_address: u64,
    data_initial: [16]u8,
    data_final: [16]u8,
    target_cases: u32,
    sail_revision: []const u8,
    elf_sha256: []const u8,
    rvfi_sha256: []const u8,
};
pub const Owner = struct {
    allocator: std.mem.Allocator,
    config: Config,
    parsed: std.json.Parsed(Oracle),
    elf: []u8,
    loaded: rv.elf.LoadedImage,
    identity: [32]u8,
    pub fn init(a: std.mem.Allocator, config: Config) !Owner {
        if (config.workers == 0 or config.workers > 64) return error.InvalidOracleWorkers;
        const raw = try std.fs.cwd().readFileAlloc(a, config.oracle, 65536);
        defer a.free(raw);
        try Request.pin(raw, config.oracle_sha256);
        var parsed = try std.json.parseFromSlice(Oracle, a, raw, .{ .ignore_unknown_fields = true, .allocate = .alloc_always });
        errdefer parsed.deinit();
        const oracle = parsed.value;
        if (oracle.schema != 1 or oracle.steps == 0 or oracle.steps >= 1 << 22 or oracle.initial_pc & 3 != 0 or oracle.final_pc & 3 != 0 or oracle.final_registers[0] != 0 or oracle.data_address & 7 != 0 or oracle.data_address > std.math.maxInt(u64) - 15 or !std.mem.eql(u8, oracle.sail_revision, "8c7f2da58de0ba5e4457e4de07e0046f0439f35f")) return error.InvalidSailOracle;
        const elf = try std.fs.cwd().readFileAlloc(a, config.elf, 32 * 1024 * 1024);
        errdefer a.free(elf);
        try Request.pin(elf, config.elf_sha256);
        try Request.pin(elf, oracle.elf_sha256);
        var loaded = try load(a, elf, oracle);
        errdefer loaded.deinit();
        var h = std.crypto.hash.sha2.Sha256.init(.{});
        h.update("RV64/word16/continuous-Sail-RV64IM/expected-image/v1\x00");
        h.update(&Request.sha(raw));
        h.update(&Request.sha(elf));
        return .{ .allocator = a, .config = config, .parsed = parsed, .elf = elf, .loaded = loaded, .identity = h.finalResult() };
    }
    pub fn load(a: std.mem.Allocator, elf: []const u8, oracle: Oracle) !rv.elf.LoadedImage {
        var loaded = try rv.elf.loadImage(a, elf, .{});
        errdefer loaded.deinit();
        if (loaded.info.entry != oracle.initial_pc) return error.SailInitialPcMismatch;
        for (loaded.memory.mappings.entries.items) |region| if (region.permissions.execute and region.permissions.write) return error.MutableOracleInstructions;
        try loaded.memory.map(.{ .start = oracle.data_address, .size = 16, .permissions = .{ .read = true, .write = true } });
        try loaded.memory.initialize(oracle.data_address, &oracle.data_initial);
        return loaded;
    }
    pub fn admission(self: *const Owner) E.Admission {
        return .{ .image = .{ .context = self, .initial_word = word, .rights_at = rights }, .image_identity = self.identity, .initial_pc = self.parsed.value.initial_pc, .initial_registers = @splat(0), .max_prefix_steps = self.parsed.value.steps };
    }
    fn word(ctx: *const anyopaque, address: u64) !u64 {
        const self: *const Owner = @ptrCast(@alignCast(ctx));
        if (address & 7 != 0) return error.MisalignedOracleWord;
        _ = try std.math.add(u64, address, 7);
        const page = self.loaded.memory.backing.table.get(address / rv.memory.PAGE_SIZE) orelse return 0;
        const offset: usize = @intCast(address % rv.memory.PAGE_SIZE);
        return std.mem.readInt(u64, page[offset..][0..8], .little);
    }
    fn rights(ctx: *const anyopaque, address: u64) !u2 {
        const self: *const Owner = @ptrCast(@alignCast(ctx));
        for (self.loaded.memory.mappings.entries.items) |region| if (region.first <= address and address <= region.last) return @as(u2, @intFromBool(region.permissions.read)) | (@as(u2, @intFromBool(region.permissions.write)) << 1);
        return 0;
    }
    pub fn validateResult(self: *const Owner, cpu: front.rv64_air.word16_execution.types.Boundary, terminal: []const Memory.Cell) !void {
        return validateExpected(self.parsed.value, cpu, terminal);
    }
    pub fn deinit(self: *Owner) void {
        self.loaded.deinit();
        self.allocator.free(self.elf);
        self.parsed.deinit();
        self.* = undefined;
    }
};
pub fn validateExpected(oracle: Oracle, cpu: front.rv64_air.word16_execution.types.Boundary, terminal: []const Memory.Cell) !void {
    if (cpu.steps != oracle.steps or cpu.final_pc != oracle.final_pc or !std.mem.eql(u64, &cpu.final_registers, &oracle.final_registers)) return error.SailCpuEndpointMismatch;
    for (0..2) |i| {
        const address = oracle.data_address + 8 * @as(u64, @intCast(i));
        const expected = std.mem.readInt(u64, oracle.data_final[8 * i ..][0..8], .little);
        var found = false;
        for (terminal) |cell| if (cell.address == address) {
            if (cell.state.value != expected) return error.SailMemoryEndpointMismatch;
            found = true;
            break;
        };
        if (!found) return error.MissingSailTerminalWord;
    }
}
