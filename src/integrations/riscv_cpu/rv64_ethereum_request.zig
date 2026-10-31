//! Independently pinned Ethereum execution input and immutable setup. Derive
//! the program, permissions and initial value root once from the admitted image.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const rv = frontend.rv64;
const R = frontend.rv64_air.memory;
const Full = @import("rv64_full.zig");
pub const Config = struct {
    elf: []const u8,
    input: []const u8,
    elf_sha256: []const u8,
    input_sha256: []const u8,
    expected_output: []const u8,
    symbols: @import("stwo_riscv_frontend").rv64.ethereum_contract.Symbols,
    output_directory: []const u8,
    terminal_pc: u64,
    batch_steps: u32 = 1 << 20,
    max_steps: u64 = 1000000000,
    max_batches: u32 = 0,
    workers: usize = 0,
    omit_unused_arithmetic: bool = true,
    shared_main_arena: bool = true,
    control_policy: @import("stwo_riscv_frontend").rv64_air.control_policy.Policy = .bytes_v1,
    state_policy: @import("stwo_riscv_frontend").rv64_air.state_policy.Policy = .cyclic_v2,
    diagnose_constraints: enum { none, cpu, ram, arithmetic, crypto, providers, all } = .none,
    profile_stages: bool = true,
    diagnose_allocations: bool = false,
};
pub const Request = struct {
    loaded: rv.elf.LoadedImage,
    authority: Full.ProgramAuthority,
    policy: R.policy.Policy,
    initial_cache: R.values.Cache,
    expected_output: [43]u8,
    pub fn init(a: std.mem.Allocator, config: Config) !Request {
        try validateBudget(config);
        const elf = try std.fs.cwd().readFileAlloc(a, config.elf, 64 * 1024 * 1024);
        defer a.free(elf);
        const input = try std.fs.cwd().readFileAlloc(a, config.input, 4 * 1024 * 1024);
        defer a.free(input);
        try pin(elf, config.elf_sha256);
        try pin(input, config.input_sha256);
        var expected: [43]u8 = undefined;
        if (config.expected_output.len != 86) return error.InvalidExpectedEthereumOutput;
        _ = try std.fmt.hexToBytes(&expected, config.expected_output);
        var loaded = try rv.ethereum_contract.load(a, config.symbols, elf, input);
        errdefer loaded.deinit();
        var program = try Program.init(a, &loaded.memory);
        defer program.deinit(a);
        var authority = try Full.ProgramAuthority.initWithControl(a, program.value(), .ethereum_services_v2, config.control_policy);
        errdefer authority.deinit();
        if (config.terminal_pc & 3 != 0 or try loaded.memory.fetch(config.terminal_pc) != 0x0000006f) return error.InvalidEthereumTerminalPc;
        _ = try authority.program.lookup(config.terminal_pc);
        var policy = try R.policy.Policy.fromMemory(a, &loaded.memory);
        errdefer policy.deinit();
        try policy.validateImmutableExecution();
        const terminal = R.terminal_air.Spec{ .geometry = .chunk512, .halt_flag = config.symbols.halt_flag, .output = expected };
        try terminal.validate();
        _ = try policy.find(.chunk512, terminal.base(), 3);
        var initial_cache = try R.values.Cache.fromMemory(a, .chunk512, &loaded.memory);
        errdefer initial_cache.deinit();
        return .{ .loaded = loaded, .authority = authority, .policy = policy, .initial_cache = initial_cache, .expected_output = expected };
    }
    pub fn deinit(self: *Request) void {
        self.initial_cache.deinit();
        self.policy.deinit();
        self.authority.deinit();
        self.loaded.deinit();
        self.* = undefined;
    }
};
pub fn pin(raw: []const u8, expected_hex: []const u8) !void {
    var expected: [32]u8 = undefined;
    if (expected_hex.len != 64) return error.InvalidExpectedInputIdentity;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    if (!std.mem.eql(u8, &expected, &sha(raw))) return error.EthereumInputIdentityMismatch;
}
pub fn sha(raw: []const u8) [32]u8 {
    var result: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(raw, &result, .{});
    return result;
}
pub const Program = struct {
    words: []u32,
    addresses: []u64,
    pub fn init(a: std.mem.Allocator, memory: *rv.memory.Memory) !Program {
        var count: usize = 0;
        for (memory.mappings.entries.items) |region| if (region.permissions.execute) {
            if (region.permissions.write or region.first & 3 != 0 or region.last & 3 != 3) return error.InvalidEthereumInstructionMapping;
            count = try std.math.add(usize, count, @intCast((region.last - region.first + 1) / 4));
        };
        if (count == 0 or count > frontend.rv64_air.program.setup.MAX_PROGRAM_WORDS) return error.InvalidEthereumProgramSize;
        const words = try a.alloc(u32, count);
        errdefer a.free(words);
        const addresses = try a.alloc(u64, count);
        errdefer a.free(addresses);
        var at: usize = 0;
        for (memory.mappings.entries.items) |region| if (region.permissions.execute) {
            const n: usize = @intCast((region.last - region.first + 1) / 4);
            for (0..n) |i| {
                const address = region.first + 4 * i;
                words[at] = try memory.fetch(address);
                addresses[at] = address;
                at += 1;
            }
        };
        return .{ .words = words, .addresses = addresses };
    }
    pub fn value(self: Program) frontend.rv64_air.program.setup.Program {
        return .{ .base = self.addresses[0], .words = self.words, .addresses = self.addresses };
    }
    pub fn deinit(self: *Program, a: std.mem.Allocator) void {
        a.free(self.addresses);
        a.free(self.words);
        self.* = undefined;
    }
};

pub fn validateBudget(config: Config) !void {
    if (config.batch_steps == 0 or config.batch_steps >= 1 << 22 or config.max_steps == 0 or config.max_steps > 10000000000 or config.workers > 32 or !frontend.rv64_air.state_policy.isCyclic(config.state_policy)) return error.InvalidEthereumProofBudget;
}

/// Runtime scheduling is separate from the statement and proof transcript.
pub fn effectiveWorkers(config: Config) !usize {
    try validateBudget(config);
    return if (config.workers != 0) config.workers else @min(16, try std.Thread.getCpuCount());
}
