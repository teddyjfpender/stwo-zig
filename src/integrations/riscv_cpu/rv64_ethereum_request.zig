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
    /// Admitted service roster. `ethereum_services_v3` adds SHA-256 compression
    /// (tag 0x0003_0010) and is served only by the Word16 services lane and
    /// native job collection; ROM decode is identical to v2.
    execution_profile: rv.execution_profile.Profile = .ethereum_services_v2,
};
/// Tape profile for a job of this request. v3 tapes carry SHA-256 records
/// next to a v2-decoded CPU statement (decode/effects are identical).
/// ROM authority profile: v2 decoding for v2/v3 (identical RV64IM ISA), the
/// Zbb profile itself for ethereum_services_v3_zbb (its ROM decodes Zbb BINARY).
/// Legacy native-statement profile: every Ethereum route (v2, v3, v3_zbb)
/// runs under the v2-decoded byte-ROM statement (packets are advice for the
/// Word16 route, whose ROM is `romProfile`).
pub fn authorityProfile(config: Config) rv.execution_profile.Profile {
    _ = config;
    return .ethereum_services_v2;
}
/// Word16 execution ROM profile: the Zbb route needs the v3_zbb ROM (the only
/// ROM that decodes Zbb BINARY rows); every other route keeps the v2 ROM.
pub fn romProfile(config: Config) rv.execution_profile.Profile {
    return if (config.execution_profile == .ethereum_services_v3_zbb) .ethereum_services_v3_zbb else .ethereum_services_v2;
}
pub fn tapeProfile(config: Config) rv.execution_profile.Profile {
    return config.execution_profile;
}
/// Immutable executable authority only. The provider must outlive the request;
/// it runs AFTER this request freshly pins and loads its own ELF/input image.
pub const AuthorityProvider = struct {
    context: *anyopaque,
    acquire: *const fn (*anyopaque, *rv.elf.LoadedImage, Config) anyerror!*const Full.ProgramAuthority,
    release: *const fn (*anyopaque) void,
};
pub const Options = struct {
    authority_provider: ?AuthorityProvider = null,
    /// Build the legacy Poseidon chunk512 sparse cache of the initial image.
    /// Only the Poseidon frontier/terminal routes (native job collection,
    /// classic proofs) read it. The in-process Word16 handoff never does: its
    /// INIT/terminal/global-memory authority is the Word16 statement, and its
    /// batches carry `Packet.ABSENT_ROOT`. When false, `initial_cache` is an
    /// EMPTY cache whose root is not the image root and must not be used.
    poseidon_initial_cache: bool = true,
};
pub const Request = struct {
    loaded: rv.elf.LoadedImage,
    authority: Full.ProgramAuthority,
    policy: R.policy.Policy,
    initial_cache: R.values.Cache,
    expected_output: [43]u8,
    /// False only under `Options.poseidon_initial_cache = false`.
    has_initial_cache: bool = true,
    shared_authority: bool = false,
    authority_provider: ?AuthorityProvider = null,
    pub fn init(a: std.mem.Allocator, config: Config) !Request {
        return initWithOptions(a, config, .{});
    }
    pub fn initWithOptions(a: std.mem.Allocator, config: Config, options: Options) !Request {
        try validateBudget(config);
        const elf = try std.fs.cwd().readFileAlloc(a, config.elf, 64 * 1024 * 1024);
        defer a.free(elf);
        const input = try std.fs.cwd().readFileAlloc(a, config.input, @import("stwo_riscv_frontend").rv64.ethereum_contract.INPUT_CAPACITY_MAX - 4);
        defer a.free(input);
        try pin(elf, config.elf_sha256);
        try pin(input, config.input_sha256);
        var expected: [43]u8 = undefined;
        if (config.expected_output.len != 86) return error.InvalidExpectedEthereumOutput;
        _ = try std.fmt.hexToBytes(&expected, config.expected_output);
        var loaded = try rv.ethereum_contract.load(a, config.symbols, elf, input);
        errdefer loaded.deinit();
        var authority = if (options.authority_provider) |provider| (try provider.acquire(provider.context, &loaded, config)).* else blk: {
            var program = try Program.init(a, &loaded.memory);
            defer program.deinit(a);
            break :blk try Full.ProgramAuthority.initWithRom(a, program.value(), authorityProfile(config), romProfile(config), config.control_policy);
        };
        errdefer if (options.authority_provider) |provider| provider.release(provider.context) else authority.deinit();
        if (config.terminal_pc & 3 != 0 or try loaded.memory.fetch(config.terminal_pc) != 0x0000006f) return error.InvalidEthereumTerminalPc;
        _ = try authority.program.lookup(config.terminal_pc);
        var policy = try R.policy.Policy.fromMemory(a, &loaded.memory);
        errdefer policy.deinit();
        try policy.validateImmutableExecution();
        const terminal = R.terminal_air.Spec{ .geometry = .chunk512, .halt_flag = config.symbols.halt_flag, .output = expected };
        try terminal.validate();
        _ = try policy.find(.chunk512, terminal.base(), 3);
        var initial_cache = if (options.poseidon_initial_cache) try R.values.Cache.fromMemory(a, .chunk512, &loaded.memory) else try R.values.Cache.empty(a, .chunk512);
        errdefer initial_cache.deinit();
        return .{ .loaded = loaded, .authority = authority, .policy = policy, .initial_cache = initial_cache, .expected_output = expected, .has_initial_cache = options.poseidon_initial_cache, .shared_authority = options.authority_provider != null, .authority_provider = options.authority_provider };
    }
    pub fn deinit(self: *Request) void {
        self.initial_cache.deinit();
        self.policy.deinit();
        if (self.authority_provider) |provider| provider.release(provider.context) else self.authority.deinit();
        self.loaded.deinit();
        self.* = undefined;
    }
};
pub const pin = @import("source_identity.zig").pin;
pub const sha = @import("source_identity.zig").sha;
pub const Program = @import("program_image.zig").Program;

pub fn validateBudget(config: Config) !void {
    if (config.batch_steps == 0 or config.batch_steps >= 1 << 23 or config.max_steps == 0 or config.max_steps > 10000000000 or config.workers > 32 or !frontend.rv64_air.state_policy.isCyclic(config.state_policy)) return error.InvalidEthereumProofBudget;
    if (config.execution_profile != .ethereum_services_v2 and !rv.execution_profile.isV3(config.execution_profile)) return error.UnsupportedEthereumExecutionProfile;
}

/// Runtime scheduling is separate from the statement and proof transcript.
pub fn effectiveWorkers(config: Config) !usize {
    try validateBudget(config);
    return if (config.workers != 0) config.workers else @min(16, try std.Thread.getCpuCount());
}
