//! Independently pinned pristine image for native INIT data. No Poseidon Cache,
//! VM execution, work-packet boundary or producer receipt establishes authority.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const R = front.rv64_air.memory;
const Full = @import("../rv64_full.zig");
const Request = @import("../rv64_ethereum_request.zig");
pub const MAX_INPUT_BYTES = rv.ethereum_contract.INPUT_CAPACITY_MAX - 4;
/// M5 platform: service-lifetime cache of the receiver-derived ProgramAuthority.
/// The authority is a function of the guest's executable regions (words and
/// addresses), the two execution profiles and the control policy only (see
/// rv64_program_authority.zig: "No request, endpoint, count, transcript or
/// proof enters this owner"), so it is keyed by exactly those and rebuilt for
/// any other value. Entries live in the session allocator; borrowing Owners
/// never free them. Request input, memory policy and identity stay per request.
pub const AuthorityCache = struct {
    allocator: std.mem.Allocator,
    entries: std.ArrayList(Entry) = .empty,
    hits: u64 = 0,
    misses: u64 = 0,
    const Entry = struct { key: [32]u8, authority: *Full.ProgramAuthority };
    const MAX_ENTRIES = 4;
    pub fn init(a: std.mem.Allocator) AuthorityCache {
        return .{ .allocator = a };
    }
    pub fn deinit(self: *AuthorityCache) void {
        for (self.entries.items) |entry| {
            entry.authority.deinit();
            self.allocator.destroy(entry.authority);
        }
        self.entries.deinit(self.allocator);
        self.* = undefined;
    }
    fn key(program: Request.Program, profile: anytype, rom: anytype, control: anytype) [32]u8 {
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        hash.update("stwo/rv64/resident/program-authority/v1\x00");
        var word: [8]u8 = undefined;
        std.mem.writeInt(u64, &word, program.words.len, .little);
        hash.update(&word);
        hash.update(std.mem.sliceAsBytes(program.words));
        hash.update(std.mem.sliceAsBytes(program.addresses));
        std.mem.writeInt(u64, &word, @intFromEnum(profile), .little);
        hash.update(&word);
        std.mem.writeInt(u64, &word, @intFromEnum(rom), .little);
        hash.update(&word);
        std.mem.writeInt(u64, &word, @intFromEnum(control), .little);
        hash.update(&word);
        return hash.finalResult();
    }
    fn get(self: *AuthorityCache, program: Request.Program, config: Request.Config) !*const Full.ProgramAuthority {
        const profile = Request.authorityProfile(config);
        const rom = Request.romProfile(config);
        const id = key(program, profile, rom, config.control_policy);
        for (self.entries.items) |entry| if (std.mem.eql(u8, &entry.key, &id)) {
            self.hits += 1;
            return entry.authority;
        };
        self.misses += 1;
        const authority = try self.allocator.create(Full.ProgramAuthority);
        errdefer self.allocator.destroy(authority);
        authority.* = try Full.ProgramAuthority.initWithRom(self.allocator, program.value(), profile, rom, config.control_policy);
        errdefer authority.deinit();
        if (self.entries.items.len >= MAX_ENTRIES) {
            const oldest = self.entries.orderedRemove(0);
            oldest.authority.deinit();
            self.allocator.destroy(oldest.authority);
        }
        try self.entries.append(self.allocator, .{ .key = id, .authority = authority });
        return authority;
    }
};
pub const Owner = struct {
    loaded: rv.elf.LoadedImage,
    authority: Full.ProgramAuthority,
    /// M5 platform: the authority is borrowed from an AuthorityCache (a
    /// by-value view of a cache-owned, immutable authority); never freed here.
    shared_authority: bool = false,
    policy: R.policy.Policy,
    expected_output: [43]u8,
    symbols: rv.ethereum_contract.Symbols,
    terminal_pc: u64,
    identity: [32]u8,
    max_prefix_steps: u32,
    initial_pc: u64,
    initial_registers: [32]u64,
    pub fn init(a: std.mem.Allocator, config: Request.Config) !Owner {
        return initWith(a, config, null);
    }
    /// Same checks and outputs as `init`; the ProgramAuthority comes from the
    /// service cache when its key (executable words/addresses, profiles,
    /// control policy) matches, and is built into the cache otherwise.
    pub fn initShared(a: std.mem.Allocator, config: Request.Config, cache: *AuthorityCache) !Owner {
        return initWith(a, config, cache);
    }
    fn initWith(a: std.mem.Allocator, config: Request.Config, cache: ?*AuthorityCache) !Owner {
        try Request.validateBudget(config);
        const elf = try std.fs.cwd().readFileAlloc(a, config.elf, 64 * 1024 * 1024);
        defer a.free(elf);
        // Same bound as the producer's request loader: the guest's widest input
        // window less its 4-byte length prefix (`ethereum_contract.load` then
        // checks the input against the ELF's actual window). The bytes are
        // pinned by `input_sha256`, so the read bound carries no authority.
        const input = try std.fs.cwd().readFileAlloc(a, config.input, MAX_INPUT_BYTES);
        defer a.free(input);
        try Request.pin(elf, config.elf_sha256);
        try Request.pin(input, config.input_sha256);
        var output: [43]u8 = undefined;
        if (config.expected_output.len != 86) return error.InvalidExpectedEthereumOutput;
        _ = try std.fmt.hexToBytes(&output, config.expected_output);
        var loaded = try rv.ethereum_contract.load(a, config.symbols, elf, input);
        errdefer loaded.deinit();
        var program = try Request.Program.init(a, &loaded.memory);
        defer program.deinit(a);
        const shared = cache != null;
        var authority = if (cache) |c| (try c.get(program, config)).* else try Full.ProgramAuthority.initWithRom(a, program.value(), Request.authorityProfile(config), Request.romProfile(config), config.control_policy);
        errdefer if (!shared) authority.deinit();
        if (config.terminal_pc & 3 != 0 or try loaded.memory.fetch(config.terminal_pc) != 0x0000006f) return error.InvalidEthereumTerminalPc;
        _ = try authority.program.lookup(config.terminal_pc);
        _ = try authority.program.lookup(loaded.info.entry);
        var policy = try R.policy.Policy.fromMemory(a, &loaded.memory);
        errdefer policy.deinit();
        try policy.validateImmutableExecution();
        const terminal = R.terminal_air.Spec{ .geometry = .chunk512, .halt_flag = config.symbols.halt_flag, .output = output };
        try terminal.validate();
        _ = try policy.find(.chunk512, terminal.base(), 3);
        const identity = try @import("../rv64_work_packet_header.zig").identityFor(config, &authority, &policy);
        const initial = rv.machine.Cpu.init(loaded.info.entry, config.symbols.stack_top);
        return .{ .loaded = loaded, .authority = authority, .shared_authority = shared, .policy = policy, .expected_output = output, .symbols = config.symbols, .terminal_pc = config.terminal_pc, .identity = identity.request, .max_prefix_steps = @intCast(@min(config.max_steps, config.batch_steps)), .initial_pc = initial.pc, .initial_registers = initial.regs };
    }
    /// Pure raw image read, not a permission grant. Operational access rights
    /// remain a separate immutable-policy relation. Unallocated bytes are zero.
    /// Unlike Memory.load, this never mutates a page/mapping lookup cache.
    pub fn initialWord(self: *const Owner, address: u64) !u64 {
        if (address & 7 != 0) return error.MisalignedInitialWord;
        _ = std.math.add(u64, address, 7) catch return error.InitialWordAddressOverflow;
        const page = self.loaded.memory.backing.table.get(address / rv.memory.PAGE_SIZE) orelse return 0;
        const offset: usize = @intCast(address % rv.memory.PAGE_SIZE);
        return std.mem.readInt(u64, page[offset..][0..8], .little);
    }
    pub fn deinit(self: *Owner) void {
        self.policy.deinit();
        if (!self.shared_authority) self.authority.deinit();
        self.loaded.deinit();
        self.* = undefined;
    }
};
