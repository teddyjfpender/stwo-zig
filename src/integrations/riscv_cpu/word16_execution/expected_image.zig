//! Independently pinned pristine image for native INIT data. No Poseidon Cache,
//! VM execution, work-packet boundary or producer receipt establishes authority.
const std = @import("std");
const front = @import("stwo_riscv_frontend");
const rv = front.rv64;
const R = front.rv64_air.memory;
const Full = @import("../rv64_full.zig");
const Request = @import("../rv64_ethereum_request.zig");
pub const Owner = struct {
    loaded: rv.elf.LoadedImage,
    authority: Full.ProgramAuthority,
    policy: R.policy.Policy,
    expected_output: [43]u8,
    identity: [32]u8,
    max_prefix_steps: u32,
    initial_pc: u64,
    initial_registers: [32]u64,
    pub fn init(a: std.mem.Allocator, config: Request.Config) !Owner {
        try Request.validateBudget(config);
        const elf = try std.fs.cwd().readFileAlloc(a, config.elf, 64 * 1024 * 1024);
        defer a.free(elf);
        const input = try std.fs.cwd().readFileAlloc(a, config.input, 4 * 1024 * 1024);
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
        var authority = try Full.ProgramAuthority.initWithControl(a, program.value(), .ethereum_services_v2, config.control_policy);
        errdefer authority.deinit();
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
        return .{ .loaded = loaded, .authority = authority, .policy = policy, .expected_output = output, .identity = identity.request, .max_prefix_steps = @intCast(@min(config.max_steps, config.batch_steps)), .initial_pc = initial.pc, .initial_registers = initial.regs };
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
        self.authority.deinit();
        self.loaded.deinit();
        self.* = undefined;
    }
};
