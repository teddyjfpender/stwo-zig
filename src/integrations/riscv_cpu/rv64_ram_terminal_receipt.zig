//! Durable q70/P26 terminal certificate qualification. Public context includes
//! the root, immutable mappings, ABI address and expected43 bytes; no RAM ledger.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const R = frontend.rv64_air.memory;
const T = R.private_trace;
const terminal = @import("rv64_ram_terminal.zig");
const base_codec = @import("rv64_ram_private_receipt.zig");
const a = std.heap.smp_allocator;
pub const MAX_CONTEXT_BYTES = base_codec.MAX_CONTEXT_BYTES + 59;
pub const Context = struct {
    base: base_codec.Context,
    halt_flag: u64,
    output: [43]u8,
    pub fn statement(self: *const Context) terminal.Statement {
        return .{ .geometry = self.base.geometry, .root = self.base.after, .policy = &self.base.policy, .halt_flag = self.halt_flag, .output = self.output };
    }
    pub fn deinit(self: *Context) void {
        self.base.deinit();
        self.* = undefined;
    }
};
pub fn encode(allocator: std.mem.Allocator, public: terminal.Statement) ![]u8 {
    try public.validate();
    const inner = try base_codec.encode(allocator, public.graphStatement());
    defer allocator.free(inner);
    const bytes = try allocator.alloc(u8, 8 + inner.len + 51);
    std.mem.writeInt(u32, bytes[0..4], 0x52544331, .little);
    std.mem.writeInt(u32, bytes[4..8], @intCast(inner.len), .little);
    @memcpy(bytes[8..][0..inner.len], inner);
    std.mem.writeInt(u64, bytes[8 + inner.len ..][0..8], public.halt_flag, .little);
    @memcpy(bytes[16 + inner.len ..], &public.output);
    return bytes;
}
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, independent_pin: [32]u8) !Context {
    if (bytes.len < 143 or bytes.len > MAX_CONTEXT_BYTES) return error.InvalidTerminalContext;
    if (!std.mem.eql(u8, &base_codec.hash(bytes), &independent_pin)) return error.TerminalContextShaMismatch;
    if (std.mem.readInt(u32, bytes[0..4], .little) != 0x52544331) return error.InvalidTerminalContext;
    const n = std.mem.readInt(u32, bytes[4..8], .little);
    if (n < 84 or n > base_codec.MAX_CONTEXT_BYTES or bytes.len != 8 + @as(usize, n) + 51) return error.InvalidTerminalContext;
    const inner = bytes[8..][0..n];
    if (!std.mem.eql(u8, inner[8..44], inner[44..80])) return error.InvalidTerminalRootObservation;
    const geometry: R.values.Geometry = switch (std.mem.readInt(u32, inner[4..8], .little)) {
        9 => .chunk512,
        12 => .page4096,
        else => return error.InvalidTerminalContext,
    };
    const halt_flag = std.mem.readInt(u64, bytes[8 + n ..][0..8], .little);
    const output = bytes[16 + n ..][0..43].*;
    try (R.terminal_air.Spec{ .geometry = geometry, .halt_flag = halt_flag, .output = output }).validate();
    // The independently pinned outer frame binds this subframe; its derived
    // hash is codec framing only, not a second advertised origin authority.
    var base = try base_codec.decode(allocator, inner, base_codec.hash(inner));
    errdefer base.deinit();
    var result = Context{ .base = base, .halt_flag = halt_flag, .output = output };
    try result.statement().validate();
    return result;
}
fn nextRows(n: usize) usize {
    return @as(usize, 1) << @intCast(@max(4, std.math.log2_int_ceil(usize, @max(1, n))));
}
pub const Cost = struct { permutations: usize, provider_rows: usize, main_field_cells: usize, interaction_field_cells: usize, fixed_field_cells: usize, terminal_selector_cells: usize, raw_main_and_interaction_bytes: usize };
pub fn cost(public: terminal.Statement) !Cost {
    try public.validate();
    const cells = public.geometry.cells();
    const depth = public.geometry.depth();
    const calls = public.geometry.permutations() + 4 * @as(usize, depth);
    const provider = nextRows(calls);
    const policy_rows = nextRows(public.policy.grants.len);
    const rows = [_]usize{ nextRows(public.geometry.permutations() + 1), cells, 16, 16, nextRows(depth), nextRows(depth), 16, 16 };
    var main: usize = 303 * provider + policy_rows + 256;
    var inter: usize = 8 * provider + 8 * policy_rows + 8 * 256;
    var fixed: usize = provider + R.policy_provider.FIXED * policy_rows + 3 * 256;
    for (T.TABLES, rows) |table, n| {
        main += T.mainWidth(table) * n;
        inter += 4 * T.sumCount(table) * n;
        fixed += T.fixedWidth(table) * n;
    }
    const selectors = R.terminal_air.SELECTORS * cells;
    fixed += selectors;
    return .{ .permutations = calls, .provider_rows = provider, .main_field_cells = main, .interaction_field_cells = inter, .fixed_field_cells = fixed, .terminal_selector_cells = selectors, .raw_main_and_interaction_bytes = 4 * (main + inter) };
}
const Fixture = struct {
    memory: frontend.rv64.memory.Memory,
    policy: R.policy.Policy,
    cache: R.values.Cache,
    output: [43]u8,
    fn init(allocator: std.mem.Allocator, geometry: R.values.Geometry) !Fixture {
        var memory = frontend.rv64.memory.Memory.init(allocator, .{});
        errdefer memory.deinit();
        try memory.map(.{ .start = 0xc00000, .size = 4096, .permissions = .{ .read = true, .write = true } });
        try memory.store(0xc00000, 8, (@as(u64, 43) << 32) | 1);
        try memory.store(0xc00030, 8, 0x9876543210000000);
        var output: [43]u8 = undefined;
        for (&output, 0..) |*byte, i| {
            byte.* = @intCast((7 * i + 3) & 255);
            try memory.store(0xc00008 + i, 1, byte.*);
        }
        var policy = try R.policy.Policy.fromMemory(allocator, &memory);
        errdefer policy.deinit();
        const cache = try R.values.Cache.fromMemory(allocator, geometry, &memory);
        return .{ .memory = memory, .policy = policy, .cache = cache, .output = output };
    }
    fn statement(self: *const Fixture) terminal.Statement {
        return .{ .geometry = self.cache.geometry, .root = self.cache.root(), .policy = &self.policy, .halt_flag = 0xc00000, .output = self.output };
    }
    fn deinit(self: *Fixture) void {
        self.cache.deinit();
        self.policy.deinit();
        self.memory.deinit();
    }
};
const Report = struct {
    schema: []const u8 = "rv64-terminal-root-observation-receipt-v1",
    status: []const u8,
    context_sha256: [64]u8,
    context_bytes: usize,
    proof_sha256: ?[64]u8 = null,
    proof_bytes: ?usize = null,
    root: R.values.Digest,
    chunk_bytes: usize,
    halt_flag: u64,
    expected_output: [86]u8,
    source_cost: Cost,
    fri_queries: u32 = 70,
    pow_bits: u32 = 26,
    root_observation_verified: bool = false,
    fresh_receiver_mode: bool = false,
    state_debt_zero: bool = true,
    synthetic_ram_events: bool = false,
    public_per_cell_ledger: bool = false,
    public_permutation_ledger: bool = false,
    absorbing_pc_checked: bool = false,
    cpu_execution_proved: bool = false,
    ethereum_execution: bool = false,
    zero_knowledge_claim: bool = false,
    benchmark: bool = false,
};
fn emit(report: Report) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try std.fs.File.stdout().writeAll(bytes);
    try std.fs.File.stdout().writeAll("\n");
}
fn write(path: []const u8, bytes: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .exclusive = true });
    errdefer std.fs.cwd().deleteFile(path) catch {};
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}
pub fn run(args: []const []const u8) !void {
    if (args.len == 4 and std.mem.eql(u8, args[1], "terminal-fixture")) {
        const geometry: R.values.Geometry = if (std.mem.eql(u8, args[2], "512")) .chunk512 else if (std.mem.eql(u8, args[2], "4096")) .page4096 else return error.ExpectedTerminalGeometry;
        var fixture = try Fixture.init(a, geometry);
        defer fixture.deinit();
        const public = fixture.statement();
        const bytes = try encode(a, public);
        defer a.free(bytes);
        try write(args[3], bytes);
        return emit(.{ .status = "synthetic_terminal_public_context_created", .context_sha256 = std.fmt.bytesToHex(base_codec.hash(bytes), .lower), .context_bytes = bytes.len, .root = public.root, .chunk_bytes = geometry.bytes(), .halt_flag = public.halt_flag, .expected_output = std.fmt.bytesToHex(public.output, .lower), .source_cost = try cost(public) });
    }
    if (args.len != 5 or args[3].len != 64) return error.ExpectedTerminalModeContextPinnedSha256Proof;
    const proving = std.mem.eql(u8, args[1], "terminal-prove");
    if (!proving and !std.mem.eql(u8, args[1], "terminal-verify")) return error.InvalidTerminalReceiptMode;
    var pin: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pin, args[3]);
    const context_bytes = try std.fs.cwd().readFileAlloc(a, args[2], MAX_CONTEXT_BYTES);
    defer a.free(context_bytes);
    var context = try decode(a, context_bytes, pin);
    defer context.deinit();
    const public = context.statement();
    var bytes: []u8 = undefined;
    if (proving) {
        var fixture = try Fixture.init(a, public.geometry);
        defer fixture.deinit();
        bytes = try terminal.prove(a, public, &fixture.cache, &fixture.memory);
        errdefer a.free(bytes);
        try write(args[4], bytes);
    } else {
        bytes = try std.fs.cwd().readFileAlloc(a, args[4], 128 * 1024 * 1024);
        errdefer a.free(bytes);
        try terminal.verify(a, public, bytes);
    }
    defer a.free(bytes);
    try emit(.{ .status = if (proving) "terminal_root_receipt_produced" else "terminal_root_receipt_verified", .context_sha256 = std.fmt.bytesToHex(pin, .lower), .context_bytes = context_bytes.len, .proof_sha256 = std.fmt.bytesToHex(base_codec.hash(bytes), .lower), .proof_bytes = bytes.len, .root = public.root, .chunk_bytes = public.geometry.bytes(), .halt_flag = public.halt_flag, .expected_output = std.fmt.bytesToHex(public.output, .lower), .source_cost = try cost(public), .root_observation_verified = !proving, .fresh_receiver_mode = !proving });
}
