//! Durable private RAM GRAPH qualification. Context contains roots/immutable
//! mappings only; no private words or permutation ledger. CPU debt remains OPEN.
//! Private witness is not a zero-knowledge claim: this profile has no ZK masks.
const std = @import("std");
const frontend = @import("stwo_riscv_frontend");
const R = frontend.rv64_air.memory;
const proof = @import("rv64_ram_private.zig");
const a = std.heap.smp_allocator;
pub const MAX_CONTEXT_BYTES = 84 + 17 * 256;
pub const Context = struct {
    geometry: R.values.Geometry,
    before: R.values.Digest,
    after: R.values.Digest,
    policy: R.policy.Policy,
    pub fn statement(self: *const Context) proof.Statement {
        return .{ .geometry = self.geometry, .before = self.before, .after = self.after, .policy = &self.policy };
    }
    pub fn deinit(self: *Context) void {
        self.policy.deinit();
        self.* = undefined;
    }
};
pub fn hash(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}
fn appendU32(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: u32) !void {
    var bytes: [4]u8 = undefined;
    std.mem.writeInt(u32, &bytes, value, .little);
    try out.appendSlice(allocator, &bytes);
}
fn appendU64(allocator: std.mem.Allocator, out: *std.ArrayList(u8), value: u64) !void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, value, .little);
    try out.appendSlice(allocator, &bytes);
}
pub fn encode(allocator: std.mem.Allocator, public: proof.Statement) ![]u8 {
    try public.policy.validateImmutableExecution();
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    try appendU32(allocator, &output, 0x52504332);
    try appendU32(allocator, &output, public.geometry.logBytes());
    for ([_]R.values.Digest{ public.before, public.after }) |digest| for (digest) |word| {
        if (word >= 0x7fff_ffff) return error.NonCanonicalDigest;
        try appendU32(allocator, &output, word);
    };
    try appendU32(allocator, &output, @intCast(public.policy.regions.len));
    for (public.policy.regions) |region| {
        try appendU64(allocator, &output, region.first);
        try appendU64(allocator, &output, region.last);
        try output.append(allocator, region.flags);
    }
    return output.toOwnedSlice(allocator);
}
/// SHA is an independently provided context pin, not an advertised prover hash.
/// All structural and digest checks occur before the first owned allocation.
pub fn decode(allocator: std.mem.Allocator, bytes: []const u8, independently_expected_sha: [32]u8) !Context {
    if (bytes.len < 84 or bytes.len > MAX_CONTEXT_BYTES) return error.InvalidPrivateRamContext;
    if (!std.mem.eql(u8, &hash(bytes), &independently_expected_sha)) return error.PrivateRamContextShaMismatch;
    if (std.mem.readInt(u32, bytes[0..4], .little) != 0x52504332) return error.InvalidPrivateRamContext;
    const geometry: R.values.Geometry = switch (std.mem.readInt(u32, bytes[4..8], .little)) {
        9 => .chunk512,
        12 => .page4096,
        else => return error.InvalidPrivateRamContext,
    };
    const count = std.mem.readInt(u32, bytes[80..84], .little);
    if (count > 256 or bytes.len != 84 + @as(usize, count) * 17) return error.InvalidPrivateRamContext;
    var before: R.values.Digest = undefined;
    var after: R.values.Digest = undefined;
    var at: usize = 8;
    for ([_]*R.values.Digest{ &before, &after }) |digest| for (digest) |*word| {
        word.* = std.mem.readInt(u32, bytes[at..][0..4], .little);
        if (word.* >= 0x7fff_ffff) return error.NonCanonicalDigest;
        at += 4;
    };
    var regions: [256]R.policy.Region = undefined;
    for (regions[0..count], 0..) |*region, i| {
        const offset = 84 + 17 * i;
        const flags = bytes[offset + 16];
        if (flags > 7) return error.InvalidPrivateRamContext;
        region.* = .{ .first = std.mem.readInt(u64, bytes[offset..][0..8], .little), .last = std.mem.readInt(u64, bytes[offset + 8 ..][0..8], .little), .flags = @intCast(flags) };
        if (region.first > region.last or (i != 0 and regions[i - 1].last >= region.first) or flags & 6 == 6) return error.InvalidPrivateRamContext;
    }
    var mappings = try R.policy.Policy.init(allocator, regions[0..count]);
    errdefer mappings.deinit();
    try mappings.validateImmutableExecution();
    return .{ .geometry = geometry, .before = before, .after = after, .policy = mappings };
}
fn write(path: []const u8, bytes: []const u8) !void {
    var file = try std.fs.cwd().createFile(path, .{ .exclusive = true });
    errdefer std.fs.cwd().deleteFile(path) catch {};
    defer file.close();
    try file.writeAll(bytes);
    try file.sync();
}
const Report = struct {
    schema: []const u8 = "rv64-private-ram-graph-receipt-v2",
    status: []const u8,
    context_sha256: [64]u8,
    context_bytes: usize,
    proof_sha256: ?[64]u8 = null,
    proof_bytes: ?usize = null,
    chunk_bytes: usize,
    before_root: R.values.Digest,
    after_root: R.values.Digest,
    fri_queries: u32 = 70,
    pow_bits: u32 = 26,
    graph_verified: bool = false,
    fresh_receiver_mode: bool = false,
    private_word_witness: bool = true,
    public_per_cell_ledger: bool = false,
    public_permutation_ledger: bool = false,
    cpu_state_closed: bool = false,
    state_continuation: bool = false,
    ethereum_execution: bool = false,
    zero_knowledge_claim: bool = false,
    benchmark: bool = false,
    elapsed_ns: ?u64 = null,
};
fn emit(report: Report) !void {
    const bytes = try std.json.Stringify.valueAlloc(a, report, .{ .whitespace = .indent_2 });
    defer a.free(bytes);
    try std.fs.File.stdout().writeAll(bytes);
    try std.fs.File.stdout().writeAll("\n");
}
fn fixtureTrace(allocator: std.mem.Allocator, geometry: R.values.Geometry, mappings: *const R.policy.Policy) !R.private_trace.Trace {
    var cache = try R.values.Cache.empty(allocator, geometry);
    defer cache.deinit();
    const before: [512]u64 = @splat(0);
    var after = before;
    after[0] = 17;
    after[geometry.cells() - 1] = 0xfedc_ba98_7654_3210;
    var clocks: [512]u32 = @splat(0);
    clocks[0] = 4;
    clocks[geometry.cells() - 1] = 8;
    const rights: [512]u2 = @splat(3);
    const openings = [_]R.batch.Opening{.{ .index = @as(u64, 0x1000) >> geometry.logBytes(), .before = before[0..geometry.cells()], .after = after[0..geometry.cells()], .terminal_clocks = clocks[0..geometry.cells()], .rights = rights[0..geometry.cells()] }};
    return R.private_trace.Trace.init(allocator, &cache, mappings, &openings);
}
fn fixture(geometry: R.values.Geometry, path: []const u8) !void {
    var mappings = try R.policy.Policy.init(a, &.{.{ .first = 0x1000, .last = 0x1fff, .flags = 3 }});
    defer mappings.deinit();
    var trace = try fixtureTrace(a, geometry, &mappings);
    defer trace.deinit();
    const bytes = try encode(a, .{ .geometry = geometry, .before = trace.witness.before, .after = trace.witness.after, .policy = &mappings });
    defer a.free(bytes);
    try write(path, bytes);
    try emit(.{ .status = "synthetic_public_root_context_created", .context_sha256 = std.fmt.bytesToHex(hash(bytes), .lower), .context_bytes = bytes.len, .chunk_bytes = geometry.bytes(), .before_root = trace.witness.before, .after_root = trace.witness.after });
}
pub fn run(args: []const []const u8) !void {
    if (args.len == 4 and std.mem.eql(u8, args[1], "private-fixture")) {
        const geometry: R.values.Geometry = if (std.mem.eql(u8, args[2], "512")) .chunk512 else if (std.mem.eql(u8, args[2], "4096")) .page4096 else return error.ExpectedPrivateRamGeometry;
        return fixture(geometry, args[3]);
    }
    if (args.len != 5 or args[3].len != 64) return error.ExpectedPrivateModeContextPinnedSha256Proof;
    const proving = std.mem.eql(u8, args[1], "private-prove");
    if (!proving and !std.mem.eql(u8, args[1], "private-verify")) return error.InvalidPrivateRamReceiptMode;
    var pin: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pin, args[3]);
    const context_bytes = try std.fs.cwd().readFileAlloc(a, args[2], MAX_CONTEXT_BYTES);
    defer a.free(context_bytes);
    var context = try decode(a, context_bytes, pin);
    defer context.deinit();
    var timer = try std.time.Timer.start();
    var bytes: []u8 = undefined;
    if (proving) {
        var trace = try fixtureTrace(a, context.geometry, &context.policy);
        defer trace.deinit();
        bytes = try proof.proveReceiptOpenState(a, context.statement(), &trace);
        errdefer a.free(bytes);
        try write(args[4], bytes);
    } else {
        bytes = try std.fs.cwd().readFileAlloc(a, args[4], 128 * 1024 * 1024);
        errdefer a.free(bytes);
        _ = try proof.verifyReceiptOpenState(a, context.statement(), bytes);
    }
    defer a.free(bytes);
    try emit(.{ .status = if (proving) "private_ram_graph_receipt_produced" else "private_ram_graph_receipt_verified", .context_sha256 = std.fmt.bytesToHex(pin, .lower), .context_bytes = context_bytes.len, .proof_sha256 = std.fmt.bytesToHex(hash(bytes), .lower), .proof_bytes = bytes.len, .chunk_bytes = context.geometry.bytes(), .before_root = context.before, .after_root = context.after, .graph_verified = !proving, .fresh_receiver_mode = !proving, .elapsed_ns = timer.read() });
}
