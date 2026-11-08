//! Bounded stage-one manifest serialization from peer-exchange device values.
//! Programs hold public framing only. A child contributes its actual device
//! length and bytes; every exchange read checks the current request flag.
const std = @import("std");
const G = @import("gpu_native.zig");
pub const magic: u32 = 0x31574d47; // GMW1
pub const header_words = 12;
pub const Kind = enum(u32) { bytes, words, child };
pub const Op = extern struct { kind: Kind, offset: u32, count: u32, flag: u32 = 0xffffffff };
pub const Run = extern struct {
    program: [*]const u32,
    program_words: u64,
    exchange: [*]const u32,
    exchange_words: u64,
    tag: u32,
    reserved: u32 = 0,
    encoded: [*]u32,
    encoded_words: u64,
    verdict: [*]u32,
    reject_code: u32,
    reserved2: u32 = 0,
};
comptime {
    if (@sizeOf(Run) != 72) @compileError("manifest wire ABI changed");
}
pub const EncodeFn = *const fn (*anyopaque, u32, *const Run) callconv(.c) c_int;
pub fn load(addon: *std.DynLib) !EncodeFn {
    return addon.lookup(EncodeFn, "stwo_rv64_manifest_encode_v1_on") orelse error.MissingManifestEncoder;
}
pub const Program = struct {
    a: std.mem.Allocator,
    words: []u32,
    max_bytes: usize,
    pub fn deinit(self: *Program) void {
        self.a.free(self.words);
    }
};
const Builder = struct {
    a: std.mem.Allocator,
    ops: std.ArrayListUnmanaged(Op) = .empty,
    pool: std.ArrayListUnmanaged(u8) = .empty,
    max_bytes: usize = 0,
    fn bytes(self: *Builder, b: []const u8) !void {
        const at = self.pool.items.len;
        try self.pool.appendSlice(self.a, b);
        try self.ops.append(self.a, .{ .kind = .bytes, .offset = @intCast(at), .count = @intCast(b.len) });
        self.max_bytes = try std.math.add(usize, self.max_bytes, b.len);
    }
    fn integer(self: *Builder, v: usize) !void {
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, std.math.cast(u32, v) orelse return error.GlobalGkrManifestLimit, .little);
        try self.bytes(&b);
    }
    fn slot(self: *Builder, kind: Kind, s: G.Exchange.Slot) !void {
        if (kind == .bytes or s.words == 0 or (kind == .child and s.words < 2)) return error.GlobalGkrManifestShape;
        try self.ops.append(self.a, .{ .kind = kind, .offset = @intCast(s.offset), .count = @intCast(s.words), .flag = @intCast(s.flag) });
        self.max_bytes = try std.math.add(usize, self.max_bytes, 4 * s.words);
    }
};
pub fn build(a: std.mem.Allocator, execution: [32]u8, entries: anytype, exchange: G.Exchange) !Program {
    if (entries.len == 0 or entries.len > 65535) return error.GlobalGkrManifestRoster;
    var b = Builder{ .a = a };
    defer b.ops.deinit(a);
    defer b.pool.deinit(a);
    try b.bytes("RV64MGK1");
    try b.bytes(&execution);
    try b.integer(entries.len);
    for (entries, 0..) |e, i| {
        if (e.ordinal != i or (e.segment != null and e.truth != null)) return error.GlobalGkrManifestOrdinal;
        try b.integer(e.ordinal);
        if (e.segment) |s| try b.slot(.words, try exchange.root(s)) else if (e.truth) |t| try b.slot(.words, try exchange.truthRoot(t)) else try b.bytes(&e.main);
        try b.integer(@intFromBool(e.local_instances != null));
        if (e.local_instances != null) {
            const s = e.segment orelse return error.GlobalGkrManifestShape;
            try b.slot(.words, try exchange.receipt(s));
            // Child slot is [byte length, bytes]. Copying this representation
            // contributes both the u32 length and its actual payload.
            try b.slot(.child, try exchange.childWire(s));
        }
    }
    if (b.max_bytes > 64 << 20) return error.GlobalGkrManifestLimit;
    const pool_at = header_words + 4 * b.ops.items.len;
    const words = try a.alloc(u32, pool_at + (b.pool.items.len + 3) / 4);
    @memset(words, 0);
    words[0..header_words].* = .{ magic, 1, @intCast(words.len), @intCast(b.ops.items.len), @intCast(b.max_bytes), @intCast(b.pool.items.len), @intCast(exchange.words()), header_words, @intCast(pool_at), 0, 0, 0 };
    @memcpy(std.mem.sliceAsBytes(words[header_words..pool_at]), std.mem.sliceAsBytes(b.ops.items));
    @memcpy(std.mem.sliceAsBytes(words[pool_at..])[0..b.pool.items.len], b.pool.items);
    return .{ .a = a, .words = words, .max_bytes = b.max_bytes };
}
pub fn emit(a: std.mem.Allocator, p: []const u32, exchange: []const u32, tag: u32) ![]u8 {
    if (p.len < header_words or p[0] != magic or p[1] != 1 or p[2] != p.len or p[6] != exchange.len or p[7] != header_words or @as(u64, p[8]) != header_words + 4 * @as(u64, p[3]) or @as(u64, p[8]) * 4 + p[5] > 4 * p.len) return error.GlobalGkrManifestShape;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(a);
    const pool = std.mem.sliceAsBytes(p[p[8]..])[0..p[5]];
    for (0..p[3]) |i| {
        const op = p[header_words + 4 * i ..][0..4];
        const kind = std.meta.intToEnum(Kind, op[0]) catch return error.GlobalGkrManifestShape;
        if (kind == .bytes) {
            if (@as(u64, op[1]) + op[2] > pool.len) return error.GlobalGkrManifestShape;
            try out.appendSlice(a, pool[op[1]..][0..op[2]]);
        } else {
            if (op[3] >= exchange.len or exchange[op[3]] != tag) return error.GlobalGkrManifestNotLanded;
            if (@as(u64, op[1]) + op[2] > exchange.len) return error.GlobalGkrManifestShape;
            const from = exchange[op[1]..][0..op[2]];
            const len = if (kind == .words) 4 * from.len else blk: {
                if (from.len < 2 or from[0] == 0 or from[0] > 16 << 20 or from[0] > (from.len - 1) * 4) return error.GlobalGkrManifestLimit;
                break :blk 4 + @as(usize, from[0]);
            };
            try out.appendSlice(a, std.mem.sliceAsBytes(from)[0..len]);
        }
        if (out.items.len > p[4]) return error.GlobalGkrManifestLimit;
    }
    return out.toOwnedSlice(a);
}
