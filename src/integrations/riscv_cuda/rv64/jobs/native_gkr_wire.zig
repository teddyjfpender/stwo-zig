//! Class-only programs for the canonical local-GKR receipt and child wire.
//! Polynomial coefficient counts remain device values: the interpreter must
//! preserve their exact lengths, including zero/short polynomials.
const std = @import("std");
const NG = @import("native_gkr.zig");
const Slab = @import("slab.zig");

pub const magic: u32 = 0x3157474c; // LGW1
pub const header_words = 12;
pub const Src = enum(u32) { pool = 0, section = 1, scope = 2, marginals = 3 };
pub const Kind = enum(u32) { bytes = 0, words = 1, felts = 2, poly32 = 3, poly64 = 4, widen_u32 = 5 };
pub const Op = extern struct { kind: Kind, source: Src, offset: u32, count: u32 };

pub const Run = extern struct {
    program: [*]const u32,
    program_words: u64,
    section: [*]const u32,
    section_words: u64,
    scope: [*]const u32,
    marginals: [*]const u32,
    marginal_words: u64,
    receipt: [*]u32,
    wire: [*]u32,
    wire_words: u64,
    verdict: [*]u32,
    reject_code: u32,
    reserved: u32 = 0,
};
comptime {
    if (@sizeOf(Run) != 96) @compileError("local GKR wire ABI changed");
}
pub const EncodeFn = *const fn (*anyopaque, u32, *const Run) callconv(.c) c_int;
pub fn load(addon: *std.DynLib) !EncodeFn {
    return addon.lookup(EncodeFn, "stwo_rv64_gkr_receipt_encode_v1_on") orelse error.MissingLocalGkrReceiptEncoder;
}

pub const Program = struct {
    a: std.mem.Allocator,
    words: []u32,
    max_wire_bytes: usize,
    pub fn deinit(self: *Program) void {
        self.a.free(self.words);
    }
    pub fn wireWords(self: Program) usize {
        return 1 + (self.max_wire_bytes + 3) / 4;
    }
};

const Builder = struct {
    a: std.mem.Allocator,
    ops: std.ArrayListUnmanaged(Op) = .empty,
    pool: *std.ArrayListUnmanaged(u8),
    max_bytes: usize = 0,
    fn deinit(self: *Builder) void {
        self.ops.deinit(self.a);
    }
    fn op(self: *Builder, kind: Kind, source: Src, offset: usize, count: usize) !void {
        const n: usize = switch (kind) {
            .bytes => count,
            .words => try std.math.mul(usize, count, 4),
            .felts => try std.math.mul(usize, count, 32),
            .poly32 => 4 + 4 * 32,
            .poly64 => 8 + 4 * 32,
            .widen_u32 => 8,
        };
        self.max_bytes = try std.math.add(usize, self.max_bytes, n);
        try self.ops.append(self.a, .{ .kind = kind, .source = source, .offset = std.math.cast(u32, offset) orelse return error.LocalGkrProofLimit, .count = std.math.cast(u32, count) orelse return error.LocalGkrProofLimit });
    }
    fn bytes(self: *Builder, value: []const u8) !void {
        const at = self.pool.items.len;
        try self.pool.appendSlice(self.a, value);
        try self.op(.bytes, .pool, at, value.len);
    }
    fn integer(self: *Builder, comptime T: type, value: anytype) !void {
        var b: [@sizeOf(T)]u8 = undefined;
        std.mem.writeInt(T, &b, std.math.cast(T, value) orelse return error.LocalGkrProofLimit, .little);
        try self.bytes(&b);
    }
};

pub fn build(a: std.mem.Allocator, instances: []const NG.Instance, variables: []const u32, fields: NG.Fields, layout: *const Slab.ProofLayout) !Program {
    if (instances.len == 0 or instances.len > 64 or instances.len != variables.len) return error.LocalGkrReceiptShape;
    var max_variables: u32 = 0;
    for (instances, variables) |instance, v| {
        if (v != try instance.variables()) return error.LocalGkrReceiptShape;
        max_variables = @max(max_variables, v);
    }
    if (max_variables == 0 or max_variables > 30 or fields.layers != max_variables) return error.LocalGkrReceiptShape;
    var pool: std.ArrayListUnmanaged(u8) = .empty;
    defer pool.deinit(a);
    var receipt = Builder{ .a = a, .pool = &pool };
    defer receipt.deinit();
    var wire = Builder{ .a = a, .pool = &pool };
    defer wire.deinit();
    const v3 = NG.v3Instances(instances);
    try receipt.bytes(if (v3) "RV64-SERVICES-LOCAL-GKR-OM31-V3" else "RV64-SERVICES-LOCAL-GKR-OM31-V1");
    try receipt.op(.words, .scope, 0, 24); // statement, FIXED, MAIN
    try receipt.op(.widen_u32, .scope, 24, 1); // ordinal
    try receipt.integer(u64, 8);
    try receipt.integer(u64, instances.len);
    for (instances) |instance| {
        for (NG.originWords(instance.origin)) |word| try receipt.integer(u64, word);
        try receipt.integer(u64, instance.row_log);
        try receipt.integer(u64, instance.terms);
        try receipt.integer(u64, try instance.variables());
        try receipt.integer(u64, instance.fixed_offset);
        try receipt.integer(u64, instance.main_offset);
    }
    try receipt.integer(u64, max_variables);
    try wire.bytes(if (v3) "RV64LGK3" else "RV64LGKO");
    try wire.integer(u32, 8);
    try wire.integer(u32, instances.len);
    const roots = try layout.get(.gkr_section, fields.roots());
    if (roots.words != 16 * instances.len) return error.LocalGkrReceiptShape;
    for (variables, 0..) |v, i| {
        try wire.integer(u32, v);
        try wire.op(.felts, .section, roots.offset + 16 * i, 2);
    }
    try wire.integer(u32, max_variables);
    for (0..max_variables) |depth| {
        const records = try layout.get(.gkr_section, fields.records(@intCast(depth)));
        if (records.words != 44 * depth) return error.LocalGkrReceiptShape;
        try receipt.integer(u64, depth);
        try wire.integer(u32, depth);
        for (0..depth) |round| {
            try receipt.op(.poly64, .section, records.offset + 44 * round, round);
            try wire.op(.poly32, .section, records.offset + 44 * round, round);
        }
    }
    for (variables, 0..) |v, i| {
        try receipt.integer(u64, v);
        for (0..v) |j| {
            const remaining = v - @as(u32, @intCast(j));
            const depth = max_variables - remaining;
            const masks = try layout.get(.gkr_section, fields.masks(depth));
            var active_before: usize = 0;
            for (variables[0..i]) |prior| active_before += @intFromBool(prior >= remaining);
            const at = masks.offset + 32 * active_before;
            if (at + 32 > masks.offset + masks.words) return error.LocalGkrReceiptShape;
            try receipt.integer(u64, 2); // columns
            for (0..2) |column| {
                try receipt.integer(u64, 2); // [left, right]
                try receipt.op(.felts, .section, at + 16 * column, 2);
            }
            try wire.op(.felts, .section, at, 4);
        }
    }
    for (0..instances.len) |i| {
        try receipt.integer(u64, 2);
        try receipt.op(.felts, .section, roots.offset + 16 * i, 2);
        try receipt.integer(u64, 2);
        try receipt.op(.felts, .marginals, 16 * i, 2);
    }
    if (wire.max_bytes > 16 << 20) return error.LocalGkrProofLimit;
    const n = header_words + 4 * (receipt.ops.items.len + wire.ops.items.len) + (pool.items.len + 3) / 4;
    const words = try a.alloc(u32, n);
    @memset(words, 0);
    words[0..header_words].* = .{ magic, 1, @intCast(n), @intCast(receipt.ops.items.len), @intCast(wire.ops.items.len), @intCast(wire.max_bytes), @intCast(pool.items.len), @intCast(layout.words), @intCast(16 * instances.len), header_words, @intCast(header_words + 4 * receipt.ops.items.len), @intCast(header_words + 4 * (receipt.ops.items.len + wire.ops.items.len)) };
    const r = std.mem.sliceAsBytes(receipt.ops.items);
    const w = std.mem.sliceAsBytes(wire.ops.items);
    @memcpy(std.mem.sliceAsBytes(words)[4 * words[9] ..][0..r.len], r);
    @memcpy(std.mem.sliceAsBytes(words)[4 * words[10] ..][0..w.len], w);
    @memcpy(std.mem.sliceAsBytes(words)[4 * words[11] ..][0..pool.items.len], pool.items);
    return .{ .a = a, .words = words, .max_wire_bytes = wire.max_bytes };
}

/// Host reference interpreter used by the codec and CUDA parity tests.
pub fn emit(a: std.mem.Allocator, p: []const u32, wire: bool, section: []const u32, scope: []const u32, marginals: []const u32) ![]u8 {
    if (p.len < header_words or p[0] != magic or p[1] != 1 or p[2] != p.len or p[7] != section.len or p[8] != marginals.len or scope.len != 25) return error.LocalGkrReceiptShape;
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(a);
    const ops_at = p[if (wire) 10 else 9];
    const count = p[if (wire) 4 else 3];
    if (@as(u64, ops_at) + 4 * @as(u64, count) > p.len or p[11] > p.len or @as(u64, p[11]) * 4 + p[6] > p.len * 4) return error.LocalGkrReceiptShape;
    const pool = std.mem.sliceAsBytes(p[p[11]..])[0..p[6]];
    for (0..count) |i| {
        const op = p[ops_at + 4 * i ..][0..4];
        const kind = std.meta.intToEnum(Kind, op[0]) catch return error.LocalGkrReceiptShape;
        const src = std.meta.intToEnum(Src, op[1]) catch return error.LocalGkrReceiptShape;
        if (kind == .bytes) {
            if (src != .pool or @as(u64, op[2]) + op[3] > pool.len) return error.LocalGkrReceiptShape;
            try out.appendSlice(a, pool[op[2]..][0..op[3]]);
            continue;
        }
        const from = switch (src) {
            .section => section,
            .scope => scope,
            .marginals => marginals,
            .pool => return error.LocalGkrReceiptShape,
        };
        const needed: u64 = switch (kind) {
            .words => op[3],
            .felts => 8 * @as(u64, op[3]),
            .poly32, .poly64 => 44,
            .widen_u32 => 1,
            .bytes => unreachable,
        };
        if (@as(u64, op[2]) + needed > from.len) return error.LocalGkrReceiptShape;
        const data = from[op[2]..][0..@intCast(needed)];
        switch (kind) {
            .words => try appendWords(a, &out, data, false),
            .felts => try appendWords(a, &out, data, true),
            .widen_u32 => {
                try appendWords(a, &out, &.{ data[0], 0 }, false);
            },
            .poly32, .poly64 => {
                const n = data[40];
                if (n > 4 or data[41] != op[3] or data[42] != 0 or data[43] != 0) return error.LocalGkrReceiptShape;
                for (data[0..40]) |value| if (value >= 0x7fffffff) return error.NoncanonicalLocalGkrCoordinate;
                for (data[8 * n .. 32]) |value| if (value != 0) return error.LocalGkrReceiptShape;
                if (n != 0 and std.mem.allEqual(u32, data[8 * (n - 1) ..][0..8], 0)) return error.LocalGkrReceiptShape;
                try appendWords(a, &out, if (kind == .poly64) &.{ n, 0 } else &.{n}, false);
                try appendWords(a, &out, data[0 .. 8 * n], true);
            },
            .bytes => unreachable,
        }
    }
    if (wire and out.items.len > p[5]) return error.LocalGkrProofLimit;
    return out.toOwnedSlice(a);
}

fn appendWords(a: std.mem.Allocator, out: *std.ArrayListUnmanaged(u8), words: []const u32, canonical: bool) !void {
    for (words) |value| {
        if (canonical and value >= 0x7fffffff) return error.NoncanonicalLocalGkrCoordinate;
        var b: [4]u8 = undefined;
        std.mem.writeInt(u32, &b, value, .little);
        try out.appendSlice(a, &b);
    }
}

test {
    _ = @import("native_gkr_wire_test.zig");
}
