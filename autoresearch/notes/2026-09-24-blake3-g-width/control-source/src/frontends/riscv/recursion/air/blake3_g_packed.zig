//! Compact typed BLAKE3 arithmetic. Call/control binding and production layout
//! admission are separate from these arithmetic and lookup obligations.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const relation = @import("../../air/lang/relation.zig");
const effects = @import("relation_effect.zig");
const Id = lang.types.ValueId;
const span = lang.source.SourceSpan.generated();
pub const COLUMN_COUNT = 124;
pub const CONSTRAINT_COUNT = 80;
pub const EVENT_COUNT = 56;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "4d97d2df517a07b5dc1b59659734f81e9ab4eaa34651e31648fba9df2921c5f2") catch @compileError("invalid packed BLAKE3 digest");
    break :blk out;
};
pub const Row = [COLUMN_COUNT]core.fields.m31.M31;
pub const Definition = struct {
    arena: lang.ir.Arena,
    input: [6][4]Id,
    output: [4][4]Id,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
};
pub fn build(allocator: std.mem.Allocator) !Definition {
    var ops = Typed{ .arena = lang.ir.Arena.init(allocator) };
    errdefer ops.arena.deinit();
    var input: [6]Typed.Word = undefined;
    for (&input) |*word| word.* = try ops.word(true);
    const output = try core.crypto.blake3_compression.g(Typed, &ops, input);
    try lang.validate.validate(&ops.arena);
    if (ops.columns != COLUMN_COUNT or ops.arena.constraintsView().len != CONSTRAINT_COUNT or ops.arena.effectsView().len != EVENT_COUNT) return error.InvalidBlake3PackedGeometry;
    const identity = try lang.digest.computeIdentity(&ops.arena);
    if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST)) return error.InvalidBlake3PackedSemantics;
    return .{ .arena = ops.arena, .input = input, .output = output };
}
/// Predeclare physical inputs for consumers whose layout contract requires an
/// input prefix. Discover types from the pinned author, then reuse the same G
/// author with those exact IDs; no arithmetic equations are transcribed.
pub fn buildForCall(comptime fixed_count: usize, allocator: std.mem.Allocator) !struct { definition: Definition, fixed: [fixed_count]Id } {
    var source = try build(allocator);
    defer source.deinit();
    var arena = lang.ir.Arena.init(allocator);
    errdefer arena.deinit();
    var ids: [COLUMN_COUNT]Id = undefined;
    var at: usize = 0;
    for (source.arena.nodesView()) |node| {
        if (node.key.op != .input) continue;
        var buf: [48]u8 = undefined;
        ids[at] = try arena.input(try std.fmt.bufPrint(&buf, "blake3_packed.value_{d}", .{at}), node.key.ty, span);
        at += 1;
    }
    std.debug.assert(at == COLUMN_COUNT);
    var fixed: [fixed_count]Id = undefined;
    for (&fixed, 0..) |*id, i| {
        var buf: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&buf, "blake3_g_call.fixed_{d}", .{i}), .felt, span);
    }
    var ops = Typed{ .arena = arena, .predeclared = &ids };
    arena = lang.ir.Arena.init(allocator);
    errdefer ops.arena.deinit();
    var input: [6]Typed.Word = undefined;
    for (&input) |*word| word.* = try ops.word(true);
    const output = try core.crypto.blake3_compression.g(Typed, &ops, input);
    try lang.validate.validate(&ops.arena);
    return .{ .definition = .{ .arena = ops.arena, .input = input, .output = output }, .fixed = fixed };
}
fn bounded(bits: u8) lang.types.Type {
    return .{ .bounded_uint = .{ .bits = bits, .representation = .canonical_field } };
}
const Typed = struct {
    pub const Word = [4]Id;
    arena: lang.ir.Arena,
    columns: usize = 0,
    predeclared: ?*const [COLUMN_COUNT]Id = null,
    fn input(self: *Typed, ty: lang.types.Type) !Id {
        if (self.predeclared) |ids| {
            const id = ids[self.columns];
            if (!std.meta.eql(ty, self.arena.node(id).?.key.ty)) return error.InvalidBlake3PackedGeometry;
            self.columns += 1;
            return id;
        }
        var buf: [48]u8 = undefined;
        const id = try self.arena.input(try std.fmt.bufPrint(&buf, "blake3_packed.value_{d}", .{self.columns}), ty, span);
        self.columns += 1;
        return id;
    }
    fn constant(self: *Typed, n: u32) !Id {
        return self.arena.constantField(n, span);
    }
    fn constrain(self: *Typed, root: Id) !void {
        var buf: [48]u8 = undefined;
        _ = try self.arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_packed.constraint_{d}", .{self.arena.constraintsView().len}), root, null, .semantic, span);
    }
    fn bit(self: *Typed) !Id {
        const id = try self.input(.bit);
        try self.constrain(try self.arena.mul(id, try self.arena.sub(id, try self.constant(1), span), span));
        return id;
    }
    fn lookup(self: *Typed, domain: relation.Domain, values: []const Id) !void {
        _ = try effects.appendGroup(1, &self.arena, .{.{ .domain = domain, .role = .request, .values = values, .weight = try self.constant(1) }}, span);
    }
    fn word(self: *Typed, range: bool) !Word {
        var out: Word = undefined;
        for (&out) |*id| id.* = try self.input(.byte);
        if (range) {
            try self.lookup(.range_check_8_8, out[0..2]);
            try self.lookup(.range_check_8_8, out[2..4]);
        }
        return out;
    }
    pub fn add(self: *Typed, a: Word, b: Word) !Word {
        const result = try self.word(true);
        var carry = try self.constant(0);
        for (a, b, result) |x, y, out| {
            const next = try self.bit();
            const lhs = try self.arena.add(try self.arena.add(x, y, span), carry, span);
            const rhs = try self.arena.add(out, try self.arena.mul(try self.constant(256), next, span), span);
            try self.constrain(try self.arena.sub(lhs, rhs, span));
            carry = next;
        }
        return result;
    }
    fn narrowByte(self: *Typed, comptime bits: u5) !Id {
        const value = try self.input(.byte);
        const scaled = try self.input(.byte);
        try self.lookup(.range_check_8_8, &.{ value, scaled });
        try self.constrain(try self.arena.sub(scaled, try self.arena.mul(try self.constant(1 << (8 - bits)), value, span), span));
        return value;
    }
    pub fn xorRotate(self: *Typed, a: Word, b: Word, comptime rotation: u5) !Word {
        const xors = try self.word(false);
        const operation = try self.arena.constantUnsigned(bounded(2), 2, span);
        for (a, b, xors) |x, y, z| try self.lookup(.bitwise, &.{ x, y, z, operation });
        if (rotation == 16 or rotation == 8) {
            var out: Word = undefined;
            for (&out, 0..) |*id, i| id.* = xors[(i + rotation / 8) % 4];
            return out;
        }
        const shift = rotation % 8;
        var low: Word = undefined;
        var high: Word = undefined;
        for (xors, 0..) |value, i| {
            low[i] = try self.narrowByte(shift);
            high[i] = if (shift == 7) try self.bit() else try self.narrowByte(4);
            const joined = try self.arena.add(low[i], try self.arena.mul(try self.constant(1 << shift), high[i], span), span);
            try self.constrain(try self.arena.sub(value, joined, span));
        }
        const result = try self.word(true);
        for (result, 0..) |out, i| {
            const at = (i + rotation / 8) % 4;
            const joined = try self.arena.add(high[at], try self.arena.mul(try self.constant(1 << (8 - shift)), low[(at + 1) % 4], span), span);
            try self.constrain(try self.arena.sub(out, joined, span));
        }
        return result;
    }
};
pub const witness = @import("blake3_g_packed_witness.zig").witness;
