//! Compact typed BLAKE3 arithmetic. Call/control binding and production layout
//! admission are separate from these arithmetic and lookup obligations.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const relation = @import("../../air/lang/relation.zig");
const effects = @import("relation_effect.zig");
const Id = lang.types.ValueId;
const span = lang.source.SourceSpan.generated();
pub const COLUMN_COUNT = 82;
pub const CONSTRAINT_COUNT = 32;
pub const EVENT_COUNT = 30;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "8bdebb78c51574ca1757f4b3ec9cce2bf0497fb86b7d94eac6b9403c7a1d0015") catch @compileError("invalid packed BLAKE3 digest");
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
    var result = try buildRaw(allocator);
    errdefer result.deinit();
    const identity = try lang.digest.computeIdentity(&result.arena);
    if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST)) return error.InvalidBlake3PackedSemantics;
    return result;
}
pub fn computeSemanticDigest(allocator: std.mem.Allocator) ![32]u8 {
    var result = try buildRaw(allocator);
    defer result.deinit();
    return (try lang.digest.computeIdentity(&result.arena)).bytes;
}
fn buildRaw(allocator: std.mem.Allocator) !Definition {
    var ops = Typed{ .arena = lang.ir.Arena.init(allocator) };
    errdefer ops.arena.deinit();
    var input: [6]Typed.Word = undefined;
    // b and d are byte-bounded by the XOR lookups that consume them.
    for (&input, 0..) |*word, i| word.* = try ops.word(i != 1 and i != 3);
    const output = try core.crypto.blake3_compression.g(Typed, &ops, input);
    try lang.validate.validate(&ops.arena);
    if (ops.columns != COLUMN_COUNT or ops.arena.constraintsView().len != CONSTRAINT_COUNT or ops.arena.effectsView().len != EVENT_COUNT) return error.InvalidBlake3PackedGeometry;
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
    // b and d are byte-bounded by the XOR lookups that consume them.
    for (&input, 0..) |*word, i| word.* = try ops.word(i != 1 and i != 3);
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
        // Every G addition result is consumed by an XOR byte lookup.
        const result = try self.word(false);
        var carry = try self.constant(0);
        // All limbs are byte-bounded by lookups. Each 16-bit sum is below
        // 2^17, so field equality is integer equality without M31 wraparound.
        for (0..2) |limb| {
            const at = limb * 2;
            const x = try self.arena.add(a[at], try self.arena.mul(try self.constant(256), a[at + 1], span), span);
            const y = try self.arena.add(b[at], try self.arena.mul(try self.constant(256), b[at + 1], span), span);
            const out = try self.arena.add(result[at], try self.arena.mul(try self.constant(256), result[at + 1], span), span);
            const next = try self.bit();
            const lhs = try self.arena.add(try self.arena.add(x, y, span), carry, span);
            const rhs = try self.arena.add(out, try self.arena.mul(try self.constant(65536), next, span), span);
            try self.constrain(try self.arena.sub(lhs, rhs, span));
            carry = next;
        }
        return result;
    }
    /// Fuse a+b+message without an intermediate word. Two boolean carry
    /// digits and their product exclude 3, so each carry is in [0,2].
    /// Byte bounds come from input range/XOR lookups and output XOR lookups;
    /// each integer equality stays below 3*2^16, safely below M31.
    pub fn add3(self: *Typed, a: Word, b: Word, message: Word) !Word {
        const result = try self.word(false);
        var carry = try self.constant(0);
        for (0..2) |limb| {
            const at = limb * 2;
            var lhs = carry;
            for ([_]Word{ a, b, message }) |word_value| {
                const value = try self.arena.add(word_value[at], try self.arena.mul(try self.constant(256), word_value[at + 1], span), span);
                lhs = try self.arena.add(lhs, value, span);
            }
            const low = try self.bit();
            const high = try self.bit();
            try self.constrain(try self.arena.mul(low, high, span));
            const next = try self.arena.add(low, try self.arena.mul(try self.constant(2), high, span), span);
            const out = try self.arena.add(result[at], try self.arena.mul(try self.constant(256), result[at + 1], span), span);
            const rhs = try self.arena.add(out, try self.arena.mul(try self.constant(65536), next, span), span);
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
        if (rotation == 7) {
            // ROTR7(x) = ROTL1(ROTR8(x)). Two bounded 16-bit limbs
            // replace four separate byte splits. Boolean cyclic carries and
            // byte-bounded outputs keep both equalities below 2^17 in M31.
            const result = try self.word(true);
            const carries = [2]Id{ try self.bit(), try self.bit() };
            for (0..2) |limb| {
                const at = 2 * limb;
                const input_limb = try self.arena.add(xors[(at + 1) % 4], try self.arena.mul(try self.constant(256), xors[(at + 2) % 4], span), span);
                const output_limb = try self.arena.add(result[at], try self.arena.mul(try self.constant(256), result[at + 1], span), span);
                const lhs = try self.arena.add(try self.arena.mul(try self.constant(2), input_limb, span), carries[1 - limb], span);
                const rhs = try self.arena.add(output_limb, try self.arena.mul(try self.constant(65536), carries[limb], span), span);
                try self.constrain(try self.arena.sub(lhs, rhs, span));
            }
            return result;
        }
        if (rotation != 12) @compileError("unsupported BLAKE3 rotation");
        // ROTR12(x) = ROTR4(ROTR8(x)). Two four-bit cyclic carries
        // suffice for the 16-bit limbs. Both sides stay below 2^20;
        // the scaled-byte lookup bounds each carry to [0,15].
        const result = try self.word(true);
        const carries = [2]Id{ try self.narrowByte(4), try self.narrowByte(4) };
        for (0..2) |limb| {
            const at = 2 * limb;
            const input_limb = try self.arena.add(xors[(at + 1) % 4], try self.arena.mul(try self.constant(256), xors[(at + 2) % 4], span), span);
            const output_limb = try self.arena.add(result[at], try self.arena.mul(try self.constant(256), result[at + 1], span), span);
            const lhs = try self.arena.add(input_limb, try self.arena.mul(try self.constant(65536), carries[1 - limb], span), span);
            const rhs = try self.arena.add(try self.arena.mul(try self.constant(16), output_limb, span), carries[limb], span);
            try self.constrain(try self.arena.sub(lhs, rhs, span));
        }
        return result;
    }
};
pub const witness = @import("blake3_g_packed_witness.zig").witness;
