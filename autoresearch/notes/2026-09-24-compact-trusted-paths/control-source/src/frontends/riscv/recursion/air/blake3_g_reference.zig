//! Typed degree-two arithmetic oracle for BLAKE3 G. Not a production row layout:
//! packed limb/lookup lowering and authenticated call relations remain required.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../../air/lang/definition.zig");
const compression = core.crypto.blake3_compression;
const M31 = core.fields.m31.M31;
const Id = lang.types.ValueId;
const span = lang.source.SourceSpan.generated();
pub const COLUMN_COUNT = 704; // 6 input words + 6*(sum + carry) + 4 XOR words.
pub const CONSTRAINT_COUNT = COLUMN_COUNT + 6 * 32 + 4 * 32;
pub const SEMANTIC_DIGEST: [32]u8 = blk: {
    var out: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, "381e79c61735c9bb5926647c7566b1cb5b5a102cc26b3f3a7c8d5e7f598f6f8c") catch @compileError("invalid BLAKE3 G digest");
    break :blk out;
};
pub const Row = [COLUMN_COUNT]M31;
pub const Definition = struct {
    arena: lang.ir.Arena,
    output: [4][32]Id,
    pub fn deinit(self: *Definition) void {
        self.arena.deinit();
    }
};
pub fn build(allocator: std.mem.Allocator) !Definition {
    var ops = Typed{ .arena = lang.ir.Arena.init(allocator) };
    errdefer ops.arena.deinit();
    var input: [6]Typed.Word = undefined;
    for (&input) |*word| word.* = try ops.word();
    const output = try compression.g(Typed, &ops, input);
    try lang.validate.validate(&ops.arena);
    if (ops.columns != COLUMN_COUNT or ops.constraints != CONSTRAINT_COUNT) return error.InvalidBlake3Geometry;
    const identity = try lang.digest.computeIdentity(&ops.arena);
    if (!std.mem.eql(u8, &identity.bytes, &SEMANTIC_DIGEST)) return error.InvalidBlake3Semantics;
    return .{ .arena = ops.arena, .output = output };
}
const Typed = struct {
    pub const Word = [32]Id;
    arena: lang.ir.Arena,
    columns: usize = 0,
    constraints: usize = 0,
    fn constrain(self: *Typed, root: Id) !void {
        var buf: [48]u8 = undefined;
        _ = try self.arena.assertZero(try std.fmt.bufPrint(&buf, "blake3_g.constraint_{d}", .{self.constraints}), root, null, .semantic, span);
        self.constraints += 1;
    }
    fn bit(self: *Typed) !Id {
        var buf: [48]u8 = undefined;
        const id = try self.arena.input(try std.fmt.bufPrint(&buf, "blake3_g.bit_{d}", .{self.columns}), .bit, span);
        self.columns += 1;
        const one = try self.arena.constantField(1, span);
        try self.constrain(try self.arena.mul(id, try self.arena.sub(id, one, span), span));
        return id;
    }
    fn word(self: *Typed) !Word {
        var out: Word = undefined;
        for (&out) |*id| id.* = try self.bit();
        return out;
    }
    pub fn add(self: *Typed, a: Word, b: Word) !Word {
        var carry = try self.arena.constantField(0, span);
        const two = try self.arena.constantField(2, span);
        var result: Word = undefined;
        for (a, b, &result) |x, y, *out| {
            out.* = try self.bit();
            const next = try self.bit();
            const sum = try self.arena.add(try self.arena.add(x, y, span), carry, span);
            const encoded = try self.arena.add(out.*, try self.arena.mul(two, next, span), span);
            try self.constrain(try self.arena.sub(sum, encoded, span));
            carry = next;
        }
        return result;
    }
    pub fn xorRotate(self: *Typed, a: Word, b: Word, comptime rotation: u5) !Word {
        var result: Word = undefined;
        const two = try self.arena.constantField(2, span);
        for (0..32) |i| {
            const source = (i + @as(usize, rotation)) % 32;
            const x = a[source];
            const y = b[source];
            result[i] = try self.bit();
            const expected = try self.arena.sub(try self.arena.add(x, y, span), try self.arena.mul(two, try self.arena.mul(x, y, span), span), span);
            try self.constrain(try self.arena.sub(result[i], expected, span));
        }
        return result;
    }
};
pub fn witness(input: [6]u32) !Row {
    var ops = Witness{};
    for (input) |word| for (0..32) |i| ops.bit(@truncate(word >> @as(u5, @intCast(i))));
    _ = try compression.g(Witness, &ops, input);
    std.debug.assert(ops.at == COLUMN_COUNT);
    return ops.row;
}
const Witness = struct {
    pub const Word = u32;
    row: Row = undefined,
    at: usize = 0,
    fn bit(self: *Witness, value: u1) void {
        self.row[self.at] = M31.fromCanonical(value);
        self.at += 1;
    }
    pub fn add(self: *Witness, a: u32, b: u32) !u32 {
        var carry: u32 = 0;
        for (0..32) |i| {
            const shift: u5 = @intCast(i);
            const sum = ((a >> shift) & 1) + ((b >> shift) & 1) + carry;
            self.bit(@truncate(sum));
            carry = sum >> 1;
            self.bit(@intCast(carry));
        }
        return a +% b;
    }
    pub fn xorRotate(self: *Witness, a: u32, b: u32, comptime rotation: u5) !u32 {
        const value = std.math.rotr(u32, a ^ b, rotation);
        for (0..32) |i| self.bit(@truncate(value >> @as(u5, @intCast(i))));
        return value;
    }
};
