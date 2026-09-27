//! Byte/16-bit-limb SHA arithmetic with bounded integer equations over M31.
//! Not an active precompile: CPU/memory/caller and inter-round wiring are separate.
const std = @import("std");
const core = @import("stwo_core");
const lang = @import("../lang/definition.zig");
const relation = @import("../lang/relation.zig");
const effects = @import("../../recursion/air/relation_effect.zig");
const program = @import("sha256_word_program.zig");
const Id = lang.types.ValueId;
const M = core.fields.m31.M31;
const span = lang.source.SourceSpan.generated();
pub const Kind = program.Kind;
pub const production_active = false;
pub fn columnCount(comptime kind: Kind) usize {
    return switch (kind) {
        .round => 164,
        .schedule => 88,
        .feed_forward => 16,
    };
}
pub fn constraintCount(comptime kind: Kind) usize {
    return switch (kind) {
        .round => 40,
        .schedule => 28,
        .feed_forward => 4,
    };
}
pub fn eventCount(comptime kind: Kind) usize {
    return switch (kind) {
        .round => 126,
        .schedule => 60,
        .feed_forward => 8,
    };
}
pub fn semanticDigest(comptime kind: Kind) [32]u8 {
    const hex = switch (kind) {
        .round => "2fd31c11ad90cdb2e803c153def2ef842133430299102c13df1412f048e0cee1",
        .schedule => "54d6181f31fb455cb38ac86cb91fbaf33004f3a041dda6c1ebf1ece565267ea1",
        .feed_forward => "1b626c272caf5b011176edb186a08ce6f15cd79ad09981f88e7fc2d3eb748864",
    };
    var digest: [32]u8 = undefined;
    _ = std.fmt.hexToBytes(&digest, hex) catch unreachable;
    return digest;
}

pub fn Definition(comptime kind: Kind) type {
    return struct {
        arena: lang.ir.Arena,
        columns: usize,
        output: [program.outputCount(kind)]Typed.Word,
        pub fn deinit(self: *@This()) void {
            self.arena.deinit();
        }
    };
}
pub fn build(comptime kind: Kind, a: std.mem.Allocator) !Definition(kind) {
    var ops = Typed{ .arena = lang.ir.Arena.init(a) };
    errdefer ops.arena.deinit();
    var input: [program.inputCount(kind)]Typed.Word = undefined;
    for (&input) |*word| word.* = try ops.word();
    const output = try program.run(kind, Typed, &ops, input);
    try lang.validate.validate(&ops.arena);
    if (ops.columns != columnCount(kind) or ops.arena.constraintsView().len != constraintCount(kind) or ops.arena.effectsView().len != eventCount(kind)) return error.InvalidPackedShaGeometry;
    const identity = try lang.digest.computeIdentity(&ops.arena);
    if (!std.mem.eql(u8, &identity.bytes, &semanticDigest(kind))) return error.InvalidPackedShaSemantics;

    return .{ .arena = ops.arena, .columns = ops.columns, .output = output };
}
pub fn witness(comptime kind: Kind, a: std.mem.Allocator, input: [program.inputCount(kind)]u32) ![]M {
    const row = try a.alloc(M, columnCount(kind));
    errdefer a.free(row);
    try witnessInto(kind, input, row);
    return row;
}
/// Emit directly into the final trace row. No per-operation scratch allocation.
pub fn witnessInto(comptime kind: Kind, input: [program.inputCount(kind)]u32, row: []M) !void {
    if (row.len != columnCount(kind)) return error.InvalidPackedShaGeometry;
    var ops = Writer{ .row = row };
    for (input) |word| try ops.word(word);
    _ = try program.run(kind, Writer, &ops, input);
    if (ops.written != row.len) return error.InvalidPackedShaGeometry;
}
/// Prefix layout for a call component: arithmetic bytes, call ID, then fixed
/// metadata. The arithmetic operation author remains the only equation source.
pub fn Bound(comptime kind: Kind, comptime fixed_count: usize) type {
    return struct { definition: Definition(kind), input: [program.inputCount(kind)][4]Id, call_id: Id, fixed: [fixed_count]Id };
}
pub fn buildBound(comptime kind: Kind, comptime fixed_count: usize, a: std.mem.Allocator) !Bound(kind, fixed_count) {
    var arena = lang.ir.Arena.init(a);
    errdefer arena.deinit();
    var ids: [columnCount(kind)]Id = undefined;
    for (&ids, 0..) |*id, i| {
        var name: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&name, "sha.call.byte_{d}", .{i}), .byte, span);
    }
    const call_id = try arena.input("sha.call.id", .felt, span);
    var fixed: [fixed_count]Id = undefined;
    for (&fixed, 0..) |*id, i| {
        var name: [48]u8 = undefined;
        id.* = try arena.input(try std.fmt.bufPrint(&name, "sha.call.fixed_{d}", .{i}), .felt, span);
    }
    var ops = Typed{ .arena = arena, .predeclared = &ids };
    arena = lang.ir.Arena.init(a);
    errdefer ops.arena.deinit();
    var input: [program.inputCount(kind)]Typed.Word = undefined;
    for (&input) |*word_value| word_value.* = try ops.word();
    const output = try program.run(kind, Typed, &ops, input);
    if (ops.columns != columnCount(kind)) return error.InvalidPackedShaGeometry;
    return .{ .definition = .{ .arena = ops.arena, .columns = ops.columns, .output = output }, .input = input, .call_id = call_id, .fixed = fixed };
}
const Typed = struct {
    pub const Word = [4]Id;
    arena: lang.ir.Arena,
    columns: usize = 0,
    predeclared: ?[]const Id = null,
    fn input(self: *Typed) !Id {
        if (self.predeclared) |ids| {
            const id = ids[self.columns];
            self.columns += 1;
            return id;
        }
        var name: [48]u8 = undefined;
        const id = try self.arena.input(try std.fmt.bufPrint(&name, "sha.packed.byte_{d}", .{self.columns}), .byte, span);
        self.columns += 1;
        return id;
    }
    fn constant(self: *Typed, n: u32) !Id {
        return self.arena.constantField(n, span);
    }
    fn constrain(self: *Typed, lhs: Id, rhs: Id) !void {
        var name: [48]u8 = undefined;
        _ = try self.arena.assertZero(try std.fmt.bufPrint(&name, "sha.packed.eq_{d}", .{self.arena.constraintsView().len}), try self.arena.sub(lhs, rhs, span), null, .semantic, span);
    }
    fn lookup(self: *Typed, domain: relation.Domain, values: []const Id) !void {
        _ = try effects.appendGroup(1, &self.arena, .{.{ .domain = domain, .role = .request, .values = values, .weight = try self.constant(1) }}, span);
    }
    fn word(self: *Typed) !Word {
        var result: Word = undefined;
        for (&result) |*id| id.* = try self.input();
        try self.lookup(.range_check_8_8, result[0..2]);
        try self.lookup(.range_check_8_8, result[2..4]);
        return result;
    }
    fn narrow(self: *Typed, comptime bits: u5) !Id {
        const value = try self.input();
        const scaled = try self.input();
        try self.lookup(.range_check_8_8, &.{ value, scaled });
        try self.constrain(scaled, try self.arena.mul(try self.constant(1 << (8 - bits)), value, span));
        return value;
    }
    fn limb(self: *Typed, bytes: []const Id) !Id {
        return self.arena.add(bytes[0], try self.arena.mul(try self.constant(256), bytes[1], span), span);
    }
    pub fn add(self: *Typed, words: []const Word) !Word {
        if (words.len < 2 or words.len > 5) return error.InvalidShaAddWidth;
        const result = try self.word();
        var carry = try self.constant(0);
        for (0..2) |i| {
            var lhs = carry;
            for (words) |word_value| lhs = try self.arena.add(lhs, try self.limb(word_value[i * 2 ..][0..2]), span);
            const next = try self.narrow(3);
            const rhs = try self.arena.add(try self.limb(result[i * 2 ..][0..2]), try self.arena.mul(try self.constant(65536), next, span), span);
            // Both sides < 2^20; range checks prevent modular aliases.
            try self.constrain(lhs, rhs);
            carry = next;
        }
        return result;
    }
    pub fn bitwise(self: *Typed, x: Word, y: Word, comptime operation: u32) !Word {
        const result = try self.word();
        const op = try self.arena.constantUnsigned(.{ .bounded_uint = .{ .bits = 2, .representation = .canonical_field } }, operation, span);
        for (x, y, result) |a, b, c| try self.lookup(.bitwise, &.{ a, b, c, op });
        return result;
    }
    pub fn rotate(self: *Typed, x: Word, comptime amount: u5, comptime shift: bool) !Word {
        const whole = amount / 8;
        const bits = amount % 8;
        var aligned: Word = undefined;
        for (&aligned, 0..) |*id, i| id.* = if (shift and i + whole >= 4) try self.constant(0) else x[(i + whole) % 4];
        if (bits == 0) return aligned;
        const result = try self.word();
        const carries = [2]Id{ try self.narrow(bits), try self.narrow(bits) };
        for (0..2) |i| {
            const incoming = if (shift and i == 1) try self.constant(0) else carries[1 - i];
            const lhs = try self.arena.add(try self.limb(aligned[2 * i ..][0..2]), try self.arena.mul(try self.constant(65536), incoming, span), span);
            const rhs = try self.arena.add(try self.arena.mul(try self.constant(1 << bits), try self.limb(result[2 * i ..][0..2]), span), carries[i], span);
            // At most seven carry bits: both integer sides stay below 2^23.
            try self.constrain(lhs, rhs);
        }
        return result;
    }
};
const Writer = struct {
    pub const Word = u32;
    row: []M,
    written: usize = 0,
    fn value(self: *Writer, n: u32) !void {
        if (self.written == self.row.len) return error.InvalidPackedShaGeometry;
        self.row[self.written] = M.fromCanonical(n);
        self.written += 1;
    }
    fn word(self: *Writer, n: u32) !void {
        for (0..4) |i| try self.value((n >> @as(u5, @intCast(i * 8))) & 255);
    }
    fn narrow(self: *Writer, n: u32, comptime bits: u5) !void {
        try self.value(n);
        try self.value(n << (8 - bits));
    }
    pub fn add(self: *Writer, words: []const u32) !u32 {
        var result: u32 = 0;
        for (words) |word_value| result +%= word_value;
        try self.word(result);
        var carry: u32 = 0;
        for (0..2) |i| {
            var sum = carry;
            for (words) |word_value| sum += (word_value >> @as(u5, @intCast(i * 16))) & 65535;
            carry = sum >> 16;
            try self.narrow(carry, 3);
        }
        return result;
    }
    pub fn bitwise(self: *Writer, a: u32, b: u32, comptime op: u32) !u32 {
        const value_word = if (op == 0) a & b else a ^ b;
        try self.word(value_word);
        return value_word;
    }
    pub fn rotate(self: *Writer, x: u32, comptime amount: u5, comptime shift: bool) !u32 {
        const bits = amount % 8;
        const result = if (shift) x >> amount else std.math.rotr(u32, x, amount);
        if (bits == 0) return result;
        try self.word(result);
        const aligned = if (shift) x >> (amount / 8 * 8) else std.math.rotr(u32, x, amount / 8 * 8);
        for (0..2) |i| try self.narrow((aligned >> @as(u5, @intCast(i * 16))) & ((1 << bits) - 1), bits);
        return result;
    }
};
