//! Signed source-use counts for typed leaves. Count wires must be the exact
//! native AIR public handles selected by the source Plan, never free hints.
const C = @import("common.zig");
const Hash = @import("canon_hash.zig");
const Public = @import("frame.zig");
const Table = @import("../vk_table.zig");
const Integer = @import("typed_integer.zig");
const Mass = @import("../../word16_global_execution/services/gkr_local/mass_authority.zig");
pub const Count = struct { word: Public.Word, value: u32 };
pub const Signed = Hash.SignedMass;
pub const Globals = Hash.SignedGlobals;
const Writer = struct {
    ctx: *C.Context,
    words: [3][2]Public.Word,
    values: [3][2]u64 = @splat(@splat(0)),
    failure: ?anyerror = null,
    pub fn term(self: *@This(), relation: Mass.Relation, positive: bool, count: Count, coefficient: usize) void {
        if (self.failure != null or coefficient == 0) return;
        self.apply(relation, positive, count, coefficient) catch |err| { self.failure = err; };
    }
    fn apply(self: *@This(), relation: Mass.Relation, positive: bool, count: Count, coefficient: usize) !void {
        const r = @intFromEnum(relation);
        const sign: usize = if (positive) 0 else 1;
        const scaled = try Integer.scale(self.ctx, count.word, count.value, coefficient);
        const value = @as(u64, count.value) * coefficient;
        self.words[r][sign] = try Integer.sum(self.ctx, &.{ self.words[r][sign], scaled }, &.{ self.values[r][sign], value });
        self.values[r][sign] += value;
    }
};
pub fn cpu(ctx: *C.Context, counts: Mass.CpuCountsFor(Count), metadata: Globals) ![3]Public.Word {
    const zero = try Table.constWord(ctx, 0);
    var writer = Writer{ .ctx = ctx, .words = @splat(@splat(zero)) };
    Mass.emitCpuTerms(counts, &writer);
    return finish(ctx, &writer, metadata);
}
pub fn truth(ctx: *C.Context, calls: Count, declaration: @import("../../word16_global_execution/services/wire.zig").TruthDeclaration, metadata: Globals) ![3]Public.Word {
    const zero = try Table.constWord(ctx, 0);
    var writer = Writer{ .ctx = ctx, .words = @splat(@splat(zero)) };
    try Mass.emitTruthTerms(declaration, calls, &writer);
    return finish(ctx, &writer, metadata);
}
fn finish(ctx: *C.Context, writer: *Writer, metadata: Globals) ![3]Public.Word {
    if (writer.failure) |err| return err;
    const zero = try Table.constWord(ctx, 0);
    var absolute: [3]Public.Word = undefined;
    inline for (.{ "ram", "kio", "wire" }, 0..) |name, r| {
        const declared = @field(metadata, name);
        try ctx.eq(declared.positive[1].get(), zero.get());
        try ctx.eq(declared.negative[1].get(), zero.get());
        try ctx.eq(declared.positive[0].get(), writer.words[r][0].get());
        try ctx.eq(declared.negative[0].get(), writer.words[r][1].get());
        absolute[r] = try Integer.sum(ctx, &writer.words[r], &writer.values[r]);
    }
    return absolute;
}
test "typed CPU signed masses are source count sums with no free high halves" {
    const std = @import("std");
    var native = Mass.CpuCountsFor(u32){ .ls = 7, .initial = 3, .terminal = 5, .calls = @splat(2),
        .dword = 11, .sponge = .{13,17}, .bulk = @splat(19) };
    native.bulk[native.bulk.len - 1] = 8448;
    const expected = try Mass.evaluateCpuCounts(native);
    const total = try expected.absolute();
    for (0..4) |mutation| {
        var ctx = try C.Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        var counts: Mass.CpuCountsFor(Count) = undefined;
        inline for (std.meta.fields(@TypeOf(native))) |field| {
            if (@typeInfo(field.type) == .array) {
                for (@field(native, field.name), 0..) |value, i| @field(counts, field.name)[i] = .{ .word = try Table.guessWord(&ctx, value), .value = value };
            } else {
                const value = @field(native, field.name);
                @field(counts, field.name) = .{ .word = try Table.guessWord(&ctx, value + @as(u32,@intFromBool(mutation == 3 and comptime std.mem.eql(u8,field.name,"ls")))), .value = value };
            }
        }
        var metadata: Globals = undefined;
        inline for (.{"ram","kio","wire"}) |name| {
            const signed = @field(expected, name);
            @field(metadata, name) = .{
                .positive = .{try Table.guessWord(&ctx, @intCast(signed.positive + @as(u64,@intFromBool(mutation == 2 and comptime std.mem.eql(u8,name,"ram"))))),try Table.guessWord(&ctx, @intFromBool(mutation == 1 and comptime std.mem.eql(u8,name,"ram")))},
                .negative = .{try Table.guessWord(&ctx, @intCast(signed.negative)),try Table.guessWord(&ctx, 0)},
            };
        }
        const result = try cpu(&ctx, counts, metadata);
        inline for (.{"ram","kio","wire"}, 0..) |name, i| try ctx.eq(result[i].get(), (try Table.constWord(&ctx, @intCast(@field(total,name)))).get());
        try std.testing.expectEqual(mutation == 0, try ctx.isCircuitValid());
    }
}
