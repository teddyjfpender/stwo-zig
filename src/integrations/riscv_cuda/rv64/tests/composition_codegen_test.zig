const std = @import("std");
const G = @import("../composition_codegen.zig");
const a = std.testing.allocator;
fn program() !G.Program {
    var b = G.ir.BuilderFor(G.O).init(a);
    defer b.deinit();
    const x = b.input(.{ .tree = 1, .column = 7, .offset = -2 });
    const y = b.input(.{ .tree = 2, .column = 3, .offset = 2 });
    const p = b.parameter(G.O.one());
    const c = b.constant(G.O.fromPartialEvals(.{ G.O.one(), G.O.zero(), G.O.one(), G.O.zero(), G.O.zero(), G.O.zero(), G.O.zero(), G.O.zero() }));
    const base = b.mul(x, y);
    const mixed = b.add(b.mul(base, p), c);
    const reversed = b.sub(x, p);
    const all = b.neg(b.mul(mixed, reversed));
    return b.finish(@splat(31), &.{ base, mixed, all, base });
}
test "OM31 CUDA lowering keeps base arithmetic narrow and streams repeated root weights" {
    var p = try program();
    defer p.deinit();
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(a);
    try G.emit(a, source.writer(a), &p, "check_om31");
    try std.testing.expect(std.mem.indexOf(u8, source.items, "=q::mul(") != null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "=scale(") != null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "=mul(") != null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "eval_log,-2)") != null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "eval_log,2)") != null);
    try std.testing.expectEqual(@as(usize, 4), std.mem.count(u8, source.items, "folded=add(folded,"));
    try std.testing.expect(std.mem.indexOf(u8, source.items, "from_words(powers+24u)") != null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "from_words(powers+0u)") != null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "store(output,stride,row,add(load(output,stride,row),result))") != null);
}
test "OM31 executable setup identity excludes invocation parameters and rejects altered authority" {
    var p = try program();
    defer p.deinit();
    const before = try G.identity(&p);
    const invocation = p.invocationDigest(5);
    p.parameters[0] = G.O.one().add(G.O.one());
    try std.testing.expectEqualSlices(u8, &before, &(try G.identity(&p)));
    try std.testing.expect(!std.mem.eql(u8, &invocation, &p.invocationDigest(5)));
    p.inputs[0].offset = -1;
    try std.testing.expectError(error.InvalidSecurePolynomialIdentity, G.identity(&p));
}
test "OM31 CUDA exporter rejects invalid symbols before emitting source" {
    var p = try program();
    defer p.deinit();
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(a);
    try std.testing.expectError(error.InvalidKernelName, G.emit(a, source.writer(a), &p, "bad;code"));
    try std.testing.expectEqual(@as(usize, 0), source.items.len);
}

test "OODS lowering loads full OM31 masks and never uses base domain mask arithmetic" {
    var p = try program();
    defer p.deinit();
    var source: std.ArrayList(u8) = .empty;
    defer source.deinit(a);
    try G.emitOods(a, source.writer(a), &p, "check_oods");
    try std.testing.expect(std.mem.indexOf(u8, source.items, "const OM31 v") != null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "from_words(inputs+8u)") != null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "composition_mask_row") == null);
    try std.testing.expect(std.mem.indexOf(u8, source.items, "=q::mul(") == null);
    try std.testing.expectEqual(p.roots.len, std.mem.count(u8, source.items, "folded=add(folded,"));
    try std.testing.expect(std.mem.indexOf(u8, source.items, "mul(folded,from_words(inverse))") != null);
    try std.testing.expectError(error.InvalidKernelName, G.emitOods(a, source.writer(a), &p, "bad;kernel"));
}
