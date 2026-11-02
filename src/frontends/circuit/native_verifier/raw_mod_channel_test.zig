const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const C = @import("raw_mod_channel.zig");
const R = core.channel.raw_mod_m31;
const Q = core.fields.qm31.QM31;
const O = core.fields.om31.OM31;
const Var = builder.Var;
const Word = builder.wrappers.U32Wrapper(Var);
const Context = builder.Context(Q);
const a = std.testing.allocator;
fn words(ctx: *Context, values: []const u32) ![]Word {
    const out = try ctx.scratch().alloc(Word, values.len);
    for (out, values) |*v, x| v.* = try builder.wrappers.guessU32(Q, ctx, builder.wrappers.u32Value(Q, x));
    return out;
}
fn same(ctx: *Context, circuit: @import("channel.zig").NativeChannel, native: core.channel.blake2s.Blake2sChannel) !void {
    try std.testing.expectEqualSlices(u8, &native.digestBytes(), &circuit.debugDigest(ctx));
    try std.testing.expectEqual(native.n_draws, circuit.n_draws);
}
test "raw-mod circuit reduces all eight boundary words and rejects forged reduction coordinates" {
    const p = core.fields.m31.Modulus;
    const raw = [8]u32{ p - 1, p, p + 1, 2 * p - 1, 2 * p, 2 * p + 1, 0, 1 };
    var ctx = try Context.init(a, 0);
    defer ctx.deinit();
    const input = try words(&ctx, &raw);
    const result = try C.reduceBlock(Q, &ctx, input[0..8]);
    const expected = O.fromM31Array(R.reduceWords(raw));
    try std.testing.expect(result.value(&ctx).eql(expected));
    // Bind both halves, so skipped/aliased upper coordinates cannot disappear.
    try ctx.eq(result.c0, try ctx.constant(expected.c0));
    try ctx.eq(result.c1, try ctx.constant(expected.c1));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    const original = ctx.value_table.items[result.c1.idx];
    ctx.value_table.items[result.c1.idx] = original.add(Q.one());
    try std.testing.expect(!try ctx.isCircuitValid());
    ctx.value_table.items[result.c1.idx] = original;
    try std.testing.expect(try ctx.isCircuitValid());
}
test "raw-mod circuit native transcript packing counter wrap and reset agree for both explicit profiles" {
    var ctx = try Context.init(a, 0);
    defer ctx.deinit();
    var q = try C.Qm31Channel.init(Q, &ctx);
    var nq = R.Qm31Channel.init();
    var o = try C.Om31Channel.init(Q, &ctx);
    var no = R.Om31Channel.init();
    try same(&ctx, q.inner, nq.inner);
    try same(&ctx, o.inner, no.inner);
    const input = [_]u32{ 0xffffffff, 0xfffffffe, 13 };
    const input_wires = try words(&ctx, &input);
    try q.mixU32s(Q, &ctx, input_wires);
    nq.mixU32s(&input);
    try o.mixU32s(Q, &ctx, input_wires);
    no.mixU32s(&input);
    const sq = try q.drawSecureFelt(Q, &ctx);
    const eq = nq.drawSecureFelt();
    try std.testing.expect(ctx.get(sq).eql(eq));
    const so = try o.drawSecureFelt(Q, &ctx);
    const eo = no.drawSecureFelt();
    try std.testing.expect(so.value(&ctx).eql(eo));
    const qs = try q.drawSecureFelts(Q, &ctx, 3);
    const nqs = try nq.drawSecureFelts(a, 3);
    defer a.free(nqs);
    for (qs, nqs) |v, expected| try std.testing.expect(ctx.get(v).eql(expected));
    const os = try o.drawSecureFelts(Q, &ctx, 3);
    const nos = try no.drawSecureFelts(a, 3);
    defer a.free(nos);
    for (os, nos) |v, expected| try std.testing.expect(v.value(&ctx).eql(expected));
    _ = try q.drawSecureFelts(Q, &ctx, 0);
    _ = try o.drawSecureFelts(Q, &ctx, 0);
    try same(&ctx, q.inner, nq.inner);
    try same(&ctx, o.inner, no.inner);
    try q.mixFelts(Q, &ctx, qs);
    nq.mixFelts(nqs);
    try o.mixFelts(Q, &ctx, os);
    no.mixFelts(nos);
    try same(&ctx, q.inner, nq.inner);
    try same(&ctx, o.inner, no.inner);
    // Counter wrap must be native u32 wrapping, not M31 arithmetic.
    q.inner.n_draws = std.math.maxInt(u32);
    nq.inner.n_draws = std.math.maxInt(u32);
    try std.testing.expect(ctx.get(try q.drawSecureFelt(Q, &ctx)).eql(nq.drawSecureFelt()));
    try same(&ctx, q.inner, nq.inner);
    o.inner.n_draws = std.math.maxInt(u32);
    no.inner.n_draws = std.math.maxInt(u32);
    try std.testing.expect((try o.drawSecureFelt(Q, &ctx)).value(&ctx).eql(no.drawSecureFelt()));
    try same(&ctx, o.inner, no.inner);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
fn topology(comptime V: type) !builder.context.GateCounts {
    var ctx = try builder.Context(V).init(a, 0);
    defer ctx.deinit();
    var channel = try C.Om31Channel.init(V, &ctx);
    const out = try channel.drawSecureFelts(V, &ctx, 3);
    try channel.mixFelts(V, &ctx, out);
    _ = try channel.drawSecureFelt(V, &ctx);
    try ctx.finalize(false);
    return ctx.gate_counts;
}
test "raw-mod circuit profile has fixed topology independent of witness value mode" {
    try std.testing.expectEqualDeep(try topology(Q), try topology(builder.ivalue.NoValue));
}

test "raw-mod actual Blake rare block keeps all eight coordinates and counter binding native exact" {
    const counter: u32 = 107289826;
    var ctx = try Context.init(a, 0);
    defer ctx.deinit();
    var circuit = try C.Om31Channel.init(Q, &ctx);
    var native = R.Om31Channel.init();
    // Independently fixed intermediate transcript checkpoint, not a protocol
    // bypass API. Full constructor/tag mixing is qualified in the test above.
    native.inner = .{ .n_draws = counter };
    for (&circuit.inner.digest.words) |*word| word.* = try builder.wrappers.constU32(Q, &ctx, 0);
    circuit.inner.n_draws = counter;
    const counter_wire = try builder.wrappers.constU32(Q, &ctx, counter);
    var oracle = native.inner;
    const raw = oracle.drawU32s();
    try std.testing.expectEqual(@as(u32, 0xffffffff), raw[2]);
    const expected = native.drawSecureFelt();
    const result = try circuit.drawSecureFelt(Q, &ctx);
    try std.testing.expectEqualDeep(R.reduceWords(raw), result.value(&ctx).toM31Array());
    try ctx.eq(result.c0, try ctx.constant(expected.c0));
    try ctx.eq(result.c1, try ctx.constant(expected.c1));
    try same(&ctx, circuit.inner, native.inner);
    // The next raw draw must be counter+1, not the legacy retry's counter+2.
    const next = native.drawU32s();
    const next_wires = try circuit.drawU32s(Q, &ctx);
    for (next_wires, next) |wire, value| try ctx.eq(wire.get(), (try builder.wrappers.constU32(Q, &ctx, value)).get());
    try same(&ctx, circuit.inner, native.inner);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    const old_counter = ctx.value_table.items[counter_wire.get().idx];
    ctx.value_table.items[counter_wire.get().idx] = builder.ivalue.packU32(Q, counter + 1);
    try std.testing.expect(!try ctx.isCircuitValid());
    ctx.value_table.items[counter_wire.get().idx] = old_counter;
    try std.testing.expect(try ctx.isCircuitValid());
}
