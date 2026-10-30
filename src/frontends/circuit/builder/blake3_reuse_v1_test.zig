const std = @import("std");
const core = @import("stwo_core");
const b = @import("mod.zig");
const h = @import("blake3_reuse_v1.zig");
const Q = core.fields.qm31.QM31;
const W = b.wrappers.U32Wrapper(b.Var);
const a = std.testing.allocator;
fn guessed(comptime V: type, ctx: *b.Context(V), words: []const u32, out: []W) !void {
    for (out, words) |*w, value| w.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, value));
}
fn match(ctx: *b.Context(Q), actual: []const W, expected: []const u32) !void {
    for (actual, expected) |word, value| {
        try std.testing.expectEqual(value, b.ivalue.unpackU32(Q, ctx.get(word.get())));
        const check = try b.wrappers.guessU32(Q, ctx, b.wrappers.u32Value(Q, value));
        try ctx.eq(word.get(), check.get());
    }
}
fn wordsOf(bytes: []const u8, out: []u32) void {
    for (out, 0..) |*w, i| w.* = std.mem.readInt(u32, bytes[i * 4 ..][0..4], .little);
}
test "circuit Blake3 reuse compression full output flags and 64-bit counters" {
    var prng = std.Random.DefaultPrng.init(0x8b5e32f4);
    const random = prng.random();
    for ([_]u64{ 0, 0xffffffff, 0x100000000, 0xffffffffffffffff }) |counter| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        var cv: [8]u32 = undefined;
        var block: [16]u32 = undefined;
        for (&cv) |*w| w.* = random.int(u32);
        for (&block) |*w| w.* = random.int(u32);
        var cv_wire: [8]W = undefined;
        var block_wire: [16]W = undefined;
        try guessed(Q, &ctx, &cv, &cv_wire);
        try guessed(Q, &ctx, &block, &block_wire);
        const flags = random.int(u32);
        const result = try h.compress(Q, &ctx, cv_wire, block_wire, counter, 64, flags);
        try std.testing.expectEqual(@as(usize, 56), ctx.circuit.blake_g_gate.items.len);
        try std.testing.expectEqual(@as(usize, 16), ctx.circuit.triple_xor.items.len);
        try match(&ctx, &result, &try core.crypto.blake3_compression.compress(cv, block, counter, 64, flags));
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
        // Gate satisfaction catches an internal compression value change.
        const index = ctx.circuit.blake_g_gate.items[19].out_base;
        ctx.value_table.items[index] = ctx.value_table.items[index].add(Q.one());
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}
test "circuit Blake3 reuse chunk root equals independent std hash at boundaries" {
    var bytes: [1024]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i * 137 + 29);
    var message: [256]u32 = undefined;
    wordsOf(&bytes, &message);
    for ([_]usize{ 0, 1, 15, 16, 17, 32, 255, 256 }) |length| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        var wires: [256]W = undefined;
        try guessed(Q, &ctx, message[0..length], wires[0..length]);
        const digest = try h.chunkWords(Q, &ctx, wires[0..length], 0, true);
        var expected_bytes: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(bytes[0 .. 4 * length], &expected_bytes, .{});
        var expected: [8]u32 = undefined;
        wordsOf(&expected_bytes, &expected);
        try match(&ctx, &digest, &expected);
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
}
test "circuit Blake3 reuse ordered parent closes two-chunk independent std hash" {
    var bytes: [2048]u8 = undefined;
    for (&bytes, 0..) |*byte, i| byte.* = @truncate(i * 31 + i / 7);
    var message: [512]u32 = undefined;
    wordsOf(&bytes, &message);
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    var wires: [512]W = undefined;
    try guessed(Q, &ctx, &message, &wires);
    const left = try h.chunkWords(Q, &ctx, wires[0..256], 0, false);
    const right = try h.chunkWords(Q, &ctx, wires[256..], 1, false);
    const digest = try h.parent(Q, &ctx, left, right, true);
    var expected_bytes: [32]u8 = undefined;
    std.crypto.hash.Blake3.hash(&bytes, &expected_bytes, .{});
    var expected: [8]u32 = undefined;
    wordsOf(&expected_bytes, &expected);
    try match(&ctx, &digest, &expected);
    const internal = try h.parent(Q, &ctx, left, right, false);
    const reversed = try h.parent(Q, &ctx, right, left, true);
    var differs_internal = false;
    var differs_reversed = false;
    for (digest, internal, reversed) |correct, not_root, swapped| {
        differs_internal = differs_internal or !ctx.get(correct.get()).eql(ctx.get(not_root.get()));
        differs_reversed = differs_reversed or !ctx.get(correct.get()).eql(ctx.get(swapped.get()));
    }
    try std.testing.expect(differs_internal and differs_reversed);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
fn buildReplay(comptime V: type, ctx: *b.Context(V)) !void {
    var wires: [17]W = undefined;
    const message: [17]u32 = @splat(0xdeadbeef);
    try guessed(V, ctx, &message, &wires);
    _ = try h.chunkWords(V, ctx, &wires, 0, true);
    _ = try h.hashPrefixedWords(V, ctx, "unaligned prefix", &wires);
    try ctx.finalize(false);
}
test "circuit Blake3 reuse topology and gate-free replay match exact values" {
    var values = try b.Context(Q).init(a, 0);
    defer values.deinit();
    var topology = try b.Context(b.NoValue).init(a, 0);
    defer topology.deinit();
    var replay = try b.Context(Q).initWithGateRecording(a, 0, false);
    defer replay.deinit();
    try buildReplay(Q, &values);
    try buildReplay(b.NoValue, &topology);
    try buildReplay(Q, &replay);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    inline for (.{ "add", "sub", "mul", "pointwise_mul", "eq", "blake_g_gate", "triple_xor", "m31_to_u32", "output" }) |field| {
        try std.testing.expectEqualDeep(@field(values.circuit, field).items, @field(topology.circuit, field).items);
    }
    try std.testing.expectEqualDeep(values.value_table.items, replay.value_table.items);
    try std.testing.expectEqualDeep(values.gate_counts, replay.gate_counts);
    try std.testing.expectEqual(@as(usize, 0), replay.circuit.blake_g_gate.items.len);
    try std.testing.expect(try values.isCircuitValid());
}
test "circuit Blake3 reuse rejects unsupported chunk and block lengths" {
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    const zero = try b.wrappers.constU32(Q, &ctx, 0);
    const too_long: [257]W = @splat(zero);
    try std.testing.expectError(error.InvalidBlake3Chunk, h.chunkWords(Q, &ctx, &too_long, 0, true));
    try std.testing.expectError(error.InvalidBlake3Chunk, h.chunkWords(Q, &ctx, &.{}, 1, true));
    try std.testing.expectError(error.InvalidBlake3BlockLength, h.compress(Q, &ctx, @splat(zero), @splat(zero), 0, 65, 0));
}

test "circuit Blake3 reuse exact native domain-framed Merkle node and partial block" {
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    var left: [32]u8 = undefined;
    var right: [32]u8 = undefined;
    for (&left, &right, 0..) |*l, *r, i| {
        l.* = @truncate(i * 7 + 5);
        r.* = @truncate(i * 19 + 11);
    }
    var left_words: [8]u32 = undefined;
    var right_words: [8]u32 = undefined;
    wordsOf(&left, &left_words);
    wordsOf(&right, &right_words);
    var left_wires: [8]W = undefined;
    var right_wires: [8]W = undefined;
    try guessed(Q, &ctx, &left_words, &left_wires);
    try guessed(Q, &ctx, &right_words, &right_wires);
    const result = try h.protocolNode(Q, &ctx, left_wires, right_wires);
    try std.testing.expectEqual(@as(usize, 112), ctx.circuit.blake_g_gate.items.len);
    try std.testing.expectEqual(@as(usize, 32), ctx.circuit.triple_xor.items.len);
    const expected_bytes = (core.channel.blake3.Frame{ .node = .{ .left = left, .right = right } }).hash();
    var expected: [8]u32 = undefined;
    wordsOf(&expected_bytes, &expected);
    try match(&ctx, &result, &expected);
    // Also pin every alignment of the prefix and the zero-length payload.
    const prefix = "a prefix";
    for (0..5) |prefix_len| {
        const output = try h.hashPrefixedWords(Q, &ctx, prefix[0..prefix_len], &.{});
        var digest_bytes: [32]u8 = undefined;
        std.crypto.hash.Blake3.hash(prefix[0..prefix_len], &digest_bytes, .{});
        var digest_words: [8]u32 = undefined;
        wordsOf(&digest_bytes, &digest_words);
        try match(&ctx, &output, &digest_words);
    }
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
    // A corrupted compression value cannot change the authenticated frame.
    const output_var = ctx.circuit.triple_xor.items[0].out;
    ctx.value_table.items[output_var] = ctx.value_table.items[output_var].add(Q.one());
    try std.testing.expect(!try ctx.isCircuitValid());
}
