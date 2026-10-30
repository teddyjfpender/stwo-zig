const std = @import("std");
const core = @import("stwo_core");
const b = @import("mod.zig");
const c = @import("blake3_channel_reuse_v1.zig");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const W = b.wrappers.U32Wrapper(b.Var);
const a = std.testing.allocator;
fn guessWords(comptime V: type, ctx: *b.Context(V), values: []const u32, wires: []W) !void {
    for (values, wires) |value, *wire| wire.* = try b.wrappers.guessU32(V, ctx, b.wrappers.u32Value(V, value));
}
fn digestWords(bytes: [32]u8) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, 0..) |*word, i| word.* = std.mem.readInt(u32, bytes[4 * i ..][0..4], .little);
    return out;
}
fn assertWords(ctx: *b.Context(Q), wires: []const W, values: []const u32) !void {
    for (wires, values) |wire, value| {
        try std.testing.expectEqual(value, b.ivalue.unpackU32(Q, ctx.get(wire.get())));
        const expected = try b.wrappers.guessU32(Q, ctx, b.wrappers.u32Value(Q, value));
        try ctx.eq(wire.get(), expected.get());
    }
}
fn assertDigest(ctx: *b.Context(Q), wires: c.Digest, digest: [32]u8) !void {
    try assertWords(ctx, &wires, &digestWords(digest));
}
test "circuit Blake3 transcript exact absorbs raw draws secure packing and reset" {
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    var native = core.channel.blake3.Channel{};
    var channel = try c.Channel(Q).init(&ctx);
    try assertDigest(&ctx, channel.digest, native.digestBytes());
    var root_bytes: [32]u8 = undefined;
    for (&root_bytes, 0..) |*byte, i| byte.* = @truncate(i * 17 + 3);
    var root: c.Digest = undefined;
    try guessWords(Q, &ctx, &digestWords(root_bytes), &root);
    native.mixRoot(root_bytes);
    try channel.mixRoot(&ctx, root);
    try assertDigest(&ctx, channel.digest, native.digestBytes());
    try assertWords(&ctx, &try channel.drawU32s(&ctx), &native.drawU32s());
    try assertWords(&ctx, &try channel.drawU32s(&ctx), &native.drawU32s());
    try std.testing.expectEqual(native.n_draws, channel.n_draws);
    native.n_draws = 0x1234567887654321;
    channel.n_draws = native.n_draws;
    try assertWords(&ctx, &try channel.drawU32s(&ctx), &native.drawU32s());
    const integer: u64 = 0xfedcba9876543210;
    var integer_wires: [2]W = undefined;
    try guessWords(Q, &ctx, &.{ @as(u32, @truncate(integer)), @as(u32, @truncate(integer >> 32)) }, &integer_wires);
    native.mixU64(integer);
    try channel.mixU64(&ctx, integer_wires);
    try std.testing.expectEqual(@as(u64, 0), channel.n_draws);
    try assertDigest(&ctx, channel.digest, native.digestBytes());
    const words = [_]u32{ 0, 0x7fffffff, 0xfffffffe, 0xffffffff, 0x80000000 };
    var word_wires: [5]W = undefined;
    try guessWords(Q, &ctx, &words, &word_wires);
    native.mixU32s(&words);
    try channel.mixU32s(&ctx, &word_wires);
    try assertDigest(&ctx, channel.digest, native.digestBytes());
    const felts = [_]Q{ Q.fromU32Unchecked(0, 1, core.fields.m31.Modulus - 1, 99), Q.fromU32Unchecked(0x12345678, 0, 17, 100) };
    var felt_wires: [2]b.Var = undefined;
    for (&felt_wires, felts) |*wire, value| wire.* = try ctx.guess(value);
    native.mixFelts(&felts);
    try channel.mixFelts(&ctx, &felt_wires);
    try assertDigest(&ctx, channel.digest, native.digestBytes());
    const first = try channel.drawSecureFelt(&ctx, 1);
    try std.testing.expectEqualDeep(native.drawSecureFelt(), ctx.get(first));
    const multiple = try channel.drawSecureFelts(&ctx, 3, &.{ 1, 1 });
    const expected = try native.drawSecureFelts(a, 3);
    defer a.free(expected);
    for (multiple, expected) |wire, value| {
        const check = try ctx.guess(value);
        try ctx.eq(wire, check);
    }
    try std.testing.expectEqual(native.n_draws, channel.n_draws);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
test "circuit Blake3 transcript multi-chunk asymmetric frames match native" {
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    var native = core.channel.blake3.Channel{};
    var channel = try c.Channel(Q).init(&ctx);
    var words: [1100]u32 = undefined;
    var wires: [1100]W = undefined;
    for (&words, 0..) |*word, i| word.* = @truncate(i * 0xfedcba9 + 0x10203040);
    try guessWords(Q, &ctx, &words, &wires);
    for ([_]usize{ 0, 239, 240, 495, 496, 751, 752, 1007, 1008, 1100 }) |length| {
        native.mixU32s(words[0..length]);
        try channel.mixU32s(&ctx, wires[0..length]);
        try assertDigest(&ctx, channel.digest, native.digestBytes());
    }
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}
test "circuit Blake3 transcript exact sampler rejects either forbidden raw word in any lane" {
    const boundary = [_]u32{ 0, core.fields.m31.Modulus - 1, core.fields.m31.Modulus, 2 * core.fields.m31.Modulus - 1, 2 * core.fields.m31.Modulus, 2 * core.fields.m31.Modulus + 1 };
    for (boundary) |value| for (0..8) |lane| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        var raw: [8]u32 = @splat(17);
        raw[lane] = value;
        var wires: c.Digest = undefined;
        try guessWords(Q, &ctx, &raw, &wires);
        const sampled = try c.sampleBlock(Q, &ctx, wires);
        const accepted = core.channel.blake3.sampleWord(value) != null;
        try c.requireAttempt(Q, &ctx, sampled, accepted);
        for (sampled.felts, 0..) |felt, half| {
            var expected: [4]M = undefined;
            for (&expected, 0..) |*out, i| out.* = M.fromU64(raw[half * 4 + i]);
            const check = try ctx.guess(Q.fromM31Array(expected));
            try ctx.eq(felt, check);
        }
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    };
}
test "circuit Blake3 transcript sampler cannot authorize skipped or invalid terminal blocks" {
    for ([_]bool{ false, true }) |terminal| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        var raw: [8]u32 = @splat(42);
        if (terminal) raw[7] = 0xfffffffe;
        var wires: c.Digest = undefined;
        try guessWords(Q, &ctx, &raw, &wires);
        try c.requireAttempt(Q, &ctx, try c.sampleBlock(Q, &ctx, wires), terminal);
        try ctx.finalize(false);
        try std.testing.expect(!try ctx.isCircuitValid());
    }
    // The actual draw is accepted: nominating a second attempt cannot skip it.
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    var channel = try c.Channel(Q).init(&ctx);
    _ = try channel.drawSecureFelt(&ctx, 2);
    try ctx.finalize(false);
    try std.testing.expect(!try ctx.isCircuitValid());
}
test "circuit Blake3 transcript PoW exact raw bits nonce wires and absorption" {
    const native = core.channel.blake3.Channel{};
    const nonce = native.grind(8);
    var invalid: u64 = nonce + 1;
    while (native.verifyPowNonce(8, invalid)) invalid += 1;
    for ([_]u64{ nonce, invalid }) |candidate| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        var channel = try c.Channel(Q).init(&ctx);
        var nonce_wires: [2]W = undefined;
        try guessWords(Q, &ctx, &.{ @as(u32, @truncate(candidate)), @as(u32, @truncate(candidate >> 32)) }, &nonce_wires);
        try channel.pow(&ctx, 8, nonce_wires);
        var expected = native;
        expected.mixU64(candidate);
        try assertDigest(&ctx, channel.digest, expected.digestBytes());
        try ctx.finalize(false);
        try std.testing.expectEqual(candidate == nonce, try ctx.isCircuitValid());
    }
    // Difficulty32 constrains the entire raw word; a constant invalid nonce
    // must fail without relying on M31 reduction or an unbounded grinder.
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    const channel = try c.Channel(Q).init(&ctx);
    var nonce_wires: [2]W = undefined;
    try guessWords(Q, &ctx, &.{ 0x12345678, 0xfedcba98 }, &nonce_wires);
    try std.testing.expect(!native.verifyPowNonce(32, 0xfedcba9812345678));
    try channel.verifyPow(&ctx, 32, nonce_wires);
    try std.testing.expectError(error.UnsupportedProofOfWorkDifficulty, channel.verifyPow(&ctx, 33, nonce_wires));
    try ctx.finalize(false);
    try std.testing.expect(!try ctx.isCircuitValid());
}
fn replay(comptime V: type, ctx: *b.Context(V), root_value: u32) !void {
    var channel = try c.Channel(V).init(ctx);
    var root: c.Digest = undefined;
    const words: [8]u32 = @splat(root_value);
    try guessWords(V, ctx, &words, &root);
    try channel.mixRoot(ctx, root);
    _ = try channel.drawSecureFelt(ctx, 1);
    try ctx.finalize(false);
}
test "circuit Blake3 transcript request roots do not change topology and state tampering fails" {
    var values = try b.Context(Q).init(a, 0);
    defer values.deinit();
    var changed = try b.Context(Q).init(a, 0);
    defer changed.deinit();
    var topology = try b.Context(b.NoValue).init(a, 0);
    defer topology.deinit();
    var replay_values = try b.Context(Q).initWithGateRecording(a, 0, false);
    defer replay_values.deinit();
    try replay(Q, &values, 0xffffffff);
    try replay(Q, &changed, 0x12345678);
    try replay(b.NoValue, &topology, 0);
    try replay(Q, &replay_values, 0xffffffff);
    try std.testing.expectEqualDeep(values.gate_counts, changed.gate_counts);
    try std.testing.expectEqual(values.circuit.n_vars, topology.circuit.n_vars);
    inline for (.{ "add", "sub", "mul", "pointwise_mul", "eq", "blake_g_gate", "triple_xor", "m31_to_u32", "output" }) |field| {
        try std.testing.expectEqualDeep(@field(values.circuit, field).items, @field(changed.circuit, field).items);
        try std.testing.expectEqualDeep(@field(values.circuit, field).items, @field(topology.circuit, field).items);
    }
    try std.testing.expectEqualDeep(values.value_table.items, replay_values.value_table.items);
    try std.testing.expect(try values.isCircuitValid());
    try std.testing.expect(try changed.isCircuitValid());
    // A fabricated intermediate digest cannot be substituted into a draw.
    const state_output = values.circuit.triple_xor.items[0].out;
    values.value_table.items[state_output] = values.value_table.items[state_output].add(Q.one());
    try std.testing.expect(!try values.isCircuitValid());
}
test "circuit Blake3 transcript rejects unsupported schedules and counter exhaustion" {
    var ctx = try b.Context(Q).init(a, 0);
    defer ctx.deinit();
    var channel = try c.Channel(Q).init(&ctx);
    try std.testing.expectError(error.UnsupportedBlake3RejectionSchedule, channel.drawSecureFelt(&ctx, 0));
    try std.testing.expectError(error.UnsupportedBlake3RejectionSchedule, channel.drawSecureFelt(&ctx, c.MAX_ATTEMPTS + 1));
    try std.testing.expectError(error.UnsupportedBlake3RejectionSchedule, channel.drawSecureFelts(&ctx, 3, &.{1}));
    channel.n_draws = std.math.maxInt(u64);
    try std.testing.expectError(error.Overflow, channel.drawU32s(&ctx));
}

test "circuit Blake3 transcript PoW raw-word boundaries include bit31 and forbid field alias" {
    for ([_]u32{ 0, 1, 2, 0x80000000, 0x7fffffff, 0xfffffffe, 0xffffffff }) |raw| for ([_]u32{ 0, 1, 16, 31, 32 }) |difficulty| {
        var ctx = try b.Context(Q).init(a, 0);
        defer ctx.deinit();
        const word = try b.wrappers.guessU32(Q, &ctx, b.wrappers.u32Value(Q, raw));
        try c.requirePowWord(Q, &ctx, difficulty, word);
        try ctx.finalize(false);
        try std.testing.expectEqual(@ctz(raw) >= difficulty, try ctx.isCircuitValid());
    };
}
