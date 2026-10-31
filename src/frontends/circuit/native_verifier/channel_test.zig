//! Value-mode parity of `NativeChannel` with `core.channel.blake2s.Blake2sChannel`
//! on a scripted transcript: mixes, draws, query bits and the proof of work.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const channel_mod = @import("channel.zig");

const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Blake2sChannel = core.channel.blake2s.Blake2sChannel;
const MerkleChannel = core.vcs_lifted.blake2_merkle.Blake2sMerkleChannel;
const Context = builder.Context(QM31);
const Var = builder.Var;
const U32Wrapper = builder.wrappers.U32Wrapper;
const NativeChannel = channel_mod.NativeChannel;

fn guessWords(ctx: *Context, values: []const u32) ![]U32Wrapper(Var) {
    const out = try ctx.scratch().alloc(U32Wrapper(Var), values.len);
    for (out, values) |*wire, value| wire.* = try builder.wrappers.guessU32(QM31, ctx, builder.wrappers.u32Value(QM31, value));
    return out;
}

fn expectDigest(ctx: *const Context, circuit: *const NativeChannel, native: *const Blake2sChannel) !void {
    try std.testing.expectEqualSlices(u8, &native.digestBytes(), &circuit.debugDigest(ctx));
    try std.testing.expectEqual(native.n_draws, circuit.n_draws);
}

test "native channel: mixes and draws follow the Blake2sChannel transcript" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var circuit = try NativeChannel.init(QM31, &ctx);
    var native = Blake2sChannel{};
    try expectDigest(&ctx, &circuit, &native);

    const words = [_]u32{ 5, 7, 0xFFFF_FFFF, 0x8000_0000, 12345 };
    try circuit.mixU32s(QM31, &ctx, try guessWords(&ctx, &words));
    native.mixU32s(&words);
    try expectDigest(&ctx, &circuit, &native);

    const felts = [_]QM31{
        QM31.fromU32Unchecked(1, 2, 3, 4),
        QM31.fromU32Unchecked(0x7FFF_FFFE, 0, 0x1234_5678, 99),
        QM31.zero(),
    };
    var felt_wires: [felts.len]Var = undefined;
    for (&felt_wires, felts) |*wire, felt| wire.* = try ctx.guess(felt);
    try circuit.mixFelts(QM31, &ctx, &felt_wires);
    native.mixFelts(&felts);
    try expectDigest(&ctx, &circuit, &native);

    var root: [32]u8 = undefined;
    for (&root, 0..) |*byte, i| byte.* = @intCast(0xA0 + i);
    const root_wire = try builder.blake.guessHash(QM31, &ctx, builder.blake.hashValueFromDigest(QM31, root));
    try circuit.mixRoot(QM31, &ctx, root_wire);
    MerkleChannel.mixRoot(&native, root);
    try expectDigest(&ctx, &circuit, &native);

    for (0..3) |_| {
        const drawn = try circuit.drawSecureFelt(QM31, &ctx);
        try std.testing.expect(ctx.get(drawn).eql(native.drawSecureFelt()));
    }
    try expectDigest(&ctx, &circuit, &native);

    const many = try circuit.drawSecureFelts(QM31, &ctx, 5);
    const native_many = try native.drawSecureFelts(std.testing.allocator, 5);
    defer std.testing.allocator.free(native_many);
    for (many, native_many) |wire, expected| try std.testing.expect(ctx.get(wire).eql(expected));
    try expectDigest(&ctx, &circuit, &native);

    try circuit.mixU64(QM31, &ctx, (try guessWords(&ctx, &.{0x3333_4444}))[0], (try guessWords(&ctx, &.{0x1111_2222}))[0]);
    native.mixU64(0x1111_2222_3333_4444);
    try expectDigest(&ctx, &circuit, &native);

    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "native channel: mix_u32s upstream digest bytes" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var circuit = try NativeChannel.init(QM31, &ctx);
    try circuit.mixU32s(QM31, &ctx, try guessWords(&ctx, &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9 }));
    const expected = [_]u8{
        0x70, 0x91, 0x76, 0x83, 0x57, 0xbb, 0x1b, 0xb3,
        0x34, 0x6f, 0xda, 0xb6, 0xb3, 0x57, 0xd7, 0xfa,
        0x46, 0xb8, 0xfb, 0xe3, 0x2c, 0x2e, 0x43, 0x24,
        0xa0, 0xff, 0xc2, 0x94, 0xcb, 0xf9, 0xa1, 0xc7,
    };
    try std.testing.expectEqualSlices(u8, &expected, &circuit.debugDigest(&ctx));
}

test "native channel: query bits are the low bits of drawQueries words" {
    const cases = [_]struct { log_domain: u32, n_queries: usize }{
        .{ .log_domain = 5, .n_queries = 3 },
        .{ .log_domain = 16, .n_queries = 9 },
        .{ .log_domain = 21, .n_queries = 4 },
    };
    for (cases) |case| {
        var ctx = try Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var circuit = try NativeChannel.init(QM31, &ctx);
        var native = Blake2sChannel{};
        try circuit.mixU32s(QM31, &ctx, try guessWords(&ctx, &.{case.log_domain}));
        native.mixU32s(&.{case.log_domain});

        const bits = try circuit.drawQueryBits(QM31, &ctx, case.log_domain, case.n_queries);
        const positions = try core.queries.drawQueries(&native, std.testing.allocator, case.log_domain, case.n_queries);
        defer std.testing.allocator.free(positions);
        try expectDigest(&ctx, &circuit, &native);
        try std.testing.expectEqual(case.log_domain, @as(u32, @intCast(bits.bits.len)));
        for (positions, 0..) |position, q| {
            for (0..case.log_domain) |i| {
                const expected: u32 = @intCast((position >> @intCast(i)) & 1);
                try std.testing.expectEqual(expected, ctx.get(bits.unpacked[i][q]).c0.a.v);
                try std.testing.expectEqual(expected, ctx.get(bits.bits[i].data[q / 4]).toM31Array()[q % 4].v);
            }
        }
        try ctx.finalize(false);
        try std.testing.expect(try ctx.isCircuitValid());
    }
}

test "native channel: pow accepts the native nonce and rejects a wrong one" {
    const n_bits: u32 = 6;
    var native = Blake2sChannel{};
    native.mixU64(42);
    const nonce = native.grind(n_bits);
    try std.testing.expect(native.verifyPowNonce(n_bits, nonce));

    for ([_]bool{ true, false }) |valid| {
        var ctx = try Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var circuit = try NativeChannel.init(QM31, &ctx);
        try circuit.mixU64(QM31, &ctx, (try guessWords(&ctx, &.{42}))[0], (try guessWords(&ctx, &.{0}))[0]);
        const used_nonce = if (valid) nonce else nonce + 1;
        const lo = try guessWords(&ctx, &.{@truncate(used_nonce)});
        const hi = try guessWords(&ctx, &.{@truncate(used_nonce >> 32)});
        try circuit.pow(QM31, &ctx, n_bits, .{ lo[0], hi[0] });
        try ctx.finalize(false);
        try std.testing.expectEqual(valid, try ctx.isCircuitValid());
        if (valid) {
            var expected = native;
            expected.mixU64(nonce);
            try expectDigest(&ctx, &circuit, &expected);
        }
    }
}

test "native channel: zero pow bits only mixes the nonce" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var circuit = try NativeChannel.init(QM31, &ctx);
    var native = Blake2sChannel{};
    const words = try guessWords(&ctx, &.{ 0xDEAD_BEEF, 0x0000_0001 });
    try circuit.pow(QM31, &ctx, 0, .{ words[0], words[1] });
    try std.testing.expect(native.verifyPowNonce(0, 0x0000_0001_DEAD_BEEF));
    native.mixU64(0x0000_0001_DEAD_BEEF);
    try expectDigest(&ctx, &circuit, &native);
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "native channel: word reduction equals M31.fromU64 below 2P" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    for ([_]u32{ 0, 1, 0xFFFF, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFD }) |word| {
        const wire = try builder.wrappers.guessU32(QM31, &ctx, builder.wrappers.u32Value(QM31, word));
        const reduced = try channel_mod.wordToM31(QM31, &ctx, wire);
        try std.testing.expect(ctx.get(reduced).eql(QM31.fromBase(M31.fromU64(word))));
    }
}
