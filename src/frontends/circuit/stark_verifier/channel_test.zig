//! `crates/stark_verifier/src/channel_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230): the upstream regression values.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const Channel = @import("channel.zig").Channel;

const QM31 = core.fields.qm31.QM31;
const Context = builder.Context(QM31);
const qm31 = builder.ivalue.qm31FromU32s;

/// `Channel::from_digest`: the digest as two constants.
fn fromDigest(ctx: *Context, digest: [2]QM31) !Channel {
    const low = try ctx.constant(digest[0]);
    return .{ .digest = .{ .low = low, .high = try ctx.constant(digest[1]) }, .n_draws = 0 };
}

fn expectValue(ctx: *const Context, v: builder.Var, expected: QM31) !void {
    try std.testing.expect(ctx.get(v).eql(expected));
}

/// `validate_circuit`: finalize, then every gate holds.
fn expectValid(ctx: *Context) !void {
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "channel: mix_commitment regression" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var channel = Channel.init(QM31, &ctx);
    const roots = [2][8]u32{
        .{ 637418335, 1672023491, 980858689, 607764934, 386900718, 430556311, 1187803054, 669301442 },
        .{ 1477561267, 1244239078, 1979857528, 1316512771, 490980261, 2016799283, 79573118, 1350641448 },
    };
    const root0 = try builder.blake.guessHash(QM31, &ctx, builder.blake.hashValue(QM31, roots[0]));
    const root1 = try builder.blake.guessHash(QM31, &ctx, builder.blake.hashValue(QM31, roots[1]));
    try channel.mixCommitment(QM31, &ctx, root0);
    const digest0 = channel.digest;
    try channel.mixCommitment(QM31, &ctx, root1);
    try expectValue(&ctx, digest0.low, qm31(1668664816, 1251290000, 263177925, 722663798));
    try expectValue(&ctx, digest0.high, qm31(484105836, 140598027, 679686738, 1985395078));
    try expectValue(&ctx, channel.digest.low, qm31(800533588, 1994201536, 2099095392, 678020158));
    try expectValue(&ctx, channel.digest.high, qm31(1950435309, 1607451911, 2421030, 565867237));
    try std.testing.expectEqual(@as(usize, 44), ctx.stats.add);
    try std.testing.expectEqual(@as(usize, 72), ctx.stats.mul);
    try std.testing.expectEqual(@as(usize, 48), ctx.stats.pointwise_mul);
    try std.testing.expectEqual(@as(usize, 32), ctx.stats.guess);
    try std.testing.expectEqual(@as(usize, 16), ctx.stats.triple_xor);
    try std.testing.expectEqual(@as(usize, 16), ctx.stats.m31_to_u32);
    try expectValid(&ctx);
}

test "channel: mix_qm31s regression" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var channel = try fromDigest(&ctx, .{
        qm31(266526289, 1341429509, 1126614795, 1001621831),
        qm31(1024638884, 1857778419, 1763024470, 1859929979),
    });
    const values = [_]QM31{
        qm31(1, 0, 0, 0),
        qm31(485399786, 1255952693, 1939438763, 1561715227),
        qm31(1757357815, 8864493, 674769946, 1715431414),
        qm31(1148846901, 1519172202, 357767101, 2129853554),
        qm31(0, 0, 0, 0),
        qm31(0, 0, 0, 0),
        qm31(0, 0, 0, 0),
    };
    var felts: [values.len]builder.Var = undefined;
    for (&felts, values) |*v, value| v.* = try ctx.newVar(value);
    try channel.mixQm31s(QM31, &ctx, &felts);
    try expectValue(&ctx, channel.digest.low, qm31(1186703962, 1584594219, 633548839, 1510969779));
    try expectValue(&ctx, channel.digest.high, qm31(1524867388, 1224019906, 1564199416, 388718964));
    try std.testing.expectEqual(@as(u32, 0), channel.n_draws);
    try expectValid(&ctx);
}

test "channel: draw_two_qm31s and draw_qm31 regression" {
    const init_digest = [2]QM31{
        qm31(800533588, 1994201536, 2099095392, 678020158),
        qm31(1950435309, 1607451911, 2421030, 565867237),
    };
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var channel = try fromDigest(&ctx, init_digest);
    const first = try channel.drawTwoQm31s(QM31, &ctx);
    try expectValue(&ctx, first[0], qm31(1511219767, 1680262446, 557532573, 1741612347));
    try expectValue(&ctx, first[1], qm31(1790671546, 1908058358, 2021264888, 1820912939));
    const second = try channel.drawTwoQm31s(QM31, &ctx);
    try expectValue(&ctx, second[0], qm31(1010544646, 1898030754, 53928552, 587440252));
    try expectValue(&ctx, second[1], qm31(868459281, 1035649663, 299576823, 539722878));
    try expectValid(&ctx);

    var single = try Context.init(std.testing.allocator, 0);
    defer single.deinit();
    var channel2 = try fromDigest(&single, init_digest);
    try expectValue(&single, try channel2.drawQm31(QM31, &single), qm31(1511219767, 1680262446, 557532573, 1741612347));
    try expectValue(&single, try channel2.drawQm31(QM31, &single), qm31(1010544646, 1898030754, 53928552, 587440252));
    try expectValid(&single);
}

test "channel: draw_point regression" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var channel = try fromDigest(&ctx, .{
        qm31(2072130922, 1322677507, 1508142866, 1010842681),
        qm31(967226388, 1861793490, 1980108433, 243066861),
    });
    const point = try channel.drawPoint(QM31, &ctx);
    try expectValue(&ctx, point.x, qm31(1343313724, 1951183646, 1685075959, 888698585));
    try expectValue(&ctx, point.y, qm31(674655034, 1516640953, 569857337, 1549701521));
    try expectValid(&ctx);
}

test "channel: pow accepts exactly the valid nonce and bit count" {
    const cases = [_]struct { n_bits: u32, nonce: u32, success: bool }{
        .{ .n_bits = 10, .nonce = 1524, .success = true },
        .{ .n_bits = 11, .nonce = 1524, .success = false },
        .{ .n_bits = 9, .nonce = 1524, .success = false },
        .{ .n_bits = 10, .nonce = 1523, .success = false },
        .{ .n_bits = 10, .nonce = 1525, .success = false },
    };
    for (cases) |case| {
        var ctx = try Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var channel = try fromDigest(&ctx, .{
            qm31(968886948, 725376924, 836084817, 484428276),
            qm31(1805658819, 300032261, 172116750, 994058243),
        });
        const nonce = try ctx.newVar(qm31(case.nonce, 0, 0, 0));
        try channel.pow(QM31, &ctx, case.n_bits, nonce);
        try std.testing.expectEqual(case.success, try ctx.isCircuitValid());
        if (case.success) {
            try expectValue(&ctx, channel.digest.low, qm31(271333035, 1833401714, 819175623, 1270120203));
            try expectValue(&ctx, channel.digest.high, qm31(1921341900, 364315769, 339695133, 365135865));
        }
    }
}

/// The core `Blake2sM31Channel` of the circuit proofs' channel profile.
const HostChannel = core.vcs_lifted.channel_profile.proving_5a7c5ed.Blake2sM31MerkleChannel.Channel;

test "channel: PoW checks reduced M31 digest words like the native verifier" {
    const digest = [2]QM31{
        qm31(968886948, 725376924, 836084817, 484428276),
        qm31(1805658819, 300032261, 172116750, 994058243),
    };
    var digest_bytes: [32]u8 = undefined;
    for (digest, 0..) |felt, half| {
        for (felt.toM31Array(), 0..) |word, i|
            std.mem.writeInt(u32, digest_bytes[(half * 4 + i) * 4 ..][0..4], word.v, .little);
    }
    var host = HostChannel{};
    host.updateDigest(digest_bytes);
    const pow_bits: u32 = 10;
    const prefix = host.computePowPrefix(pow_bits);

    // The first raw BLAKE2s word crosses the M31 modulus in both cases.
    // Nonce 2392 is valid only after the mandated M31 reduction; nonce 866
    // has ten zero raw bits but becomes invalid after that reduction.
    for ([_]struct { nonce: u64, accepted: bool }{
        .{ .nonce = 2392, .accepted = true },
        .{ .nonce = 866, .accepted = false },
    }) |case| {
        var message: [40]u8 = undefined;
        @memcpy(message[0..32], &prefix);
        std.mem.writeInt(u64, message[32..40], case.nonce, .little);
        var raw_hash: [32]u8 = undefined;
        std.crypto.hash.blake2.Blake2s256.hash(&message, &raw_hash, .{});
        const raw_first = std.mem.readInt(u32, raw_hash[0..4], .little);
        try std.testing.expect(raw_first >= core.fields.m31.Modulus);
        const raw_accepts = (raw_first & ((@as(u32, 1) << pow_bits) - 1)) == 0;
        try std.testing.expectEqual(!case.accepted, raw_accepts);
        try std.testing.expectEqual(case.accepted, host.verifyPowNonce(pow_bits, case.nonce));

        var ctx = try Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var circuit_channel = try fromDigest(&ctx, digest);
        const nonce = try ctx.newVar(qm31(@intCast(case.nonce), 0, 0, 0));
        try circuit_channel.pow(QM31, &ctx, pow_bits, nonce);
        try std.testing.expectEqual(case.accepted, try ctx.isCircuitValid());
    }
}

fn expectHostDigest(ctx: *const Context, channel: Channel, host: HostChannel) !void {
    const expected = builder.blake.reducedHashValueFromDigest(host.digestBytes());
    try expectValue(ctx, channel.digest.low, expected.low);
    try expectValue(ctx, channel.digest.high, expected.high);
}

test "channel: mix_u32s matches stwo, full 32-bit words included" {
    const data = [_]u32{ 1, 0x8000_0000, 0xFFFF_FFFF, 2, 3 };
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var channel = Channel.init(QM31, &ctx);
    var host: HostChannel = .{};
    // Twice: the second mix starts from a non-zero digest.
    for (0..2) |_| {
        var words: [data.len]builder.wrappers.U32Wrapper(builder.Var) = undefined;
        for (&words, data) |*word, value| word.* = .newUnsafe(try ctx.guess(builder.ivalue.packU32(QM31, value)));
        try channel.mixU32s(QM31, &ctx, &words);
        host.mixU32s(&data);
        try expectHostDigest(&ctx, channel, host);
    }
    try std.testing.expectEqual(@as(u32, 0), channel.n_draws);
    try expectValid(&ctx);
}

test "channel: unpack_qm31s_to_u32_words then mix_u32s matches stwo mix_felts" {
    const M31 = core.fields.m31.M31;
    const m = M31.fromCanonical;
    const rounds = [_][]const QM31{
        &.{
            QM31.fromM31(m(42), m(1337), m(999999), m(2147483646)),
            QM31.fromM31(m(1), m(0), m(0), m(0)),
            QM31.fromM31(m(485399786), m(1255952693), m(1939438763), m(1561715227)),
        },
        &.{QM31.fromM31(m(1757357815), m(8864493), m(674769946), m(1715431414))},
    };
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var channel = Channel.init(QM31, &ctx);
    var host: HostChannel = .{};
    for (rounds) |felts| {
        host.mixFelts(felts);
        const vars = try ctx.scratch().alloc(builder.Var, felts.len);
        for (vars, felts) |*v, felt| v.* = try ctx.newVar(felt);
        const words = try builder.blake.unpackQm31sToU32Words(QM31, &ctx, vars);
        try channel.mixU32s(QM31, &ctx, words);
        try expectHostDigest(&ctx, channel, host);
    }
    try expectValid(&ctx);
}

test "channel: fused transcript salt, profile tag, field claims and independent lookup draws match native" {
    const m = core.fields.m31.M31.fromCanonical;
    const felts = [_]QM31{
        QM31.fromM31(m(42), m(1337), m(0), m(0)),
        QM31.fromM31(m(1), m(2), m(3), m(4)),
    };
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    var channel = Channel.init(QM31, &ctx);
    var host: HostChannel = .{};

    const tag: u64 = 0x5333_3146_4346_3031;
    try channel.mixU64(QM31, &ctx, tag);
    host.mixU64(tag);
    try expectHostDigest(&ctx, channel, host);

    const salt = core.fields.m31.Modulus + 5;
    try channel.mixChannelSalt(QM31, &ctx, salt);
    core.channel.lookup_transcript.mixChannelSalt(&host, salt);
    try expectHostDigest(&ctx, channel, host);

    var vars: [felts.len]builder.Var = undefined;
    for (&vars, felts) |*v, value| v.* = try ctx.newVar(value);
    try channel.mixFelts(QM31, &ctx, &vars);
    host.mixFelts(&felts);
    try expectHostDigest(&ctx, channel, host);

    const first = try channel.drawLookupElements(QM31, &ctx);
    const host_first = try core.channel.lookup_transcript.drawLookupElements(std.testing.allocator, &host);
    try expectValue(&ctx, first[0], host_first.z);
    try expectValue(&ctx, first[1], host_first.alpha);
    const second = try channel.drawLookupElements(QM31, &ctx);
    const host_second = try core.channel.lookup_transcript.drawLookupElements(std.testing.allocator, &host);
    try expectValue(&ctx, second[0], host_second.z);
    try expectValue(&ctx, second[1], host_second.alpha);
    try std.testing.expect(!ctx.get(first[0]).eql(ctx.get(second[0])));
    try expectHostDigest(&ctx, channel, host);
    try expectValid(&ctx);
}
