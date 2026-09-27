const std = @import("std");
const core = @import("stwo_core");
const protocol = core.channel.blake3;
const Channel = protocol.Channel;
const M31 = core.fields.m31.M31;
const QM31 = core.fields.qm31.QM31;
const Hasher = core.vcs_lifted.blake3_merkle.MerkleHasher;
fn expectHex(expected: []const u8, actual: [32]u8) !void {
    try std.testing.expectEqualStrings(expected, &std.fmt.bytesToHex(actual, .lower));
}
test "BLAKE3 official primitive vectors and streaming boundaries" {
    const cases = .{
        .{ @as(usize, 0), "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262" },
        .{ @as(usize, 1), "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213" },
        .{ @as(usize, 2), "7b7015bb92cf0b318037702a6cdd81dee41224f734684c2c122cd6359cb1ee63" },
        .{ @as(usize, 3), "e1be4d7a8ab5560aa4199eea339849ba8e293d55ca0a81006726d184519e647f" },
        .{ @as(usize, 4), "f30f5ab28fe047904037f77b6da4fea1e27241c5d132638d8bedce9d40494f32" },
        .{ @as(usize, 5), "b40b44dfd97e7a84a996a91af8b85188c66c126940ba7aad2e7ae6b385402aa2" },
        .{ @as(usize, 6), "06c4e8ffb6872fad96f9aaca5eee1553eb62aed0ad7198cef42e87f6a616c844" },
        .{ @as(usize, 7), "3f8770f387faad08faa9d8414e9f449ac68e6ff0417f673f602a646a891419fe" },
        .{ @as(usize, 8), "2351207d04fc16ade43ccab08600939c7c1fa70a5c0aaca76063d04c3228eaeb" },
        .{ @as(usize, 63), "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b" },
        .{ @as(usize, 64), "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98" },
        .{ @as(usize, 65), "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee" },
        .{ @as(usize, 127), "d81293fda863f008c09e92fc382a81f5a0b4a1251cba1634016a0f86a6bd640d" },
        .{ @as(usize, 128), "f17e570564b26578c33bb7f44643f539624b05df1a76c81f30acd548c44b45ef" },
        .{ @as(usize, 129), "683aaae9f3c5ba37eaaf072aed0f9e30bac0865137bae68b1fde4ca2aebdcb12" },
        .{ @as(usize, 1023), "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11" },
        .{ @as(usize, 1024), "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7" },
        .{ @as(usize, 1025), "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444" },
        .{ @as(usize, 2048), "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a" },
        .{ @as(usize, 2049), "5f4d72f40d7a5f82b15ca2b2e44b1de3c2ef86c426c95c1af0b6879522563030" },
        .{ @as(usize, 3072), "b98cb0ff3623be03326b373de6b9095218513e64f1ee2edd2525c7ad1e5cffd2" },
        .{ @as(usize, 3073), "7124b49501012f81cc7f11ca069ec9226cecb8a2c850cfe644e327d22d3e1cd3" },
        .{ @as(usize, 4096), "015094013f57a5277b59d8475c0501042c0b642e531b0a1c8f58d2163229e969" },
        .{ @as(usize, 4097), "9b4052b38f1c5fc8b1f9ff7ac7b27cd242487b3d890d15c96a1c25b8aa0fb995" },
        .{ @as(usize, 5120), "9cadc15fed8b5d854562b26a9536d9707cadeda9b143978f319ab34230535833" },
        .{ @as(usize, 5121), "628bd2cb2004694adaab7bbd778a25df25c47b9d4155a55f8fbd79f2fe154cff" },
        .{ @as(usize, 6144), "3e2e5b74e048f3add6d21faab3f83aa44d3b2278afb83b80b3c35164ebeca205" },
        .{ @as(usize, 6145), "f1323a8631446cc50536a9f705ee5cb619424d46887f3c376c695b70e0f0507f" },
        .{ @as(usize, 7168), "61da957ec2499a95d6b8023e2b0e604ec7f6b50e80a9678b89d2628e99ada77a" },
        .{ @as(usize, 7169), "a003fc7a51754a9b3c7fae0367ab3d782dccf28855a03d435f8cfe74605e7817" },
        .{ @as(usize, 8192), "aae792484c8efe4f19e2ca7d371d8c467ffb10748d8a5a1ae579948f718a2a63" },
        .{ @as(usize, 8193), "bab6c09cb8ce8cf459261398d2e7aef35700bf488116ceb94a36d0f5f1b7bc3b" },
        .{ @as(usize, 16384), "f875d6646de28985646f34ee13be9a576fd515f76b5b0a26bb324735041ddde4" },
        .{ @as(usize, 31744), "62b6960e1a44bcc1eb1a611a8d6235b6b4b78f32e7abc4fb4c6cdcce94895c47" },
        .{ @as(usize, 102400), "bc3e3d41a1146b069abffad3c0d44860cf664390afce4d9661f7902e7943e085" },
    };
    var data: [102400]u8 = undefined;
    for (&data, 0..) |*byte, i| byte.* = @intCast(i % 251);
    inline for (cases) |case| {
        try expectHex(case[1], core.vcs.blake3_hash.Blake3Hasher.hash(data[0..case[0]]));
        var stream = core.vcs.blake3_hash.Blake3Hasher.init();
        var i: usize = 0;
        while (i < case[0]) {
            const end = @min(i + 63, case[0]);
            stream.update(data[i..end]);
            i = end;
        }
        try expectHex(case[1], stream.finalize());
    }
}
test "BLAKE3 independent protocol vectors retain full digest bits" {
    var channel = Channel{};
    try expectHex("bafb413e8e24e787d52202bb4decd21c8191a4eec29bc0822d59660bdc493856", channel.digestBytes());
    channel.mixU32s(&.{ 0, 0x80000000, 0xffffffff });
    try expectHex("f1c69d00a16875b0040e0f7c850c1e10ec968f043842e90ca6a2bb56e4706ac4", channel.digestBytes());
    const draw0 = channel.drawU32s();
    var bytes0: [32]u8 = undefined;
    for (draw0, 0..) |word, j| std.mem.writeInt(u32, bytes0[4 * j ..][0..4], word, .little);
    try expectHex("d775315db7825f028798384e27d75fc1815498230ed8670cc6ff785f6245fdaa", bytes0);
    const draw1 = channel.drawU32s();
    var bytes1: [32]u8 = undefined;
    for (draw1, 0..) |word, j| std.mem.writeInt(u32, bytes1[4 * j ..][0..4], word, .little);
    try expectHex("c86893caabf48f1772f080da9d686b0c84027bb8f1f4e4ab31e9e53d53237536", bytes1);
    channel.mixU64(0xfedcba9876543210);
    try expectHex("242793819901649e1ac172b527746ab7d871244b0ccca00e2f26347fced7d265", channel.digestBytes());
    const values = [_]M31{ M31.zero(), M31.one(), M31.fromCanonical(2147483646), M31.fromCanonical(7) };
    channel.mixFelts(&.{QM31.fromM31Array(values)});
    try expectHex("d13aad4493688d29f93f832c277bd45c89988fb4a3badcbbe26e8b971dfaab1a", channel.digestBytes());
    var leaf = Hasher.defaultWithInitialState();
    leaf.updateLeaf(values[0..1]);
    leaf.updateLeaf(values[1..]);
    try expectHex("8fa0e18a6390128fdde5cfa70b5ec7c7b6133c83867babdfd80ab2a823515b3d", leaf.finalize());
    var right: [32]u8 = undefined;
    for (&right, 0..) |*byte, i| byte.* = @intCast(i);
    const node = Hasher.hashChildren(.{ .left = leaf.finalize(), .right = right });
    try expectHex("8f5ce152d54d5f724a7aefd4361c05db0843ab16a9a8b4724724f218e67bbbff", node);
    channel.mixRoot(node);
    try expectHex("8c4cc736ec4f7bb9738fd03b34e4daaac4fe057f497497f1f208eb8960daa9f8", channel.digestBytes());
    try std.testing.expectEqual(@as(u64, 131), channel.grind(8));
    try std.testing.expect(channel.verifyPowNonce(8, channel.grind(8)));
    try std.testing.expect(!channel.verifyPowNonce(33, 0));
}
test "BLAKE3 field rejection and operation domains" {
    const p = core.fields.m31.Modulus;
    try std.testing.expectEqual(@as(u32, 0), protocol.sampleWord(0).?.toU32());
    try std.testing.expectEqual(@as(u32, 0), protocol.sampleWord(p).?.toU32());
    try std.testing.expectEqual(p - 1, protocol.sampleWord(2 * p - 1).?.toU32());
    try std.testing.expect(protocol.sampleWord(2 * p) == null);
    try std.testing.expect(protocol.sampleWord(0xffffffff) == null);
    var a = Channel{};
    var b = Channel{};
    var c = Channel{};
    a.mixU64(1);
    b.mixU32s(&.{ 1, 0 });
    c.mixFelts(&.{QM31.fromBase(M31.one())});
    try std.testing.expect(!std.mem.eql(u8, &a.digestBytes(), &b.digestBytes()));
    try std.testing.expect(!std.mem.eql(u8, &b.digestBytes(), &c.digestBytes()));
    var single = Channel{};
    var batch = Channel{};
    try std.testing.expect(single.drawSecureFelt().eql(batch.drawSecureFelt()));
    const values = try batch.drawSecureFelts(std.testing.allocator, 5);
    defer std.testing.allocator.free(values);
    const first = single.drawSecureFelt();
    try std.testing.expect(first.eql(values[0]));
    try std.testing.expectEqual(@as(u64, 4), batch.n_draws);
    batch.mixU32s(&.{});
    try std.testing.expectEqual(@as(u64, 0), batch.n_draws);
    var leaf = Hasher.defaultWithInitialState();
    const node = Hasher.hashChildren(.{ .left = [_]u8{0} ** 32, .right = [_]u8{0} ** 32 });
    leaf.updateLeaf(&([_]M31{M31.zero()} ** 16));
    try std.testing.expect(!std.mem.eql(u8, &node, &leaf.finalize()));
}

test "BLAKE3 transcript receipts preserve full counters and legacy bytes" {
    const receipt = core.channel.transcript_receipt;
    const digest: [32]u8 = @splat(0xab);
    try expectHex("cae213ace49fae81c625ed0d308f9832d3130bc2ceb9d66fc493ea896f7b358a", receipt.blake3Digest(digest, 0));
    try expectHex("b92c9c7f1b2bc65aadfd69f31548dd15a6b2603dbdb761d295b878b3b76d5e20", receipt.blake3Digest(digest, 1));
    try expectHex("97b4d684f741b054f0b9a54f8b8801f38dfa2271313baa2929824585237e9b60", receipt.blake3Digest(digest, 4294967296));
    try expectHex("b2569b57e04d829cf545cbfd15338d5ef974b354331b0b89c7dd3a3a762d627e", receipt.blake3Digest(digest, 18446744073709551615));
    try expectHex("27b6ef19323bcd77276c525a2a7c3f019b1a0d2559969459354df57d60a80f6d", receipt.legacyDigest(digest, 0));

    const legacy = receipt.fromChannel(core.channel.blake2s.Blake2sChannel{ .digest = digest });
    const modern = receipt.fromChannel(Channel{ .digest = digest, .n_draws = @as(u64, 1) << 32 });
    try std.testing.expectEqual(receipt.Suite.blake2s, legacy.suite);
    try std.testing.expectEqual(@as(u16, 1), legacy.version);
    try std.testing.expectEqual(receipt.Suite.blake3, modern.suite);
    try std.testing.expectEqual(@as(u16, 2), modern.version);
    try std.testing.expectEqualSlices(u8, &receipt.blake3Digest(digest, @as(u64, 1) << 32), &modern.digest);
    try std.testing.expect(!std.mem.eql(u8, &legacy.digest, &modern.digest));
}

test "BLAKE3 pooled PoW preserves minimum nonce across worker counts" {
    const prover = @import("stwo_prover_engine");
    const search = prover.pcs.proof_of_work;
    for ([_]usize{ 1, 2, 3, 8, 16 }) |workers| {
        var pool: prover.work_pool.WorkPool = undefined;
        try pool.initInPlaceWithOptions(.{ .worker_count = workers });
        defer pool.deinit();
        for (0..4) |state| {
            var channel = Channel{};
            channel.mixU64(@intCast(state));
            const expected = channel.grind(10);
            try std.testing.expectEqual(expected, search.grindBlake3InPool(channel, 10, &pool));
            try std.testing.expectEqual(@as(u64, 0), search.grindBlake3InPool(channel, 0, &pool));
            for ([_]u64{ 0, 1, expected, std.math.maxInt(u64) }) |nonce| {
                try std.testing.expectEqual(channel.verifyPowNonce(10, nonce), Channel.validNonce(channel.powPrefix(10), 10, nonce));
            }
            try std.testing.expect(!Channel.validNonce(channel.powPrefix(33), 33, 0));
        }
    }
}
