//! `crates/stark_verifier/src/merkle_test.rs`
//! (https://github.com/starkware-libs/proving at
//! 5a7c5ede4299c91a61df19a07cba4f7502c14230): leaf and node hashes against
//! the host Blake2s, and a Merkle path that must fail on a wrong bit or root.

const std = @import("std");
const core = @import("stwo_core");
const builder = @import("../builder/mod.zig");
const merkle = @import("merkle.zig");

const QM31 = core.fields.qm31.QM31;
const Context = builder.Context(QM31);
const Blake2sHasher = core.vcs.blake2_hash.Blake2sHasher;
const Blake2sHash = core.vcs.blake2_hash.Blake2sHash;
const HashValue = builder.blake.HashValue;
const Var = builder.Var;

fn hostWords(hash: Blake2sHash) [8]u32 {
    return core.vcs.blake2_hash.digestToU32s(hash);
}

fn circuitWords(ctx: *const Context, hash: HashValue(Var)) [8]u32 {
    var out: [8]u32 = undefined;
    for (&out, hash.words) |*word, wire| word.* = builder.ivalue.unpackU32(QM31, ctx.get(wire.get()));
    return out;
}

fn guessDigest(ctx: *Context, hash: Blake2sHash) !HashValue(Var) {
    return builder.blake.guessHash(QM31, ctx, builder.blake.hashValueFromDigest(QM31, hash));
}

fn concatAndHash(left: Blake2sHash, right: Blake2sHash) Blake2sHash {
    var bytes: [64]u8 = undefined;
    @memcpy(bytes[0..32], &left);
    @memcpy(bytes[32..], &right);
    return Blake2sHasher.hash(&bytes);
}

test "merkle: hash_leaf_qm31 and hash_node match the host Blake2s" {
    var ctx = try Context.init(std.testing.allocator, 0);
    defer ctx.deinit();
    const words = [4]u32{ 106879334, 2000582330, 760086299, 1036436096 };
    const value = try ctx.guess(builder.ivalue.qm31FromU32s(words[0], words[1], words[2], words[3]));
    const leaf = try merkle.hashLeafQm31(QM31, &ctx, value);
    try std.testing.expectEqual(hostWords(Blake2sHasher.hash(std.mem.sliceAsBytes(&words))), circuitWords(&ctx, leaf));

    var left_hash: Blake2sHash = undefined;
    var right_hash: Blake2sHash = undefined;
    for (&left_hash, &right_hash, 0..) |*l, *r, i| {
        l.* = @intCast(i);
        r.* = @intCast(i + 50);
    }
    const node = try merkle.hashNode(QM31, &ctx, try guessDigest(&ctx, left_hash), try guessDigest(&ctx, right_hash));
    try std.testing.expectEqual(hostWords(concatAndHash(left_hash, right_hash)), circuitWords(&ctx, node));
    try ctx.finalize(false);
    try std.testing.expect(try ctx.isCircuitValid());
}

test "merkle: verify_merkle_path accepts the path and rejects a wrong bit or root" {
    const cases = [_]struct { wrong_bit: bool, wrong_root: bool }{
        .{ .wrong_bit = false, .wrong_root = false },
        .{ .wrong_bit = true, .wrong_root = false },
        .{ .wrong_bit = false, .wrong_root = true },
    };
    for (cases) |case| {
        var ctx = try Context.init(std.testing.allocator, 0);
        defer ctx.deinit();
        var leaf_hash: Blake2sHash = undefined;
        for (&leaf_hash, 0..) |*byte, i| byte.* = @intCast(i);
        var siblings: [5]Blake2sHash = undefined;
        for (&siblings, 0..) |*sibling, i| {
            for (sibling, 0..) |*byte, j| byte.* = @intCast((i + 1) * 40 + j);
        }
        var auth_path: [5]HashValue(Var) = undefined;
        for (&auth_path, siblings) |*node, sibling| node.* = try guessDigest(&ctx, sibling);
        const leaf = try guessDigest(&ctx, leaf_hash);
        const bit_values = [5]u32{ if (case.wrong_bit) 0 else 1, 1, 0, 0, 1 };
        var bits: [5]Var = undefined;
        for (&bits, bit_values) |*bit, value| bit.* = try ctx.guess(builder.ivalue.qm31FromU32s(value, 0, 0, 0));

        // Bit 1 puts the current node on the right.
        var node = leaf_hash;
        node = concatAndHash(siblings[0], node);
        node = concatAndHash(siblings[1], node);
        node = concatAndHash(node, siblings[2]);
        node = concatAndHash(node, siblings[3]);
        node = concatAndHash(siblings[4], node);
        if (case.wrong_root) node[0] ^= 1;
        const root = try guessDigest(&ctx, node);

        try merkle.verifyMerklePath(QM31, &ctx, leaf, &bits, root, &auth_path);
        try std.testing.expectEqual(!case.wrong_bit and !case.wrong_root, try ctx.isCircuitValid());
    }
}
