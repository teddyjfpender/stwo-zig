//! Dedicated-row gadget integration: source-use closure and exact native replay.
const std = @import("std");
const core = @import("stwo_core");
const B = @import("stwo_circuit_frontend").builder;
const Context = @import("context.zig").Context;
const Sponge = @import("sponge.zig");
const Channel = @import("channel.zig");
const Merkle = @import("merkle.zig").ForContext(Context);
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const a = std.testing.allocator;
fn digestEqual(ctx: *Context, actual: Sponge.Hash, expected: core.crypto.poseidon2_m31_sponge.Digest) !void {
    for (actual, try core.crypto.poseidon2_m31_sponge.decode(expected)) |wire, word| try std.testing.expect(ctx.algebra().get(wire).eql(Q.fromBase(word)));
}
test "dedicated Poseidon channel replays native fields, words, queries and PoW" {
    inline for (.{ 4, 8 }) |degree| {
        inline for (.{ 1, 2 }) |version| {
            const S = if (degree == 4) Q else core.fields.om31.OM31;
            const C = if (version == 1) Channel.ForContext(Context, degree) else Channel.ForContextV2(Context, degree);
            var ctx = try Context.init(a, 1);
            defer ctx.deinit();
            const Native = if (version == 1) core.channel.poseidon2_m31.ForField(S) else core.channel.poseidon2_m31.ForFieldV2(S);
            var native = Native.init();
            var channel = try C.init(&ctx);
            const constants = [_]u32{ 0, 1, 0xffffffff, core.fields.m31.Modulus };
            native.mixU32s(&constants);
            try channel.mixConstU32s(&ctx, &constants);
            try digestEqual(&ctx, channel.digest, native.digestBytes());
            var dynamic: [constants.len]B.wrappers.U32Wrapper(B.Var) = undefined;
            for (&dynamic, constants) |*word, value| word.* = try B.wrappers.guessU32(Q, ctx.algebra(), B.wrappers.u32Value(Q, value));
            native.mixU32s(&constants);
            try channel.mixU32s(&ctx, &dynamic);
            try digestEqual(&ctx, channel.digest, native.digestBytes());
            var field_words: [degree]M = undefined;
            for (&field_words, 0..) |*word, i| word.* = M.fromCanonical(@intCast(11 + i));
            const field = S.fromM31Array(field_words);
            var wires: C.Felt = undefined;
            for (&wires, 0..) |*wire, i| wire.* = try ctx.algebra().guess(Q.fromM31Array(field_words[4 * i ..][0..4].*));
            native.mixFelts(&.{field});
            try channel.mixFelts(&ctx, &.{wires});
            try digestEqual(&ctx, channel.digest, native.digestBytes());
            const root = core.vcs.poseidon2_m31_merkle.Poseidon2M31MerkleHasher.hashNode(null, &.{M.one()});
            var root_wires: Sponge.Hash = undefined;
            for (&root_wires, try core.crypto.poseidon2_m31_sponge.decode(root)) |*wire, word| wire.* = try ctx.algebra().guess(Q.fromBase(word));
            native.mixRoot(root);
            try channel.mixRoot(&ctx, root_wires);
            try digestEqual(&ctx, channel.digest, native.digestBytes());
            for (0..3) |_| {
                const expected = native.drawSecureFelt().toM31Array();
                const drawn = try channel.drawSecureFelt(&ctx);
                for (drawn, 0..) |wire, i| try std.testing.expect(ctx.algebra().get(wire).eql(Q.fromM31Array(expected[4 * i ..][0..4].*)));
            }
            const bits = try channel.drawQueryBits(&ctx, 25, 13);
            var at: usize = 0;
            while (at < 13) {
                const expected = native.drawU32s();
                for (expected) |word| {
                    if (at == 13) break;
                    for (bits.unpacked, 0..) |bit, i| try std.testing.expect(ctx.algebra().get(bit[at]).eql(Q.fromBase(M.fromCanonical((word >> @intCast(i)) & 1))));
                    at += 1;
                }
            }
            const nonce = native.grind(5);
            const low = try B.wrappers.guessU32(Q, ctx.algebra(), B.wrappers.u32Value(Q, @truncate(nonce)));
            const high = try B.wrappers.guessU32(Q, ctx.algebra(), B.wrappers.u32Value(Q, @truncate(nonce >> 32)));
            try channel.pow(&ctx, 5, .{ low, high });
            native.mixU64(nonce);
            try digestEqual(&ctx, channel.digest, native.digestBytes());
            try ctx.setOutputs(&.{channel.digest[0]});
            try ctx.finalize();
            try std.testing.expect(try ctx.isCircuitValid());
            const fixed = try ctx.fixedRows(a);
            defer a.free(fixed);
            const census_json = try std.json.Stringify.valueAlloc(a, .{ .kind = "channel", .degree = degree, .version = version, .raw_counts = try ctx.rawCounts(), .classic = try ctx.census(false), .gkr = try ctx.census(true) }, .{});
            defer a.free(census_json);
            std.debug.print("P2_DEDICATED_CENSUS {s}\n", .{census_json});
            try std.testing.expect(fixed.len > 10);
            const output = ctx.calls.items[ctx.calls.items.len / 2].outputs[7];
            ctx.algebra().value_table.items[output] = ctx.algebra().value_table.items[output].add(Q.fromU32Unchecked(0, 1, 0, 0));
            try std.testing.expect(!try ctx.isCircuitValid());
            std.debug.print("P2_DEDICATED_CHANNEL degree={} version={} perms={} vars={} exact_native=true\n", .{ degree, version, fixed.len, ctx.algebra().circuit.n_vars });
        }
    }
}
test "dedicated Poseidon Merkle native parity and authenticated direction bits" {
    var ctx = try Context.init(a, 1);
    defer ctx.deinit();
    var values: [479]M = undefined;
    var wires: [479]B.Var = undefined;
    for (&values, &wires, 0..) |*value, *wire, i| {
        value.* = M.fromCanonical(@intCast(i));
        wire.* = try ctx.algebra().guess(Q.fromBase(value.*));
    }
    const native_leaf = core.vcs.poseidon2_m31_merkle.Poseidon2M31MerkleHasher.hashNode(null, &values);
    const leaf = try Merkle.leaf(&ctx, &wires);
    try digestEqual(&ctx, leaf, native_leaf);
    const parent = try Merkle.children(&ctx, leaf, leaf);
    const native_parent = core.vcs.poseidon2_m31_merkle.Poseidon2M31MerkleHasher.hashChildren(.{ .left = native_leaf, .right = native_leaf });
    try digestEqual(&ctx, parent, native_parent);
    const direction = try ctx.algebra().guess(Q.one());
    try Merkle.verifyPath(&ctx, leaf, &.{direction}, &.{leaf}, parent);
    try ctx.setOutputs(&.{parent[0]});
    try ctx.finalize();
    try std.testing.expect(try ctx.isCircuitValid());
    ctx.algebra().value_table.items[direction.idx] = Q.fromU32Unchecked(2, 0, 0, 0);
    try std.testing.expect(!try ctx.isCircuitValid());
}
test "dedicated Poseidon raw-u32 unsafe wrapper cannot hide upper coordinates or wide limbs" {
    for ([_]Q{ Q.fromU32Unchecked(7, 0, 1, 0), Q.fromU32Unchecked(65536, 0, 0, 0), Q.fromU32Unchecked(0, 65536, 0, 0) }) |value| {
        var ctx = try Context.init(a, 1);
        defer ctx.deinit();
        var channel = try Channel.ForContext(Context, 8).init(&ctx);
        const bad = try ctx.algebra().guess(value);
        try channel.mixU32s(&ctx, &.{.newUnsafe(bad)});
        try ctx.setOutputs(&.{channel.digest[0]});
        try ctx.finalize();
        try std.testing.expect(!try ctx.isCircuitValid());
    }
}

test "dedicated Poseidon exact padded leaf census includes all five components" {
    for ([_]usize{ 0, 9, 18, 52, 128, 304, 479 }) |count| {
        var ctx = try Context.init(a, 1);
        defer ctx.deinit();
        const values = try a.alloc(M, count);
        defer a.free(values);
        const wires = try a.alloc(B.Var, count);
        defer a.free(wires);
        for (values, wires, 0..) |*value, *wire, i| {
            value.* = M.fromCanonical(@intCast(i * 97 + 3));
            wire.* = try ctx.algebra().guess(Q.fromBase(value.*));
        }
        const digest = try Merkle.leaf(&ctx, wires);
        try digestEqual(&ctx, digest, core.vcs.poseidon2_m31_merkle.Poseidon2M31MerkleHasher.hashNode(null, values));
        try ctx.setOutputs(&.{digest[0]});
        try ctx.finalize();
        try std.testing.expect(try ctx.isCircuitValid());
        const encoded = try std.json.Stringify.valueAlloc(a, .{ .kind = "leaf", .words = count, .permutations = ctx.calls.items.len, .raw_counts = try ctx.rawCounts(), .classic = try ctx.census(false), .gkr = try ctx.census(true) }, .{});
        defer a.free(encoded);
        std.debug.print("P2_DEDICATED_CENSUS {s}\n", .{encoded});
    }
}
