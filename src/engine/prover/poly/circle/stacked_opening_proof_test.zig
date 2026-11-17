//! Small authenticated PCS fixture. The receiver owns the mask, layout,
//! security parameters and query schedule. No Ethereum protocol uses this ID.
const std = @import("std");
const core = @import("stwo_core");
const stack = @import("stacked_opening.zig");
const Poly = @import("poly.zig").CircleCoefficients;
const Base = core.fields.m31.M31;
const Secure = core.fields.om31.OM31;
const Point = core.circle.CirclePoint(Secure);
const Channel = core.channel.raw_mod_m31.Om31Channel;
const Hash = core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleHasher;
const Host = @import("../../pcs/commitment_tree.zig").HostMerkleBackend;
const Tree = Host.MerkleTree(Hash);
const TreeVerifier = core.vcs_lifted.verifier.MerkleVerifierLifted(Hash);
const FRI = core.fri.ForField(Secure);
const Mix = struct {
    pub fn mixRoot(channel: *Channel, root: Hash.Hash) void {
        core.vcs_lifted.blake2_merkle.Blake2sPlainMerkleChannel.mixRoot(&channel.inner, root);
    }
};
const Prover = @import("../../fri_family.zig").ForField(Secure).FriProver(Host, Hash, Mix);
const Verifier = FRI.FriVerifier(Hash, Mix);
const Column = @import("../../secure_column.zig").SecureColumnByCoordsFor(Secure);
const alloc = std.testing.allocator;
const width = 4;
const rows = 16;
const degree_log = 6;
const domain_log = 8;
const domain = core.poly.circle.canonic.CanonicCoset.new(domain_log).circleDomain();
const Samples = [2][width]Secure;

fn config() core.fri.FriConfig {
    var c = core.fri.FriConfig.init(0, 2, 15) catch unreachable;
    c.fold_step = 4;
    return c;
}

fn start(channel: *Channel, root: Hash.Hash) ![2]Point {
    channel.mixU32s(&.{ 0x53544b50, width, rows, domain_log, 0, 1 });
    Mix.mixRoot(channel, root);
    const z = try core.circle.randomSecureFieldPointFor(Secure, channel);
    const step = core.poly.circle.canonic.CanonicCoset.new(4).step();
    return .{ z, z.add(.{ .x = Secure.fromBase(step.x), .y = Secure.fromBase(step.y) }) };
}

fn weights(channel: *Channel, samples: *const Samples) [3]Secure {
    for (samples) |mask| channel.mixFelts(&mask);
    return .{ channel.drawSecureFelt(), channel.drawSecureFelt(), channel.drawSecureFelt() };
}

fn answer(i: usize, opened: Base, sibling: Base, z: [2]Point, samples: *const Samples, alpha: [3]Secure) !Secure {
    const w = domain.at(core.utils.bitReverseIndex(i, domain_log));
    var sum = alpha[0].mulM31(opened);
    for (z, samples, alpha[1..]) |point, mask, coefficient| {
        sum = sum.add(coefficient.mul(try stack.quotient(w, opened, sibling, point, &mask)));
    }
    return sum;
}

fn pairs(queries: []const usize, out: *[2 * 15]usize) []const usize {
    var n: usize = 0;
    for (queries) |i| {
        const first = i & ~@as(usize, 1);
        if (n != 0 and out[n - 2] == first) continue;
        out[n..][0..2].* = .{ first, first + 1 };
        n += 2;
    }
    return out[0..n];
}

const Opening = Tree.DecommitmentResult;
const Proof = FRI.FriProof(Hash);
fn receive(root: Hash.Hash, samples: *const Samples, opening: *const Opening, proof: Proof) !void {
    var channel = Channel.init();
    const z = try start(&channel, root);
    const alpha = weights(&channel, samples);
    var verifier = try Verifier.commit(alloc, &channel, config(), proof, FRI.CirclePolyDegreeBound.init(degree_log));
    defer verifier.deinit(alloc);
    const queries = try verifier.sampleQueryPositions(alloc, &channel);
    defer alloc.free(queries);
    var positions: [30]usize = undefined;
    const both = pairs(queries, &positions);
    var auth = try TreeVerifier.init(alloc, root, &.{domain_log});
    defer auth.deinit(alloc);
    try auth.verify(alloc, both, opening.queried_values, opening.decommitment.decommitment);

    const payload = opening.queried_values[0];
    var answers: [15]Secure = undefined;
    var at: usize = 0;
    for (queries, 0..) |i, j| {
        while (both[at] != i) at += 1;
        answers[j] = try answer(i, payload[at], payload[at ^ 1], z, samples, alpha);
    }
    try verifier.decommit(alloc, answers[0..queries.len]);
}

test "stacked Circle opening authenticates both siblings and verifies a two-mask OM31 FRI proof" {
    var columns: [width][rows]Base = undefined;
    for (&columns, 0..) |*c, j| for (c, 0..) |*v, i| {
        v.* = Base.fromU64((j + 13) * (i + 5) * (i + 101) + 311 * j * j);
    };
    var coefficients: [width * rows]Base = undefined;
    try stack.pack(std.mem.bytesAsSlice(Base, std.mem.asBytes(&columns)), width, &coefficients);
    const packed_poly = try Poly.initBorrowed(&coefficients);
    var trace: [1 << domain_log]Base = undefined;
    for (&trace, 0..) |*v, i| {
        const p = domain.at(core.utils.bitReverseIndex(i, domain_log));
        v.* = packed_poly.evalAtPointFor(Secure, .{ .x = Secure.fromBase(p.x), .y = Secure.fromBase(p.y) }).toM31Array()[0];
    }
    var tree = try Tree.commit(alloc, &.{&trace});
    defer tree.deinit(alloc);
    var channel = Channel.init();
    const z = try start(&channel, tree.root());
    var samples: Samples = undefined;
    for (z, &samples) |p, *mask| for (columns, mask) |col, *sample| {
        sample.* = (try Poly.initBorrowed(&col)).evalAtPointFor(Secure, p);
    };
    const alpha = weights(&channel, &samples);
    var values = try Column.uninitialized(alloc, trace.len);
    var owns_values = true;
    defer if (owns_values) values.deinit(alloc);
    for (trace, 0..) |opened, i| values.set(i, try answer(i, opened, trace[i ^ 1], z, &samples, alpha));
    owns_values = false; // commit takes ownership, including on errors.
    const prover = try Prover.commit(alloc, &channel, config(), domain, values);
    var result = try prover.decommit(alloc, &channel);
    defer result.deinit(alloc);
    var positions: [30]usize = undefined;
    var opening = try tree.decommit(alloc, pairs(result.query_positions, &positions), &.{&trace});
    defer opening.deinit(alloc);
    try receive(tree.root(), &samples, &opening, result.fri_proof.proof);

    const index = if (result.query_positions[0] & 1 == 0) @as(usize, 1) else 0;
    const word = &opening.queried_values[0][index];
    const saved = word.*;
    word.* = saved.add(Base.one());
    try std.testing.expectError(error.RootMismatch, receive(tree.root(), &samples, &opening, result.fri_proof.proof));
    word.* = saved;
    // Changing the shifted mask changes the Fiat-Shamir query set.
    samples[1][2] = samples[1][2].add(Secure.one());
    try std.testing.expectError(error.InvalidQueryShape, receive(tree.root(), &samples, &opening, result.fri_proof.proof));
    samples[1][2] = samples[1][2].sub(Secure.one());
    // Mutate an unqueried FRI witness under the original transcript. The trace
    // authentication still succeeds, so the FRI verifier must reject it.
    const witness = &result.fri_proof.proof.first_layer.fri_witness[0];
    witness.* = witness.add(Secure.one());
    try std.testing.expectError(error.FirstLayerCommitmentInvalid, receive(tree.root(), &samples, &opening, result.fri_proof.proof));
}
