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
const groups = 3;
const Samples = [2][groups * width]Secure;
const Weights = [3][groups]Secure;
const Row = [groups]Base;

fn config() core.fri.FriConfig {
    var c = core.fri.FriConfig.init(0, 2, 15) catch unreachable;
    c.fold_step = 4;
    return c;
}

fn start(channel: *Channel, root: Hash.Hash) ![2]Point {
    channel.mixU32s(&.{ 0x53544b50, groups, width, rows, domain_log, 0, 1 });
    Mix.mixRoot(channel, root);
    const z = try core.circle.randomSecureFieldPointFor(Secure, channel);
    const step = core.poly.circle.canonic.CanonicCoset.new(4).step();
    return .{ z, z.add(.{ .x = Secure.fromBase(step.x), .y = Secure.fromBase(step.y) }) };
}

fn weights(channel: *Channel, samples: *const Samples) Weights {
    for (samples) |mask| channel.mixFelts(&mask);
    var result: Weights = undefined;
    for (&result) |*stage| for (stage) |*alpha| {
        alpha.* = channel.drawSecureFelt();
    };
    return result;
}

fn rawAnswer(opened: Row, alpha: [groups]Secure) Secure {
    var sum = Secure.zero();
    for (opened, alpha) |v, weight| sum = sum.add(weight.mulM31(v));
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
    var auth = try TreeVerifier.init(alloc, root, &([_]u32{domain_log} ** groups));
    defer auth.deinit(alloc);
    try auth.verify(alloc, both, opening.queried_values, opening.decommitment.decommitment);

    var first = try stack.Batch.init(alloc, width, &alpha[1], z[0], &samples[0]);
    defer first.deinit(alloc);
    var second = try stack.Batch.init(alloc, width, &alpha[2], z[1], &samples[1]);
    defer second.deinit(alloc);
    var answers: [15]Secure = undefined;
    var at: usize = 0;
    for (queries, 0..) |i, j| {
        while (both[at] != i) at += 1;
        var opened: Row = undefined;
        var sibling: Row = undefined;
        for (opening.queried_values, &opened, &sibling) |payload, *v, *s| {
            v.* = payload[at];
            s.* = payload[at ^ 1];
        }
        const w = domain.at(core.utils.bitReverseIndex(i, domain_log));
        answers[j] = rawAnswer(opened, alpha[0]).add(try first.answer(w, &opened, &sibling)).add(try second.answer(w, &opened, &sibling));
    }
    try verifier.decommit(alloc, answers[0..queries.len]);
}

test "stacked Circle opening authenticates both siblings and verifies a two-mask OM31 FRI proof" {
    var columns: [groups * width][rows]Base = undefined;
    for (&columns, 0..) |*c, j| for (c, 0..) |*v, i| {
        v.* = Base.fromU64((j + 13) * (i + 5) * (i + 101) + 311 * j * j);
    };
    var traces: [groups][1 << domain_log]Base = undefined;
    var trace_columns: [groups][]const Base = undefined;
    for (&traces, &trace_columns, 0..) |*trace, *column, g| {
        var coefficients: [width * rows]Base = undefined;
        try stack.pack(std.mem.bytesAsSlice(Base, std.mem.sliceAsBytes(columns[g * width ..][0..width])), width, &coefficients);
        const packed_poly = try Poly.initBorrowed(&coefficients);
        for (trace, 0..) |*v, i| {
            const p = domain.at(core.utils.bitReverseIndex(i, domain_log));
            v.* = packed_poly.evalAtPointFor(Secure, .{ .x = Secure.fromBase(p.x), .y = Secure.fromBase(p.y) }).toM31Array()[0];
        }
        column.* = trace;
    }
    var tree = try Tree.commit(alloc, &trace_columns);
    defer tree.deinit(alloc);
    var channel = Channel.init();
    const z = try start(&channel, tree.root());
    var samples: Samples = undefined;
    for (z, &samples) |p, *mask| for (columns, mask) |col, *sample| {
        sample.* = (try Poly.initBorrowed(&col)).evalAtPointFor(Secure, p);
    };
    const alpha = weights(&channel, &samples);
    var values = try Column.uninitialized(alloc, traces[0].len);
    var owns_values = true;
    defer if (owns_values) values.deinit(alloc);
    // Use separate group equations on the prover and the shared projection on the receiver.
    for (0..traces[0].len) |i| {
        const w = domain.at(core.utils.bitReverseIndex(i, domain_log));
        var answer = Secure.zero();
        for (trace_columns, 0..) |trace, g| {
            answer = answer.add(alpha[0][g].mulM31(trace[i]));
            for (z, samples, alpha[1..]) |point, mask, coefficient| {
                answer = answer.add(coefficient[g].mul(try stack.quotient(w, trace[i], trace[i ^ 1], point, mask[g * width ..][0..width])));
            }
        }
        values.set(i, answer);
    }
    owns_values = false; // commit takes ownership, including on errors.
    const prover = try Prover.commit(alloc, &channel, config(), domain, values);
    var result = try prover.decommit(alloc, &channel);
    defer result.deinit(alloc);
    var positions: [30]usize = undefined;
    var opening = try tree.decommit(alloc, pairs(result.query_positions, &positions), &trace_columns);
    defer opening.deinit(alloc);
    try receive(tree.root(), &samples, &opening, result.fri_proof.proof);

    const index = if (result.query_positions[0] & 1 == 0) @as(usize, 1) else 0;
    const word = &opening.queried_values[groups - 1][index];
    const saved = word.*;
    word.* = saved.add(Base.one());
    try std.testing.expectError(error.RootMismatch, receive(tree.root(), &samples, &opening, result.fri_proof.proof));
    word.* = saved;
    // Changing the shifted mask changes the Fiat-Shamir query set.
    samples[1][width + 2] = samples[1][width + 2].add(Secure.one());
    try std.testing.expectError(error.InvalidQueryShape, receive(tree.root(), &samples, &opening, result.fri_proof.proof));
    samples[1][width + 2] = samples[1][width + 2].sub(Secure.one());
    // Mutate an unqueried FRI witness under the original transcript. The trace
    // authentication still succeeds, so the FRI verifier must reject it.
    const witness = &result.fri_proof.proof.first_layer.fri_witness[0];
    witness.* = witness.add(Secure.one());
    try std.testing.expectError(error.FirstLayerCommitmentInvalid, receive(tree.root(), &samples, &opening, result.fri_proof.proof));
}
