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
const direct_log = domain_log - 2;
const direct_domain = core.poly.circle.canonic.CanonicCoset.new(direct_log).circleDomain();
const Samples = [2][groups * width]Secure;
const Weights = [3][groups]Secure;
const Row = [groups]Base;

fn config() core.fri.FriConfig {
    var c = core.fri.FriConfig.init(0, 2, 15) catch unreachable;
    c.fold_step = 4;
    return c;
}

fn start(channel: *Channel, roots: [2]Hash.Hash) ![2]Point {
    channel.mixU32s(&.{ 0x53544b50, groups, width, rows, domain_log, direct_log, 0, 1 });
    for (roots) |root| Mix.mixRoot(channel, root);
    const z = try core.circle.randomSecureFieldPointFor(Secure, channel);
    const step = core.poly.circle.canonic.CanonicCoset.new(4).step();
    return .{ z, z.add(.{ .x = Secure.fromBase(step.x), .y = Secure.fromBase(step.y) }) };
}

fn weights(channel: *Channel, samples: *const Samples, direct_sample: Secure) Weights {
    for (samples) |mask| channel.mixFelts(&mask);
    channel.mixFelts(&.{direct_sample});
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
fn directPositions(queries: []const usize) ![]usize {
    const projected = try core.pcs.utils.prepareTreeQueryPositions(alloc, queries, domain_log, direct_log);
    defer alloc.free(projected);
    return core.queries.sortedUniquePositions(alloc, projected);
}

fn receive(roots: [2]Hash.Hash, samples: *const Samples, direct_sample: Secure, opening: *const Opening, direct_opening: *const Opening, proof: Proof) !void {
    var channel = Channel.init();
    const z = try start(&channel, roots);
    const alpha = weights(&channel, samples, direct_sample);
    const direct_raw = channel.drawSecureFelt();
    const direct_deep = channel.drawSecureFelt();
    var verifier = try Verifier.commit(alloc, &channel, config(), proof, FRI.CirclePolyDegreeBound.init(degree_log));
    defer verifier.deinit(alloc);
    const queries = try verifier.sampleQueryPositions(alloc, &channel);
    defer alloc.free(queries);
    var positions: [30]usize = undefined;
    const both = pairs(queries, &positions);
    var auth = try TreeVerifier.init(alloc, roots[0], &([_]u32{domain_log} ** groups));
    defer auth.deinit(alloc);
    try auth.verify(alloc, both, opening.queried_values, opening.decommitment.decommitment);

    const direct_indices = try directPositions(queries);
    defer alloc.free(direct_indices);
    var direct_auth = try TreeVerifier.init(alloc, roots[1], &.{direct_log});
    defer direct_auth.deinit(alloc);
    try direct_auth.verify(alloc, direct_indices, direct_opening.queried_values, direct_opening.decommitment.decommitment);
    var direct = try stack.Batch.init(alloc, 1, &.{direct_deep}, z[0], &.{direct_sample});
    defer direct.deinit(alloc);

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
        const small_index = (i >> (domain_log - direct_log + 1) << 1) | (i & 1);
        const index = std.mem.indexOfScalar(usize, direct_indices, small_index) orelse return error.InvalidQueryShape;
        const small = direct_opening.queried_values[0][index];
        answers[j] = answers[j].add(direct_raw.mulM31(small)).add(try direct.answer(w.repeatedDouble(domain_log - direct_log), &.{small}, &.{small}));
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
    // A separate direct tree uses the shorter source domain and one OODS mask.
    var coefficients: [rows]Base = undefined;
    for (&coefficients, 0..) |*v, i| v.* = Base.fromU64(23 * i * i + 101);
    const direct_poly = try Poly.initBorrowed(&coefficients);
    var small_trace: [1 << direct_log]Base = undefined;
    for (&small_trace, 0..) |*v, i| {
        const w = direct_domain.at(core.utils.bitReverseIndex(i, direct_log));
        v.* = direct_poly.evalAtPointFor(Secure, .{ .x = Secure.fromBase(w.x), .y = Secure.fromBase(w.y) }).toM31Array()[0];
    }
    var small_tree = try Tree.commit(alloc, &.{&small_trace});
    defer small_tree.deinit(alloc);
    const roots = [2]Hash.Hash{ tree.root(), small_tree.root() };
    var channel = Channel.init();
    const z = try start(&channel, roots);
    var samples: Samples = undefined;
    for (z, &samples) |p, *mask| for (columns, mask) |col, *sample| {
        sample.* = (try Poly.initBorrowed(&col)).evalAtPointFor(Secure, p);
    };
    const direct_sample = direct_poly.evalAtPointFor(Secure, z[0]);
    const alpha = weights(&channel, &samples, direct_sample);
    const direct_raw = channel.drawSecureFelt();
    const direct_deep = channel.drawSecureFelt();
    const line = try core.constraints.quadraticConjugateLineCoeffs(Secure, z[0], direct_sample, direct_deep);
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
        const index = (i >> (domain_log - direct_log + 1) << 1) | (i & 1);
        const p = direct_domain.at(core.utils.bitReverseIndex(index, direct_log));
        try std.testing.expectEqual(p, w.repeatedDouble(domain_log - direct_log));
        const v = small_trace[index];
        const d = core.constraints.quadraticLineDenominator(Secure, z[0], p);
        const q = line.c.mulM31(v).sub(line.a.mulM31(p.y)).sub(line.b).mulInner(try d.inv());
        values.set(i, answer.add(q).add(direct_raw.mulM31(v)));
    }
    owns_values = false; // commit takes ownership, including on errors.
    const prover = try Prover.commit(alloc, &channel, config(), domain, values);
    var result = try prover.decommit(alloc, &channel);
    defer result.deinit(alloc);
    var positions: [30]usize = undefined;
    var opening = try tree.decommit(alloc, pairs(result.query_positions, &positions), &trace_columns);
    defer opening.deinit(alloc);
    const direct_indices = try directPositions(result.query_positions);
    defer alloc.free(direct_indices);
    var direct_opening = try small_tree.decommit(alloc, direct_indices, &.{&small_trace});
    defer direct_opening.deinit(alloc);
    try receive(roots, &samples, direct_sample, &opening, &direct_opening, result.fri_proof.proof);

    const small_word = &direct_opening.queried_values[0][0];
    small_word.* = small_word.add(Base.one());
    try std.testing.expectError(error.RootMismatch, receive(roots, &samples, direct_sample, &opening, &direct_opening, result.fri_proof.proof));
    small_word.* = small_word.sub(Base.one());

    const index = if (result.query_positions[0] & 1 == 0) @as(usize, 1) else 0;
    const word = &opening.queried_values[groups - 1][index];
    const saved = word.*;
    word.* = saved.add(Base.one());
    try std.testing.expectError(error.RootMismatch, receive(roots, &samples, direct_sample, &opening, &direct_opening, result.fri_proof.proof));
    word.* = saved;
    // Changing the shifted mask changes the Fiat-Shamir query set.
    samples[1][width + 2] = samples[1][width + 2].add(Secure.one());
    try std.testing.expectError(error.InvalidQueryShape, receive(roots, &samples, direct_sample, &opening, &direct_opening, result.fri_proof.proof));
    samples[1][width + 2] = samples[1][width + 2].sub(Secure.one());
    // Mutate an unqueried FRI witness under the original transcript. The trace
    // authentication still succeeds, so the FRI verifier must reject it.
    const witness = &result.fri_proof.proof.first_layer.fri_witness[0];
    witness.* = witness.add(Secure.one());
    try std.testing.expectError(error.FirstLayerCommitmentInvalid, receive(roots, &samples, direct_sample, &opening, &direct_opening, result.fri_proof.proof));
}
