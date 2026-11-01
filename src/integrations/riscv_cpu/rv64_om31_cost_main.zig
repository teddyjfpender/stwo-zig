//! Isolated arithmetic cost oracle, not a migrated proof/security profile.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const fields = core.fields;
const m31 = fields.m31;
const M = m31.M31;
const Q = fields.qm31.QM31;
const O = fields.om31.OM31;
const PQ = fields.packed_qm31.PackedQM31;
const PO = fields.packed_om31.PackedOM31;
const Lane = @import("rv64_recursion/circuit_lane.zig");
const F = Lane.Lane;
const WireOps = struct {
    pub fn mulByU(x: F) F {
        return x.mul(F.fromQm31(fields.om31.NONRESIDUE));
    }
    pub fn square(x: F) F {
        return x.square();
    }
    pub fn scale(x: F, b: F) F {
        return x.mul(b);
    }
};
const WireO = fields.om31.Quadratic(F, WireOps);
fn randomQ(rng: std.Random) Q {
    var c: [4]M = undefined;
    for (&c) |*v| v.* = M.fromCanonical(rng.int(u32) % m31.Modulus);
    return Q.fromM31Array(c);
}
const Kind = enum { multiply, secure_by_base, inverse };
fn circuitCost(wide: bool, kind: Kind) !struct { arithmetic: circuit.builder.context.GateCounts, gates: circuit.builder.context.GateCounts, stats: circuit.builder.context.Stats, variables: u32, valid: bool } {
    var ctx = try Lane.Context.init(std.heap.smp_allocator, 0);
    defer ctx.deinit();
    var prng = std.Random.DefaultPrng.init(9981);
    const rng = prng.random();
    Lane.begin(&ctx);
    var bound = true;
    defer if (bound) Lane.finish() catch {};
    const a = F.wire(try ctx.guess(randomQ(rng)));
    const b = if (wide or kind == .multiply) F.wire(try ctx.guess(randomQ(rng))) else F.zero();
    const base = if (kind == .secure_by_base) F.wire(try ctx.guessM31(Q.fromBase(M.fromCanonical(1729)))) else F.zero();
    var arithmetic: circuit.builder.context.GateCounts = undefined;
    if (wide) {
        const x = WireO{ .c0 = a, .c1 = b };
        const y = if (kind == .multiply) WireO{ .c0 = F.wire(try ctx.guess(randomQ(rng))), .c1 = F.wire(try ctx.guess(randomQ(rng))) } else WireO.zero();
        const result = switch (kind) {
            .multiply => x.mul(y),
            .secure_by_base => x.mulBase(base),
            .inverse => x.conjugate().mulInner(x.norm().inv()),
        };
        arithmetic = ctx.gate_counts;
        const nx = O{ .c0 = ctx.get(a.v), .c1 = ctx.get(b.v) };
        const ny = O{ .c0 = ctx.get(y.c0.v), .c1 = ctx.get(y.c1.v) };
        const expected = switch (kind) {
            .multiply => nx.mul(ny),
            .secure_by_base => nx.mulBase(M.fromCanonical(1729)),
            .inverse => try nx.inv(),
        };
        try ctx.eq(result.c0.v, try ctx.constant(expected.c0));
        try ctx.eq(result.c1.v, try ctx.constant(expected.c1));
    } else {
        const result = switch (kind) {
            .multiply => a.mul(b),
            .secure_by_base => a.mul(base),
            .inverse => a.inv(),
        };
        arithmetic = ctx.gate_counts;
        const nx = ctx.get(a.v);
        const ny = ctx.get(b.v);
        const expected = switch (kind) {
            .multiply => nx.mul(ny),
            .secure_by_base => nx.mulM31(M.fromCanonical(1729)),
            .inverse => try nx.inv(),
        };
        try ctx.eq(result.v, try ctx.constant(expected));
    }
    bound = false;
    try Lane.finish();
    try ctx.finalize(false);
    return .{ .arithmetic = arithmetic, .gates = ctx.gate_counts, .stats = ctx.stats, .variables = ctx.circuit.n_vars, .valid = try ctx.isCircuitValid() };
}
pub fn main() !void {
    const allocator = std.heap.smp_allocator;
    const args = try std.process.argsAlloc(allocator);
    defer std.process.argsFree(allocator, args);
    const n = if (args.len > 1) try std.fmt.parseUnsigned(usize, args[1], 10) else 65536;
    const repetitions = if (args.len > 2) try std.fmt.parseUnsigned(usize, args[2], 10) else 12;
    if (args.len > 3 or n < 32 or n > 1 << 22 or n % 16 != 0 or repetitions == 0 or repetitions > 100) return error.InvalidBenchmarkSize;
    var prng = std.Random.DefaultPrng.init(0x4f4d3842);
    const rng = prng.random();
    const inputQ = try allocator.alloc(Q, n);
    defer allocator.free(inputQ);
    const inputO = try allocator.alloc(O, n);
    defer allocator.free(inputO);
    const outQ = try allocator.alloc(Q, n);
    defer allocator.free(outQ);
    const outPackedO = try allocator.alloc(O, n);
    defer allocator.free(outPackedO);
    const outO = try allocator.alloc(O, n);
    defer allocator.free(outO);
    const workQ = try allocator.alloc(Q, n);
    defer allocator.free(workQ);
    const scratchO = try allocator.alloc(Q, 2 * n);
    defer allocator.free(scratchO);
    const scales = try allocator.alloc(M, n);
    defer allocator.free(scales);
    const residuals = try allocator.alloc(m31.PackedM31, n / m31.PACK_WIDTH);
    defer allocator.free(residuals);
    for (inputQ, inputO, scales) |*q, *o, *scale| {
        q.* = randomQ(rng);
        o.* = .{ .c0 = q.*, .c1 = randomQ(rng) };
        scale.* = M.fromCanonical(17);
    }
    for (residuals) |*block| for (0..m31.PACK_WIDTH) |i| {
        block.*[i] = rng.int(u32) % m31.Modulus;
    };
    var timer = try std.time.Timer.start();
    var qscalar: u64 = 0;
    var oscalar: u64 = 0;
    var qpacked: u64 = 0;
    var opacked: u64 = 0;
    var qinverse: u64 = 0;
    var oinverse: u64 = 0;
    var opackedinverse: u64 = 0;
    const qcoef = PQ.splat(inputQ[0]);
    const ocoef = fields.packed_om31.splat(inputO[0]);
    var checksumQ = Q.zero();
    var checksumO = O.zero();
    // One warmup, fixed control/candidate order. These isolated exploratory
    // timings are not a controlled whole-prover speedup qualification.
    for (0..repetitions + 1) |iteration| {
        timer.reset();
        var qa = Q.one();
        for (inputQ) |x| qa = qa.mul(x).add(x);
        const qt = timer.read();
        checksumQ = checksumQ.add(qa);
        timer.reset();
        var oa = O.one();
        for (inputO) |x| oa = oa.mul(x).add(x);
        const ot = timer.read();
        checksumO = checksumO.add(oa);
        timer.reset();
        var qp = PQ.zero();
        for (residuals) |x| qp = qp.add(qcoef.mulBase(x));
        const qpt = timer.read();
        std.mem.doNotOptimizeAway(qp);
        timer.reset();
        var op = PO.zero();
        for (residuals) |x| op = op.add(ocoef.mulBase(x));
        const opt = timer.read();
        std.mem.doNotOptimizeAway(op);
        @memcpy(workQ, inputQ);
        timer.reset();
        try fields.qm31_norm_batch.invertScaledOwned(workQ, outQ, scales);
        const qit = timer.read();
        timer.reset();
        try fields.om31.invertScaled(inputO, outO, scratchO, scales);
        const oit = timer.read();
        timer.reset();
        try fields.om31.invertScaledPacked(inputO, outPackedO, scratchO, scales);
        const opit = timer.read();
        if (iteration != 0) {
            qscalar += qt;
            oscalar += ot;
            qpacked += qpt;
            opacked += opt;
            qinverse += qit;
            oinverse += oit;
            opackedinverse += opit;
        }
    }
    for (inputQ, outQ, inputO, outO) |q, qi, o, oi| {
        if (!q.mul(qi).eql(Q.fromBase(M.fromCanonical(17))) or !o.mul(oi).eql(O.fromBase(M.fromCanonical(17)))) return error.InverseMismatch;
    }
    for (inputO, outPackedO) |o, inverse| if (!o.mul(inverse).eql(O.fromBase(M.fromCanonical(17)))) return error.PackedInverseMismatch;
    const report = .{ .schema = "om31-additive-cost-v1", .whole_protocol_128 = false, .production_protocol_changed = false, .rows = n, .repetitions = repetitions, .warmups = 1, .native_simd_rows = m31.PACK_WIDTH, .grouped_rows = 16, .scope = "isolated native primitives and satisfied circuit arithmetic graphs; not whole prover/recursion timing", .scalar_recurrence_ns = .{ .qm31 = qscalar / repetitions, .om31 = oscalar / repetitions }, .packed_constant_secure_coefficient_times_base_ns = .{ .qm31 = qpacked / repetitions, .om31 = opacked / repetitions }, .scaled_batch_inverse_ns = .{ .qm31_optimized_owned = qinverse / repetitions, .om31_bounded_norm_scratch = oinverse / repetitions, .om31_packed_norm_scratch = opackedinverse / repetitions }, .batch_active_bytes_per_element = .{ .qm31_owned = 36, .om31_non_destructive_candidate = 100 }, .secure_bytes = .{ .qm31 = @sizeOf(Q), .om31 = @sizeOf(O) }, .checksums = .{ checksumQ.toM31Array(), checksumO.toM31Array() }, .circuit = .{ .qm31_multiply = try circuitCost(false, .multiply), .om31_multiply = try circuitCost(true, .multiply), .qm31_secure_by_base = try circuitCost(false, .secure_by_base), .om31_secure_by_base = try circuitCost(true, .secure_by_base), .qm31_inverse = try circuitCost(false, .inverse), .om31_inverse = try circuitCost(true, .inverse) } };
    const json = try std.json.Stringify.valueAlloc(allocator, report, .{ .whitespace = .indent_2 });
    defer allocator.free(json);
    try std.fs.File.stdout().writeAll(json);
    try std.fs.File.stdout().writeAll("\n");
}
