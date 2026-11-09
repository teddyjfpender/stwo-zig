//! Terminal recipe reuses the exact classic BYTE source emitter, including
//! committed provider multiplicity and padded (0,1) lanes.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const E = A.evaluation;
const N = @import("native.zig");
const Q = N.Q;
const M = N.M;
pub const MP = @import("../../../logup_gkr/mle_point.zig");
const Shared = @import("../../../word16_global_execution/services/gkr_local/witness.zig");
pub const Data = struct {
    allocator: std.mem.Allocator,
    weights: []Q,
    point: MP.MleEvalPointFor(Q),
    beta: Q,
    eta: Q,
    target: Q,
    pub fn init(a: std.mem.Allocator, artifact: *const N.GV.GkrArtifact, beta: Q, eta: Q) !Data {
        try N.validateArtifact(artifact);
        const weights = try @import("../../../poseidon2_outer/truth_local_gkr/projection.zig").laneWeightsFor(Q, a, artifact.ood_point[N.ROW_LOG..]);
        errdefer a.free(weights);
        const claims = artifact.claims_to_verify_by_instance[0];
        return .{ .allocator = a, .weights = weights, .point = try MP.MleEvalPointFor(Q).init(artifact.ood_point[0..N.ROW_LOG]), .beta = beta, .eta = eta, .target = claims[0].add(eta.mul(claims[1])).mulM31(try M.fromCanonical(256).inv()) };
    }
    pub fn deinit(self: *Data) void {
        self.allocator.free(self.weights);
        self.* = undefined;
    }
};
pub fn evaluate(comptime kind: D.spec.Kind, comptime F: type, v: anytype, beta: Q, weights: []const Q) !struct { E.SecureFor(F), E.SecureFor(F) } {
    if (weights.len != N.LANES) return error.DenseProjectionShape;
    var n = E.SecureFor(F).zero();
    var d = E.SecureFor(F).zero();
    for (weights, 0..) |weight, index| {
        const f = D.fixture_component.rangeFraction(kind, F, v, beta, index);
        const w = E.splatFor(F, weight);
        n = n.add(E.mulBaseFor(F, w, f[0]));
        d = d.add(w.mul(f[1]));
    }
    return .{ n, d };
}
fn get(data: []const M, start: usize, p: usize) Q {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = data[(start + i) * 256 + p];
    return Q.fromM31Array(c);
}
fn set(data: []M, start: usize, p: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, i| data[(start + i) * 256 + p] = v;
}
pub fn witness(comptime kind: D.spec.Kind, a: std.mem.Allocator, trace: *const D.fixture_trace.Trace(kind), data: *const Data) ![]M {
    const out = try a.alloc(M, 16 * 256);
    errdefer a.free(out);
    try Shared.eqInto(out, 256, data.point.p[0..data.point.n]);
    const reader = N.Reader(kind){ .trace = trace, .beta = data.beta };
    const source = reader.source();
    for (0..256) |p| {
        var n: [512]M = undefined;
        var d: [512]Q = undefined;
        try source.read_fn(source.context, p * 512, &n, &d);
        var pn = Q.zero();
        var pd = Q.zero();
        for (data.weights, n, d) |weight, nn, dd| {
            pn = pn.add(weight.mulM31(nn));
            pd = pd.add(weight.mul(dd));
        }
        set(out, 8, p, get(out, 0, p).mul(pn.add(data.eta.mul(pd))).sub(data.target));
    }
    try Shared.prefixProjectedWithOptions(out, 256, N.ROW_LOG, .{});
    return out;
}
/// The output debt remains classic and separately transcript-bound; it is not
/// silently closed or absorbed into the BYTE child.
pub fn globalWitness(comptime kind: D.spec.Kind, a: std.mem.Allocator, trace: *const D.fixture_trace.Trace(kind), wire: A.crypto.curves.equations.WireFor(Q), expected: [12]u256) !struct { columns: []M, claim: Q } {
    const ch = D.fixture_component.Challenges{ .byte = Q.zero(), .wire = wire };
    const claim = try D.fixture_trace.Trace(kind).expectedClaim(ch, expected);
    const shift = claim.mulM31(try M.fromCanonical(256).inv());
    const out = try a.alloc(M, 8 * 256);
    errdefer a.free(out);
    var prefix = Q.zero();
    for (0..256) |logical| {
        const v = trace.view(logical);
        const active = v.main(0);
        prefix = prefix.add(active.mul(try D.fixture_component.outputDenominator(kind, Q, &v, ch).inv())).sub(shift);
        const p = A.memory.closed_ram.trace.physical(logical, 8);
        set(out, 0, p, prefix);
    }
    if (!prefix.isZero()) return error.DenseOutputDebtNotClosed;
    return .{ .columns = out, .claim = claim };
}
