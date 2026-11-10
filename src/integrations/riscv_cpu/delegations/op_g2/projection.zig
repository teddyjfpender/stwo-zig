//! Source-derived BYTE and SSA terminal projections for the closed two-op DAG.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const D = A.crypto.bn254_dense;
const G = A.crypto.bn254_g2;
const S = G.spec;
const E = A.evaluation;
const N = @import("native.zig");
const Q = N.Q;
const M = N.M;
pub const MP = @import("../../logup_gkr/mle_point.zig");
const C = G.fixture;
const Shared = @import("../../word16_global_execution/services/gkr_local/witness.zig");
pub const Data = struct {
    allocator: std.mem.Allocator,
    instance: N.Instance,
    weights: []Q,
    point: MP.MleEvalPointFor(Q),
    beta: Q,
    ssa: C.Wire,
    eta: Q,
    target: Q,
    pub fn init(a: std.mem.Allocator, index: usize, artifact: *const N.GV.GkrArtifact, beta: Q, ssa: C.Wire, eta: Q) !Data {
        try N.validateArtifact(artifact);
        const ii = N.INSTANCES;
        if (index >= ii.len) return error.DenseProjectionShape;
        const instance = ii[index];
        const vars = try instance.variables();
        const local = artifact.ood_point[artifact.ood_point.len - vars ..];
        const weights = try @import("../../poseidon2_outer/truth_local_gkr/projection.zig").laneWeightsFor(Q, a, local[instance.row_log..]);
        errdefer a.free(weights);
        const claims = artifact.claims_to_verify_by_instance[index];
        return .{ .allocator = a, .instance = instance, .weights = weights, .point = try MP.MleEvalPointFor(Q).init(local[0..instance.row_log]), .beta = beta, .ssa = ssa, .eta = eta, .target = claims[0].add(eta.mul(claims[1])).mulM31(try M.fromCanonical(@intCast(instance.rows())).inv()) };
    }
    pub fn deinit(self: *Data) void {
        self.allocator.free(self.weights);
        self.* = undefined;
    }
};
pub fn evaluate(comptime kind: S.Kind, comptime F: type, v: anytype, data: *const Data) !struct { E.SecureFor(F), E.SecureFor(F) } {
    if (data.weights.len != data.instance.lanes()) return error.DenseSsaProjection;
    var n = E.SecureFor(F).zero();
    var d = E.SecureFor(F).zero();
    for (data.weights, 0..) |weight, lane| {
        const pair = if (data.instance.family == .bytes) switch (data.instance.role) {
            .arithmetic => C.byteFraction(kind, .arithmetic, F, v, data.beta, lane),
            .table => C.byteFraction(kind, .table, F, v, data.beta, lane),
            else => return error.G2ProjectionShape,
        } else switch (data.instance.role) {
            .arithmetic => C.ssaFraction(kind, .arithmetic, F, v, data.ssa, lane),
            .frontier => C.ssaFraction(kind, .frontier, F, v, data.ssa, lane),
            else => return error.G2ProjectionShape,
        };
        const w = E.splatFor(F, weight);
        n = n.add(E.mulBaseFor(F, w, pair[0]));
        d = d.add(w.mul(pair[1]));
    }
    return .{ n, d };
}
fn get(data: []const M, rows: usize, start: usize, p: usize) Q {
    var c: [8]M = undefined;
    for (&c, 0..) |*v, i| v.* = data[(start + i) * rows + p];
    return Q.fromM31Array(c);
}
fn set(data: []M, rows: usize, start: usize, p: usize, value: Q) void {
    for (value.toM31Array(), 0..) |v, i| data[(start + i) * rows + p] = v;
}
pub fn witness(comptime kind: S.Kind, a: std.mem.Allocator, source: *const C.Model(kind), data: *const Data) ![]M {
    const rows = data.instance.rows();
    const out = try a.alloc(M, 16 * rows);
    errdefer a.free(out);
    try Shared.eqInto(out, rows, data.point.p[0..data.point.n]);
    const reader = N.Reader(kind){ .witness = source, .instance = data.instance, .beta = data.beta, .ssa = data.ssa };
    const input = reader.source();
    for (0..rows) |p| {
        var n: [512]M = undefined;
        var d: [512]Q = undefined;
        const lanes = data.instance.lanes();
        try input.read_fn(input.context, p * lanes, n[0..lanes], d[0..lanes]);
        var pn = Q.zero();
        var pd = Q.zero();
        for (data.weights, n[0..lanes], d[0..lanes]) |weight, nn, dd| {
            pn = pn.add(weight.mulM31(nn));
            pd = pd.add(weight.mul(dd));
        }
        set(out, rows, 8, p, get(out, rows, 0, p).mul(pn.add(data.eta.mul(pd))).sub(data.target));
    }
    try Shared.prefixProjectedWithOptions(out, rows, data.instance.row_log, .{});
    return out;
}
