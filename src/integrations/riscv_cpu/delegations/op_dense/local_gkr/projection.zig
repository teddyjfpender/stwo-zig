//! Source terminal projections for independently sized arithmetic and BYTE
//! provider components. The two instances share beta and close together.
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
    instance: N.Instance,
    weights: []Q,
    point: MP.MleEvalPointFor(Q),
    beta: Q,
    eta: Q,
    target: Q,
    pub fn init(a: std.mem.Allocator, log: u32, index: usize, artifact: *const N.GV.GkrArtifact, beta: Q, eta: Q) !Data {
        try N.validateArtifact(log, artifact);
        const ii = try N.instances(log);
        if (index >= ii.len) return error.DenseProjectionShape;
        const instance = ii[index];
        const vars = try instance.variables();
        const local = artifact.ood_point[artifact.ood_point.len - vars ..];
        const weights = try @import("../../../poseidon2_outer/truth_local_gkr/projection.zig").laneWeightsFor(Q, a, local[instance.row_log..]);
        errdefer a.free(weights);
        const claims = artifact.claims_to_verify_by_instance[index];
        return .{ .allocator = a, .instance = instance, .weights = weights, .point = try MP.MleEvalPointFor(Q).init(local[0..instance.row_log]), .beta = beta, .eta = eta, .target = claims[0].add(eta.mul(claims[1])).mulM31(try M.fromCanonical(@intCast(instance.rows())).inv()) };
    }
    pub fn deinit(self: *Data) void {
        self.allocator.free(self.weights);
        self.* = undefined;
    }
};
pub fn evaluate(comptime kind: D.spec.Kind, comptime role: N.Role, comptime F: type, v: anytype, beta: Q, weights: []const Q) !struct { E.SecureFor(F), E.SecureFor(F) } {
    if (weights.len != @as(usize, if (role == .arithmetic) 512 else 1)) return error.DenseProjectionShape;
    var n = E.SecureFor(F).zero();
    var d = E.SecureFor(F).zero();
    for (weights, 0..) |weight, index| {
        const pair = if (role == .arithmetic) D.fixture_component.rangeFraction(kind, F, v, beta, index) else .{ v.main(0).neg(), E.splatFor(F, beta).sub(E.liftFor(F, v.fixed(0))) };
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
pub fn witness(comptime kind: D.spec.Kind, comptime log: u32, a: std.mem.Allocator, trace: *const D.fixture_trace.TraceForLog(kind, log), table: []const M, data: *const Data) ![]M {
    const rows = data.instance.rows();
    const out = try a.alloc(M, 16 * rows);
    errdefer a.free(out);
    try Shared.eqInto(out, rows, data.point.p[0..data.point.n]);
    const reader = N.Reader(kind, log){ .trace = trace, .table = table, .beta = data.beta, .instance = data.instance };
    const source = reader.source();
    for (0..rows) |p| {
        var n: [512]M = undefined;
        var d: [512]Q = undefined;
        const lanes = data.instance.lanes();
        try source.read_fn(source.context, p * lanes, n[0..lanes], d[0..lanes]);
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
/// Move histogram ownership into an independently committed log8 MAIN column;
/// the obsolete embedded provider column is constrained zero in arithmetic AIR.
pub fn splitProvider(comptime kind: D.spec.Kind, comptime log: u32, a: std.mem.Allocator, trace: *D.fixture_trace.TraceForLog(kind, log)) ![]M {
    const rows = @as(usize, 1) << log;
    const out = try a.alloc(M, 256);
    const offset = D.row.Layout(kind).MULT * rows;
    for (0..256) |i| out[A.memory.closed_ram.trace.physical(i, 8)] = trace.main[offset + A.memory.closed_ram.trace.physical(i, log)];
    @memset(trace.main[offset..][0..rows], M.zero());
    return out;
}
pub fn tableFixed(a: std.mem.Allocator) ![]M {
    const out = try a.alloc(M, 256);
    for (0..256) |i| out[A.memory.closed_ram.trace.physical(i, 8)] = M.fromCanonical(@intCast(i));
    return out;
}
/// The public output debt stays classic and independent of the BYTE child.
pub fn globalWitness(comptime kind: D.spec.Kind, comptime log: u32, a: std.mem.Allocator, trace: *const D.fixture_trace.TraceForLog(kind, log), wire: A.crypto.curves.equations.WireFor(Q), expected: [12]u256) !struct { columns: []M, claim: Q } {
    const rows = @as(usize, 1) << log;
    const ch = D.fixture_component.Challenges{ .byte = Q.zero(), .wire = wire };
    const claim = try D.fixture_trace.TraceForLog(kind, log).expectedClaim(ch, expected);
    const shift = claim.mulM31(try M.fromCanonical(@intCast(rows)).inv());
    const out = try a.alloc(M, 8 * rows);
    errdefer a.free(out);
    var prefix = Q.zero();
    for (0..rows) |logical| {
        const v = trace.view(logical);
        prefix = prefix.add(v.main(0).mul(try D.fixture_component.outputDenominator(kind, Q, &v, ch).inv())).sub(shift);
        set(out, rows, 0, A.memory.closed_ram.trace.physical(logical, log), prefix);
    }
    if (!prefix.isZero()) return error.DenseOutputDebtNotClosed;
    return .{ .columns = out, .claim = claim };
}
