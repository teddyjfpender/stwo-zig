//! Source-derived BYTE and SSA terminal projections for the complete finite four-pair DAG.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const G = A.crypto.bn254_pairing_mac12;
const S = G.source;
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
        if (index >= ii.len) return error.PairingMac12ProjectionShape;
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
pub fn evaluate(comptime F: type, v: anytype, data: *const Data) !struct { E.SecureFor(F), E.SecureFor(F) } {
    if (data.weights.len != data.instance.lanes()) return error.PairingMac12SsaProjection;
    var n = E.SecureFor(F).zero();
    var d = E.SecureFor(F).zero();
    for (data.weights, 0..) |weight, lane| {
        const pair = if (data.instance.family == .bytes) switch (data.instance.role) {
            .arithmetic => C.byteFraction(.arithmetic, F, v, data.beta, lane),
            .hints => C.byteFraction(.hints, F, v, data.beta, lane),
            .table => C.byteFraction(.table, F, v, data.beta, lane),
            else => return error.PairingMac12ProjectionShape,
        } else switch (data.instance.role) {
            .arithmetic => C.ssaFraction(.arithmetic, F, v, data.ssa, lane),
            .hints => C.ssaFraction(.hints, F, v, data.ssa, lane),
            .frontier => C.ssaFraction(.frontier, F, v, data.ssa, lane),
            else => return error.PairingMac12ProjectionShape,
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
fn validateWitness(source: *const C.Model, data: *const Data) !void {
    var known = false;
    for (N.INSTANCES) |instance| known = known or std.meta.eql(instance, data.instance);
    if (!known or data.weights.len != data.instance.lanes() or data.point.n != data.instance.row_log) return error.PairingMac12ProjectionShape;
    try source.requireColumns();
}
pub fn witness(a: std.mem.Allocator, source: *const C.Model, data: *const Data) ![]M {
    try validateWitness(source, data);
    const F = E.PackedFields.BaseForField(Q);
    const rows = data.instance.rows();
    const out = try a.alloc(M, 16 * rows);
    errdefer a.free(out);
    try Shared.eqInto(out, rows, data.point.p[0..data.point.n]);
    const PackedView = struct {
        columns: []const M,
        rows: usize,
        start: usize,
        fixed_values: [40]F,
        pub fn main(v: *const @This(), c: usize) F {
            return F.load(v.columns.ptr + c * v.rows + v.start);
        }
        pub fn fixed(v: *const @This(), c: usize) F {
            return v.fixed_values[c];
        }
    };
    const Work = @import("stwo_prover_engine").lookups.row_work;
    const Context = struct {
        source: *const C.Model,
        data: *const Data,
        out: []M,
        rows: usize,
        errors: [Work.MAX_SHARDS]?anyerror = @splat(null),
        pub fn runRange(c: *@This(), index: usize, start: usize, end: usize) void {
            c.calculate(start, end) catch |err| {
                c.errors[index] = err;
            };
        }
        fn calculate(c: *@This(), start: usize, end: usize) !void {
            const role = c.data.instance.role;
            const main = c.source.columns[@intFromEnum(role)].?;
            const fixed_width = switch (role) {
                inline else => |r| C.fixedWidth(r),
            };
            for (start..end) |block| {
                const p = block * E.LANES;
                var v = PackedView{ .columns = main, .rows = c.rows, .start = p, .fixed_values = undefined };
                // The GKR source indexes physical rows. Only FIXED is gathered
                // through the exact inverse used by Native.Reader.read.
                for (v.fixed_values[0..fixed_width], 0..) |*fixed, col| {
                    var values: [E.LANES]M = undefined;
                    for (&values, 0..) |*value, lane| {
                        const logical = core.utils.circleDomainIndexToCosetIndex(core.utils.bitReverseIndex(p + lane, c.data.instance.row_log), c.data.instance.row_log);
                        value.* = c.source.fixed(role, logical, col).toM31Array()[0];
                    }
                    fixed.* = F.fromLanes(values);
                }
                const projected = try evaluate(F, &v, c.data);
                var eq_coordinates: [8]F = undefined;
                for (&eq_coordinates, 0..) |*x, i| x.* = F.load(c.out.ptr + i * c.rows + p);
                const eq = E.secureFromCoordinatesForField(Q, F, eq_coordinates);
                const value = eq.mul(projected[0].add(E.splatFor(F, c.data.eta).mul(projected[1]))).sub(E.splatFor(F, c.data.target));
                for (value.coordinates(), 0..) |coordinate, i| coordinate.store(c.out.ptr + (8 + i) * c.rows + p);
            }
        }
    };
    var context = Context{ .source = source, .data = data, .out = out, .rows = rows };
    const shards = Work.forEachRange(rows / E.LANES, &context, .{ .min_rows_per_shard = 64 });
    for (context.errors[0..shards]) |maybe| if (maybe) |err| return err;
    try Shared.prefixProjectedWithOptions(out, rows, data.instance.row_log, .{});
    return out;
}
/// Exact original reader/dot reduction retained only as an independent numeric
/// oracle. It never selects protocol parameters or derives source authority.
pub fn witnessReferenceForTesting(a: std.mem.Allocator, source: *const C.Model, data: *const Data) ![]M {
    if (!@import("builtin").is_test) @compileError("test-only scalar projection reference");
    try validateWitness(source, data);
    const rows = data.instance.rows();
    const out = try a.alloc(M, 16 * rows);
    errdefer a.free(out);
    try Shared.eqInto(out, rows, data.point.p[0..data.point.n]);
    const reader = N.Reader(){ .witness = source, .instance = data.instance, .beta = data.beta, .ssa = data.ssa };
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
    try Shared.prefixProjectedWithOptions(out, rows, data.instance.row_log, .{ .max_shards = 1 });
    return out;
}
