//! Eq and N+eta*D prefix witness in16 column-major base planes. Constructed
//! before raw GKR inputs are released; no second metadata replay or FFT.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const V = engine.lookups.gkr_verifier.ForField(O);
const Frame = @import("frame.zig");
const Input = @import("inputs.zig").Inputs;
fn get(data: []const M, rows: usize, offset: usize, p: usize) O {
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*v, i| v.* = data[(offset + i) * rows + p];
    return O.fromM31Array(coordinates);
}
fn set(data: []M, rows: usize, offset: usize, p: usize, value: O) void {
    for (value.toM31Array(), 0..) |v, i| data[(offset + i) * rows + p] = v;
}
pub fn eqInto(data: []M, rows: usize, point: []const O) !void {
    if (data.len < 8 * rows or rows != @as(usize, 1) << @intCast(point.len)) return error.LocalGkrEqShape;
    set(data, rows, 0, 0, O.one());
    var len: usize = 1;
    for (point) |r| {
        var i = len;
        while (i > 0) {
            i -= 1;
            const value = get(data, rows, 0, i);
            set(data, rows, 0, 2 * i + 1, value.mul(r));
            set(data, rows, 0, 2 * i, value.mul(O.one().sub(r)));
        }
        len *= 2;
    }
}
pub const Witness = struct {
    allocator: std.mem.Allocator,
    columns: [][]M,
    pub fn init(a: std.mem.Allocator, instances: []const Frame.Instance, inputs: *const Input, artifact: *const V.GkrArtifact, eta: O) !Witness {
        if (instances.len != inputs.layers.len or instances.len != artifact.claims_to_verify_by_instance.len) return error.LocalGkrProjectionShape;
        const out = try a.alloc([]M, instances.len);
        var done: usize = 0;
        errdefer {
            for (out[0..done]) |v| a.free(v);
            a.free(out);
        }
        for (instances, inputs.layers, artifact.claims_to_verify_by_instance, 0..) |instance, layer, claims, index| {
            if (claims.len != 2 or layer != .LogUpMultiplicities) return error.LocalGkrProjectionShape;
            const point = try Frame.splitPoint(instance, artifact.ood_point, artifact.n_variables_by_instance[index]);
            const rows = try instance.rows();
            const lanes: usize = @as(usize, 1) << @intCast(try instance.laneLog());
            const data = try a.alloc(M, try std.math.mul(usize, rows, 16));
            errdefer a.free(data);
            try eqInto(data, rows, point.rows);
            var lane_planes: [8 * 128]M = undefined;
            try eqInto(lane_planes[0 .. 8 * lanes], lanes, point.lanes);
            var lane_weights: [128]O = undefined;
            for (lane_weights[0..lanes], 0..) |*v, i| v.* = get(&lane_planes, lanes, 0, i);
            const target = claims[0].add(eta.mul(claims[1]));
            const uniform = target.mulM31(try M.fromCanonical(@intCast(rows)).inv());
            const vectors = layer.LogUpMultiplicities;
            var prefix = O.zero();
            for (0..rows) |logical| {
                const p = @import("stwo_riscv_frontend").rv64_air.witness.physical(logical, instance.row_log);
                var n = O.zero();
                var d = O.zero();
                for (lane_weights[0..lanes], 0..) |weight, lane| {
                    const at = p * lanes + lane;
                    n = n.add(weight.mulM31(vectors.numerators.evals[at]));
                    d = d.add(weight.mul(vectors.denominators.evals[at]));
                }
                prefix = prefix.add(get(data, rows, 0, p).mul(n.add(eta.mul(d)))).sub(uniform);
                set(data, rows, 8, p, prefix);
            }
            if (!prefix.isZero()) return error.UnboundLocalGkrInput;
            out[index] = data;
            done += 1;
        }
        return .{ .allocator = a, .columns = out };
    }
    pub fn deinit(self: *Witness) void {
        for (self.columns) |v| self.allocator.free(v);
        self.allocator.free(self.columns);
        self.* = undefined;
    }
};
