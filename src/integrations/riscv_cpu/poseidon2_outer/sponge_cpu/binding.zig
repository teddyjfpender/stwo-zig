//! Existing legacy bindings plus one narrow frontier binding, one source pass.
const std = @import("std");
const core = @import("stwo_core");
const A = @import("stwo_riscv_frontend").rv64_air;
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const Shared = @import("../../word16_global_execution/services/gkr_local/witness.zig");
const Frame = @import("frame.zig");
const Native = @import("native.zig");
const Eq = @import("equations.zig");
const MP = @import("../../logup_gkr/mle_point.zig");
pub const Data = struct {
    point: MP.MleEvalPointFor(O),
    binding: Eq.Binding,
    pub fn init(instance: Frame.Instance, terminal: *const Native.Pending, index: usize) !Data {
        if (instance != .frontier or index >= terminal.artifact.claims_to_verify_by_instance.len) return error.SpongeCpuGeometry;
        const split = try Frame.splitPoint(instance, terminal.artifact.ood_point, terminal.artifact.n_variables_by_instance[index]);
        const claims = terminal.artifact.claims_to_verify_by_instance[index];
        if (claims.len != 2 or split.lanes.len != 2) return error.SpongeCpuGeometry;
        var plane: [32]M = undefined;
        try Shared.eqInto(&plane, 4, split.lanes);
        var weights: [4]O = undefined;
        for (&weights, 0..) |*v, i| v.* = get(&plane, 4, 0, i);
        return .{ .point = try MP.MleEvalPointFor(O).init(split.rows), .binding = .{ .weights = weights, .eta = terminal.eta, .target = claims[0].add(terminal.eta.mul(claims[1])).mulM31(try M.fromCanonical(@intCast(try instance.rows())).inv()) } };
    }
};
pub fn get(data: []const M, rows: usize, start: usize, p: usize) O {
    var values: [8]M = undefined;
    for (&values, 0..) |*v, c| v.* = data[(start + c) * rows + p];
    return O.fromM31Array(values);
}
pub fn set(data: []M, rows: usize, start: usize, p: usize, value: O) void {
    for (value.toM31Array(), 0..) |v, c| data[(start + c) * rows + p] = v;
}
pub const Witness = struct {
    allocator: std.mem.Allocator,
    data: []M,
    claim: O,
    pub fn init(a: std.mem.Allocator, instance: Frame.Instance, provider: @import("provider.zig").Provider, terminal: *const Native.Pending, part: *const Data, wire: A.crypto.secp256k1.equations.WireFor(O)) !Witness {
        if (instance != .frontier) return error.SpongeCpuGeometry;
        const rows = try instance.rows();
        const data = try a.alloc(M, try std.math.mul(usize, rows, Eq.Layout.INTERACTION));
        errdefer a.free(data);
        try Shared.eqInto(data, rows, terminal.artifact.ood_point[terminal.artifact.ood_point.len - try instance.variables() ..][0..instance.rowLog()]);
        var sum = O.zero();
        var claim = O.zero();
        for (0..rows) |logical| {
            const p = A.witness.physical(logical, instance.rowLog());
            var n: [3]M = undefined;
            var d: [3]O = undefined;
            try provider.emitRange(instance, logical, 0, &n, &d, terminal.challenges);
            var projection = part.binding.weights[3].mul(terminal.eta);
            for (part.binding.weights[0..3], n, d) |weight, nn, dd| projection = projection.add(weight.mulM31(nn).add(weight.mul(dd).mul(terminal.eta)));
            sum = sum.add(get(data, rows, 0, p).mul(projection).sub(part.binding.target));
            set(data, rows, 8, p, sum);
            const row = try provider.frontier.row(logical);
            if (!row[0].isZero()) {
                const tuple = A.crypto.keccak_sponge.serialized.frontier.wireTuple(M, M.fromCanonical(provider.frontier.ordinal), A.crypto.keccak_sponge.serialized.frontier.owner(M, &row));
                var denominator = wire.offset;
                for (tuple, wire.coefficients) |value, coefficient| denominator = denominator.sub(coefficient.mulM31(value));
                if (denominator.isZero()) return error.LocalGkrPole;
                claim = claim.add(try denominator.inv());
            }
            set(data, rows, 16, p, claim);
        }
        if (!sum.isZero()) return error.SpongeCpuBindingMismatch;
        return .{ .allocator = a, .data = data, .claim = claim };
    }
    pub fn deinit(self: *Witness) void {
        self.allocator.free(self.data);
        self.* = undefined;
    }
};
