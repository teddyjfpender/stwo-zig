//! Late MAIN binding projection: precombined lane weights, native-width SIMD,
//! and bounded joined row work. The scalar binding_v2 path remains the oracle.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const P = @import("profile.zig");
const S = @import("section.zig");
const Legacy = @import("binding.zig");
const O = core.fields.om31.OM31;
const M = core.fields.m31;
const Pack = core.fields.packed_om31;
const Term = struct { n: ?[]const M.M31, d: []const O, n_weight: Pack.PackedOM31, d_weight: Pack.PackedOM31 };
const Fill = struct {
    terms: []const Term,
    output: []O,
    constant: Pack.PackedOM31,
    pub fn runRange(self: *@This(), _: usize, first: usize, end: usize) void {
        for (first..end) |tile| {
            const row = tile * M.PACK_WIDTH;
            var value = self.constant;
            for (self.terms) |term| {
                var coordinates: [8]M.PackedM31 = undefined;
                inline for (0..M.PACK_WIDTH) |lane| {
                    const scalar = term.d[row + lane].toM31Array();
                    inline for (0..8) |c| coordinates[c][lane] = scalar[c].v;
                }
                if (term.n) |numerators| value = value.add(term.n_weight.mulBase(M.loadPacked(numerators[row..].ptr)));
                value = value.add(Pack.mul(term.d_weight, Pack.fromCoordinates(coordinates)));
            }
            inline for (0..M.PACK_WIDTH) |lane| self.output[row + lane] = Pack.lane(value, lane);
        }
    }
};
pub fn project(a: std.mem.Allocator, class: *const P.Class, component: P.Component, point: []const O, inputs: *const S.Inputs, ch: *const Legacy.Challenges) ![]O {
    try class.validate();
    if (class.binding_version != .cyclic_eq_v2 or !P.gkrBound(component) or point.len != class.layers() or inputs.numerators.len != class.instances.len or inputs.denominators.len != class.instances.len) return error.OuterGkrBindingShape;
    const log = class.row_logs[@intFromEnum(component)];
    const rows = @as(usize, 1) << @intCast(log);
    if (rows % M.PACK_WIDTH != 0) return error.OuterGkrBindingShape;
    _ = try @import("../logup_gkr/mle_point.zig").MleEvalPointFor(O).init(point[point.len - log ..]);
    var terms: [26]Term = undefined;
    var count: usize = 0;
    var constant = O.zero();
    for (class.instances, 0..) |inst, group| {
        if (inst.component != component) continue;
        const length = @as(usize, 1) << @intCast(inst.variables());
        if (inputs.numerators[group].len != length or inputs.denominators[group].len != length) return error.OuterGkrBindingShape;
        const unit = S.unitNumerators(inputs.numerators[group]);
        const weights = try Legacy.eqTable(a, point[point.len - inst.variables() .. point.len - log]);
        defer a.free(weights);
        if (count + weights.len > terms.len) return error.OuterGkrBindingShape;
        for (weights, 0..) |weight, lane| {
            const n_weight = ch.rho[group].mul(weight);
            if (unit) constant = constant.add(n_weight);
            terms[count] = .{ .n = if (unit) null else inputs.numerators[group][lane * rows ..][0..rows], .d = inputs.denominators[group][lane * rows ..][0..rows], .n_weight = Pack.splat(n_weight), .d_weight = Pack.splat(n_weight.mul(ch.gamma)) };
            count += 1;
        }
    }
    if (count != P.FACTS[@intFromEnum(component)].lookups) return error.OuterGkrBindingShape;
    const out = try a.alloc(O, rows);
    var fill = Fill{ .terms = terms[0..count], .output = out, .constant = Pack.splat(constant) };
    _ = engine.lookups.row_work.forEachRange(rows / M.PACK_WIDTH, &fill, .{ .min_rows_per_shard = 128 });
    return out;
}
