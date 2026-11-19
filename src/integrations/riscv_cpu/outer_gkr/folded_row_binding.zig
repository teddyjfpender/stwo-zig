//! M7 outer-GKR terminal binding, version 2. The v1 reference remains in
//! binding.zig; it does not constrain its Eq column and cannot be promoted.
//!
//! Both the native receiver and its in-circuit counterpart derive first,
//! second and carry from the GKR row point and the folded PCS point. They
//! are never committed columns or producer-supplied auxiliaries. The actual
//! three AIR equations are the native binding authority, reused verbatim.
const std = @import("std");
const core = @import("stwo_core");
const MP = @import("../logup_gkr/mle_point.zig");
const Native = @import("../word16_global_execution/services/gkr_local/binding.zig");
const Legacy = @import("binding.zig");
const P = @import("profile.zig");
const S = @import("section.zig");
const A = @import("stwo_riscv_frontend").rv64_air;
const O = core.fields.om31.OM31;
const M = core.fields.m31.M31;

pub const CONSTRAINTS = Native.CONSTRAINTS;
pub const INTERACTION_COLUMNS = Native.INTERACTION_COLUMNS;
pub const AuxFor = Native.AuxFor;
pub const MaskFor = Native.MaskFor;
pub const emitFor = Native.emitFor;
pub const residualsFor = Native.residualsFor;

/// `point` is already folded to this component's trace coset. Over circuit
/// wires, point initialization emits inverse constraints for every z_i and
/// 1-z_i, making a degenerate point unsatisfiable just as native admission
/// rejects it. Complexity O(log^2(rows)); no interpolant is materialized.
pub fn auxFor(comptime F: type, z_row: []const F, point: core.circle.CirclePoint(F)) !AuxFor(F) {
    const mle = try MP.MleEvalPointFor(F).init(z_row);
    const anchors = try MP.evalAnchorsFor(F, @intCast(z_row.len), point);
    return .{
        .first = anchors[0],
        .second = anchors[1],
        .carry = try MP.evalCarryQuotientFor(F, &mle, point),
        .eq0 = mle.eq0,
        .eq1 = mle.eq1,
    };
}

/// Verifier-side OODS hook. The component/log and terminal target are derived
/// from the receiver's class and the verified GKR artifact. The only inputs
/// to be supplied by PCS masks are Eq(current,next2), Pre(current,previous)
/// and MAIN's lane-weighted projection; no auxiliary may come from the proof.
///
/// Every input column, carry and anchor has circle degree at most rows-1.
/// The projection is affine in authenticated MAIN/FIXED columns, so all three
/// residuals have degree <=2*rows-2. Its composition evaluation log is log+1.
pub fn evaluateFor(comptime F: type, class: *const P.Class, component: P.Component, gkr_point: []const F, global_point: core.circle.CirclePoint(F), global_log: u32, masks: MaskFor(F), projection: F, target: F, sink: *A.evaluation.SinkFor(F)) !void {
    try class.validate();
    if (class.binding_version != .cyclic_eq_v2 or !P.gkrBound(component)) return error.OuterGkrBindingVersion;
    const log: u32 = class.row_logs[@intFromEnum(component)];
    if (log == 0 or log > gkr_point.len or global_log < log) return error.OuterGkrBindingShape;
    const local = try A.geometry.localPointFor(F, global_point, global_log, log);
    const aux = try auxFor(F, gkr_point[gkr_point.len - log ..], local);
    const inverse_rows = try M.fromU64(@as(u64, 1) << @intCast(log)).inv();
    emitFor(F, masks, aux, projection, target.mul(F.fromBase(inverse_rows)), sink);
}

pub const Columns = struct {
    eq: []O,
    prefix: []O,
    pub fn deinit(self: *Columns, a: std.mem.Allocator) void {
        a.free(self.eq);
        a.free(self.prefix);
    }
};

/// CPU differential/reference construction in the production lane-major
/// instance order. GPU projection uses this same class-defined grouping.
/// Gamma and rho must have been drawn AFTER the verified GKR section.
pub fn projectFromInputs(a: std.mem.Allocator, class: *const P.Class, component: P.Component, point: []const O, inputs: *const S.Inputs, ch: *const Legacy.Challenges) ![]O {
    try class.validate();
    if (class.binding_version != .cyclic_eq_v2 or !P.gkrBound(component)) return error.OuterGkrBindingVersion;
    if (inputs.numerators.len != class.instances.len or inputs.denominators.len != class.instances.len or point.len != class.layers()) return error.OuterGkrBindingShape;
    const log: u32 = class.row_logs[@intFromEnum(component)];
    const rows = @as(usize, 1) << @intCast(log);
    _ = try MP.MleEvalPointFor(O).init(point[point.len - log ..]);
    const out = try a.alloc(O, rows);
    errdefer a.free(out);
    @memset(out, O.zero());
    for (class.instances, 0..) |inst, g| {
        if (inst.component != component) continue;
        const count = @as(usize, 1) << @intCast(inst.variables());
        if (inputs.numerators[g].len != count or inputs.denominators[g].len != count) return error.OuterGkrBindingShape;
        const weights = try Legacy.eqTable(a, point[point.len - inst.variables() .. point.len - log]);
        defer a.free(weights);
        for (out, 0..) |*value, row| {
            var acc = O.zero();
            for (weights, 0..) |weight, lane| {
                const index = lane * rows + row;
                acc = acc.add(weight.mul(O.fromBase(inputs.numerators[g][index]).add(ch.gamma.mul(inputs.denominators[g][index]))));
            }
            value.* = value.add(ch.rho[g].mul(acc));
        }
    }
    return out;
}

/// Build the two committed columns in physical (bit-reversed circle) order.
/// `projection[p]` is MAIN's lane-weighted N+gamma*D at row p. Its target
/// comes from the GKR terminal claims fixed BEFORE gamma/rho, never from an
/// untrusted claimed sum. Prefix has exactly rows entries and is CYCLIC:
/// Pre(k)-Pre(k-1)=E(k)*projection(k)-target/rows, including k=0.
pub fn columns(a: std.mem.Allocator, z_row: []const O, projection: []const O, target: O) !Columns {
    _ = try MP.MleEvalPointFor(O).init(z_row);
    const log: u32 = @intCast(z_row.len);
    const rows = @as(usize, 1) << @intCast(log);
    if (projection.len != rows) return error.OuterGkrBindingShape;
    const eq = try Legacy.eqTable(a, z_row);
    errdefer a.free(eq);
    const prefix = try a.alloc(O, rows);
    errdefer a.free(prefix);
    const uniform = target.mulM31(try M.fromU64(rows).inv());
    var sum = O.zero();
    for (0..rows) |k| {
        const p = MP.storageIndex(k, log);
        sum = sum.add(eq[p].mul(projection[p])).sub(uniform);
        prefix[p] = sum;
    }
    if (!sum.isZero()) return error.OuterGkrTerminalMismatch;
    return .{ .eq = eq, .prefix = prefix };
}
