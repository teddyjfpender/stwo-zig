//! Reuse exact circuit MAIN and lookup tuples; only LogUp arithmetic widens.
const std = @import("std");
const core = @import("stwo_core");
const prover = @import("stwo_prover_engine");
const circuit = @import("stwo_circuit_frontend");
const P = @import("protocol.zig");
const O = P.O;
const Q = P.Q;
const M = P.M;
const T = circuit.witness.trace;
const List = circuit.common.component_list;
const C = circuit.witness.components;
const L = prover.air.logup_columns.ForField(O);
const Col = prover.pcs.ColumnEvaluation;
pub const Claims = List.PerComponent(O);
pub const Elements = struct {
    z: O,
    powers: [C.MAX_TUPLE]O,
    pub fn init(z: O, alpha: O) Elements {
        var powers: [C.MAX_TUPLE]O = undefined;
        var power = O.one();
        for (&powers) |*out| {
            out.* = power;
            power = power.mul(alpha);
        }
        return .{ .z = z, .powers = powers };
    }
    pub fn combine(self: *const Elements, tuple: []const M) O {
        // The relation tag has coefficient alpha^0 = 1 by construction.
        // Circuit tuples also contain many canonical zero coordinates (u16
        // limbs, encoded u32s and base-field wires). Their products are zero
        // in every extension coordinate; do not execute eight scalar products.
        if (tuple.len == 0) return self.z.neg();
        var result = O.fromBase(tuple[0]);
        for (tuple[1..], self.powers[1..tuple.len]) |value, power| {
            if (!value.isZero()) result = result.add(power.mulM31(value));
        }
        return result.sub(self.z);
    }
};
pub const Interaction = struct {
    allocator: std.mem.Allocator,
    columns: []Col,
    claimed_sums: Claims,
    pub fn deinit(self: *@This()) void {
        T.freeColumns(self.allocator, self.columns);
        self.* = undefined;
    }
    pub fn takeColumns(self: *@This()) []Col {
        const out = self.columns;
        self.columns = &.{};
        return out;
    }
};
pub fn pairFractions(elements: *const Elements, lookups: []const C.Lookup, out: []L.Fraction) !void {
    if (out.len != (lookups.len + 1) / 2) return error.InvalidOm31LookupWidth;
    for (out, 0..) |*fraction, i| {
        const first = &lookups[2 * i];
        const d0 = elements.combine(first.values());
        if (2 * i + 1 == lookups.len) fraction.* = .{ .numerator = O.fromBase(first.numerator), .denominator = d0 } else {
            const second = &lookups[2 * i + 1];
            const d1 = elements.combine(second.values());
            fraction.* = .{ .numerator = d1.mulM31(first.numerator).add(d0.mulM31(second.numerator)), .denominator = d0.mul(d1) };
        }
    }
}
const Row = struct {
    raw: *const T.RawLookupRows,
    kind: List.ComponentList,
    elements: *const Elements,
    fn fill(self: @This(), row: usize, out: []L.Fraction) !void {
        var storage: [T.RawLookupRows.MAX_LOOKUPS]C.Lookup = undefined;
        try pairFractions(self.elements, try self.raw.fill(self.kind, row, &storage), out);
    }
};
pub fn outputTerm(elements: *const Elements, address: usize, output: Q) !O {
    const limbs = output.toM31Array();
    const tuple = [_]M{ M.fromCanonical(List.GATE_RELATION_ID), M.fromU64(address), limbs[0], limbs[1], limbs[2], limbs[3] };
    return elements.combine(&tuple).inv();
}
pub fn lookupSum(outputs: []const Q, claims: Claims, elements: *const Elements) !O {
    var sum = O.zero();
    for (claims.toArray()) |claim| sum = sum.add(claim);
    for (outputs, 0..) |output, i| sum = sum.add(try outputTerm(elements, T.U_VAR_IDX + 1 + i, output));
    return sum.add(try outputTerm(elements, T.U_VAR_IDX, T.U_VALUE));
}
/// Atomic ownership: no MAIN plane is retired until all eleven new INTER
/// components, independent public closure and output headers exist.
pub fn write(a: std.mem.Allocator, base: *T.BaseTrace, pp: *const circuit.common.preprocessed.PreprocessedCircuit, z: O, alpha: O) !Interaction {
    return writeImpl(a, base, pp, z, alpha, false);
}
pub fn writeReleasing(a: std.mem.Allocator, base: *T.BaseTrace, pp: *const circuit.common.preprocessed.PreprocessedCircuit, z: O, alpha: O) !Interaction {
    return writeImpl(a, base, pp, z, alpha, true);
}
fn writeImpl(a: std.mem.Allocator, base: *T.BaseTrace, pp: *const circuit.common.preprocessed.PreprocessedCircuit, z: O, alpha: O, release: bool) !Interaction {
    const rows = try T.RawLookupRows.init(base.columns, pp);
    const elements = Elements.init(z, alpha);
    var outputs: [List.N_COMPONENTS]?L.Output = @splat(null);
    defer for (outputs) |maybe| if (maybe) |out| T.freeColumns(a, out.columns);
    var total: usize = 0;
    var claims: [List.N_COMPONENTS]O = undefined;
    for (std.enums.values(List.ComponentList), base.log_sizes.toArray(), 0..) |kind, log, i| {
        const out = try L.build(a, log, (T.RawLookupRows.count(kind) + 1) / 2, Row{ .raw = &rows, .kind = kind, .elements = &elements }, Row.fill);
        outputs[i] = out;
        if (out.columns.len != 8 * ((T.RawLookupRows.count(kind) + 1) / 2)) return error.InvalidOm31InteractionWidth;
        claims[i] = out.claimed_sum;
        total = try std.math.add(usize, total, out.columns.len);
    }
    const sums = Claims.fromArray(claims);
    if (!(try lookupSum(base.output_values, sums, &elements)).isZero()) return error.InvalidOm31CircuitLookupSum;
    const columns = try a.alloc(Col, total);
    var cursor: usize = 0;
    for (&outputs) |*maybe| {
        const output = maybe.*.?;
        @memcpy(columns[cursor..][0..output.columns.len], output.columns);
        cursor += output.columns.len;
        a.free(output.columns);
        maybe.* = null;
    }
    if (release) T.freeColumns(base.allocator, base.takeColumns());
    return .{ .allocator = a, .columns = columns, .claimed_sums = sums };
}
