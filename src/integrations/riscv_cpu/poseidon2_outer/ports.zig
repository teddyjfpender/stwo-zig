//! Exact scalar circuit-port admission for the new component. Production uses
//! the authenticated Var lookup bus; this focused seam checks the same full
//! QM31 values and rejects extension coordinates, rather than a phantom type.
const std = @import("std");
const Core = @import("stwo_core");
const B = @import("stwo_circuit_frontend").builder;
const L = @import("layout.zig");
const Row = @import("row.zig");
const Base = @import("../rv64_recursion/poseidon2_circuit.zig");
const Q = Core.fields.qm31.QM31;
const O = Core.fields.om31.OM31;
const M = Core.fields.m31.M31;
pub fn constrain(ctx: *B.Context(Q), fixed: *const L.Fixed, inputs: [24]B.Var, outputs: [24]B.Var) !void {
    if (fixed[L.ENABLED].v != 1) return error.DisabledPoseidonSourceGate;
    for (0..24) |i| {
        const input = fixed[L.INPUT_ID + i].v;
        const output = fixed[L.OUTPUT_ID + i].v;
        if (input >= ctx.circuit.n_vars or output >= ctx.circuit.n_vars) return error.InvalidPoseidonPortAddress;
        const actual_in = B.Var{ .idx = input };
        const actual_out = B.Var{ .idx = output };
        try Base.requireM31(ctx, actual_in);
        try Base.requireM31(ctx, actual_out);
        try ctx.eq(actual_in, inputs[i]);
        try ctx.eq(actual_out, outputs[i]);
    }
}
fn combine(tuple: [6]M, z: O, powers: [6]O) O {
    var d = z.neg();
    for (tuple, powers) |value, power| d = d.add(power.mulM31(value));
    return d;
}
/// A focused complete Var-bus closure: the external producer/consumer uses
/// actual four-coordinate circuit values; the dedicated row uses M31 ports.
fn closure(row: *const L.Row, fixed: *const L.Fixed, actual: []const Q, z: O, powers: [6]O) !O {
    var sum = O.zero();
    const ports = Row.portsFor(M, row, fixed);
    for (ports) |port| {
        const address = port.tuple[1].v;
        if (address >= actual.len) return error.InvalidPoseidonPortAddress;
        const full = actual[address].toM31Array();
        var external = port.tuple;
        external[2..6].* = full;
        sum = sum.add(O.fromBase(port.numerator).mul(try combine(port.tuple, z, powers).inv()));
        sum = sum.sub(O.fromBase(port.numerator).mul(try combine(external, z, powers).inv()));
    }
    return sum;
}
test "dedicated Poseidon input and output ports reject non-base extension witnesses in circuit and global lookup closure" {
    const a = std.testing.allocator;
    const row = try Row.fill(@splat(M.fromCanonical(11)));
    var random = Core.channel.raw_mod_m31.Om31Channel.init();
    const z = random.drawSecureFelt();
    var powers: [6]O = undefined;
    var power = O.one();
    const alpha = random.drawSecureFelt();
    for (&powers) |*value| {
        value.* = power;
        power = power.mul(alpha);
    }
    for ([_]usize{ 48, 0, 7, 23, 24, 31, 47 }) |bad_port| {
        var ctx = try B.Context(Q).init(a, 0);
        defer ctx.deinit();
        ctx.assert_eq_on_eval = false;
        var gate: L.Gate = undefined;
        var input: [24]B.Var = undefined;
        var output: [24]B.Var = undefined;
        var actual: [64]Q = @splat(Q.zero());
        for (0..48) |i| {
            const value = Q.fromBase(row[if (i < 24) L.INPUT + i else L.OUTPUT + i - 24]);
            const mutated = if (i == bad_port) value.add(Q.fromU32Unchecked(0, 1, 0, 0)) else value;
            const wire = try ctx.guess(mutated);
            actual[wire.idx] = mutated;
            if (i < 24) gate.inputs[i] = wire.idx else gate.outputs[i - 24] = wire.idx;
        }
        const uses = [_]u32{1} ** 64;
        const fixed = try L.fixedFor(gate, .{ .counts = &uses, .max_per_wire = 1, .max_total = 64 });
        for (&input, &output, 0..) |*in, *out, i| {
            in.* = try ctx.guess(Q.fromBase(row[L.INPUT + i]));
            out.* = try ctx.guess(Q.fromBase(row[L.OUTPUT + i]));
        }
        try constrain(&ctx, &fixed, input, output);
        try ctx.finalize(false);
        try std.testing.expectEqual(bad_port == 48, try ctx.isCircuitValid());
        try std.testing.expectEqual(bad_port == 48, (try closure(&row, &fixed, &actual, z, powers)).isZero());
    }
}
