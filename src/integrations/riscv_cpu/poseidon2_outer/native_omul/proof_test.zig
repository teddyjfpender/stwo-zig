//! Small physical R6 qualification before any real-source performance claim.
const std = @import("std");
const Core = @import("stwo_core");
const C = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Scope = @import("scope.zig");
const K = @import("authority.zig");
const Proof = @import("proof.zig");
const Q = C.Q;
const O = C.O;
const M = Core.fields.m31.M31;
const a = std.testing.allocator;
fn fixture(trace: bool) !C.PoseidonContext {
    var structural = C.lane.StructuralScope.init();
    defer structural.deinit();
    var scope = Scope.begin();
    defer scope.deinit();
    var owner = if (trace) try C.PoseidonContext.initTraceOnly(a, 3) else try C.PoseidonContext.init(a, 3);
    errdefer owner.deinit();
    C.begin(&owner);
    var active = true;
    defer if (active) C.finish() catch {};
    const x = try C.F.guess(owner.algebra(), operand(7));
    const y = try C.F.guess(owner.algebra(), operand(41));
    const first = x.mul(y);
    const second = first.mul(x);
    var inputs: [24]C.Var = undefined;
    for (&inputs, 0..) |*input, i| input.* = try owner.algebra().guess(Q.fromBase(M.fromCanonical(@intCast(i + 1))));
    const hashed = try owner.permute(inputs);
    const joined = try owner.algebra().add(second.c0.v, hashed[0]);
    try C.finish();
    active = false;
    try owner.setOutputs(&.{ joined, second.c1.v, hashed[1] });
    try owner.finalize();
    return owner;
}
fn operand(seed: u32) O {
    var fields: [8]M = undefined;
    for (&fields, 0..) |*field, i| field.* = M.fromCanonical(seed + @as(u32, @intCast(i)) * 37);
    return O.fromM31Array(fields);
}
fn outputs() [3]Q {
    var state: Core.crypto.poseidon2_m31_w24.State = undefined;
    for (&state, 0..) |*field, i| field.* = M.fromCanonical(@intCast(i + 1));
    Core.crypto.poseidon2_m31_w24.permute(&state);
    const product = operand(7).mul(operand(41)).mul(operand(7));
    return .{ product.c0.add(Q.fromBase(state[0])), product.c1, Q.fromBase(state[1]) };
}
fn rejected(result: anytype) !void {
    if (result) |bytes| {
        a.free(bytes);
        return error.NativeOmulMutationAccepted;
    } else |_| {}
}
test "OP R6 physical six-component proof closes complete Var and range relations" {
    var owner = try fixture(false);
    defer owner.deinit();
    try std.testing.expect(try owner.isCircuitValid());
    var trace = try fixture(true);
    defer trace.deinit();
    var key = try K.Key.init(a, &trace, .op_target_b4_q72_p0_fold4_v1);
    defer key.deinit();
    const expected = outputs();
    const proof = try Proof.prove(a, &owner, &key, &expected);
    defer a.free(proof);
    var full_key = try K.Key.initFullStorageControl(a, &trace, .op_target_b4_q72_p0_fold4_v1);
    defer full_key.deinit();
    try std.testing.expectEqualSlices(u8, &full_key.base.identity, &key.base.identity);
    try std.testing.expectEqualSlices(u8, &full_key.base.fixed_root, &key.base.fixed_root);
    const full_control = try Proof.proveFullStorageControl(a, &owner, &full_key, &expected);
    defer a.free(full_control);
    try std.testing.expectEqualSlices(u8, full_control, proof);
    // Rebuild source geometry/FIXED under a distinct trace owner.
    var fresh = try fixture(true);
    defer fresh.deinit();
    var receiver = try K.Key.init(a, &fresh, .op_target_b4_q72_p0_fold4_v1);
    defer receiver.deinit();
    try std.testing.expectEqualSlices(u8, &key.base.identity, &receiver.base.identity);
    try Proof.verify(a, &receiver, &expected, proof);
    var captured = try Proof.verifyCaptured(a, &receiver, &expected, proof);
    defer captured.deinit(a);
    try std.testing.expectEqual(@as(usize, 6), captured.claims.len);
    // The recursive verifier consumes the same source-authorized six-component
    // geometry and equations. No native result is trusted as a circuit oracle.
    {
        const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
        const F = V.common.F;
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("capture.zig").geometry(arena.allocator(), &receiver);
        const values = try V.proof.fromNative(arena.allocator(), &captured.proof, &captured.capture, &shape);
        var structural = C.lane.StructuralScope.init();
        defer structural.deinit();
        var circuit = try C.PoseidonContext.init(a, expected.len);
        defer circuit.deinit();
        V.common.begin(&circuit);
        var active = true;
        defer if (active) V.common.finish() catch {};
        const wire = try V.proof.guess(circuit.algebra(), &values, &shape);
        var ports: [3]C.Var = undefined;
        for (&ports, expected) |*port, value| port.* = try circuit.algebra().guess(value);
        var claims: [6]F = undefined;
        for (&claims, captured.claims) |*claim, value| claim.* = try F.guess(circuit.algebra(), value);
        var statement = @import("statement.zig").Statement{ .key = &receiver, .fixed = wire.commitments[0], .outputs = &ports, .claims = claims };
        _ = try V.verify(circuit.algebra(), &shape, &wire, &statement);
        try V.common.finish();
        active = false;
        try circuit.setOutputs(&ports);
        try circuit.finalize();
        try std.testing.expect(try circuit.isCircuitValid());
        const saved_port = circuit.algebra().get(ports[0]);
        circuit.base.value_table.items[ports[0].idx] = saved_port.add(Q.one());
        try std.testing.expect(!try circuit.isCircuitValid());
        circuit.base.value_table.items[ports[0].idx] = saved_port;
    }
    const changed = try a.dupe(u8, proof);
    defer a.free(changed);
    changed[40] ^= 1;
    try std.testing.expect(std.meta.isError(Proof.verify(a, &receiver, &expected, changed)));
    std.mem.writeInt(u32, changed[40..44], Core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.NoncanonicalPoseidonClaim, Proof.verify(a, &receiver, &expected, changed));
    var wrong = expected;
    wrong[0] = wrong[0].add(Q.one());
    try std.testing.expect(std.meta.isError(Proof.verify(a, &receiver, &wrong, proof)));
    // The bad intermediate is used by another product, so all Var tuples stay
    // consistent. Its product equations, not merely lookup closure, reject it.
    const id = owner.native_mul_calls.items[0].outputs[1];
    const saved = owner.base.value_table.items[id];
    owner.base.value_table.items[id] = saved.add(Q.one());
    try rejected(Proof.prove(a, &owner, &key, &expected));
    owner.base.value_table.items[id] = saved;
    try rejected(Proof.proveMutation(a, &owner, &key, &expected, .native_prefix));
    try rejected(Proof.proveMutation(a, &owner, &key, &expected, .claim_balanced));
    std.debug.print("OP_R6_PHYSICAL bytes={} mul_rows={} legacy_arith_rows={} all6claims_bound=true globalclosed=true fresh_source=true production_admission=false\n", .{ proof.len, key.mul_rows, key.base.rows[1] });
}
