//! Tiny physical correctness only. This suite is not runtime admission.
const std = @import("std");
const Core = @import("stwo_core");
const C = @import("../../../rv64_recursion/om31_poseidon/common.zig");
const K = @import("authority.zig");
const Suite = @import("profile.zig");
const P = @import("proof.zig");
const OldK = @import("../../native_omul/authority.zig");
const OldP = @import("../../native_omul/proof.zig");
const a = std.testing.allocator;
fn operand(seed: u32) C.O {
    var words: [8]Core.fields.m31.M31 = undefined;
    for (&words, 0..) |*word, i| word.* = Core.fields.m31.M31.fromCanonical(seed + @as(u32, @intCast(i)) * 37);
    return C.O.fromM31Array(words);
}
fn fixture(trace: bool) !C.PoseidonContext {
    var structural = C.lane.StructuralScope.init();
    defer structural.deinit();
    var scope = @import("../../native_omul/scope.zig").begin();
    defer scope.deinit();
    var owner = if (trace) try C.PoseidonContext.initTraceOnly(a, 9) else try C.PoseidonContext.init(a, 9);
    errdefer owner.deinit();
    C.begin(&owner);
    var active = true;
    defer if (active) C.finish() catch {};
    const x = try C.F.guess(owner.algebra(), operand(7));
    const y = try C.F.guess(owner.algebra(), operand(41));
    const z = x.mul(y);
    var inputs: [24]C.Var = undefined;
    for (&inputs, 0..) |*input, i| input.* = try owner.algebra().guess(C.Q.fromBase(Core.fields.m31.M31.fromCanonical(@intCast(i + 1))));
    const hashed = try owner.permute(inputs);
    const joined = try owner.algebra().add(z.c0.v, hashed[0]);
    try C.finish();
    active = false;
    try owner.setOutputs(&.{ joined, z.c1.v, hashed[1], hashed[2], hashed[3], hashed[4], hashed[5], hashed[6], hashed[7] });
    try owner.finalize();
    return owner;
}
fn expected() [9]C.Q {
    var state: Core.crypto.poseidon2_m31_w24.State = undefined;
    for (&state, 0..) |*v, i| v.* = Core.fields.m31.M31.fromCanonical(@intCast(i + 1));
    Core.crypto.poseidon2_m31_w24.permute(&state);
    const z = operand(7).mul(operand(41));
    return .{ z.c0.add(C.Q.fromBase(state[0])), z.c1, C.Q.fromBase(state[1]), C.Q.fromBase(state[2]), C.Q.fromBase(state[3]), C.Q.fromBase(state[4]), C.Q.fromBase(state[5]), C.Q.fromBase(state[6]), C.Q.fromBase(state[7]) };
}
test "terminal Blake R6 physical proof preserves original AIR and separate source authority" {
    var numeric = try fixture(false);
    defer numeric.deinit();
    try std.testing.expect(try numeric.isCircuitValid());
    var source = try fixture(true);
    defer source.deinit();
    try std.testing.expectEqualDeep(numeric.base.circuit, source.base.circuit);
    try std.testing.expectEqualDeep(numeric.calls.items, source.calls.items);
    try std.testing.expectEqualDeep(numeric.native_mul_calls.items, source.native_mul_calls.items);
    var key = try K.Key.init(a, &source);
    defer key.deinit();
    const output = expected();
    if (P.proveBalancedClaimsForTest(a, &numeric, &key, &output)) |invalid| {
        a.free(invalid);
        return error.TerminalBlakeCoherentMutationProduced;
    } else |_| {}
    const proof = try P.prove(a, &numeric, &key, &output);
    defer a.free(proof);
    var fresh_source = try fixture(true);
    defer fresh_source.deinit();
    var fresh = try K.Key.init(a, &fresh_source);
    defer fresh.deinit();
    try std.testing.expectEqualSlices(u8, &key.identity, &fresh.identity);
    try std.testing.expectEqualSlices(u8, &key.fixed_root, &fresh.fixed_root);
    fresh.retireProverData();
    fresh.retireProverData();
    try P.verify(a, &fresh, &output, proof);
    try std.testing.expectError(error.TerminalBlakeProverDataRetired, P.prove(a, &numeric, &fresh, &output));
    var wrong = output;
    wrong[8] = wrong[8].add(C.Q.one());
    try std.testing.expect(std.meta.isError(P.verify(a, &fresh, &wrong, proof)));
    const changed = try a.dupe(u8, proof);
    defer a.free(changed);
    changed[40] ^= 1;
    try std.testing.expect(std.meta.isError(P.verify(a, &fresh, &output, changed)));
    @memcpy(changed, proof);
    changed[changed.len / 2] ^= 1;
    try std.testing.expect(std.meta.isError(P.verify(a, &fresh, &output, changed)));
    @memcpy(changed, proof);
    std.mem.writeInt(u32, changed[40..44], Core.fields.m31.Modulus, .little);
    try std.testing.expectError(error.TerminalBlakeNoncanonicalClaim, P.verify(a, &fresh, &output, changed));
    var wrong_key = fresh;
    wrong_key.identity[0] ^= 1;
    try std.testing.expectError(error.TerminalBlakeAuthority, P.verify(a, &wrong_key, &output, proof));
    var old = try OldK.Key.init(a, &source, Suite.fri_policy);
    defer old.deinit();
    const p2_proof = try OldP.prove(a, &numeric, &old, &output);
    defer a.free(p2_proof);
    try OldP.verify(a, &old, &output, p2_proof);
    try std.testing.expectError(error.TerminalBlakeWire, P.verify(a, &fresh, &output, p2_proof));
    try std.testing.expectError(error.InvalidNativeOmulWire, OldP.verify(a, &old, &output, proof));
    try P.verify(a, &fresh, &output, proof);
    std.debug.print("OP_TERMINAL_BLAKE_TINY bytes={} cold_p2_source_setup_ns={} additional_blake_fixed_ns={} fresh_source=true original6AIR=true crosssuite_reject=true production_admission=false\n", .{ proof.len, key.p2_source_setup_ns, key.blake_fixed_setup_ns });
}
