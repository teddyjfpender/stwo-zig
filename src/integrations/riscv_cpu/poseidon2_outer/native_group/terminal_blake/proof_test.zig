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
    if (std.posix.getenv("STWO_OP_TERMINAL_BLAKE_R6_TINY_CONTROL")) |path| {
        const retained = try std.fs.cwd().readFileAlloc(a, path, P.MAX_PROOF_BYTES);
        defer a.free(retained);
        try std.testing.expectEqualSlices(u8, retained, proof);
    }
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
fn fixtureR7(alloc: std.mem.Allocator, trace: bool) !C.PoseidonContext {
    var structural = C.lane.StructuralScope.init();
    defer structural.deinit();
    var owner = if (trace) try C.PoseidonContext.initTraceOnly(alloc, 10) else try C.PoseidonContext.init(alloc, 10);
    errdefer owner.deinit();
    var mul = @import("../../native_omul/scope.zig").begin();
    defer mul.deinit();
    var dot = @import("../../native_dot/scope.zig").Scope.begin(&owner);
    defer dot.deinit();
    C.begin(&owner);
    var active = true;
    defer if (active) C.finish() catch {};
    const x = try C.F.guess(owner.algebra(), operand(3));
    const y = try C.F.guess(owner.algebra(), operand(17));
    _ = try owner.base.guessM31(C.Q.fromU32Unchecked(7, 0, 0, 0));
    _ = try owner.base.guessU16(C.Q.fromU32Unchecked(9, 0, 0, 0));
    const seventeen = try owner.base.constant(C.Q.fromU32Unchecked(17, 0, 0, 0));
    try owner.base.eq(seventeen, seventeen);
    const product = x.mul(y);
    const s0 = try owner.base.guess(C.Q.fromU32Unchecked(5, 0, 0, 0));
    const s1 = try owner.base.guess(C.Q.fromU32Unchecked(11, 0, 0, 0));
    const result = try @import("../../../rv64_recursion/om31_native/deep_dot.zig").current().?(owner.algebra(), &.{ product, x, x }, &.{ s0, s1, s0 });
    const empty = try @import("../../../rv64_recursion/om31_native/deep_dot.zig").current().?(owner.algebra(), &.{}, &.{});
    _ = try owner.permute(@splat(s0));
    try C.finish();
    active = false;
    try owner.setOutputs(&.{ x.c0.v, x.c1.v, y.c0.v, y.c1.v, s0, s1, result.c0.v, result.c1.v, empty.c0.v, empty.c1.v });
    try owner.finalizeForNativeDot();
    return owner;
}
fn expectedR7() [10]C.Q {
    const x = operand(3);
    const y = operand(17);
    const z = x.mul(y).mulM31(Core.fields.m31.M31.fromCanonical(5)).add(x.mulM31(Core.fields.m31.M31.fromCanonical(16)));
    return .{ x.c0, x.c1, y.c0, y.c1, C.Q.fromU32Unchecked(5, 0, 0, 0), C.Q.fromU32Unchecked(11, 0, 0, 0), z.c0, z.c1, C.Q.zero(), C.Q.zero() };
}
test "terminal Blake R7 eight role physical source closure and format authority" {
    const budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(std.testing.allocator, 2 << 30);
    defer budget.destroy();
    const alloc = budget.allocator();
    {
        var numeric = try fixtureR7(alloc, false);
        defer numeric.deinit();
        var source = try fixtureR7(alloc, true);
        defer source.deinit();
        try std.testing.expectEqualDeep(numeric.base.circuit, source.base.circuit);
        try std.testing.expectEqualDeep(numeric.calls.items, source.calls.items);
        try std.testing.expectEqualDeep(numeric.native_mul_calls.items, source.native_mul_calls.items);
        try std.testing.expectEqualDeep(numeric.native_dot_calls.items, source.native_dot_calls.items);
        try std.testing.expectEqualDeep(numeric.native_input_ids.items, source.native_input_ids.items);
        try std.testing.expect(std.meta.isError(K.Key.init(alloc, &source)));
        var key = try K.R7.Key.init(alloc, &source);
        defer key.deinit();
        try std.testing.expect(key.inner.dot_raw > 1 and key.inner.input_raw > 0);
        const out = expectedR7();
        for ([_]@import("arithmetic.zig").Mutation{ .balanced_claims, .dot_accumulator, .input_value }) |mutation| {
            if (P.R7.proveMutationForTest(alloc, &numeric, &key, &out, mutation)) |invalid| {
                alloc.free(invalid);
                return error.TerminalBlakeR7FalseWitnessProved;
            } else |err| if (err != error.ConstraintsNotSatisfied and err != error.PoseidonGlobalLookupSum) return err;
        }
        const bytes = try P.R7.prove(alloc, &numeric, &key, &out);
        defer alloc.free(bytes);
        var fresh_source = try fixtureR7(alloc, true);
        defer fresh_source.deinit();
        var fresh = try K.R7.Key.init(alloc, &fresh_source);
        defer fresh.deinit();
        fresh.retireProverData();
        fresh.retireProverData();
        try std.testing.expectEqualSlices(u8, &key.identity, &fresh.identity);
        try P.R7.verify(alloc, &fresh, &out, bytes);
        try std.testing.expectError(error.TerminalBlakeProverDataRetired, P.R7.prove(alloc, &numeric, &fresh, &out));
        var wrong_source = try fixtureR7(alloc, true);
        defer wrong_source.deinit();
        const terms = @constCast(wrong_source.native_dot_calls.items[0].terms);
        std.mem.swap(u32, &terms[0].weight[0], &terms[0].weight[1]);
        var wrong_key = try K.R7.Key.init(alloc, &wrong_source);
        defer wrong_key.deinit();
        try std.testing.expectError(error.TerminalBlakeAuthority, P.R7.verify(alloc, &wrong_key, &out, bytes));
        var wrong = out;
        wrong[4] = wrong[4].add(C.Q.one());
        try std.testing.expect(std.meta.isError(P.R7.verify(alloc, &fresh, &wrong, bytes)));
        const changed = try alloc.dupe(u8, bytes);
        defer alloc.free(changed);
        changed[changed.len / 2] ^= 1;
        try std.testing.expect(std.meta.isError(P.R7.verify(alloc, &fresh, &out, changed)));
        @memcpy(changed, bytes);
        std.mem.writeInt(u32, changed[40..44], Core.fields.m31.Modulus, .little);
        try std.testing.expectError(error.TerminalBlakeNoncanonicalClaim, P.R7.verify(alloc, &fresh, &out, changed));
        const P7 = @import("../../native_dot/outer_proof.zig");
        var p2_key = try @import("../../native_dot/outer_authority.zig").Key.init(alloc, &source, Suite.fri_policy);
        defer p2_key.deinit();
        const p2 = try P7.prove(alloc, &numeric, &p2_key, &out);
        defer alloc.free(p2);
        try P7.verify(alloc, &p2_key, &out, p2);
        try std.testing.expectError(error.TerminalBlakeWire, P.R7.verify(alloc, &fresh, &out, p2));
        try std.testing.expectError(error.InvalidNativeDotR7Wire, P7.verify(alloc, &p2_key, &out, bytes));
        var r6_source = try fixture(true);
        defer r6_source.deinit();
        var r6 = try K.Key.init(alloc, &r6_source);
        defer r6.deinit();
        try std.testing.expectError(error.TerminalBlakeWire, P.verify(alloc, &r6, &expected(), bytes));
        try P.R7.verify(alloc, &fresh, &out, bytes);
        std.debug.print("OP_TERMINAL_BLAKE_R7_TINY bytes={} roles=8 dot_rows={} input_rows={} originalDotInputAIR=true fresh_source=true mutations_and_cross_format_reject=true cold_P2_source_ns={} extra_Blake_FIXED_ns={} production_admission=false\n", .{ bytes.len, key.inner.dot_rows, key.inner.input_rows, key.p2_source_setup_ns, key.blake_fixed_setup_ns });
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
}
