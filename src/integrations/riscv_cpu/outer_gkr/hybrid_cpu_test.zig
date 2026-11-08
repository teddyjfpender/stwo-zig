//! Physical CPU M7 proof against the existing independent hybrid receiver.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const R = @import("hybrid_receiver.zig");
const CPU = @import("hybrid_cpu.zig");
const a = std.testing.allocator;
fn balancedFalseFacts(inputs: *@import("section.zig").Inputs) !void {
    for (inputs.numerators, inputs.denominators) |n, d| {
        for (0..@min(d.len, 64)) |i| for (i + 1..@min(d.len, 64)) |j| {
            if (!d[i].eql(d[j])) continue;
            n[i] = n[i].add(@import("stwo_core").fields.m31.M31.one());
            n[j] = n[j].sub(@import("stwo_core").fields.m31.M31.one());
            return;
        };
    }
    return error.MissingDuplicateLookupForAttack;
}
fn rejected(key: *const R.Key, proof: *CPU.Produced) !void {
    var capture = key.verify(a, proof.base.outputs, proof.base.claims, &proof.section, &proof.base.proof.proof) catch |err| {
        if (err == error.OutOfMemory) return err;
        return;
    };
    capture.deinit(a);
    return error.ExpectedHybridCpuRejection;
}
test "outer GKR CPU physical proof receiver and mutations" {
    const old = Outer.protocol.active();
    Outer.protocol.selectForTesting(.m7_outer_gkr_k4_cap3_r1_b2_q108_p20_fold4_v1);
    defer Outer.protocol.selectForTesting(old);
    var ctx = try circuit.builder.Context(Outer.protocol.Q).init(a, 1);
    defer ctx.deinit();
    const x = try ctx.guess(Outer.protocol.Q.fromU32Unchecked(3, 1, 2, 4));
    const y = try ctx.guess(Outer.protocol.Q.fromU32Unchecked(7, 2, 3, 5));
    const product = try ctx.mul(x, y);
    try ctx.setOutputs(&.{product});
    try ctx.finalize(true);
    try circuit.common.finalize.padToTargets(Outer.protocol.Q, &ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var source = try Outer.prove.Authority.init(a, &pp);
    defer source.deinit();
    var key = try R.Key.init(a, &source, 256);
    defer key.deinit();
    const expected = [_]Outer.protocol.Q{Outer.protocol.Q.fromU32Unchecked(3, 1, 2, 4).mul(Outer.protocol.Q.fromU32Unchecked(7, 2, 3, 5))};
    var timer = try std.time.Timer.start();
    var proof = CPU.prove(a, &key, ctx.values(), &expected) catch |err| {
        std.debug.print("CPU_HYBRID_PRODUCE_FAILURE {s}\n", .{@errorName(err)});
        return err;
    };
    defer proof.deinit();
    const prove_ns = timer.lap();
    var independent = try R.Key.init(a, &source, 256);
    defer independent.deinit();
    var capture = independent.verify(a, proof.base.outputs, proof.base.claims, &proof.section, &proof.base.proof.proof) catch |err| {
        std.debug.print("CPU_HYBRID_RECEIVER_FAILURE {s}\n", .{@errorName(err)});
        return err;
    };
    defer capture.deinit(a);
    const verify_ns = timer.lap();
    const child_budget = try @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget.create(a, 8 << 30);
    defer child_budget.destroy();
    @import("child_verifier.zig").checkFixture(child_budget.allocator(), &independent, proof.base.outputs, proof.base.claims, &proof.section, &proof.base.proof.proof, &capture) catch |err| {
        std.debug.print("CPU_HYBRID_CHILD_CIRCUIT_FAILURE {s}\n", .{@errorName(err)});
        return err;
    };
    try std.testing.expectEqual(@as(usize, 0), child_budget.snapshot().live_bytes);
    {
        const domain = @import("cpu_domain.zig");
        domain.test_failure = .triple_xor;
        defer domain.test_failure = null;
        try std.testing.expectError(error.InjectedHybridDomainFailure, CPU.prove(a, &key, ctx.values(), &expected));
        var wrapper = try circuit.builder.Context(Outer.protocol.Q).init(a, 8);
        defer wrapper.deinit();
        var outputs: [8]circuit.builder.Var = undefined;
        for (&outputs) |*out| out.* = try wrapper.guess(Outer.protocol.Q.zero());
        try wrapper.setOutputs(&outputs);
        wrapper.finalize(true) catch |err| {
            std.debug.print("CPU_WRAPPER_FINALIZE_FAILURE {s}\n", .{@errorName(err)});
            return err;
        };
        if (@import("../rv64_recursion/om31_native/outer_wrap.zig").wrapGraph(a, &wrapper, @splat(0))) |success| {
            var unexpected = success;
            unexpected.deinit();
            return error.ExpectedInjectedDomainFailure;
        } else |err| {
            std.debug.print("CPU_WRAPPER_FAILURE_ATOMIC {s} outputs={}\n", .{ @errorName(err), wrapper.circuit.output.items.len });
            try std.testing.expectEqual(error.InjectedHybridDomainFailure, err);
        }
        domain.test_failure = null;
        const Wrap = @import("../rv64_recursion/om31_native/outer_wrap.zig");
        var wrapped = try Wrap.wrapGraph(a, &wrapper, @splat(0));
        const encoded = try wrapped.serialize(a);
        defer a.free(encoded);
        _ = wrapped.retireProverData();
        wrapped.deinit();
        var restored = try Wrap.wrapGraphOrLoad(a, &wrapper, @splat(0), encoded);
        _ = restored.retireProverData();
        restored.deinit();
    }
    // Equal-denominator +/-1 edits preserve the complete rational lookup
    // sum. A valid GKR for these false facts must still fail its MAIN binding.
    try std.testing.expectError(error.ConstraintsNotSatisfied, CPU.proveWithInputsForTesting(a, &key, ctx.values(), &expected, balancedFalseFacts));
    proof.base.outputs[0] = proof.base.outputs[0].add(Outer.protocol.Q.one());
    try rejected(&independent, &proof);
    proof.base.outputs[0] = proof.base.outputs[0].sub(Outer.protocol.Q.one());
    proof.base.claims.eq = proof.base.claims.eq.add(Outer.protocol.O.basis());
    try rejected(&independent, &proof);
    proof.base.claims.eq = proof.base.claims.eq.sub(Outer.protocol.O.basis());
    const salt = proof.section.salt;
    proof.section.salt = salt.add(Outer.protocol.O.one());
    try rejected(&independent, &proof);
    proof.section.salt = salt;
    const masks = &proof.base.proof.proof.commitment_scheme_proof.sampled_values.items[2][0][0];
    masks.* = masks.add(Outer.protocol.O.basis());
    try rejected(&independent, &proof);
    std.debug.print("OUTER_GKR_CPU_PROOF fresh_accepted=true interaction_columns=128 physical_mutants=4 prove_ns={} verify_ns={}\n", .{ prove_ns, verify_ns });
}
