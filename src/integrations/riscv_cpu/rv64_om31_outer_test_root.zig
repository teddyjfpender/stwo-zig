const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Bridge = @import("rv64_recursion/om31_outer.zig");
test "om31 outer bridge actual child verifies in shared lane" {
    const a = std.testing.allocator;
    var ctx = try circuit.builder.Context(Outer.protocol.Q).init(a, 8);
    defer ctx.deinit();
    var outputs: [8]circuit.builder.Var = undefined;
    for (&outputs, 0..) |*out, i| out.* = try ctx.guess(Outer.protocol.Q.fromU32Unchecked(@intCast(i + 3), 0, 0, 0));
    try ctx.setOutputs(&outputs);
    try ctx.finalize(true);
    try circuit.common.finalize.padToTargets(Outer.protocol.Q, &ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var authority = try Outer.prove.Authority.init(a, &pp);
    defer authority.deinit();
    std.debug.print("OUTER leaf key ready\n", .{});
    var produced = try Outer.prove.prove(a, &authority, ctx.values());
    defer produced.deinit();
    var capture = try Outer.prove.verify(a, &authority, produced.outputs, produced.claims, &produced.proof.proof);
    defer capture.deinit(a);
    authority.retireProverData();
    try std.testing.expect(authority.fixed == null);
    try std.testing.expectError(error.Om31CircuitProverDataRetired, Outer.prove.prove(a, &authority, ctx.values()));
    const child = Bridge.Child{ .authority = &authority, .produced = &produced, .capture = &capture };
    produced.outputs[0] = produced.outputs[0].add(Outer.protocol.Q.one());
    try std.testing.expectError(error.EqFailedOnEval, Bridge.buildFold(a, .{ child, child }));
    produced.outputs[0] = produced.outputs[0].sub(Outer.protocol.Q.one());
    produced.proof.proof.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    try std.testing.expectError(error.EqFailedOnEval, Bridge.buildFold(a, .{ child, child }));
    produced.proof.proof.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    produced.claims.eq = produced.claims.eq.add(Outer.protocol.O.basis());
    try std.testing.expectError(error.EqFailedOnEval, Bridge.buildFold(a, .{ child, child }));
    produced.claims.eq = produced.claims.eq.sub(Outer.protocol.O.basis());
    std.debug.print("OUTER leaf proved/verified; building fold\n", .{});
    var graph = try Bridge.buildFold(a, .{ child, child });
    defer graph.deinit();
    std.debug.print("OUTER graph built; checking gates\n", .{});
    {
        var trace = try Bridge.buildFoldTraceOnly(a, .{ child, child });
        defer trace.deinit();
        try std.testing.expectEqualDeep(graph.ctx.circuit, trace.ctx.circuit);
        try std.testing.expectEqual(@as(usize, 0), trace.ctx.value_table.capacity);
        var plan = try circuit.builder.witness_plan.build(a, &trace.ctx);
        defer plan.deinit();
        const values = try circuit.builder.witness_plan.evaluate(a, &trace.ctx, plan);
        defer a.free(values);
        try std.testing.expectEqualDeep(graph.ctx.values(), values);
    }
    if (try graph.ctx.circuit.check(a, graph.ctx.values())) |failure| {
        std.debug.print("OUTER failure={any}\n", .{failure});
        return error.InvalidOuterGraph;
    }
    try std.testing.expectEqual(try Bridge.expectedDigest(.{ child, child }), graph.output_digest);
    const graph_only = std.process.hasEnvVarConstant("STWO_OM31_OUTER_GRAPH_ONLY");
    if (graph_only) return;
    const Q = Outer.protocol.Q;
    try circuit.common.finalize.padToTargets(Q, &graph.ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&graph.ctx.circuit)));
    var root_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &graph.ctx.circuit);
    defer root_pp.deinit(a);
    var root_key = try Outer.prove.Authority.init(a, &root_pp);
    defer root_key.deinit();
    std.debug.print("OUTER proving folded root\n", .{});
    var root = try Outer.prove.prove(a, &root_key, graph.ctx.values());
    defer root.deinit();
    var root_capture = try Outer.prove.verify(a, &root_key, root.outputs, root.claims, &root.proof.proof);
    defer root_capture.deinit(a);
    for (root.outputs, 0..) |actual, i| {
        const value = std.mem.readInt(u32, graph.output_digest[4 * i ..][0..4], .little);
        try std.testing.expectEqual(circuit.builder.wrappers.u32Value(Q, value).get(), actual);
    }
    const encoded = try Outer.wire.encode(a, root_key.identity, root.outputs, root.claims, &root.proof.proof);
    defer a.free(encoded);
    var decoded = try Outer.wire.decode(a, root_key.identity, 8, encoded);
    defer decoded.deinit();
    var fresh = try Outer.prove.verify(a, &root_key, decoded.outputs, decoded.claims, &decoded.proof);
    defer fresh.deinit(a);
    decoded.outputs[0] = decoded.outputs[0].add(Q.one());
    if (Outer.prove.verify(a, &root_key, decoded.outputs, decoded.claims, &decoded.proof)) |bad| {
        var owned = bad;
        owned.deinit(a);
        return error.ExpectedRootTamperRejection;
    } else |err| if (err == error.OutOfMemory) return err;
    std.debug.print("OM31_FOLD_ROOT fresh_accepted=true child_count=2 native_wire_roundtrip=true output_tamper_rejected=true bytes={}\n", .{encoded.len});
}
