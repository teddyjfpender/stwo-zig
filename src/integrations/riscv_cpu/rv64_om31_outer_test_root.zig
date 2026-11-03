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
    const child = Bridge.Child{ .authority = &authority, .produced = &produced, .capture = &capture };
    std.debug.print("OUTER leaf proved/verified; building fold\n", .{});
    var graph = try Bridge.buildFold(a, .{ child, child });
    defer graph.deinit();
    std.debug.print("OUTER graph built; checking gates\n", .{});
    if (try graph.ctx.circuit.check(a, graph.ctx.values())) |failure| {
        std.debug.print("OUTER failure={any}\n", .{failure});
        return error.InvalidOuterGraph;
    }
    try std.testing.expectEqual(try Bridge.expectedDigest(.{ child, child }), graph.output_digest);
}
