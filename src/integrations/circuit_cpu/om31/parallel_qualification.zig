//! Actual outer proof parity across serial and bounded row-parallel evaluation.
const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const prover = @import("stwo_prover_engine");
const P = @import("protocol.zig");
const Outer = @import("prove.zig");
const Wire = @import("wire.zig");
test "om31 outer parallel domain has exact proof bytes and fresh acceptance" {
    const a = std.testing.allocator;
    var ctx = try circuit.builder.Context(P.Q).init(a, 1);
    defer ctx.deinit();
    const x = try ctx.guess(P.Q.fromU32Unchecked(3, 1, 2, 4));
    const y = try ctx.guess(P.Q.fromU32Unchecked(7, 2, 3, 5));
    try ctx.setOutputs(&.{try ctx.mul(x, y)});
    try ctx.finalize(true);
    try circuit.common.finalize.padToTargets(P.Q, &ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var authority = try Outer.Authority.init(a, &pp);
    defer authority.deinit();
    var timer = try std.time.Timer.start();
    var serial = try Outer.prove(a, &authority, ctx.values());
    defer serial.deinit();
    const serial_ns = timer.lap();
    var pool: prover.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 2 });
    defer pool.deinit();
    var binding = try prover.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var parallel_pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer parallel_pp.deinit(a);
    const expected_layout = pp.layout();
    const actual_layout = parallel_pp.layout();
    try std.testing.expect(expected_layout.eql(&actual_layout));
    for (pp.columns, parallel_pp.columns) |serial_column, parallel_column| {
        try std.testing.expectEqualStrings(serial_column.id, parallel_column.id);
        try std.testing.expectEqualSlices(core.fields.m31.M31, serial_column.values, parallel_column.values);
    }
    var parallel_authority = try Outer.Authority.init(a, &parallel_pp);
    defer parallel_authority.deinit();
    try std.testing.expectEqualSlices(u8, &authority.fixedRoot(), &parallel_authority.fixedRoot());
    try std.testing.expectEqualSlices(u8, &authority.identity, &parallel_authority.identity);
    timer.reset();
    var parallel = try Outer.prove(a, &parallel_authority, ctx.values());
    defer parallel.deinit();
    const parallel_ns = timer.lap();
    const expected = try Wire.encode(a, authority.identity, serial.outputs, serial.claims, &serial.proof.proof);
    defer a.free(expected);
    const actual = try Wire.encode(a, authority.identity, parallel.outputs, parallel.claims, &parallel.proof.proof);
    defer a.free(actual);
    try std.testing.expectEqualSlices(u8, expected, actual);
    var capture = try Outer.verify(a, &authority, parallel.outputs, parallel.claims, &parallel.proof.proof);
    defer capture.deinit(a);
    std.debug.print("OM31_OUTER_DOMAIN_PARITY workers=2 exact_bytes=true fresh_accepted=true serial_ns={} parallel_ns={}\n", .{ serial_ns, parallel_ns });
}
