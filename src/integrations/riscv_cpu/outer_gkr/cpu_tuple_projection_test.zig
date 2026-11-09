const std = @import("std");
const core = @import("stwo_core");
const circuit = @import("stwo_circuit_frontend");
const engine = @import("stwo_prover_engine");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Packed = @import("cpu_tuple_projection.zig");
const W = @import("cpu_witness.zig");
const P = @import("profile.zig");
const M = core.fields.m31.M31;
const O = core.fields.om31.OM31;
const a = std.testing.allocator;

fn word(seed: usize) O {
    var coordinates: [8]M = undefined;
    for (&coordinates, 0..) |*v, c| v.* = M.fromU64(17 + seed * 131 + c * 61);
    return O.fromM31Array(coordinates);
}

test "outer GKR packed tuple projection preserves all eight coordinates and widths" {
    const scalar = Outer.witness.Elements.init(word(1), word(3));
    const simd = Packed.Elements.init(&scalar);
    for (0..circuit.witness.components.MAX_TUPLE + 1) |len| {
        var rows: Packed.Rows = undefined;
        for (&rows, 0..) |*row, r| {
            row[0] = .{ .len = @intCast(len), .numerator = M.fromU64(r) };
            for (row[0].tuple[0..len], 0..) |*v, c|
                v.* = if (c == 2 or (r + c) % 3 == 0) M.zero() else M.fromU64(991 * r + c * 71);
        }
        const actual = try simd.combine(&rows, 0);
        for (rows, 0..) |row, r|
            try std.testing.expect(scalar.combine(row[0].values()).eql(core.fields.packed_om31.lane(actual, r)));
        if (Packed.LANES > 1) {
            rows[1][0].len = @intCast(len + 1);
            try std.testing.expectError(error.OuterGkrTupleShape, simd.combine(&rows, 0));
        }
    }
}

fn mainDigest(base: *const circuit.witness.trace.BaseTrace) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    for (base.columns) |column| h.update(std.mem.sliceAsBytes(column.values));
    return h.finalResult();
}

test "outer GKR SIMD raw source inputs match scalar authority across lane groups and pools" {
    var ctx = try circuit.builder.Context(Outer.protocol.Q).init(a, 1);
    defer ctx.deinit();
    const x = try ctx.guess(Outer.protocol.Q.fromU32Unchecked(3, 1, 2, 4));
    try ctx.setOutputs(&.{try ctx.mul(x, x)});
    try ctx.finalize(true);
    try circuit.common.finalize.padToTargets(Outer.protocol.Q, &ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&ctx.circuit)));
    var pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &ctx.circuit);
    defer pp.deinit(a);
    var base = try circuit.witness.trace.writeTrace(a, ctx.values(), &pp);
    defer base.deinit();
    const before = mainDigest(&base);
    const raw = try circuit.witness.trace.RawLookupRows.init(base.columns, &pp);
    var logs: [P.N_COMPONENTS]u8 = undefined;
    for (&logs, base.log_sizes.toArray()) |*out, log| out.* = @intCast(log);
    var storage: [P.MAX_INSTANCES]P.Instance = undefined;
    const instances = try P.instancesFor(logs, &storage);
    // Receiver-admitted classes may have padding lanes even though today's
    // binary-decomposed production roster uses every lane. Check both owners.
    storage[0].lane_log += 1;
    const class = P.Class{ .id = 0, .name = "source projection test", .row_logs = logs, .instances = instances };
    const elements = Outer.witness.Elements.init(word(7), word(19));
    var reference = try W.inputsReference(a, &class, &raw, &elements);
    defer reference.deinit(a);
    for ([_]usize{ 0, 2, 3 }) |workers| {
        var pool: engine.work_pool.WorkPool = undefined;
        var binding: ?engine.work_pool.ScopedPoolBinding = null;
        if (workers != 0) {
            try pool.initInPlaceWithOptions(.{ .worker_count = workers });
            binding = try engine.work_pool.ScopedPoolBinding.init(&pool);
        }
        defer if (binding) |*owned| {
            owned.deinit();
            pool.deinit();
        };
        var actual = try W.inputs(a, &class, &raw, &elements);
        defer actual.deinit(a);
        for (reference.numerators, actual.numerators) |expected, found|
            try std.testing.expectEqualSlices(M, expected, found);
        for (reference.denominators, actual.denominators) |expected, found|
            try std.testing.expectEqualSlices(O, expected, found);
        try std.testing.expectEqual(before, mainDigest(&base));
    }
}
