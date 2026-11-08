//! Two real OM31 proofs over synthetic OD/OP public values. This tests the
//! fold's public wire binding, not Kona derivation or OP execution semantics.
const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const engine = @import("stwo_prover_engine");
const Outer = @import("stwo_circuit_cpu_integration").om31;
const Bridge = @import("rv64_recursion/om31_outer.zig");
const Q = Outer.protocol.Q;
const B = circuit.builder;
const PP = circuit.common.preprocessed.PreprocessedCircuit;

const derivation = "79dc71b2ef04d3b09ab72857909758cc2d94b77d82907b8568d187e7b529ba72010a000000000000004f44";
const execution = "a1070315845855c79cb5c43f2782fa954672205424a5b42a47d1962a0ca2a9ca010a000000000000004f50";

fn packet(hex: []const u8) ![11]Q {
    var bytes: [44]u8 = @splat(0);
    _ = try std.fmt.hexToBytes(bytes[0..43], hex);
    var outputs: [11]Q = undefined;
    for (&outputs, 0..) |*out, i| {
        out.* = B.wrappers.u32Value(Q, std.mem.readInt(u32, bytes[4 * i ..][0..4], .little)).get();
    }
    return outputs;
}

fn pad(ctx: *B.Context(Q)) !void {
    const f = circuit.common.finalize;
    try f.padToTargets(Q, ctx, f.computePaddedSizes(.fromBuilder(&ctx.circuit)));
}

const Child = struct {
    pp: PP,
    key: Outer.prove.Authority,
    proof: Outer.prove.Produced,
    capture: Outer.prove.Capture,

    fn make(a: std.mem.Allocator, values: []const Q) !*Child {
        const child = try a.create(Child);
        errdefer a.destroy(child);
        var ctx = try B.Context(Q).init(a, values.len);
        defer ctx.deinit();
        const outputs = try a.alloc(B.Var, values.len);
        defer a.free(outputs);
        for (outputs, values) |*out, value| out.* = try ctx.constant(value);
        try ctx.setOutputs(outputs);
        try ctx.finalize(true);
        try pad(&ctx);
        child.pp = try PP.fromBuilderCircuit(a, &ctx.circuit);
        errdefer child.pp.deinit(a);
        child.key = try Outer.prove.Authority.init(a, &child.pp);
        errdefer child.key.deinit();
        child.proof = try Outer.prove.prove(a, &child.key, ctx.values());
        errdefer child.proof.deinit();
        child.capture = try Outer.prove.verify(a, &child.key, child.proof.outputs, child.proof.claims, &child.proof.proof.proof);
        child.key.retireProverData();
        return child;
    }

    fn view(self: *const Child) Bridge.Child {
        return .{ .authority = &self.key, .produced = &self.proof, .capture = &self.capture };
    }

    fn deinit(self: *Child, a: std.mem.Allocator) void {
        self.capture.deinit(a);
        self.proof.deinit();
        self.key.deinit();
        self.pp.deinit(a);
        a.destroy(self);
    }
};

fn buildFixture(a: std.mem.Allocator, children: *const [2]Bridge.Child, trace_only: bool) !Bridge.Graph {
    var graph = try Bridge.buildPublicBinaryFold(a, children, trace_only);
    errdefer graph.deinit();
    try pad(&graph.ctx);
    std.debug.print("OP_PUBLIC_FOLD_SHAPE trace_only={} variables={d} blake_g_rows={d} qm31_rows={d}\n", .{
        trace_only, graph.ctx.circuit.n_vars, graph.ctx.circuit.blake_g_gate.items.len, graph.ctx.circuit.nQm31OpsRows(),
    });
    return graph;
}

test "public binary fold proves synthetic ordered OD and OP outputs" {
    const base = std.heap.smp_allocator;
    const max_bytes = if (std.posix.getenv("STWO_OP_FOLD_MAX_BYTES")) |raw|
        try std.fmt.parseUnsigned(usize, raw, 10)
    else
        32 << 30;
    const budget = try engine.host_budget_allocator.SharedHostBudget.create(base, max_bytes);
    defer budget.destroy();
    const a = budget.allocator();
    const old_profile = Outer.protocol.active();
    defer Outer.protocol.selectForTesting(old_profile);
    Outer.protocol.selectForTesting(.r1_b2_q108_p20_fold4);
    const od = try packet(derivation);
    const op = try packet(execution);
    const derivation_child = try Child.make(a, &od);
    defer derivation_child.deinit(a);
    const execution_child = try Child.make(a, &op);
    defer execution_child.deinit(a);
    const children = [2]Bridge.Child{ derivation_child.view(), execution_child.view() };
    const expected = [2][]const Q{ &od, &op };
    const expected_digest = try Bridge.expectedDigest(&children);
    try std.testing.expect(!std.meta.eql(expected_digest, try Bridge.expectedDigest(&.{ children[1], children[0] })));

    const encoded, const key_identity = blk: {
        var graph = try buildFixture(a, &children, false);
        defer graph.deinit();
        try std.testing.expectEqual(expected_digest, graph.output_digest);
        var pp = try PP.fromBuilderCircuit(a, &graph.ctx.circuit);
        defer pp.deinit(a);
        var key = try Outer.prove.Authority.init(a, &pp);
        defer key.deinit();
        var root = try Outer.prove.prove(a, &key, graph.ctx.values());
        defer root.deinit();
        break :blk .{ try Outer.wire.encode(a, key.identity, root.outputs, root.claims, &root.proof.proof), key.identity };
    };
    defer a.free(encoded);

    var trace = try buildFixture(a, &children, true);
    defer trace.deinit();
    try std.testing.expectEqual(@as(usize, 0), trace.ctx.value_table.capacity);
    var pp = try PP.fromBuilderCircuit(a, &trace.ctx.circuit);
    defer pp.deinit(a);
    var key = try Outer.prove.Authority.init(a, &pp);
    defer key.deinit();
    try std.testing.expectEqual(key_identity, key.identity);
    var decoded = try Outer.wire.decode(a, key.identity, 8 + od.len + op.len, encoded);
    defer decoded.deinit();
    var captured = try Outer.prove.verify(a, &key, decoded.outputs, decoded.claims, &decoded.proof);
    defer captured.deinit(a);
    try Bridge.requirePublicBinaryOutputs(decoded.outputs, expected_digest, expected);
    try std.testing.expectError(error.ApplicationFoldOutputMismatch, Bridge.requirePublicBinaryOutputs(decoded.outputs, expected_digest, .{ &op, &od }));
    var changed = op;
    changed[0] = changed[0].add(Q.one());
    try std.testing.expectError(error.ApplicationFoldOutputMismatch, Bridge.requirePublicBinaryOutputs(decoded.outputs, expected_digest, .{ &od, &changed }));
    decoded.outputs[8] = decoded.outputs[8].add(Q.one());
    if (Outer.prove.verify(a, &key, decoded.outputs, decoded.claims, &decoded.proof)) |bad| {
        var capture = bad;
        capture.deinit(a);
        return error.ExpectedFoldProofRejection;
    } else |err| if (err == error.OutOfMemory) return err;
    std.debug.print("OP_PUBLIC_FOLD_ROOT fixture=synthetic wire_bytes={d} accepted=true\n", .{encoded.len});
}
