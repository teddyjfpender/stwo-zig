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
    try std.testing.expectError(error.EqFailedOnEval, Bridge.buildFold(a, &.{ child, child }));
    produced.outputs[0] = produced.outputs[0].sub(Outer.protocol.Q.one());
    produced.proof.proof.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    try std.testing.expectError(error.EqFailedOnEval, Bridge.buildFold(a, &.{ child, child }));
    produced.proof.proof.commitment_scheme_proof.commitments.items[0][0] ^= 1;
    produced.claims.eq = produced.claims.eq.add(Outer.protocol.O.basis());
    try std.testing.expectError(error.EqFailedOnEval, Bridge.buildFold(a, &.{ child, child }));
    produced.claims.eq = produced.claims.eq.sub(Outer.protocol.O.basis());
    std.debug.print("OUTER leaf proved/verified; building fold\n", .{});
    var graph = try Bridge.buildFold(a, &.{ child, child });
    defer graph.deinit();
    std.debug.print("OUTER graph built; checking gates\n", .{});
    {
        var trace = try Bridge.buildFoldTraceOnly(a, &.{ child, child });
        defer trace.deinit();
        try std.testing.expectEqualDeep(graph.ctx.circuit, trace.ctx.circuit);
        try std.testing.expectEqual(@as(usize, 0), trace.ctx.value_table.capacity);
        var plan = try circuit.builder.witness_plan.build(a, &trace.ctx);
        defer plan.deinit();
        var reference = try circuit.builder.witness_plan.buildDfsReference(a, &trace.ctx);
        defer reference.deinit();
        try std.testing.expectEqualDeep(reference.tasks, plan.tasks);
        try std.testing.expectEqualDeep(reference.seeds, plan.seeds);
        try std.testing.expectEqualSlices(usize, reference.level_ends, plan.level_ends);
        const values = try circuit.builder.witness_plan.evaluate(a, &trace.ctx, plan);
        defer a.free(values);
        try std.testing.expectEqualDeep(graph.ctx.values(), values);
    }
    if (try graph.ctx.circuit.check(a, graph.ctx.values())) |failure| {
        std.debug.print("OUTER failure={any}\n", .{failure});
        return error.InvalidOuterGraph;
    }
    try std.testing.expectEqual(try Bridge.expectedDigest(&.{ child, child }), graph.output_digest);
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

const Child = struct {
    ctx: circuit.builder.Context(Outer.protocol.Q),
    pp: circuit.common.preprocessed.PreprocessedCircuit,
    authority: Outer.prove.Authority,
    produced: Outer.prove.Produced,
    capture: Outer.prove.Capture,
    fn init(self: *Child, a: std.mem.Allocator, constant: u32) !void {
        const Q = Outer.protocol.Q;
        self.ctx = try circuit.builder.Context(Q).init(a, 8);
        var outputs: [8]circuit.builder.Var = undefined;
        // Same gate shape for every `constant`; only a constant VALUE differs,
        // so PP/FIXED root/identity differ while row logs stay equal.
        for (&outputs, 0..) |*out, i| out.* = try self.ctx.add(try self.ctx.guess(Q.fromU32Unchecked(@intCast(i + 3), 0, 0, 0)), try self.ctx.constant(Q.fromU32Unchecked(constant + @as(u32, @intCast(i)), 0, 0, 0)));
        try self.ctx.setOutputs(&outputs);
        try self.ctx.finalize(true);
        try circuit.common.finalize.padToTargets(Q, &self.ctx, circuit.common.finalize.computePaddedSizes(.fromBuilder(&self.ctx.circuit)));
        self.pp = try circuit.common.preprocessed.PreprocessedCircuit.fromBuilderCircuit(a, &self.ctx.circuit);
        self.authority = try Outer.prove.Authority.init(a, &self.pp);
        self.produced = try Outer.prove.prove(a, &self.authority, self.ctx.values());
        self.capture = try Outer.prove.verify(a, &self.authority, self.produced.outputs, self.produced.claims, &self.produced.proof.proof);
    }
    fn deinit(self: *Child, a: std.mem.Allocator) void {
        self.capture.deinit(a);
        self.produced.deinit();
        self.authority.deinit();
        self.pp.deinit(a);
        self.ctx.deinit();
    }
    fn child(self: *const Child) Bridge.Child {
        return .{ .authority = &self.authority, .produced = &self.produced, .capture = &self.capture };
    }
};

test "om31 fold v2 topology is proof-independent and digest binds child keys" {
    const a = std.testing.allocator;
    var first: Child = undefined;
    try first.init(a, 1000);
    defer first.deinit(a);
    var second: Child = undefined;
    try second.init(a, 2000);
    defer second.deinit(a);
    // Distinct child keys of one geometry class.
    try std.testing.expect(!std.mem.eql(u8, &first.authority.fixedRoot(), &second.authority.fixedRoot()));
    try std.testing.expect(!std.mem.eql(u8, &first.authority.identity, &second.authority.identity));
    try std.testing.expectEqual(first.authority.logs, second.authority.logs);
    const c1 = first.child();
    const c2 = second.child();
    try std.testing.expectEqual(try Bridge.classKey(&.{ c1, c1 }), try Bridge.classKey(&.{ c2, c2 }));
    try std.testing.expectEqual(try Bridge.classKey(&.{ c1, c2 }), try Bridge.classKey(&.{ c2, c1 }));
    var g11 = try Bridge.buildFoldTraceOnly(a, &.{ c1, c1 });
    defer g11.deinit();
    var g22 = try Bridge.buildFoldTraceOnly(a, &.{ c2, c2 });
    defer g22.deinit();
    var g12 = try Bridge.buildFoldTraceOnly(a, &.{ c1, c2 });
    defer g12.deinit();
    // v2: identical topology (gates AND interned constant table), hence an
    // identical PP / FIXED root / authority for every fold of this class.
    try std.testing.expectEqualDeep(g11.ctx.circuit, g22.ctx.circuit);
    try std.testing.expectEqualDeep(g11.ctx.circuit, g12.ctx.circuit);
    try std.testing.expectEqualSlices(u128, g11.ctx.constants.keys(), g22.ctx.constants.keys());
    try std.testing.expectEqualSlices(u128, g11.ctx.constants.keys(), g12.ctx.constants.keys());
    // ...while the public digest binds the specific child keys: a key swap
    // (c2 presented where the receiver trusts c1) yields a different digest.
    const d11 = try Bridge.expectedDigest(&.{ c1, c1 });
    const d12 = try Bridge.expectedDigest(&.{ c1, c2 });
    const d22 = try Bridge.expectedDigest(&.{ c2, c2 });
    try std.testing.expectEqual(d11, g11.output_digest);
    try std.testing.expectEqual(d12, g12.output_digest);
    try std.testing.expect(!std.mem.eql(u8, &d11, &d12));
    try std.testing.expect(!std.mem.eql(u8, &d11, &d22));
    // Full-value build: the in-circuit digest wires equal the receiver digest.
    var full = try Bridge.buildFold(a, &.{ c1, c2 });
    defer full.deinit();
    try std.testing.expectEqualDeep(g12.ctx.circuit, full.ctx.circuit);
    if (try full.ctx.circuit.check(a, full.ctx.values())) |failure| {
        std.debug.print("FOLD_V2 failure={any}\n", .{failure});
        return error.InvalidOuterGraph;
    }
    var circuit_digest: [32]u8 = undefined;
    for (full.ctx.circuit.output.items[1..9], 0..) |out, i| std.mem.writeInt(u32, circuit_digest[4 * i ..][0..4], circuit.builder.ivalue.unpackU32(Outer.protocol.Q, full.ctx.values()[out]), .little);
    try std.testing.expectEqual(d12, circuit_digest);
    // A child proof presented under a different key's identity is rejected
    // by the child's own in-circuit transcript (identity is absorbed there).
    const swapped = Bridge.Child{ .authority = &second.authority, .produced = &first.produced, .capture = &first.capture };
    try std.testing.expectError(error.EqFailedOnEval, Bridge.buildFold(a, &.{ swapped, c1 }));
}

// M6 hint-tape (HT1): the fold seed tape, recorded without the verifier body,
// equals the full trace-only graph's seed origins value-for-value, and the
// constant VALUES of a v2 fold class do not depend on the child keys.
test "om31 fold seed tape equals graph seeds and class constants are key independent" {
    const a = std.testing.allocator;
    const Tape = @import("rv64_recursion/om31_native/fold_tape.zig");
    var first: Child = undefined;
    try first.init(a, 1000);
    defer first.deinit(a);
    var second: Child = undefined;
    try second.init(a, 2000);
    defer second.deinit(a);
    const c1 = first.child();
    const c2 = second.child();
    const pairs = [_][2]Bridge.Child{ .{ c1, c1 }, .{ c1, c2 }, .{ c2, c1 }, .{ c2, c2 } };
    var reference_constants: ?[]const u128 = null;
    var graphs: [pairs.len]Bridge.Graph = undefined;
    var built: usize = 0;
    defer for (graphs[0..built]) |*g| g.deinit();
    for (pairs, 0..) |pair, i| {
        graphs[i] = try Bridge.buildFoldTraceOnly(a, &pair);
        built += 1;
        const tape = try Tape.record(a, &pair);
        defer a.free(tape);
        try std.testing.expect(tape.len > 0);
        try Tape.compare(a, tape, &graphs[i].ctx);
        // Constants (keys ARE the values) and their variables are class data.
        if (reference_constants) |keys| {
            try std.testing.expectEqualSlices(u128, keys, graphs[i].ctx.constants.keys());
            for (graphs[0].ctx.constants.values(), graphs[i].ctx.constants.values()) |x, y| try std.testing.expectEqual(x.idx, y.idx);
        } else reference_constants = graphs[i].ctx.constants.keys();
    }
    // A tape of other children differs (the values are per node).
    const t11 = try Tape.record(a, &pairs[0]);
    defer a.free(t11);
    const t22 = try Tape.record(a, &pairs[3]);
    defer a.free(t22);
    try std.testing.expectEqual(t11.len, t22.len);
    try std.testing.expect(!std.mem.eql(u8, std.mem.sliceAsBytes(t11), std.mem.sliceAsBytes(t22)));
    try std.testing.expectError(error.FoldSeedTapeMismatch, Tape.compare(a, t22, &graphs[0].ctx));
}
