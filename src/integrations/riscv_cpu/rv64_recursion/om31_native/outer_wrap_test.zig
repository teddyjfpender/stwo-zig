const std = @import("std");
const circuit = @import("stwo_circuit_frontend");
const Wrap = @import("outer_wrap.zig");
const C = @import("common.zig");
const Refusal = struct {
    calls: usize = 0,
    fn prepare(raw: *anyopaque, a: std.mem.Allocator, key: *const @import("stwo_circuit_cpu_integration").om31.prove.Authority, values: []const C.Q, scope: @import("stwo_prover_api").device_pcs.Scope) anyerror!Wrap.Device.Source {
        _ = a;
        const self: *Refusal = @ptrCast(@alignCast(raw));
        if (scope.ordinal != 42 or key.pp.n_outputs != 8 or values.len == 0) return error.BadGpuDispatch;
        self.calls += 1;
        return error.ExpectedGpuRefusal;
    }
};
test "OM31 native PCS outer wrapper produces actual proof fresh receiver bounded wire" {
    const a = std.testing.allocator;
    var ctx = try C.Context.init(a, circuit.common.component_list.N_RESERVED);
    defer ctx.deinit();
    const digest = [_]u8{0xa5} ** 32;
    var outputs: [8]circuit.builder.Var = undefined;
    for (0..8) |i| {
        const input = try ctx.guess(circuit.builder.ivalue.packU32(C.Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little)));
        outputs[i] = input;
    }
    try ctx.setOutputs(&outputs);
    try ctx.finalize(false);
    var refusal = Refusal{};
    const factory = Wrap.Device.Factory{ .context = &refusal, .prepare = Refusal.prepare };
    try std.testing.expectError(error.ExpectedGpuRefusal, Wrap.wrapGraphOrLoadWithFactory(a, &ctx, digest, null, 42, factory));
    try std.testing.expectEqual(@as(usize, 1), refusal.calls);
    var wrapped = try Wrap.wrapGraph(a, &ctx, digest);
    defer wrapped.deinit();
    const bytes = try wrapped.serialize(a);
    defer a.free(bytes);
    var decoded = try @import("stwo_circuit_cpu_integration").om31.wire.decode(a, wrapped.authority.identity, 8, bytes);
    defer decoded.deinit();
    var fresh = try @import("stwo_circuit_cpu_integration").om31.prove.verify(a, wrapped.authority, decoded.outputs, decoded.claims, &decoded.proof);
    defer fresh.deinit(a);
    var restored = try Wrap.wrapGraphOrLoad(a, &ctx, digest, bytes);
    defer restored.deinit();
    try std.testing.expect(restored.restored);
    try std.testing.expectEqual(@as(u64, 0), restored.timings.prove_ns);
    const replay = try restored.serialize(a);
    defer a.free(replay);
    try std.testing.expectEqualSlices(u8, bytes, replay);
    var receiver_graph = try C.Context.initTraceOnly(a, circuit.common.component_list.N_RESERVED);
    defer receiver_graph.deinit();
    var receiver_outputs: [8]circuit.builder.Var = undefined;
    for (&receiver_outputs, 0..) |*out, i| out.* = try receiver_graph.guess(circuit.builder.ivalue.packU32(C.Q, std.mem.readInt(u32, digest[4 * i ..][0..4], .little)));
    try receiver_graph.setOutputs(&receiver_outputs);
    try receiver_graph.finalize(false);
    var trace_restored = try Wrap.wrapGraphOrLoad(a, &receiver_graph, digest, bytes);
    defer trace_restored.deinit();
    try std.testing.expect(trace_restored.restored);
    try std.testing.expectEqual(@as(u64, 0), trace_restored.timings.prove_ns);
    try std.testing.expectEqual(@as(usize, 0), receiver_graph.value_table.capacity);
    try std.testing.expectEqual(wrapped.authority.identity, trace_restored.authority.identity);
    var device_selected_restore = try Wrap.wrapGraphOrLoadWithFactory(a, &ctx, digest, bytes, 99, factory);
    defer device_selected_restore.deinit();
    try std.testing.expect(device_selected_restore.restored);
    try std.testing.expectEqual(@as(usize, 1), refusal.calls);
    const mutant = try a.dupe(u8, bytes);
    defer a.free(mutant);
    mutant[40] ^= 1;
    try std.testing.expectError(error.Om31CircuitWireAuthority, Wrap.wrapGraphOrLoad(a, &ctx, digest, mutant));
    var bad = digest;
    bad[31] ^= 1;
    try std.testing.expectError(error.CurrentOm31OutputDigest, Wrap.requireDigest(decoded.outputs, bad));
    const root_before = wrapped.authority.fixedRoot();
    const identity_before = wrapped.authority.identity;
    try std.testing.expect(wrapped.retireProverData() > 0);
    try std.testing.expectEqual(@as(usize, 0), wrapped.retireProverData());
    try std.testing.expect(wrapped.authority.fixed == null);
    for (wrapped.pp.columns) |column| try std.testing.expectEqual(@as(usize, 0), column.values.len);
    try std.testing.expectEqual(root_before, wrapped.authority.fixedRoot());
    try std.testing.expectEqual(identity_before, wrapped.authority.identity);
    try std.testing.expectError(error.Om31CircuitProverDataRetired, @import("stwo_circuit_cpu_integration").om31.prove.prove(a, wrapped.authority, ctx.values()));
    var retired_fresh = try @import("stwo_circuit_cpu_integration").om31.prove.verify(a, wrapped.authority, decoded.outputs, decoded.claims, &decoded.proof);
    defer retired_fresh.deinit(a);
    const retired_bytes = try wrapped.serialize(a);
    defer a.free(retired_bytes);
    try std.testing.expectEqualSlices(u8, bytes, retired_bytes);

    {
        var failed = try C.Context.init(a, circuit.common.component_list.N_RESERVED);
        defer failed.deinit();
        try std.testing.expect(failed.value_table.capacity != 0);
        try std.testing.expectError(error.Om31CircuitProverDataRetired, @import("stwo_circuit_cpu_integration").om31.prove.proveDisposableContext(a, wrapped.authority, &failed));
        try std.testing.expectEqual(@as(usize, 0), failed.value_table.capacity);
    }
    var disposable = try Wrap.wrapDisposableCpuGraph(a, &ctx, digest, 0);
    defer disposable.deinit();
    const disposable_bytes = try disposable.serialize(a);
    defer a.free(disposable_bytes);
    try std.testing.expectEqualSlices(u8, bytes, disposable_bytes);
    try std.testing.expectEqual(@as(usize, 0), ctx.circuit.output.items.len);
    try std.testing.expectEqual(@as(usize, 0), ctx.value_table.capacity);
}
