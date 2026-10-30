//! Genuine mixed-family originals, independently admitted metadata and exact
//! deterministic live rows under serial/parallel preparation. No public receipt
//! substitutes for fresh original captures in either route.
const std = @import("std");
const engine = @import("stwo_prover_engine");
const Fixture = @import("../prover/block_v7_execution_caller_test_v1.zig");
const Metadata = @import("block_v7_mixed_metadata_v1.zig");
const Collection = @import("block_v7_mixed_collection_v1.zig");
const Cold = @import("block_v7_mixed_fixed_v1.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Mixed = @import("block_v7_mixed_preparation_v1.zig");
pub fn equal(input: @import("block_v7_mixed_inputs_v1.zig").Input, left: *Mixed.Prepared, right: *Mixed.Prepared) !void {
    try std.testing.expectEqualDeep(left.wires, right.wires);
    try std.testing.expectEqualDeep(left.expected, right.expected);
    try std.testing.expectEqualDeep(left.recursive.context, right.recursive.context);
    var canonical = try @import("block_v7_mixed_inputs_v1.zig").Owned.init(std.testing.allocator, input);
    defer canonical.deinit();
    try canonical.requireSame(left.values());
    try canonical.requireSame(right.values());
    inline for (0..Storage.Airs.len) |i| {
        try std.testing.expectEqualDeep(left.recursive.rows.fixed[i], right.recursive.rows.fixed[i]);
        try std.testing.expectEqual(left.recursive.rows.main[i].len, right.recursive.rows.main[i].len);
        for (left.recursive.rows.main[i], right.recursive.rows.main[i]) |x, y| {
            try std.testing.expectEqual(x.log_size, y.log_size);
            try std.testing.expectEqualDeep(x.values, y.values);
        }
    }
}
const Protocol = @import("block_v7_mixed_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
pub fn prove(a: std.mem.Allocator, ready: *Mixed.Prepared, key: Protocol.Key) ![]u8 {
    const admission = try Protocol.Admission.init(key, try key.identity(), ready.wires, ready.values(), ready.expected);
    const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(@import("stwo_cpu_backend").CpuBackend, Protocol);
    const plan = try Plan.init(a, &ready.recursive.rows, admission);
    defer plan.deinit();
    var proof = try plan.prove(a, &ready.recursive.rows);
    defer proof.deinit();
    return Parent.codec.encode(a, &proof, &admission);
}
const Consumer = struct {
    pub const Result = void;
    pub fn consume(f: Fixture.Fixture) !void {
        const a = f.allocator;
        const metadata = try Metadata.Owned.init(a, f.trusted, f.input);
        defer metadata.deinit();
        const input = metadata.input();
        const count = try input.count();
        var cold = try Cold.Owned.derive(a, input, 2, .{});
        defer cold.deinit();
        var serial = try Collection.prepareWindow(a, f.input, input, 0, count, .{});
        defer serial.deinit();
        try cold.validateLive(&serial);
        const base = try Parent.ForBackend(@import("stwo_cpu_backend").CpuBackend).deriveKeyFromFixed(a, cold.fixed, cold.context, .diagnostic_q8_pow0);
        const key = try Protocol.Key.fromGeometry(base, cold.wires, cold.expected);
        const serial_bytes = try prove(a, &serial, key);
        defer a.free(serial_bytes);
        for ([_]usize{ 2, 4 }) |width| {
            var parallel = try Collection.prepareWindow(a, f.input, input, 0, count, .{ .parallel_preparation = width });
            defer parallel.deinit();
            try cold.validateLive(&parallel);
            try equal(input, &serial, &parallel);
            if (width == 4) {
                const bytes = try prove(a, &parallel, key);
                defer a.free(bytes);
                try std.testing.expectEqualSlices(u8, serial_bytes, bytes);
                var received = try @import("block_v7_mixed_receiver_v1.zig").verify(a, bytes, f.trusted, input, key, cold.wires, .{});
                defer received.deinit();
                try std.testing.expectEqualDeep(f.original.statement, received.summary.statement);
                try std.testing.expectEqual(f.original.cycles, received.summary.cycles);
            }
        }
        // Partial successfully prepared families must all release after a
        // genuine malformed original is rejected by its fresh verifier.
        var broken = f.input;
        var proof = f.input.program.*;
        proof.claim = proof.claim.add(@import("stwo_core").fields.qm31.QM31.one());
        broken.program = &proof;
        const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 8 << 30);
        defer budget.destroy();
        var accepted = Collection.prepareWindow(budget.allocator(), broken, input, 0, count, .{ .parallel_preparation = 4 }) catch {
            try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
            return;
        };
        accepted.deinit();
        return error.AcceptedMalformedOriginal;
    }
};
test "parallel preparation genuine families canonical cold live rows and rejection cleanup" {
    try Fixture.runFixture(true, true, Consumer);
}
