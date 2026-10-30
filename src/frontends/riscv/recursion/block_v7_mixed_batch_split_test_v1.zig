const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Fixture = @import("../prover/block_v7_execution_caller_test_v1.zig");
const Metadata = @import("block_v7_mixed_metadata_v1.zig");
const Inputs = @import("block_v7_mixed_inputs_v1.zig");
const Direct = @import("block_v7_mixed_protocol_v1.zig");
const Cold = @import("block_v7_mixed_fixed_v1.zig");
const Collect = @import("block_v7_mixed_collection_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Reduce = @import("block_v7_mixed_batch_producer_v1.zig");
const Receive = @import("block_v7_mixed_batch_receiver_v1.zig");
const counts = [_]u32{ 5, 1 };
const Output = struct {
    metadata: *Metadata.Owned,
    proofs: [2][]u8,
    pins: [2]Receive.DirectPin,
    fn deinit(self: *Output) void {
        const a = self.metadata.allocator;
        for (self.proofs, self.pins) |bytes, pin| {
            a.free(bytes);
            a.free(pin.wires);
        }
        self.metadata.deinit();
    }
};
const Consumer = struct {
    pub const Result = Output;
    pub fn consume(f: Fixture.Fixture) !Output {
        const a = f.allocator;
        const metadata = try Metadata.Owned.init(a, f.trusted, f.input);
        errdefer metadata.deinit();
        var result: Output = .{ .metadata = metadata, .proofs = @splat(&.{}), .pins = undefined };
        var done: usize = 0;
        errdefer for (0..done) |i| {
            a.free(result.proofs[i]);
            a.free(result.pins[i].wires);
        };
        var first: usize = 0;
        for (counts, 0..) |count, i| {
            var cold = try Cold.Owned.deriveWindow(a, metadata.input(), first, count, 64, 2, .{});
            defer cold.deinit();
            var ready = try Collect.prepareWindow(a, f.input, metadata.input(), first, count, .{});
            defer ready.deinit();
            try cold.validateLive(&ready);
            const base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, cold.fixed, cold.context, .diagnostic_q8_pow0);
            const key = try Direct.Key.fromGeometry(base, cold.wires, cold.expected);
            const admission = try Direct.Admission.init(key, try key.identity(), cold.wires, ready.values(), cold.expected);
            const Plan = @import("blake3_native_parent_producer.zig").PlanForProtocol(Cpu, Direct);
            const plan = try Plan.init(a, &ready.recursive.rows, admission);
            defer plan.deinit();
            var proof = try plan.prove(a, &ready.recursive.rows);
            defer proof.deinit();
            const bytes = try Parent.codec.encode(a, &proof, &admission);
            errdefer a.free(bytes);
            const wires = try a.dupe(@import("block_v7_mixed_public_v1.zig").Wire, cold.wires);
            result.proofs[i] = bytes;
            result.pins[i] = .{ .key = key, .wires = wires };
            done += 1;
            first += count;
            std.debug.print("V7_SPLIT_ROOT stage=direct_batch ordinal={d} original_children={d} bytes={d} retained_bytes={d} cold_live_equal=true\n", .{ i, count, bytes.len, try ready.recursive.rows.retainedBytes() });
        }
        if (first != metadata.input().entries.len) return error.InvalidSplitFixture;
        return result;
    }
};
test "v7 two open batches including singleton reduce to one detached globally closed root" {
    const a = std.testing.allocator;
    var output = try Fixture.runFixture(true, true, Consumer);
    defer output.deinit();
    // Original proof producers are now gone; no caller/source provider is
    // duplicated across windows. Batch0 is open without its memory provider.
    var pool: @import("stwo_prover_engine").work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var binding = try @import("stwo_prover_engine").work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var root = try Reduce.prove(a, output.metadata.input(), &counts, &output.pins, &.{ output.proofs[0], output.proofs[1] }, .{});
    defer root.deinit();
    for (&output.proofs) |*bytes| {
        a.free(bytes.*);
        bytes.* = &.{};
    }
    var verified = try Receive.verify(a, root.bytes, output.metadata.trusted, output.metadata.input(), &counts, &output.pins, root.key, root.wires, .{});
    defer verified.deinit();
    try std.testing.expectEqual(@as(u32, 2), verified.summary.segments);
    try std.testing.expectEqual(@as(u64, 77), verified.summary.ram_events);
    try std.testing.expectEqualDeep(output.metadata.trusted.terminal.output, verified.summary.output);
    try std.testing.expectError(error.InvalidMixedBatchCoverage, Receive.verify(a, root.bytes, output.metadata.trusted, output.metadata.input(), &.{5}, output.pins[0..1], root.key, root.wires, .{}));
    std.debug.print("V7_SPLIT_ROOT verified=true batches=2 counts=5,1 original_children=6 proof_bytes={d} global_closed=true all_originals_destroyed=true all_batches_destroyed=true singleton_lifetime=true canonical_security=false more_than64_proof_qualified=false\n", .{root.bytes.len});
}
