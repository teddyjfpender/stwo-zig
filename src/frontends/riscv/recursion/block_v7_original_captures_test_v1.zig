//! Fresh source verification retained once, detached deterministic recursion.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Receive = @import("../prover/block_v7_execution_receiver_v1.zig");
const Fixture = @import("../prover/block_v7_execution_caller_test_v1.zig");
const Metadata = @import("block_v7_mixed_metadata_v1.zig");
const Collection = @import("block_v7_mixed_collection_v1.zig");
const Cold = @import("block_v7_mixed_fixed_v1.zig");
const Mixed = @import("block_v7_mixed_preparation_v1.zig");
const Protocol = @import("block_v7_mixed_protocol_v1.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Compare = @import("block_v7_parallel_preparation_test_v1.zig");
const Q = core.fields.qm31.QM31;
const Ready = struct {
    a: std.mem.Allocator,
    trusted: Receive.Trusted,
    verified: Receive.Verified,
    metadata: *Metadata.Owned,
    cold: Cold.Owned,
    serial: Mixed.Prepared,
    reused: Mixed.Prepared,
    fn deinit(self: *Ready) void {
        self.reused.deinit();
        self.serial.deinit();
        self.cold.deinit();
        self.metadata.deinit();
        self.a.free(self.trusted.elf);
    }
};
const Consumer = struct {
    pub const Result = Ready;
    pub fn consume(f: Fixture.Fixture) !Ready {
        const a = f.allocator;
        const metadata = try Metadata.Owned.init(a, f.trusted, f.input);
        errdefer metadata.deinit();
        const input = metadata.input();
        const count = try input.count();
        var cold = try Cold.Owned.derive(a, input, 2, .{});
        errdefer cold.deinit();
        const captured = try Receive.For(Cpu).verifyWithCaptures(a, f.trusted, f.input, .{}, .{});
        var captures_live = true;
        defer if (captures_live) captured.captures.deinit();
        try std.testing.expectEqualDeep(f.original, captured.verified);
        try captured.captures.requireRequest(f.input);
        try std.testing.expectError(error.UndrainedOriginalCaptures, captured.captures.requireDrained());
        var other = f.input;
        other.epoch.digest[0] ^= 1;
        try std.testing.expectError(error.OriginalCaptureRequestMismatch, captured.captures.requireRequest(other));
        const n = f.input.natives[0];
        const entry = try n.pin.entry(a);
        var wrong = entry;
        wrong.identity[0] ^= 1;
        try std.testing.expectError(error.OriginalCaptureProfileMismatch, captured.captures.take(.native, 0, wrong, n.proof));
        {
            try std.testing.expect(n.proof.claims.len > 0);
            const old = n.proof.claims[0].sum;
            n.proof.claims[0].sum = old.add(Q.one());
            defer n.proof.claims[0].sum = old;
            try std.testing.expectError(error.OriginalCaptureProofMismatch, captured.captures.take(.native, 0, entry, n.proof));
        }
        {
            const samples = n.proof.stark.commitment_scheme_proof.sampled_values.items;
            const sample: *Q = found: {
                for (samples) |tree| for (tree) |column| {
                    if (column.len != 0) break :found &column[0];
                };
                return error.MissingOriginalOodsSample;
            };
            const old = sample.*;
            sample.* = old.add(Q.one());
            defer sample.* = old;
            try std.testing.expectError(error.OriginalCaptureProofMismatch, captured.captures.take(.native, 0, entry, n.proof));
        }
        try std.testing.expectError(error.CaptureFingerprintResourceLimit, @import("../prover/block_v7_original_capture_fingerprint_v1.zig").compute(.native, n.proof, .{ .max_bytes = 1 }));
        var serial = try Collection.prepareWindow(a, f.input, input, 0, count, .{});
        errdefer serial.deinit();
        var reused = try Collection.prepareWindow(a, f.input, input, 0, count, .{ .parallel_preparation = 4, .original_captures = captured.captures });
        errdefer reused.deinit();
        try captured.captures.requireDrained();
        try std.testing.expectError(error.OriginalCaptureAlreadyDrained, captured.captures.take(.native, 0, entry, n.proof));
        captured.captures.deinit();
        captures_live = false;
        try cold.validateLive(&serial);
        try cold.validateLive(&reused);
        try Compare.equal(input, &serial, &reused);
        // A moved capture must retain its allocator after the set and every
        // other slot have died. No caller metadata or proof arrays are borrowed.
        const extra = try Receive.For(Cpu).verifyWithCaptures(a, f.trusted, f.input, .{}, .{});
        var retained = try extra.captures.take(.native, 0, entry, n.proof);
        extra.captures.deinit();
        try std.testing.expect(retained.capture.proof.sampled_values.len > 0);
        retained.deinit();
        const budget = try engine.host_budget_allocator.SharedHostBudget.create(a, 1 << 20);
        defer budget.destroy();
        try std.testing.expectError(error.OutOfMemory, Receive.For(Cpu).verifyWithCaptures(budget.allocator(), f.trusted, f.input, .{}, .{ .max_bytes = 256 }));
        try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
        var trusted = f.trusted;
        trusted.elf = try a.dupe(u8, f.trusted.elf);
        return .{ .a = a, .trusted = trusted, .verified = f.original, .metadata = metadata, .cold = cold, .serial = serial, .reused = reused };
    }
};
test "capture once genuine source verification exact parent bytes detached receiver and substitutions" {
    const a = std.testing.allocator;
    // All original producer/capture owners are gone before either parent proof.
    var ready = try Fixture.runFixture(true, true, Consumer);
    defer ready.deinit();
    var pool: engine.work_pool.WorkPool = undefined;
    try pool.initInPlaceWithOptions(.{ .worker_count = 4, .backing_allocator = a });
    defer pool.deinit();
    var scoped = try engine.work_pool.ScopedPoolBinding.init(&pool);
    defer scoped.deinit();
    const base = try Parent.ForBackend(Cpu).deriveKeyFromFixed(a, ready.cold.fixed, ready.cold.context, .diagnostic_q8_pow0);
    const key = try Protocol.Key.fromGeometry(base, ready.cold.wires, ready.cold.expected);
    const first = try Compare.prove(a, &ready.serial, key);
    defer a.free(first);
    const second = try Compare.prove(a, &ready.reused, key);
    defer a.free(second);
    try std.testing.expectEqualSlices(u8, first, second);
    var verified = try @import("block_v7_mixed_receiver_v1.zig").verify(a, second, ready.trusted, ready.metadata.input(), key, ready.cold.wires, .{});
    defer verified.deinit();
    try std.testing.expectEqualDeep(ready.verified.statement, verified.summary.statement);
    try std.testing.expectEqual(ready.verified.cycles, verified.summary.cycles);
}
