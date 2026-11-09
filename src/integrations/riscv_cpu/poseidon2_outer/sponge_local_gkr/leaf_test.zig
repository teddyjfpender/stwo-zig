//! Actual complete detached source leaf from the closed four-worker fixture.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const C = @import("../full_p2_common.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const Worker = @import("worker.zig");
const Native = @import("native.zig");
const View = @import("leaf.zig").View;
const W = @import("../pure_p2_worker_protocol.zig").W;
const Hook = struct {
    pub fn detached(a: std.mem.Allocator, worker: *const Worker.Worker, encoded: *const Worker.Encoded, manifest: [36]u8, main: [36]u8) !void {
        var captured: core.pcs.ForField(C.O).verifier.VerifiedProofCapture(W.H) = undefined;
        _ = try Worker.verifyWithCapture(a, worker.geometry, worker.key, worker.expected.ordinal, manifest, main, encoded, &captured);
        defer captured.deinit(a);
        var parsed = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer parsed.deinit(a);
        var local = try Native.decode(a, worker.geometry, encoded.local);
        defer local.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        const shape = try @import("capture.zig").geometry(arena.allocator(), worker.geometry, worker.key);
        const values = try V.proof.fromNative(arena.allocator(), &parsed, &captured, &shape);
        const source = View{ .key = worker.key, .geometry = worker.geometry, .ordinal = worker.expected.ordinal, .manifest = manifest, .main = main, .receipt = encoded.receipt, .claims = encoded.claims, .child = &local.proof, .shape = &shape, .values = &values };
        var scope = @import("../native_omul/scope.zig").begin();
        defer scope.deinit();
        var owner = try source.build(a, false);
        defer owner.deinit();
        var trace = try source.build(a, true);
        defer trace.deinit();
        try std.testing.expectEqual(try owner.rawCounts(), try trace.rawCounts());
        const report = try std.json.Stringify.valueAlloc(a, .{ .scope = "complete_detached_MAIN_GKR_PCS_FRI_public_frame", .raw = try owner.rawCounts(), .native_mul_calls = owner.native_mul_calls.items.len, .census = try owner.census(false), .fresh_trace_geometry_exact = true, .production_admission = false }, .{});
        defer a.free(report);
        std.debug.print("OP_DETACHED_COMPLETE_LEAF {s}\n", .{report});
        if (std.posix.getenv("STWO_OP_R6_PHYSICAL_KIND")) |selected| if (std.mem.eql(u8, selected, "detached_sponge")) {
            const Budget = engine.host_budget_allocator.SharedHostBudget;
            const native = Budget.fromAllocator(a) orelse return error.MissingSpongeNativeFixtureBudget;
            const combined = native.backing_owner orelse return error.MissingSpongeCombinedFixtureBudget;
            if (native.limit != 4 << 30 or combined.limit != 10 << 30) return error.InvalidSpongeFixtureBudget;
            const outer = try Budget.createRetainingParent(combined.allocator(), 8 << 30);
            defer outer.destroy();
            try @import("../native_omul/source_physical.zig").maybe(outer.allocator(), "detached_sponge", source, &owner);
            try std.testing.expectEqual(@as(usize, 0), outer.snapshot().live_bytes);
            std.debug.print("OP_DETACHED_OUTER_BUDGET peak={} combined_peak={}\n", .{ outer.snapshot().peak_live_bytes, combined.snapshot().peak_live_bytes });
        };
    }
};
test "detached sponge complete recursive source leaf authenticates eight roles and all buses" {
    const combined = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 10 << 30);
    defer combined.destroy();
    try @import("../sponge_cpu/join_test.zig").exerciseWithHookBacking(false, Hook, combined.allocator());
    try std.testing.expectEqual(@as(usize, 0), combined.snapshot().live_bytes);
}
