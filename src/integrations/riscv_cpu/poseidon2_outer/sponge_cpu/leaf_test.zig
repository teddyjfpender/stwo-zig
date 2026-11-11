//! Complete actual source proof -> native capture -> new CPU verifier graph.
const std = @import("std");
const core = @import("stwo_core");
const engine = @import("stwo_prover_engine");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const R = @import("../../word16_global_execution/services/roster.zig");
const Request = @import("../../word16_global_execution/services/protocol.zig").Request;
const T = @import("../../word16_global_execution/services/types.zig");
const CPU = @import("worker.zig");
const Key = @import("key.zig").Key;
const W = @import("../pure_p2_worker_protocol.zig").W;
const View = @import("leaf.zig").View;
const Hook = struct {
    pub fn verified(a: std.mem.Allocator, setup: *const R.CpuSetup, request: Request, first: [T.FAMILIES]u32, ordinal: u32, key: *const Key, manifest: [36]u8, main: [36]u8, encoded: *const CPU.Encoded, capture: *const core.pcs.ForField(core.fields.om31.OM31).verifier.VerifiedProofCapture(W.H)) !void {
        // One complete source leaf suffices; the native fixture still proves
        // and receives both CPU shards and all shared counterpart providers.
        if (ordinal != 0) return;
        var scope = @import("../native_omul/scope.zig").begin();
        defer scope.deinit();
        var arena = std.heap.ArenaAllocator.init(a);
        defer arena.deinit();
        var native = try W.Wire.decodeProofBytesBinary(a, encoded.bytes);
        defer native.deinit(a);
        var roster = try @import("frame.zig").Roster.init(a, setup, request.sponge.calls, key.frontier_log, request.base.epoch, ordinal);
        defer roster.deinit();
        var child = try @import("native.zig").decode(a, roster.instances, encoded.local);
        defer child.deinit();
        const shape = try @import("capture.zig").geometry(arena.allocator(), setup, key);
        const values = try V.proof.fromNative(arena.allocator(), &native, capture, &shape);
        var native_sha: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(encoded.bytes, &native_sha, .{});
        const native_hex = std.fmt.bytesToHex(native_sha, .lower);
        // The native wrapper/semantic IR is unchanged by sharing circuit publics.
        try std.testing.expectEqualStrings("13d5fabb5e847915e6753d781aca9f753bfa44a9e2ffe70770ae32915a642bcc", &native_hex);
        const view = View{ .setup = setup, .request = request, .span = .{}, .first = first, .key = key, .expected = .{ .ordinal = ordinal, .statement = try key.statement(setup, request, first, .{}, ordinal) }, .manifest = manifest, .main = main, .receipt = encoded.receipt, .claims = encoded.claims, .child = &child.proof, .shape = &shape, .values = &values };
        var owner = try view.build(a, false);
        defer owner.deinit();
        var receiver = try view.build(a, true);
        defer receiver.deinit();
        try std.testing.expectEqualDeep(try owner.rawCounts(), try receiver.rawCounts());
        const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "complete_new_CPU_frontier_native_AIR_GKR_PCS_FRI_public_frame", .raw = try owner.rawCounts(), .native_mul_calls = owner.native_mul_calls.items.len, .census = try owner.census(false), .fresh_trace_geometry_exact = true, .source_mask_terminal_Wire_ninth_limb_mutations_rejected = true, .production_admission = false, .physical_outer_proof = false }, .{});
        defer a.free(json);
        std.debug.print("OP_SPONGE_CPU_COMPLETE_LEAF {s}\n", .{json});
        const physical_kind = std.posix.getenv("STWO_OP_R6_PHYSICAL_KIND");
        const retained = std.posix.getenv("STWO_OP_SPONGE_R6_RETAINED");
        const physical_requested = if (physical_kind) |selected| std.mem.eql(u8, selected, "sponge_cpu") else false;
        if (physical_requested or retained != null) {
            const Budget = engine.host_budget_allocator.SharedHostBudget;
            const native_budget = Budget.fromAllocator(a) orelse return error.MissingSpongeNativeFixtureBudget;
            const combined = native_budget.backing_owner orelse return error.MissingSpongeCombinedFixtureBudget;
            if (native_budget.limit != 4 << 30 or combined.limit != 10 << 30) return error.InvalidSpongeFixtureBudget;
            const outer = try Budget.createRetainingParent(combined.allocator(), 8 << 30);
            defer outer.destroy();
            if (retained) |path| try @import("../native_omul/source_physical.zig").verifyRetained(outer.allocator(), view, path) else try @import("../native_omul/source_physical.zig").maybe(outer.allocator(), "sponge_cpu", view, &owner);
            try std.testing.expectEqual(@as(usize, 0), outer.snapshot().live_bytes);
            std.debug.print("OP_SPONGE_CPU_OUTER_BUDGET peak={} limit={} combined_peak={}\n", .{ outer.snapshot().peak_live_bytes, outer.limit, combined.snapshot().peak_live_bytes });
        }
    }
};
test "sponge CPU complete source leaf binds new frontier and all original CPU constraints" {
    const combined = try engine.host_budget_allocator.SharedHostBudget.createRetainingParent(std.testing.allocator, 10 << 30);
    defer combined.destroy();
    try @import("join_test.zig").exerciseWithHookBacking(false, Hook, combined.allocator());
    try std.testing.expectEqual(@as(usize, 0), combined.snapshot().live_bytes);
}
