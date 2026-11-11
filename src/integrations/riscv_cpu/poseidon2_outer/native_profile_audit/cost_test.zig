//! Complete CPU verifier topology only: no new key/profile/proof or admission.
const std = @import("std");
const E = @import("stwo_prover_engine");
const P = @import("../../rv64_recursion/om31_poseidon/common.zig");
const V = @import("../../rv64_recursion/om31_poseidon/mod.zig");
const Runtime = @import("../sponge_cpu/runtime.zig");
const Receiver = @import("../sponge_cpu/receiver.zig");
const Adapter = @import("../native_group/native_adapter.zig");
const Capture = @import("../sponge_cpu/captured_source.zig");
const Cost = @import("../native_dot/group_source.zig").Cost;
const State = struct {
    seen: usize = 0,
    complete: bool = false,
    fn visit(raw: *anyopaque, a: std.mem.Allocator, member: Capture.View) !void {
        const self: *State = @ptrCast(@alignCast(raw));
        if (member != .cpu) return;
        if (self.seen != 0 or member.ordinal() != 0) return error.ProfileModelSingleCpu;
        self.seen += 1;
        const original = member.cpu;
        for ([_]u32{ 2, 1 }) |blowup| {
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            const scratch = arena.allocator();
            var shape = original.shape.*;
            shape.pcs.fri_config.log_blowup_factor = blowup;
            shape.pcs.fri_config.n_queries = if (blowup == 2) 72 else 144;
            shape.pcs.pow_bits = 0;
            try shape.validate();
            const values = try @import("../pure_p2_trace_skeleton.zig").init(scratch, &shape);
            var hypothetical = original;
            hypothetical.shape = &shape;
            hypothetical.values = &values;
            // Do NOT normalize/admit this candidate: the existing source key
            // and statement are B4. Only count the full verifier graph with a
            // hypothetical PCS shape; a legal B2 suite would need new keys/FS.
            var owner = try P.PoseidonContext.initTraceOnly(a, 9);
            defer owner.deinit();
            var structural = @import("../../rv64_recursion/circuit_lane.zig").StructuralScope.init();
            defer structural.deinit();
            var mul = @import("../native_omul/scope.zig").begin();
            defer mul.deinit();
            var dot = @import("../native_dot/scope.zig").Scope.begin(&owner);
            defer dot.deinit();
            P.begin(&owner);
            var active = true;
            defer if (active) P.finish() catch {};
            const emission = try hypothetical.emitInto(a, owner.algebra(), true);
            try P.finish();
            active = false;
            try owner.setOutputs(&emission.output);
            try owner.finalizeForNativeDot();
            const cost = try Cost.derive(&owner);
            var cells: [4]u64 = @splat(0);
            var columns: [4]usize = undefined;
            var heights: [4]u32 = undefined;
            var opened: usize = 0;
            for (0..shape.nTrees()) |tree| {
                columns[tree] = shape.nColumns(tree);
                heights[tree] = shape.treeHeight(tree);
                opened += shape.nColumns(tree) * shape.nQueries();
                for (shape.tree_column_log_sizes[tree]) |log| cells[tree] += @as(u64, 1) << @intCast(log + blowup);
            }
            const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "actual_selected_CPU_complete_R7_verifier_topology_hypothetical_PCS_shape_not_admitted", .log_blowup = blowup, .queries = shape.nQueries(), .cost = cost, .p2_permutations = owner.calls.items.len, .columns = columns, .tree_heights = heights, .extended_cells = cells, .uncompressed_column_query_values = opened, .gkr_AIR_public_frame_present = true, .new_dummy_PCS_values = true, .B4_source_key_retained_for_framing_only = true, .new_profile_or_key = false, .proof_or_validity_claim = false }, .{});
            defer a.free(json);
            std.debug.print("NATIVE_PROFILE_FULL_CPU_MODEL {s}\n", .{json});
        }
    }
    fn fragment(raw: ?*anyopaque, a: std.mem.Allocator, value: Receiver.Verified) !void {
        try Adapter.visit(a, value, .{ .context = raw.?, .visit = visit });
    }
    fn done(raw: ?*anyopaque, _: std.mem.Allocator, _: Runtime.SourceDirectory, _: *const Receiver.Closed) !void {
        const self: *State = @ptrCast(@alignCast(raw.?));
        try std.testing.expectEqual(@as(usize, 1), self.seen);
        self.complete = true;
    }
};
test "terminal Blake native B2 full CPU source model no proof or admission" {
    const config_path = std.posix.getenv("STWO_OP_NATIVE_PROFILE_CONFIG") orelse return error.SkipZigTest;
    const input = std.posix.getenv("STWO_OP_NATIVE_PROFILE_NATIVE") orelse return error.MissingProfileModelInput;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
    defer std.testing.allocator.free(raw);
    const config = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, std.testing.allocator, raw, .{});
    defer config.deinit();
    if (config.value.max_steps > 10_000_000) return error.ProfileModelSmallOnly;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 8 << 30);
    defer budget.destroy();
    var state = State{};
    try Runtime.verifyDirectoryWithHooks(budget.allocator(), config.value, input, .op_target_b4_q72_p0_fold4_v1, .{}, .{ .context = &state, .complete = State.done, .fragments = .{ .context = &state, .fragment = State.fragment } });
    try std.testing.expect(state.complete);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
}
