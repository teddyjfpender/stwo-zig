//! Counterfactual topology only. Deliberately no source normalization/key/proof.
const std = @import("std");
const E = @import("stwo_prover_engine");
const P = @import("../../rv64_recursion/om31_poseidon/common.zig");
const Runtime = @import("../sponge_cpu/runtime.zig");
const Receiver = @import("../sponge_cpu/receiver.zig");
const Adapter = @import("../native_group/native_adapter.zig");
const Capture = @import("../sponge_cpu/captured_source.zig");
const Group = @import("../native_dot/group_source.zig");
const State = struct {
    groups: [2]?Group.Stream = .{ null, null },
    seen: u32 = 0,
    complete: bool = false,
    fn deinit(self: *State) void {
        for (&self.groups) |*group| if (group.*) |*stream| stream.deinit();
    }
    fn emit(a: std.mem.Allocator, stream: *Group.Stream, member: Capture.View) !void {
        // Intentionally bypass normalized(): a B2 shape is NOT authorized by
        // the B4 source key. This API is only a trace-cost experiment.
        var structural = @import("../../rv64_recursion/circuit_lane.zig").StructuralScope.init();
        defer structural.deinit();
        var mul = @import("../native_omul/scope.zig").begin();
        defer mul.deinit();
        var dot = @import("../native_dot/scope.zig").Scope.begin(&stream.inner.owner);
        defer dot.deinit();
        P.begin(&stream.inner.owner);
        var active = true;
        defer if (active) P.finish() catch {};
        const emission = try member.emit(a, stream.inner.owner.algebra(), true);
        try P.finish();
        active = false;
        const i = stream.inner.appended;
        stream.inner.roots[i] = emission.output;
        stream.inner.expected_roots[i] = try member.expected(a);
        stream.inner.bindings[i] = .{ .ordinal = member.ordinal(), .fixed_identity = member.fixedIdentity() };
        stream.inner.appended += 1;
    }
    fn visit(raw: *anyopaque, a: std.mem.Allocator, member: Capture.View) !void {
        const self: *State = @ptrCast(@alignCast(raw));
        if (member.ordinal() != self.seen or self.seen >= 4) return error.ProfileGroupOrder;
        for (&self.groups, 0..) |*slot, index| {
            if (slot.* == null) slot.* = try Group.Stream.init(a, true, 0, 4, member.profile(), member.manifest());
            var arena = std.heap.ArenaAllocator.init(a);
            defer arena.deinit();
            if (index == 1 and member == .cpu) {
                var shape = member.cpu.shape.*;
                shape.pcs.fri_config.log_blowup_factor = 1;
                shape.pcs.fri_config.n_queries = 144;
                shape.pcs.pow_bits = 0;
                try shape.validate();
                const values = try @import("../pure_p2_trace_skeleton.zig").init(arena.allocator(), &shape);
                var candidate = member.cpu;
                candidate.shape = &shape;
                candidate.values = &values;
                try emit(a, &slot.*.?, .{ .cpu = candidate });
            } else try emit(a, &slot.*.?, member);
        }
        self.seen += 1;
    }
    fn fragment(raw: ?*anyopaque, a: std.mem.Allocator, value: Receiver.Verified) !void {
        try Adapter.visit(a, value, .{ .context = raw.?, .visit = visit });
    }
    fn done(raw: ?*anyopaque, a: std.mem.Allocator, _: Runtime.SourceDirectory, _: *const Receiver.Closed) !void {
        const self: *State = @ptrCast(@alignCast(raw.?));
        if (self.seen != 4) return error.ProfileGroupCount;
        for (&self.groups, 0..) |*slot, index| {
            var owner = try slot.*.?.finish();
            defer owner.deinit();
            const cost = try Group.Cost.derive(&owner);
            if (index == 0) try std.testing.expectEqual(@as(u64, 643035136), cost.total_cells);
            const json = try std.json.Stringify.valueAlloc(a, .{ .scope = "ACTUAL_selected_fourmember_R7_complete_group_source_emission_only_not_admitted", .hypothetical_CPU_B2 = index == 1, .other_three_members_B4 = true, .cost = cost, .p2_permutations = owner.calls.items.len, .source_normalization_intentionally_not_admitted = true, .new_key_or_profile = false, .physical_proof = false }, .{});
            defer a.free(json);
            std.debug.print("NATIVE_PROFILE_FOUR_GROUP_MODEL {s}\n", .{json});
        }
        self.complete = true;
    }
};
test "terminal Blake native B2 selected four group source plateau model no proof" {
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
    {
        defer state.deinit();
        try Runtime.verifyDirectoryWithHooks(budget.allocator(), config.value, input, .op_target_b4_q72_p0_fold4_v1, .{}, .{ .context = &state, .complete = State.done, .fragments = .{ .context = &state, .fragment = State.fragment } });
    }
    try std.testing.expect(state.complete);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
}
