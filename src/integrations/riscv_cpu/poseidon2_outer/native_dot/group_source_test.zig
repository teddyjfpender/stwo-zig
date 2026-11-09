//! Closed R7 direct-group source costs from retained actual native proofs.
//! No guest execution, native proving or recursive physical proof is performed.
const std = @import("std");
const E = @import("stwo_prover_engine");
const Runtime = @import("../sponge_cpu/runtime.zig");
const Receiver = @import("../sponge_cpu/receiver.zig");
const Adapter = @import("../native_group/native_adapter.zig");
const Captured = @import("../sponge_cpu/captured_source.zig");
const Group = @import("group_source.zig");
const Root = @import("../sponge_cpu/root_admission.zig");
const State = struct {
    stream: ?Group.Stream = null,
    cost: ?Group.Cost = null,
    expected: ?@import("../native_omul/fold.zig").Digest = null,
    leaves: ?[]@import("../pure_p2_op_root_receiver.zig").Leaf = null,
    seen: usize = 0,
    fn deinit(self: *State, a: std.mem.Allocator) void {
        if (self.stream) |*s| s.deinit();
        if (self.leaves) |leaves| {
            for (leaves[0..self.seen]) |leaf| a.free(leaf.claims);
            a.free(leaves);
        }
    }
    fn visit(raw: *anyopaque, a: std.mem.Allocator, member: Captured.View) !void {
        const self: *State = @ptrCast(@alignCast(raw));
        if (member.ordinal() != self.seen) return error.R7GroupSourceOrder;
        if (self.stream == null) self.stream = try Group.Stream.init(a, true, 0, 4, member.profile(), member.manifest());
        if (self.leaves == null) self.leaves = try a.alloc(@import("../pure_p2_op_root_receiver.zig").Leaf, 4);
        try self.stream.?.append(member);
        self.leaves.?[self.seen] = try Adapter.metadata(a, member);
        self.seen += 1;
    }
    fn fragment(raw: ?*anyopaque, a: std.mem.Allocator, value: Receiver.Verified) !void {
        if (value.manifest.entries.len != 4) return error.R7GroupNeedsPinnedFourMemberSource;
        try Adapter.visit(a, value, .{ .context = raw.?, .visit = visit });
    }
    fn complete(raw: ?*anyopaque, a: std.mem.Allocator, source: Runtime.SourceDirectory, closed: *const Receiver.Closed) !void {
        const self: *State = @ptrCast(@alignCast(raw.?));
        if (self.seen != 4 or self.stream == null) return error.R7GroupSourceCoverage;
        self.expected = try self.stream.?.expectedOutput();
        var prepared = try Root.prepare(a, .{ .inventory = source.inventory, .cpus = source.authority.cpu, .detached = source.authority.detached, .catalog = source.authority.catalogs, .towers = source.authority.catalog.miller, .image = source.image }, .{ .execution = source.inventory.execution, .manifest = closed.pending.digest, .leaves = self.leaves.? });
        defer prepared.deinit();
        try std.testing.expectEqualDeep(try prepared.expectedRoot(), self.expected.?);
        var owner = try self.stream.?.finish();
        defer owner.deinit();
        try std.testing.expect(owner.native_dot_finalized and !owner.finalized);
        try std.testing.expectError(error.PoseidonContextNotFinalized, owner.rawCounts());
        try std.testing.expectError(error.PoseidonContextNotFinalized, @import("../native_omul/authority.zig").Key.init(std.testing.failing_allocator, &owner, source.metadata.profile));
        self.cost = try Group.Cost.derive(&owner);
        try std.testing.expect(self.cost.?.dot_calls != 0 and self.cost.?.dot_terms != 0 and self.cost.?.raw[7] != 0);
    }
};
test "R7 direct grouped actual native source lowering with joint eight-role closure" {
    const config_path = std.posix.getenv("STWO_OP_R7_GROUP_CONFIG") orelse return error.SkipZigTest;
    const path = std.posix.getenv("STWO_OP_R7_GROUP_NATIVE") orelse return error.MissingOpNativeDirectory;
    const report = std.posix.getenv("STWO_OP_R7_GROUP_REPORT") orelse return error.MissingR7Report;
    const raw = try std.fs.cwd().readFileAlloc(std.testing.allocator, config_path, 16384);
    defer std.testing.allocator.free(raw);
    const parsed = try std.json.parseFromSlice(@import("../../rv64_ethereum_request.zig").Config, std.testing.allocator, raw, .{});
    defer parsed.deinit();
    if (parsed.value.max_steps > 10_000_000) return error.SmallCapturePlanControlRequired;
    const budget = try E.host_budget_allocator.SharedHostBudget.create(std.heap.smp_allocator, 32 << 30);
    defer budget.destroy();
    var pool: E.work_pool.WorkPool = .{};
    try pool.initInPlaceWithOptions(.{ .worker_count = 8 });
    defer pool.deinit();
    var binding = try E.work_pool.ScopedPoolBinding.init(&pool);
    defer binding.deinit();
    var state = State{};
    var timer = try std.time.Timer.start();
    {
        defer state.deinit(budget.allocator());
        try Runtime.verifyDirectoryWithHooks(budget.allocator(), parsed.value, path, .op_target_b4_q72_p0_fold4_v1, .{}, .{ .context = &state, .complete = State.complete, .fragments = .{ .context = &state, .fragment = State.fragment } });
    }
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().live_bytes);
    try std.testing.expectEqual(@as(usize, 0), budget.snapshot().external_live_bytes);
    const json = try std.json.Stringify.valueAlloc(std.testing.allocator, .{ .scope = "R7 eight-role direct-group actual source-only; no execution/native/recursive proving", .cost = state.cost.?, .expected_root = state.expected.?, .wall_ns = timer.read(), .peak_live_bytes = budget.snapshot().peak_live_bytes, .end_live_bytes = budget.snapshot().live_bytes, .root_admission = false, .production_admission = false }, .{ .whitespace = .indent_2 });
    defer std.testing.allocator.free(json);
    var file = try std.fs.cwd().createFile(report, .{ .exclusive = true });
    defer file.close();
    try file.writeAll(json);
    try file.sync();
    std.debug.print("OP_R7_GROUP_SOURCE_ONLY total_cells={} qraw={} qlog={} dot_calls={} input_rows={} peak={} no_proof=true\n", .{ state.cost.?.total_cells, state.cost.?.raw[1], state.cost.?.logs[1], state.cost.?.dot_calls, state.cost.?.raw[7], budget.snapshot().peak_live_bytes });
}
