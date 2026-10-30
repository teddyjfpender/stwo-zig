//! Independent enclosing batch-reduction setup from original admitted policy.
//! Compiles one original child at a time and releases its intermediate setup.
const std = @import("std");
const core = @import("stwo_core");
const Capture = @import("block_v6_mixed_batch_capture_v1.zig");
const Original = @import("block_v6_mixed_batch_fixed_v1.zig");
const Bus = @import("block_v6_mixed_batch_public_v1.zig");
const Protocol = @import("block_v6_mixed_batch_protocol_v1.zig");
const Base = @import("blake3_execution_parent_protocol.zig");
const Parent = @import("blake3_execution_parent_proof.zig");
const Storage = @import("air/blake3_parent_row_storage.zig");
const Namespace = @import("air/block_v5_recursive_fixed_namespace_v1.zig");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Lists = blk: {
    var entries: [Storage.Airs.len]type = undefined;
    for (Storage.Airs, &entries) |Air, *T| T.* = std.ArrayList(Storage.FixedRow(Air));
    break :blk std.meta.Tuple(&entries);
};
pub const Limits = struct { max_bytes: usize = 8 << 30, max_row_log: u32 = 25, original: Original.Limits = .{} };
pub const Owned = struct {
    a: std.mem.Allocator,
    budget: *Budget,
    fixed: Storage.FixedTuple(false),
    wires: []Bus.Wire,
    expected: []Bus.Expected,
    context: Base.Context,
    profile: Base.Profile,
    pub const complete_block_authority = false;
    pub fn derive(backing: std.mem.Allocator, policies: []const Capture.Policy, expected: []const Bus.Expected, capacity: u32, limits: Limits) !Owned {
        @setEvalBranchQuota(20000);
        _ = try Bus.rosterDigest(expected);
        if (policies.len != expected.len or capacity == 0 or limits.max_bytes == 0 or limits.max_row_log == 0 or limits.max_row_log > 30) return error.InvalidMixedBatchLimits;
        const budget = try Budget.createRetainingParent(backing, limits.max_bytes);
        errdefer budget.destroy();
        const a = budget.allocator();
        var lists: Lists = undefined;
        inline for (0..Storage.Airs.len) |i| lists[i] = .empty;
        defer inline for (0..Storage.Airs.len) |i| lists[i].deinit(a);
        var wires: std.ArrayList(Bus.Wire) = .empty;
        errdefer wires.deinit(a);
        var contexts: [5]core.channel.blake3.Channel = @splat(.{});
        for (&contexts, 0..) |*channel, i| channel.mixU32s(&.{ 0x42364247, Bus.VERSION, @intCast(i), @intCast(policies.len) });
        contexts[0].mixRoot(try Bus.rosterDigest(expected));
        var next_namespace: u32 = 1;
        for (policies, expected, 0..) |policy, pin, i| {
            var piece = try Original.Owned.derive(a, policy, capacity, limits.original);
            defer piece.deinit();
            if (!std.meta.eql(Bus.Expected.from(piece.source), pin)) return error.UntrustedMixedBatchRoster;
            piece.namespace.original.first = next_namespace;
            const identity = try piece.namespace.identity();
            next_namespace = try piece.namespace.end();
            for (piece.wires) |wire| {
                if (wire.child != 0) return error.InvalidMixedBatchSchedule;
                var out = wire;
                out.circuit = piece.namespace.original.map(wire.circuit) orelse return error.MissingMixedBatchNamespace;
                out.child = @intCast(i);
                try wires.append(a, out);
            }
            try Namespace.apply(&piece.fixed, &piece.namespace, identity);
            inline for (0..Storage.Airs.len) |j| {
                const count = try std.math.add(usize, lists[j].items.len, piece.fixed[j].len);
                if (count > @as(usize, 1) << @intCast(limits.max_row_log)) return error.MixedBatchResourceLimit;
                try lists[j].appendSlice(a, piece.fixed[j]);
            }
            contexts[0].mixRoot(piece.context.child_key_id);
            for (contexts[1..4], piece.context.graph_ids) |*channel, digest| {
                channel.mixRoot(digest);
                channel.mixRoot(identity);
            }
            contexts[4].mixRoot(piece.context.transcript_plan_id);
            contexts[4].mixRoot(identity);
        }
        var fixed: Storage.FixedTuple(false) = undefined;
        inline for (0..Storage.Airs.len) |i| fixed[i] = &.{};
        errdefer inline for (0..Storage.Airs.len) |i| a.free(fixed[i]);
        inline for (0..Storage.Airs.len) |i| fixed[i] = try lists[i].toOwnedSlice(a);
        try @import("block_v6_mixed_direct_fixed_v1.zig").partitionFixed(a, &fixed);
        std.mem.sort(Bus.Wire, wires.items, {}, struct {
            fn less(_: void, l: Bus.Wire, r: Bus.Wire) bool {
                return l.circuit < r.circuit or (l.circuit == r.circuit and l.wire < r.wire);
            }
        }.less);
        _ = try Bus.scheduleDigest(wires.items);
        const owned_wires = try wires.toOwnedSlice(a);
        errdefer a.free(owned_wires);
        const pins = try a.dupe(Bus.Expected, expected);
        return .{ .a = a, .budget = budget, .fixed = fixed, .wires = owned_wires, .expected = pins, .profile = policies[0].scope.profile, .context = .{ .child_key_id = contexts[0].digestBytes(), .child_config = policies[0].scope.profile.config(), .graph_ids = .{ contexts[1].digestBytes(), contexts[2].digestBytes(), contexts[3].digestBytes() }, .transcript_plan_id = contexts[4].digestBytes() } };
    }
    pub fn validateLive(self: *const Owned, live: *@import("block_v6_mixed_batch_prepare_v1.zig").Prepared) !void {
        try live.recursive.rows.partitionHashRows();
        if (!std.meta.eql(self.context, live.recursive.context) or self.wires.len != live.wires.len or self.expected.len != live.expected.len) return error.UntrustedMixedBatchFixed;
        for (self.expected, live.expected) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedMixedBatchFixed;
        for (self.wires, live.wires) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedMixedBatchFixed;
        inline for (0..Storage.Airs.len) |i| {
            if (self.fixed[i].len != live.recursive.rows.fixed[i].len) return error.UntrustedMixedBatchFixed;
            for (self.fixed[i], live.recursive.rows.fixed[i]) |left, right| if (!std.meta.eql(left, right)) return error.UntrustedMixedBatchFixed;
        }
    }
    pub fn deriveKey(self: *const Owned, comptime Backend: type, a: std.mem.Allocator) !Protocol.Key {
        const geometry = try Parent.ForBackend(Backend).deriveKeyFromFixed(a, self.fixed, self.context, self.profile);
        return Protocol.Key.fromGeometry(geometry, self.wires, self.expected);
    }
    pub fn deinit(self: *Owned) void {
        const budget = self.budget;
        inline for (0..Storage.Airs.len) |i| self.a.free(self.fixed[i]);
        self.a.free(self.wires);
        self.a.free(self.expected);
        self.* = undefined;
        budget.destroy();
    }
};
