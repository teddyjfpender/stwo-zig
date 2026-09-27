//! Ordered one-node-at-a-time original proof publication. No complete-block
//! token; artifacts remain proposals until independently freshly received.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Bus = @import("block_v5_ram_range_forest_bus_v1.zig");
const Authority = @import("block_v5_ram_range_forest_authority_v1.zig");
const Plan = @import("block_v5_ram_range_forest_plan_v1.zig");
const Prepare = @import("block_v5_ram_range_forest_preparation_v1.zig");
const Receive = @import("block_v5_ram_range_forest_summary_receiver_v1.zig");
pub const Loader = struct {
    context: *anyopaque,
    /// Must enforce the supplied cap before allocation. Returns an owned byte
    /// proposal on a; success transfers it, failure retains no allocation.
    take: *const fn (*anyopaque, std.mem.Allocator, Plan.Ref, usize) anyerror![]u8,
};
pub const Sink = struct {
    context: *anyopaque,
    /// Copies/persists bytes synchronously. All earlier publications remain
    /// provisional if any later node fails. May not retain Fresh or borrowed bytes.
    put: *const fn (*anyopaque, u32, []const u8) anyerror!void,
};
pub const Limits = struct {
    max_owned_bytes: usize = 4 << 30,
    max_proof_bytes: usize = 512 << 20,
    capacity: u32 = 1 << 20,
    public: Bus.Limits = .{},
    preparation: Prepare.Limits = .{},
    worker: @import("block_v5_ram_range_forest_producer_v1.zig").Options = .{ .worker_count = 1, .host_byte_limit = 4 << 30, .retained_scratch_limit = 64 << 20 },
};
const Live = union(enum) {
    ram: *Authority.Ram.Fresh,
    range: *Authority.Range.Fresh,
    node: *Receive.Fresh,
    fn deinit(self: *@This()) void {
        switch (self.*) {
            .ram => |v| v.deinit(),
            .range => |v| v.deinit(),
            .node => |v| v.deinit(),
        }
        self.* = undefined;
    }
    fn capture(self: @This()) Prepare.Capture {
        return switch (self) {
            .ram => |v| .{ .ram = v },
            .range => |v| .{ .range = v },
            .node => |v| .{ .node = v },
        };
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Producer = @import("block_v5_ram_range_forest_producer_v1.zig").ForBackend(Backend);
        pub const complete_block_authority = false;
        pub fn publish(backing: std.mem.Allocator, forest: *const Authority.Owned, expected: [32]u8, specs: []const Bus.Spec, loader: Loader, sink: Sink, limits: Limits) !void {
            if (limits.max_owned_bytes == 0 or limits.max_proof_bytes == 0 or limits.capacity == 0) return error.RamRangeForestResourceLimit;
            try forest.require(expected);
            if (specs.len != forest.geometry.nodes.len) return error.UntrustedRamRangeForestRoster;
            const budget = try Budget.createRetainingParent(backing, limits.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            for (forest.geometry.nodes, 0..) |_, index| {
                const policy = Bus.Policy{ .forest = forest, .expected_plan = expected, .specs = specs, .index = @intCast(index) };
                const node = try forest.node(policy.index, expected);
                try policy.validate();
                var live: [4]?Live = @splat(null);
                var made: usize = 0;
                defer for (live[0..made]) |*child| child.*.?.deinit();
                var captures: [4]Prepare.Capture = undefined;
                for (node.children[0..node.child_count], 0..) |ref, ordinal| {
                    const bytes = try loader.take(loader.context, a, ref, limits.max_proof_bytes);
                    defer a.free(bytes);
                    if (bytes.len > limits.max_proof_bytes) return error.RamRangeForestResourceLimit;
                    live[ordinal] = switch (ref) {
                        .ram => |i| .{ .ram = try Authority.Ram.verify(a, forest.ram[i], bytes) },
                        .range => |i| .{ .range = try Authority.Range.verify(a, forest.range[i], bytes) },
                        .node => |i| block: {
                            var lower = policy;
                            lower.index = i;
                            break :block .{ .node = try Receive.verify(a, .{ .public = lower, .public_limits = limits.public, .max_proof_bytes = limits.max_proof_bytes }, bytes) };
                        },
                    };
                    made += 1;
                    captures[ordinal] = live[ordinal].?.capture();
                }
                const encoded = block: {
                    var public = try Bus.Owner.init(a, policy, limits.public);
                    defer public.deinit();
                    var rows = try Prepare.prepare(a, &public, captures[0..node.child_count], limits.capacity, limits.preparation);
                    defer rows.deinit();
                    const worker = try Producer.init(a, &rows, &public, limits.worker);
                    defer worker.deinit();
                    break :block try Producer.proveEncodedConsuming(a, worker, &rows, &public);
                };
                defer a.free(encoded);
                // Release all producer/capture owners before independent CPU
                // verification. Only bounded artifact bytes survive this epoch.
                for (live[0..made]) |*child| child.*.?.deinit();
                made = 0;
                if (encoded.len > limits.max_proof_bytes) return error.RamRangeForestResourceLimit;
                const fresh = try Receive.verify(a, .{ .public = policy, .public_limits = limits.public, .max_proof_bytes = limits.max_proof_bytes }, encoded);
                defer fresh.deinit();
                try sink.put(sink.context, policy.index, encoded);
            }
            try forest.require(expected);
        }
    };
}
