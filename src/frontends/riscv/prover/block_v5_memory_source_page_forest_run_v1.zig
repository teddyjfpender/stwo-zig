//! Exact ordered durable PAGE forest execution. Buffers contain original Parent
//! codec bytes. Files/constructor manifests never confer verified authority.
const std = @import("std");
const Cpu = @import("stwo_cpu_backend").CpuBackend;
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Plan = @import("../recursion/block_v5_memory_source_page_forest_plan_v1.zig");
const Bus = @import("../recursion/block_v5_memory_source_page_forest_bus_v1.zig");
const Receiver = @import("../recursion/block_v5_memory_source_page_forest_receiver_v1.zig");
const Stage = @import("block_v5_memory_source_page_forest_stage_v1.zig");
pub const Loader = struct { context: ?*anyopaque, read: *const fn (?*anyopaque, std.mem.Allocator, Plan.Ref) anyerror![]u8 };
pub const Limits = struct { stage: Stage.Limits = .{}, max_owned_bytes: usize = 12 << 30 };
pub fn ForBackend(comptime Backend: type) type {
    const Producer = Stage.ForBackend(Backend);
    return struct {
        pub const Sink = struct { context: ?*anyopaque, put: *const fn (?*anyopaque, u32, *Producer.Artifact) anyerror!void };
        const Forward = struct {
            sink: Sink,
            index: u32,
            fn put(context: ?*anyopaque, artifact: *Producer.Artifact) !void {
                const self: *@This() = @ptrCast(@alignCast(context orelse return error.MissingPageForestSink));
                try self.sink.put(self.sink.context, self.index, artifact);
            }
        };
        pub const Result = union(enum) { absent, open: *Receiver.Fresh };
        /// Expected node templates are independently reconstructed from fresh
        /// source children. The supplied writer must make each successful node
        /// available to the original-byte loader before its later parent reads it.
        pub fn run(backing: std.mem.Allocator, policy: Receiver.Policy, loader: Loader, limits: Limits, sink: Sink) !Result {
            try policy.public.forest.require(policy.public.expected_plan);
            const root = policy.public.forest.geometry.root orelse return .absent;
            if (policy.public.index != root or limits.max_owned_bytes == 0) return error.UntrustedPageForestRoot;
            const budget = try Budget.createRetainingParent(backing, limits.max_owned_bytes);
            defer budget.destroy();
            const a = budget.allocator();
            for (policy.public.forest.geometry.nodes, 0..) |_, index| {
                var local = policy;
                local.public.index = @intCast(index);
                const node = try local.public.forest.node(@intCast(index), local.public.expected_plan);
                var files: [4][]u8 = undefined;
                var made: usize = 0;
                defer for (files[0..made]) |bytes| a.free(bytes);
                for (node.children[0..node.child_count], 0..) |ref, child| {
                    files[child] = try loader.read(loader.context, a, ref);
                    made += 1;
                    if (files[child].len == 0 or files[child].len > limits.stage.max_child_proof_bytes) return error.PageForestResourceLimit;
                }
                var forward = Forward{ .sink = sink, .index = @intCast(index) };
                const bytes = try a.alloc([]const u8, made);
                defer a.free(bytes);
                for (bytes, files[0..made]) |*out, file| out.* = file;
                try Producer.publish(backing, local, bytes, limits.stage, .{ .context = &forward, .put_open = Forward.put });
            }
            const original = try loader.read(loader.context, a, .{ .node = root });
            defer a.free(original);
            // The returned genuine fresh equation retains the nested budget.
            return .{ .open = try Receiver.verifyRoot(a, policy, original) };
        }
    };
}
pub const CpuRun = ForBackend(Cpu);
