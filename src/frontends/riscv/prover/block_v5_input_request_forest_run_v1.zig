//! Genuine bounded forest execution, selectable only with independent original
//! WM/v2 policies and node template recipes. Transport pins select bytes; every
//! publication and final read still invokes the actual typed fresh verifier.
const std = @import("std");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Files = @import("block_v5_artifact_files_v1.zig");
const Plan = @import("../recursion/block_v5_input_request_forest_plan_v1.zig");
const Receiver = @import("../recursion/block_v5_input_request_forest_receiver_v1.zig");
const StageModule = @import("block_v5_input_request_forest_stage_v1.zig");
pub const Pin = struct { byte_len: u64, sha256: [32]u8 };
pub const InputFile = struct { dir: std.fs.Dir, path: []const u8, pin: Pin };
pub const Loader = struct {
    context: ?*anyopaque,
    /// Return borrowed file coordinates, not an acceptance token. Bounded
    /// readPinned checks length BEFORE allocating; publisher then verifies the
    /// original proof. Directory/path must survive the synchronous read.
    leaf: *const fn (?*anyopaque, u32) anyerror!InputFile,
    carrier: *const fn (?*anyopaque) anyerror!InputFile,
};
pub fn filename(buffer: []u8, index: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, "input-request-{d}.b5ir", .{index});
}
pub const Result = struct {
    allocator: std.mem.Allocator,
    allocation_owner: ?*Budget,
    policy: Receiver.Policy,
    pins: []Pin,
    pub const complete_source_authority = false;
    /// All independently owned original policies, schedules, job owner and the
    /// Plan must outlive this result and its fresh readers. No borrowed stack
    /// setup may be installed into a durable driver policy.
    pub fn verifyRoot(self: *const Result, a: std.mem.Allocator, dir: std.fs.Dir) !*Receiver.Fresh {
        try self.policy.public.validate();
        if (self.policy.public.index != self.policy.public.forest.geometry.root or self.pins.len != self.policy.public.forest.geometry.nodes.len) return error.UntrustedInputRequestForestRoot;
        const pin = self.pins[self.policy.public.index];
        var buffer: [96]u8 = undefined;
        const bytes = try Files.readPinned(a, dir, try filename(&buffer, self.policy.public.index), pin.byte_len, pin.sha256, self.policy.max_proof_bytes);
        defer a.free(bytes);
        return Receiver.verifyRoot(a, self.policy, bytes);
    }
    pub fn deinit(self: *Result) void {
        const lease = self.allocation_owner;
        self.allocator.free(self.pins);
        self.* = undefined;
        if (lease) |owner| owner.destroy();
    }
};
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Stage = StageModule.ForBackend(Backend);
        const Output = struct {
            dir: std.fs.Dir,
            index: u32,
            pin: ?Pin = null,
            fn put(context: ?*anyopaque, artifact: *Stage.Artifact) !void {
                const self: *@This() = @ptrCast(@alignCast(context orelse return error.InvalidInputRequestSink));
                if (self.pin != null) return error.InvalidInputRequestSink;
                var buffer: [96]u8 = undefined;
                // No key/schedule/claim is accepted from this file. The exact
                // original independent policy selects all of those at read.
                const pin = Pin{ .byte_len = artifact.bytes.len, .sha256 = Files.hash(artifact.bytes) };
                try Files.publish(self.dir, try filename(&buffer, self.index), artifact.bytes);
                self.pin = pin;
                artifact.deinit();
            }
        };
        pub fn run(a: std.mem.Allocator, dir: std.fs.Dir, root_policy: Receiver.Policy, loader: Loader, limits: StageModule.Limits) !Result {
            try root_policy.public.validate();
            const geometry = &root_policy.public.forest.geometry;
            if (root_policy.public.index != geometry.root or limits.max_child_proof_bytes == 0) return error.UntrustedInputRequestForestRoot;
            // Admit every exact template before any loader or file side effect.
            for (geometry.nodes, 0..) |_, index| {
                var p = root_policy;
                p.public.index = @intCast(index);
                _ = try Receiver.admit(p);
            }
            const lease = if (Budget.fromAllocator(a)) |owner| owner.retain() else null;
            errdefer if (lease) |owner| owner.destroy();
            const pins = try a.alloc(Pin, geometry.nodes.len);
            errdefer a.free(pins);
            var published: usize = 0;
            errdefer for (0..published) |index| {
                var buffer: [96]u8 = undefined;
                const path = filename(&buffer, @intCast(index)) catch continue;
                // Only files successfully created by this invocation are removed.
                dir.deleteFile(path) catch {};
            };
            for (geometry.nodes, 0..) |node, index| {
                var p = root_policy;
                p.public.index = @intCast(index);
                var child_bytes: [Plan.FAN_IN][]const u8 = undefined;
                var loaded: usize = 0;
                defer for (child_bytes[0..loaded]) |bytes| a.free(bytes);
                for (node.children[0..node.child_count], 0..) |ref, ordinal| {
                    const bytes = switch (ref) {
                        .leaf => |leaf| block: {
                            const file = try loader.leaf(loader.context, leaf);
                            break :block try Files.readPinned(a, file.dir, file.path, file.pin.byte_len, file.pin.sha256, limits.max_child_proof_bytes);
                        },
                        .node => |prior| block: {
                            if (prior >= index) return error.InvalidInputRequestForest;
                            const pin = pins[prior];
                            var buffer: [96]u8 = undefined;
                            break :block try Files.readPinned(a, dir, try filename(&buffer, prior), pin.byte_len, pin.sha256, @min(root_policy.max_proof_bytes, limits.max_child_proof_bytes));
                        },
                    };
                    child_bytes[ordinal] = bytes;
                    loaded += 1;
                    if (bytes.len == 0 or bytes.len > limits.max_child_proof_bytes) return error.InputRequestNodeResourceLimit;
                }
                const carrier = if (node.kind == .carrier) block: {
                    const file = try loader.carrier(loader.context);
                    break :block try Files.readPinned(a, file.dir, file.path, file.pin.byte_len, file.pin.sha256, limits.max_child_proof_bytes);
                } else null;
                defer if (carrier) |bytes| a.free(bytes);
                var output = Output{ .dir = dir, .index = @intCast(index) };
                try Stage.publish(a, p, carrier, child_bytes[0..loaded], limits, .{ .context = &output, .put_open = Output.put });
                pins[index] = output.pin orelse return error.InvalidInputRequestSink;
                published += 1;
            }
            return .{ .allocator = a, .allocation_owner = lease, .policy = root_policy, .pins = pins };
        }
    };
}
