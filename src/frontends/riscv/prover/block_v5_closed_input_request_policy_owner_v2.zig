//! Version5 instance-pinned durable closed-node selection. Every original
//! WM/native/carrier verification and count is retained. Original child files
//! are still required for independent reconstruction of capture-shaped keys;
//! this is not final self-contained block authority or invariant geometry.
//! Actual independent WM/v2 and request-node setup reconstruction. Expected
//! templates are derived from genuine original verifier rows, never envelopes.
//! Publish and standalone reconstruct share every admission/geometry check.
const std = @import("std");
const core = @import("stwo_core");
const Budget = @import("stwo_prover_engine").host_budget_allocator.SharedHostBudget;
const Snapshot = @import("../recursion/block_v5_input_request_policy_snapshot_v1.zig");
const Base = @import("../recursion/blake3_execution_parent_protocol.zig");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Files = @import("block_v5_artifact_files_v1.zig");
const Run = @import("block_v5_input_request_forest_run_v1.zig");
const Plan = @import("../recursion/block_v5_input_request_forest_plan_v1.zig");
const Native = @import("../recursion/block_v5_wide_original_child_source_v1.zig").ForSubtype(.capacity_v1);
const WP = @import("../recursion/block_v5_reusable_tail_linked_public_windows_protocol_v2.zig");
const WB = @import("../recursion/block_v5_tail_linked_public_windows_bus_v2.zig");
const W = @import("../recursion/block_v5_tail_linked_public_windows_v2.zig");
const WR = @import("../recursion/block_v5_tail_linked_public_windows_receiver_v2.zig");
const WRows = @import("../recursion/block_v5_tail_linked_public_windows_preparation_v2.zig");
const FB = @import("../recursion/block_v5_closed_input_request_forest_bus_v2.zig");
const FP = @import("../recursion/block_v5_closed_input_request_forest_protocol_v2.zig");
const FR = @import("../recursion/block_v5_closed_input_request_forest_receiver_v2.zig");
const FRows = @import("../recursion/block_v5_closed_input_request_forest_preparation_v2.zig");
const Public = @import("../recursion/block_v5_input_request_forest_public_v1.zig");
const Carrier = @import("../recursion/block_v5_input_tail_receiver_v1.zig");
pub const Limits = struct {
    max_metadata_bytes: usize = 1 << 30,
    max_live_bytes: usize = 8 << 30,
    max_proof_bytes: usize = 512 << 20,
    max_total_proof_bytes: u64 = 64 << 30,
    transcript_capacity: u32 = 1 << 24,
    max_windows: usize = 8192,
    max_schedule_terms: usize = 1 << 20,
    plan: Plan.Limits = .{},
    window_public: W.Limits = .{},
    window_rows: WRows.Limits = .{},
    node_public: Public.Limits = .{},
    node_rows: FRows.Limits = .{},
    pub fn validate(self: Limits) !void {
        if (self.max_metadata_bytes == 0 or self.max_live_bytes == 0 or self.max_proof_bytes == 0 or self.max_total_proof_bytes == 0 or self.transcript_capacity == 0 or self.max_windows == 0 or self.max_schedule_terms == 0) return error.InputRequestPolicyResourceLimit;
    }
};
pub const Built = struct {
    owner: *Owner,
    root: *FR.Fresh,
    pub const complete_block_authority = false;
    pub fn deinit(self: *Built) void {
        self.root.deinit();
        self.owner.deinit();
        self.* = undefined;
    }
};
pub const Loader = struct {
    context: ?*anyopaque,
    native: *const fn (?*anyopaque, u32) anyerror!Run.InputFile,
    carrier: *const fn (?*anyopaque) anyerror!Run.InputFile,
};
pub const Existing = struct { windows: []const Run.Pin, nodes: []const Run.Pin };
pub const Action = union(enum) { publish, reconstruct: Existing };
pub fn windowFilename(buffer: []u8, index: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, "closed-input-window-{d}.b5wm2", .{index});
}
pub fn nodeFilename(buffer: []u8, index: u32) ![]const u8 {
    return std.fmt.bufPrint(buffer, "closed-input-node-{d}.b5ir5", .{index});
}
pub fn rangesFor(a: std.mem.Allocator, count: usize, limit: usize) ![]Plan.Range {
    if (count == 0 or count > limit or count >= 1 << 30) return error.InputRequestPolicyResourceLimit;
    const n = (count + 3) / 4;
    const ranges = try a.alloc(Plan.Range, n);
    for (ranges, 0..) |*range, index| range.* = .{ .first = @intCast(index * 4), .count = @intCast(@min(4, count - index * 4)), .leaves = 1 };
    return ranges;
}
/// Storage-only future slots, not admitted keys. Each slot is replaced by
/// actual independently reconstructed rows before any positive receiver use.
pub fn specsFor(a: std.mem.Allocator, count: usize, maximum: usize, profile: Base.Profile) ![]Public.Spec {
    if (count == 0 or count > maximum) return error.InputRequestPolicyResourceLimit;
    const specs = try a.alloc(Public.Spec, count);
    for (specs) |*spec| spec.* = .{ .geometry = initialGeometry(profile), .schedule = &.{}, .expected_id = @splat(0) };
    return specs;
}
pub fn requireExisting(action: Action, windows: usize, nodes: usize) !void {
    if (action == .reconstruct and (action.reconstruct.windows.len != windows or action.reconstruct.nodes.len != nodes)) return error.IncompleteInputRequestPolicyFiles;
}
pub const Owner = struct {
    budget: *Budget,
    arena: std.heap.ArenaAllocator,
    refs: std.atomic.Value(usize),
    snapshot: *Snapshot.Owner,
    expected: Snapshot.Pins,
    profile: Base.Profile,
    limits: Limits,
    windows: []WR.Policy,
    window_files: []Run.Pin,
    specs: []Public.Spec,
    node_files: []Run.Pin,
    forest: Plan.Owned,
    forest_initialized: bool,
    ready: bool,
    identity: [32]u8,
    pub const complete_source_authority = false;
    pub const complete_block_authority = false;
    pub fn validate(self: *const Owner, expected: Snapshot.Pins) !void {
        if (!self.ready or !self.forest_initialized or !std.meta.eql(self.expected, expected)) return error.UnfinishedInputRequestPolicyOwner;
        try self.snapshot.validate(expected);
        try self.forest.validate();
        if (self.windows.ptr != self.forest.policies.ptr or self.windows.len != self.forest.policies.len or self.specs.len != self.forest.geometry.nodes.len or self.window_files.len != self.windows.len or self.node_files.len != self.specs.len or !std.meta.eql(try self.computeIdentity(), self.identity)) return error.MutatedInputRequestPolicyOwner;
    }
    /// Frozen derived recipe, checked against independently expected original
    /// authority. No metadata seal is a successful-proof or global-closure flag.
    pub fn rootPolicy(self: *const Owner, expected: Snapshot.Pins) !FR.Policy {
        try self.validate(expected);
        return self.nodePolicy(self.forest.geometry.root);
    }
    fn nodePolicy(self: *const Owner, index: u32) FR.Policy {
        return .{ .public = .{ .forest = &self.forest, .specs = self.specs, .index = index, .carrier = self.snapshot.carrier }, .public_limits = self.limits.node_public, .max_proof_bytes = self.limits.max_proof_bytes };
    }
    fn computeIdentity(self: *const Owner) ![32]u8 {
        var channel = core.channel.blake3.Channel{};
        channel.mixU32s(&.{ 0x4235494b, 5, @intFromEnum(self.profile), @intCast(self.windows.len), @intCast(self.specs.len) });
        channel.mixRoot(self.expected.coverage);
        channel.mixRoot(self.expected.original_roster);
        channel.mixRoot(self.expected.carrier_key);
        channel.mixRoot(self.expected.input.root);
        channel.mixU32s(&.{self.expected.input.word_count});
        channel.mixRoot(self.forest.geometry.digest);
        for (self.windows, 0..) |window, index| {
            if (window.public.coverage != &self.snapshot.coverage or window.public.expected != self.snapshot.input.job or window.public.input != self.snapshot.input or window.public.instances.ptr != self.snapshot.natives.ptr + index * 4 or window.public.instances.len != @min(4, self.snapshot.natives.len - index * 4) or window.public.first_window != index * 4) return error.MutatedInputRequestPolicyOwner;
            try window.public.validate();
            if (!std.meta.eql(window.public_limits, self.limits.window_public) or window.max_proof_bytes != self.limits.max_proof_bytes or !std.meta.eql(window.key.config, self.profile.config())) return error.MutatedInputRequestPolicyOwner;
            if (!std.meta.eql(try window.key.identity(), window.expected_id)) return error.MutatedInputRequestPolicyOwner;
            channel.mixRoot(window.expected_id);
            channel.mixRoot(try WB.scheduleDigest(window.schedule));
        }
        for (self.specs) |spec| {
            const key = try FP.Key.fromGeometry(spec.geometry, spec.schedule);
            if (!std.meta.eql(spec.geometry.config, self.profile.config())) return error.MutatedInputRequestPolicyOwner;
            if (!std.meta.eql(try key.identity(), spec.expected_id)) return error.MutatedInputRequestPolicyOwner;
            channel.mixRoot(spec.expected_id);
            channel.mixRoot(try FB.scheduleDigest(spec.schedule));
        }
        return channel.digestBytes();
    }
    pub fn retain(self: *Owner) *Owner {
        const previous = self.refs.fetchAdd(1, .monotonic);
        std.debug.assert(previous > 0 and previous < std.math.maxInt(usize));
        return self;
    }
    pub fn deinit(self: *Owner) void {
        if (self.refs.fetchSub(1, .acq_rel) != 1) return;
        const budget = self.budget;
        if (self.forest_initialized) self.forest.deinit();
        self.snapshot.deinit();
        self.arena.deinit();
        budget.allocator().destroy(self);
        budget.destroy();
    }
    /// Returned bytes are transport only; callers must retain the owner through
    /// the real root fresh receiver and all nested source readers.
    pub fn readRoot(self: *const Owner, a: std.mem.Allocator, dir: std.fs.Dir, expected: Snapshot.Pins) !*FR.Fresh {
        const policy = try self.rootPolicy(expected);
        var buffer: [96]u8 = undefined;
        const pin = self.node_files[self.forest.geometry.root];
        const bytes = try Files.readPinned(a, dir, try nodeFilename(&buffer, self.forest.geometry.root), pin.byte_len, pin.sha256, self.limits.max_proof_bytes);
        defer a.free(bytes);
        return FR.verifyRoot(a, policy, bytes);
    }
};
fn initialGeometry(profile: Base.Profile) Base.Key {
    // Private self-slot scaffolding ONLY. Future/self keys are not consulted
    // by prepare; genuine earlier-child keys replace each slot in order. This
    // value never enters a receiver/capture or positive admission.
    return .{ .profile = profile, .config = profile.config(), .context = .{ .child_key_id = @splat(0), .child_config = profile.config(), .graph_ids = @splat(@splat(0)), .transcript_plan_id = @splat(0) }, .log_sizes = @splat(1), .preprocessed_root = @splat(1) };
}
fn originalBytes(a: std.mem.Allocator, file: Run.InputFile, max_bytes: usize) ![]u8 {
    return Files.readPinned(a, file.dir, file.path, file.pin.byte_len, file.pin.sha256, max_bytes);
}
fn chooseBytes(comptime Backend: type, comptime Protocol: type, a: std.mem.Allocator, dir: std.fs.Dir, path: []const u8, received: ?Run.Pin, rows: anytype, admission: anytype, max_bytes: usize) ![]u8 {
    if (received) |pin| return Files.readPinned(a, dir, path, pin.byte_len, pin.sha256, max_bytes);
    const Producer = @import("../recursion/blake3_native_parent_producer.zig").PlanForProtocol(Backend, Protocol);
    const producer = try Producer.init(a, &rows.rows, admission);
    defer producer.deinit();
    var proof = try producer.prove(a, &rows.rows);
    defer proof.deinit();
    const bytes = try Parent.codec.encode(a, &proof, &admission);
    errdefer a.free(bytes);
    if (bytes.len == 0 or bytes.len > max_bytes) return error.InputRequestPolicyResourceLimit;
    return bytes;
}
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        /// Reconstruct mode independently derives every expected geometry from
        /// freshly verified original children, then accepts the proposed stored
        /// parents under those recipes. It never decodes a key from a file.
        pub fn build(backing: std.mem.Allocator, dir: std.fs.Dir, snapshot: *Snapshot.Owner, expected: Snapshot.Pins, loader: Loader, profile: Base.Profile, limits: Limits, action: Action) !Built {
            try limits.validate();
            try snapshot.validate(expected);
            if (!std.meta.eql(profile.config(), snapshot.coverage.meta.security.recursive) or !std.meta.eql(profile.config(), snapshot.carrier.key.config)) return error.UntrustedInputRequestPolicySecurity;
            const budget = try Budget.createRetainingParent(backing, limits.max_metadata_bytes);
            errdefer budget.destroy();
            const a = budget.allocator();
            const self = try a.create(Owner);
            errdefer a.destroy(self);
            self.budget = budget;
            self.arena = std.heap.ArenaAllocator.init(a);
            errdefer self.arena.deinit();
            const owned = self.arena.allocator();
            self.refs = std.atomic.Value(usize).init(1);
            self.snapshot = snapshot.retain();
            errdefer self.snapshot.deinit();
            self.expected = expected;
            self.profile = profile;
            self.limits = limits;
            self.ready = false;
            self.forest_initialized = false;
            const ranges = try rangesFor(owned, snapshot.natives.len, limits.max_windows);
            self.windows = try owned.alloc(WR.Policy, ranges.len);
            self.window_files = try owned.alloc(Run.Pin, ranges.len);
            var geometry = try Plan.derive(a, ranges, @intCast(snapshot.natives.len), limits.plan);
            defer geometry.deinit();
            try requireExisting(action, ranges.len, geometry.nodes.len);
            self.specs = try specsFor(owned, geometry.nodes.len, limits.plan.max_nodes, profile);
            self.node_files = try owned.alloc(Run.Pin, geometry.nodes.len);
            var window_published: usize = 0;
            var node_published: usize = 0;
            errdefer if (action == .publish) {
                for (0..window_published) |index| {
                    var buffer: [96]u8 = undefined;
                    dir.deleteFile(windowFilename(&buffer, @intCast(index)) catch continue) catch {};
                }
                for (0..node_published) |index| {
                    var buffer: [96]u8 = undefined;
                    dir.deleteFile(nodeFilename(&buffer, @intCast(index)) catch continue) catch {};
                }
            };
            var total: u64 = 0;
            for (ranges, 0..) |range, index| {
                const live = try Budget.createRetainingParent(backing, limits.max_live_bytes);
                defer live.destroy();
                const scratch = live.allocator();
                const instances = snapshot.natives[range.first..][0..range.count];
                var originals: [4]Native.Fresh = undefined;
                var initialized: usize = 0;
                defer for (originals[0..initialized]) |*fresh| fresh.deinit();
                for (instances, 0..) |policy, local| {
                    const bytes = try originalBytes(scratch, try loader.native(loader.context, @intCast(range.first + local)), limits.max_proof_bytes);
                    defer scratch.free(bytes);
                    originals[local] = try Native.verify(scratch, policy, bytes, limits.window_public.original);
                    initialized += 1;
                }
                const public_policy = W.Policy{ .coverage = &snapshot.coverage, .expected = snapshot.input.job, .input = snapshot.input, .input_expected = expected.input, .instances = instances, .first_window = range.first };
                var public = try W.init(scratch, public_policy, limits.window_public);
                defer public.deinit();
                var rows = try WRows.prepare(scratch, &public, originals[0..initialized], limits.transcript_capacity, limits.window_rows);
                defer rows.deinit();
                const base_key = try Parent.ForBackend(Backend).deriveKeyWithProfile(scratch, &rows.recursive, profile);
                const key = try WP.Key.fromGeometry(base_key, rows.wires);
                const id = try key.identity();
                const schedule = try @import("../recursion/block_v5_input_request_schedule_custody_v1.zig").ForWire(WB.Wire, WB.scheduleDigest).copy(owned, rows.wires, try WB.scheduleDigest(rows.wires), limits.max_schedule_terms);
                const policy = WR.Policy{ .public = public_policy, .key = key, .expected_id = id, .schedule = schedule, .public_limits = limits.window_public, .max_proof_bytes = limits.max_proof_bytes };
                const admission = try WP.Admission.init(key, id, rows.wires, .{ .public = &public });
                var buffer: [96]u8 = undefined;
                const path = try windowFilename(&buffer, @intCast(index));
                const bytes = try chooseBytes(Backend, WP, scratch, dir, path, if (action == .reconstruct) action.reconstruct.windows[index] else null, &rows.recursive, admission, limits.max_proof_bytes);
                defer scratch.free(bytes);
                const fresh = try WR.verify(scratch, policy, bytes);
                defer fresh.deinit();
                total = try std.math.add(u64, total, bytes.len);
                if (total > limits.max_total_proof_bytes) return error.InputRequestPolicyResourceLimit;
                if (action == .publish) {
                    try Files.publish(dir, path, bytes);
                    window_published += 1;
                }
                self.windows[index] = policy;
                self.window_files[index] = .{ .byte_len = bytes.len, .sha256 = Files.hash(bytes) };
            }
            self.forest = try Plan.Owned.init(a, snapshot.input, expected.input, self.windows, limits.plan);
            self.forest_initialized = true;
            errdefer self.forest.deinit();
            var root_capture: ?*FR.Fresh = null;
            errdefer if (root_capture) |fresh| fresh.deinit();
            for (self.forest.geometry.nodes, 0..) |node, index| {
                const live = try Budget.createRetainingParent(backing, limits.max_live_bytes);
                defer live.destroy();
                const scratch = live.allocator();
                const policy = self.nodePolicy(@intCast(index));
                var verified: [4]FRows.Verified = undefined;
                var initialized: usize = 0;
                defer for (verified[0..initialized]) |child| switch (child) {
                    .leaf => |fresh| @constCast(fresh).deinit(),
                    .node => |fresh| @constCast(fresh).deinit(),
                };
                for (node.children[0..node.child_count], 0..) |ref, local| {
                    var buffer: [96]u8 = undefined;
                    const pin = switch (ref) {
                        .leaf => |leaf| self.window_files[leaf],
                        .node => |prior| self.node_files[prior],
                    };
                    const path = switch (ref) {
                        .leaf => |leaf| try windowFilename(&buffer, leaf),
                        .node => |prior| try nodeFilename(&buffer, prior),
                    };
                    const bytes = try Files.readPinned(scratch, dir, path, pin.byte_len, pin.sha256, limits.max_proof_bytes);
                    defer scratch.free(bytes);
                    verified[local] = switch (ref) {
                        .leaf => |leaf| .{ .leaf = try WR.verify(scratch, self.windows[leaf], bytes) },
                        .node => |prior| .{ .node = try FR.verify(scratch, self.nodePolicy(prior), bytes) },
                    };
                    initialized += 1;
                }
                const carrier = if (node.kind == .carrier) block: {
                    const bytes = try originalBytes(scratch, try loader.carrier(loader.context), limits.max_proof_bytes);
                    defer scratch.free(bytes);
                    break :block try Carrier.verify(scratch, snapshot.carrier, bytes);
                } else null;
                defer if (carrier) |fresh| fresh.deinit();
                var public = try FB.init(scratch, policy.public, limits.node_public);
                defer public.deinit();
                var rows = try FRows.prepare(scratch, &public, verified[0..initialized], carrier, limits.transcript_capacity, limits.node_rows);
                defer rows.deinit();
                const base_key = try Parent.ForBackend(Backend).deriveKeyWithProfile(scratch, &rows.recursive, profile);
                if (rows.wires.len != 0) return error.ClosedInputRequestNodeHasNoPublicTerms;
                const schedule: []const FB.Wire = &.{};
                const key = try FP.Key.fromGeometry(base_key, schedule);
                const id = try key.identity();
                self.specs[index] = .{ .geometry = base_key, .schedule = schedule, .expected_id = id };
                const admitted_policy = try FR.admit(self.nodePolicy(@intCast(index)));
                const admission = try FP.Admission.init(key, id, rows.wires, .{ .public = &public });
                _ = admitted_policy;
                var buffer: [96]u8 = undefined;
                const path = try nodeFilename(&buffer, @intCast(index));
                const bytes = try chooseBytes(Backend, FP, scratch, dir, path, if (action == .reconstruct) action.reconstruct.nodes[index] else null, &rows.recursive, admission, limits.max_proof_bytes);
                defer scratch.free(bytes);
                const fresh = if (node.kind == .carrier) try FR.verifyRoot(scratch, self.nodePolicy(@intCast(index)), bytes) else try FR.verify(scratch, self.nodePolicy(@intCast(index)), bytes);
                var transferred = false;
                defer if (!transferred) fresh.deinit();
                total = try std.math.add(u64, total, bytes.len);
                if (total > limits.max_total_proof_bytes) return error.InputRequestPolicyResourceLimit;
                if (action == .publish) {
                    try Files.publish(dir, path, bytes);
                    node_published += 1;
                }
                self.node_files[index] = .{ .byte_len = bytes.len, .sha256 = Files.hash(bytes) };
                if (node.kind == .carrier) {
                    root_capture = fresh;
                    transferred = true;
                }
            }
            self.identity = try self.computeIdentity();
            self.ready = true;
            try self.validate(expected);
            return .{ .owner = self, .root = root_capture orelse return error.IncompleteInputRequestPolicyFiles };
        }
    };
}
