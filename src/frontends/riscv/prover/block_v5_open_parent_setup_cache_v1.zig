//! Exclusive lane-owned authenticated OpenV2 setup cache. The allocator must
//! be the forest's single aggregate budget; this cache adds no independent cap.
//! The lane owns the active pool binding. No traces or child captures survive
//! a request, and every request replaces dynamic admission, including same IDs.
const std = @import("std");
const Parent = @import("../recursion/blake3_execution_parent_proof.zig");
const Protocol = @import("../recursion/block_v5_reusable_open_parent_protocol_v2.zig");
const Bus = @import("../recursion/block_v5_open_parent_public_bus_v2.zig");
const Preparation = @import("../recursion/block_v5_open_parent_preparation_v2.zig");
const Producer = @import("../recursion/blake3_native_parent_producer.zig");
const Child = @import("../recursion/block_v5_open_child_frames_v2.zig").Child;

pub const Options = struct {
    profile: Parent.protocol.Profile,
    max_entries: usize = 1,
    retained_scratch_bytes: usize = 0,
};
pub const Stats = struct { hits: usize = 0, misses: usize = 0, evictions: usize = 0 };
pub fn ForBackend(comptime Backend: type) type {
    return struct {
        const Self = @This();
        const Plan = Producer.PlanForProtocol(Backend, Protocol);
        const Entry = struct {
            key: Protocol.Key,
            key_id: [32]u8,
            wires: []Bus.Wire,
            // Owned shallow metadata snapshots; child arenas belong to the
            // stream and outlive the cache. Never borrow a lane's stack slice.
            children: []Child,
            plan: *Plan,
            last_use: u64,
        };
        a: std.mem.Allocator,
        options: Options,
        entries: []?Entry,
        workspace: Producer.Workspace,
        stats: Stats = .{},
        clock: u64 = 0,
        busy: std.Thread.Mutex = .{},

        pub fn init(a: std.mem.Allocator, options: Options) !Self {
            if (options.max_entries == 0 or options.max_entries > 64) return error.InvalidV5OpenSetupCacheLimits;
            const entries = try a.alloc(?Entry, options.max_entries);
            @memset(entries, null);
            return .{ .a = a, .options = options, .entries = entries, .workspace = Producer.Workspace.init(a, options.retained_scratch_bytes) };
        }
        pub fn deinit(self: *Self) void {
            if (!self.busy.tryLock()) @panic("destroying leased OpenV2 setup cache");
            for (self.entries) |*entry| self.drop(entry);
            self.workspace.deinit();
            self.a.free(self.entries);
            self.busy.unlock();
            self.* = undefined;
        }
        fn drop(self: *Self, slot: *?Entry) void {
            if (slot.*) |entry| {
                entry.plan.deinit();
                self.a.free(entry.children);
                self.a.free(entry.wires);
                slot.* = null;
            }
        }
        pub const Proved = struct { key: Protocol.Key, key_id: [32]u8, proof: Parent.artifact.Owned };
        /// All output proof bytes own storage through `a`. It does not borrow
        /// setup, workspace, rows, or a previous request's public values.
        pub fn proveConsuming(self: *Self, prepared: *Preparation.Prepared) !Proved {
            if (!self.busy.tryLock()) return error.V5OpenSetupCacheAlreadyLeased;
            defer self.busy.unlock();
            defer prepared.recursive.rows.releaseRows();
            if (!std.meta.eql(prepared.recursive.context.child_config, self.options.profile.config())) return error.V5OpenSetupCacheSecurityMismatch;
            try prepared.values.validate();
            try prepared.recursive.rows.partitionHashRows();
            const digest = try Bus.scheduleDigest(prepared.wires);
            self.clock = try std.math.add(u64, self.clock, 1);
            var selected: ?usize = null;
            for (self.entries, 0..) |*slot, i| if (slot.*) |*entry| {
                if (!std.meta.eql(entry.key.context, prepared.recursive.context) or
                    !std.meta.eql(entry.key.config, self.options.profile.config()) or
                    !std.meta.eql(entry.key.public_schedule_digest, digest) or
                    !sameWires(entry.wires, prepared.wires)) continue;
                entry.plan.validateRows(&prepared.recursive.rows) catch |err| switch (err) {
                    error.InvalidBlake3ParentRows => continue,
                    else => return err,
                };
                const children = try self.a.dupe(Child, prepared.values.children);
                errdefer self.a.free(children);
                const admission = try Protocol.Admission.init(entry.key, entry.key_id, entry.wires, .{ .purpose = prepared.values.purpose, .children = children });
                // Never skip this when the immutable key/expected ID matches.
                if (!try entry.plan.tryRebindAdmission(&prepared.recursive.rows, admission)) return error.V5OpenSetupCacheRebindMismatch;
                self.a.free(entry.children);
                entry.children = children;
                entry.last_use = self.clock;
                self.stats.hits += 1;
                selected = i;
                break;
            };
            if (selected == null) {
                var victim: usize = 0;
                for (self.entries, 0..) |entry, i| {
                    if (entry == null) { victim = i; break; }
                    if (entry.?.last_use < self.entries[victim].?.last_use) victim = i;
                }
                if (self.entries[victim] != null) self.stats.evictions += 1;
                // Evict before a miss to avoid temporarily doubling fixed data.
                self.drop(&self.entries[victim]);
                const geometry = try Parent.ForBackend(Backend).deriveKeyWithProfile(self.a, &prepared.recursive, self.options.profile);
                const key = try Protocol.Key.fromGeometry(geometry, prepared.wires);
                const key_id = try key.identity();
                const wires = try self.a.dupe(Bus.Wire, prepared.wires);
                errdefer self.a.free(wires);
                const children = try self.a.dupe(Child, prepared.values.children);
                errdefer self.a.free(children);
                const admission = try Protocol.Admission.init(key, key_id, wires, .{ .purpose = prepared.values.purpose, .children = children });
                const plan = try Plan.init(self.a, &prepared.recursive.rows, admission);
                self.entries[victim] = .{ .key = key, .key_id = key_id, .wires = wires, .children = children, .plan = plan, .last_use = self.clock };
                self.stats.misses += 1;
                selected = victim;
            }
            const entry = &self.entries[selected.?].?;
            const proof = try entry.plan.proveConsumingWithWorkspace(self.a, &prepared.recursive.rows, &self.workspace);
            return .{ .key = entry.key, .key_id = entry.key_id, .proof = proof };
        }
        fn sameWires(left: []const Bus.Wire, right: []const Bus.Wire) bool {
            if (left.len != right.len) return false;
            for (left, right) |l, r| if (!std.meta.eql(l, r)) return false;
            return true;
        }
    };
}
