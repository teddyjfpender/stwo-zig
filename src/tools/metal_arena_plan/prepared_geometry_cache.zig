const std = @import("std");
const arena = @import("stwo").backends.metal.arena_plan;
const PreparedStateKey = @import("host_geometry.zig").PreparedStateKey;

pub const PreparedStateIdentity = struct {
    key: PreparedStateKey,
    logical_plan_hash: u64,
    plan_hash: u64,
    arena_bytes: u64,

    pub fn eql(lhs: PreparedStateIdentity, rhs: PreparedStateIdentity) bool {
        return std.mem.eql(u8, &lhs.key, &rhs.key) and
            lhs.logical_plan_hash == rhs.logical_plan_hash and
            lhs.plan_hash == rhs.plan_hash and lhs.arena_bytes == rhs.arena_bytes;
    }
};

pub fn logicalPlanHash(logical: []const arena.LogicalBuffer) u64 {
    var hash = std.hash.Fnv1a_64.init();
    const count: u64 = @intCast(logical.len);
    hash.update(std.mem.asBytes(&count));
    for (logical) |buffer| {
        hash.update(std.mem.asBytes(&buffer.id));
        hash.update(std.mem.asBytes(&buffer.size_bytes));
        hash.update(std.mem.asBytes(&buffer.alignment));
        hash.update(std.mem.asBytes(&buffer.placement_priority));
        const range_count: u64 = @intCast(buffer.live_ranges.len);
        hash.update(std.mem.asBytes(&range_count));
        for (buffer.live_ranges) |range| {
            hash.update(std.mem.asBytes(&range.first));
            hash.update(std.mem.asBytes(&range.last));
        }
        const has_spill: u8 = @intFromBool(buffer.spill_cost_ns != null);
        hash.update(std.mem.asBytes(&has_spill));
        if (buffer.spill_cost_ns) |value| hash.update(std.mem.asBytes(&value));
        const has_recompute: u8 = @intFromBool(buffer.recompute_cost_ns != null);
        hash.update(std.mem.asBytes(&has_recompute));
        if (buffer.recompute_cost_ns) |value| hash.update(std.mem.asBytes(&value));
    }
    return hash.final();
}

pub const PreparedStateAdmission = struct {
    pub const Status = enum { empty, pending, ready, borrowed, poisoned };
    pub const Decision = enum { miss, hit };

    status: Status = .empty,
    identity: ?PreparedStateIdentity = null,

    pub fn begin(
        self: *PreparedStateAdmission,
        identity: PreparedStateIdentity,
        allow_reuse: bool,
    ) !Decision {
        switch (self.status) {
            .pending, .borrowed => return error.PreparedStateAlreadyBorrowed,
            .ready => if (allow_reuse and self.identity.?.eql(identity)) {
                self.status = .borrowed;
                return .hit;
            },
            .empty, .poisoned => {},
        }
        self.identity = identity;
        self.status = .pending;
        return .miss;
    }

    pub fn validateCommit(self: *const PreparedStateAdmission) !void {
        if (self.status != .pending and self.status != .borrowed)
            return error.PreparedStateNotBorrowed;
    }

    pub fn commitAssumeValid(self: *PreparedStateAdmission) void {
        self.status = .ready;
    }

    pub fn commit(self: *PreparedStateAdmission) !void {
        try self.validateCommit();
        self.commitAssumeValid();
    }

    pub fn poison(self: *PreparedStateAdmission) void {
        self.status = .poisoned;
        self.identity = null;
    }
};

pub const prepared_geometry_capacity = 4;

pub const PreparedGeometryEntry = struct {
    identity: PreparedStateIdentity,
    plan: arena.Plan,
    last_used: u64,

    pub fn deinit(self: *PreparedGeometryEntry) void {
        self.plan.deinit();
        self.* = undefined;
    }
};

pub const PendingPreparedGeometry = struct {
    identity: PreparedStateIdentity,
    plan: arena.Plan,
};

pub const PreparedGeometryPlanTransfer = struct {
    owner: *?arena.Plan,
    transferred: *bool,
};

pub const PreparedGeometryHandle = struct {
    index: u8,
    plan: *const arena.Plan,
};

pub const PreparedGeometryTransaction = union(enum) {
    none,
    hit: u8,
    pending: PendingPreparedGeometry,
};

pub const PreparedGeometryCache = struct {
    allocator: std.mem.Allocator,
    entries: [prepared_geometry_capacity]?PreparedGeometryEntry =
        [_]?PreparedGeometryEntry{null} ** prepared_geometry_capacity,
    active: PreparedGeometryTransaction = .none,
    clock: u64 = 0,

    pub fn init(allocator: std.mem.Allocator) PreparedGeometryCache {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *PreparedGeometryCache) void {
        self.poisonActive();
        for (&self.entries) |*entry| {
            if (entry.*) |*value| value.deinit();
            entry.* = null;
        }
        self.* = undefined;
    }

    pub fn validateEntry(entry: *const PreparedGeometryEntry) !void {
        if (entry.plan.plan_hash != entry.identity.plan_hash or
            entry.plan.total_bytes != entry.identity.arena_bytes)
        {
            return error.PreparedStatePlanIdentityMismatch;
        }
    }

    pub fn findCommitted(
        self: *PreparedGeometryCache,
        key: PreparedStateKey,
        logical_plan_hash: u64,
    ) !?PreparedGeometryHandle {
        if (self.active != .none) return error.PreparedGeometryAlreadyBorrowed;
        for (&self.entries, 0..) |*entry, index| {
            const value = if (entry.*) |*candidate| candidate else continue;
            if (!std.mem.eql(u8, &value.identity.key, &key) or
                value.identity.logical_plan_hash != logical_plan_hash)
            {
                continue;
            }
            validateEntry(value) catch |err| {
                self.evictIndex(index);
                return err;
            };
            const slot: u8 = @intCast(index);
            self.active = .{ .hit = slot };
            return .{ .index = slot, .plan = &value.plan };
        }
        return null;
    }

    pub fn validateActiveHit(
        self: *const PreparedGeometryCache,
        handle: PreparedGeometryHandle,
        identity: PreparedStateIdentity,
    ) !void {
        const active_index = switch (self.active) {
            .hit => |index| index,
            else => return error.PreparedGeometryHitNotActive,
        };
        if (active_index != handle.index) return error.PreparedGeometryHitNotActive;
        const index: usize = active_index;
        const entry = if (self.entries[index]) |*value| value else return error.PreparedGeometryHitNotActive;
        try validateEntry(entry);
        if (!entry.identity.eql(identity) or handle.plan != &entry.plan)
            return error.PreparedStatePlanIdentityMismatch;
    }

    pub fn stageMiss(
        self: *PreparedGeometryCache,
        identity: PreparedStateIdentity,
        transfer: PreparedGeometryPlanTransfer,
    ) !void {
        if (self.active != .none) return error.PreparedGeometryAlreadyBorrowed;
        if (transfer.transferred.*) return error.PreparedStatePlanAlreadyTransferred;
        const plan = transfer.owner.* orelse return error.MissingPreparedStatePlanOwner;
        if (plan.plan_hash != identity.plan_hash or plan.total_bytes != identity.arena_bytes)
            return error.PreparedStatePlanIdentityMismatch;
        self.active = .{ .pending = .{ .identity = identity, .plan = plan } };
        transfer.transferred.* = true;
    }

    pub fn validateCommit(self: *const PreparedGeometryCache) !void {
        switch (self.active) {
            .none => {},
            .hit => |raw_index| {
                const index: usize = raw_index;
                const entry = if (self.entries[index]) |*value| value else return error.PreparedGeometryHitNotActive;
                try validateEntry(entry);
            },
            .pending => |pending| {
                if (pending.plan.plan_hash != pending.identity.plan_hash or
                    pending.plan.total_bytes != pending.identity.arena_bytes)
                {
                    return error.PreparedStatePlanIdentityMismatch;
                }
            },
        }
    }

    pub fn commitAssumeValid(self: *PreparedGeometryCache) void {
        switch (self.active) {
            .none => {},
            .hit => |raw_index| self.touch(raw_index),
            .pending => |pending| {
                const index = self.chooseVictim();
                self.evictIndex(index);
                self.clock = self.clock +| 1;
                self.entries[index] = .{
                    .identity = pending.identity,
                    .plan = pending.plan,
                    .last_used = self.clock,
                };
            },
        }
        self.active = .none;
    }

    pub fn poisonActive(self: *PreparedGeometryCache) void {
        switch (self.active) {
            .none => {},
            .hit => |raw_index| self.evictIndex(raw_index),
            .pending => |pending| {
                var owned = pending.plan;
                owned.deinit();
            },
        }
        self.active = .none;
    }

    pub fn touch(self: *PreparedGeometryCache, raw_index: u8) void {
        const index: usize = raw_index;
        self.clock = self.clock +| 1;
        self.entries[index].?.last_used = self.clock;
    }

    pub fn chooseVictim(self: *const PreparedGeometryCache) usize {
        for (self.entries, 0..) |entry, index| {
            if (entry == null) return index;
        }
        var victim: usize = 0;
        for (self.entries[1..], 1..) |entry, index| {
            if (entry.?.last_used < self.entries[victim].?.last_used) victim = index;
        }
        return victim;
    }

    pub fn evictIndex(self: *PreparedGeometryCache, index: usize) void {
        if (self.entries[index]) |*entry| entry.deinit();
        self.entries[index] = null;
    }
};
