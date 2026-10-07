//! Deterministic lifetime-aware device arena for one resident proof.

const std = @import("std");
const column = @import("column.zig");
const context_module = @import("context.zig");
const native_api = @import("../abi/runtime.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");

pub const SlotId = u32;

/// Explicit research mode: only an arena that would otherwise fail the
/// device-capacity gate may use managed memory. Ordinary proofs keep the
/// device-pool allocation and its performance characteristics.
pub fn managedOversubscriptionEnabled() bool {
    const value = std.posix.getenv("STWO_CUDA_MANAGED_ARENA") orelse return false;
    return std.mem.eql(u8, value, "1");
}

pub const Requirement = struct {
    id: SlotId,
    words: usize,
    alignment_words: usize = 1,
    live_from: telemetry.Stage,
    live_through: telemetry.Stage,
    // Two ordered points within a stage. The default occupies the full
    // stage; a producer finishing in phase 0 may alias a consumer that first
    // writes in phase 1, provided their execution is ordered on the stream.
    live_from_phase: u1 = 0,
    live_through_phase: u1 = 1,
};

pub const Placement = struct {
    requirement: Requirement,
    offset_words: usize,

    pub fn endWords(self: Placement) runtime_error.Error!usize {
        return std.math.add(
            usize,
            self.offset_words,
            self.requirement.words,
        ) catch error.SizeOverflow;
    }
};

pub const Plan = struct {
    placements: []Placement,
    total_words: usize,

    pub fn init(
        allocator: std.mem.Allocator,
        requirements: []const Requirement,
    ) (std.mem.Allocator.Error || runtime_error.Error)!Plan {
        if (requirements.len == 0) return error.EmptyArenaPlan;
        const ordered = try allocator.dupe(Requirement, requirements);
        defer allocator.free(ordered);
        for (ordered, 0..) |requirement, index| {
            try validateRequirement(requirement);
            for (ordered[0..index]) |previous| {
                if (previous.id == requirement.id) return error.DuplicateArenaSlot;
            }
        }
        std.mem.sort(Requirement, ordered, {}, orderRequirements);

        var placements = try allocator.alloc(Placement, ordered.len);
        errdefer allocator.free(placements);
        var total_words = try placeSorted(ordered, placements);

        // First-fit decreasing is usually tight, but large mixed-lifetime
        // proofs can strand several GB in holes. Try a bounded set of stable
        // orderings and keep only a strictly smaller layout. Small arenas
        // retain the original fast path and all results remain deterministic.
        if (ordered.len >= 64 and total_words > 25_000_000_000) {
            const lower_bound = try peakLiveWords(requirements);
            var max_alignment: usize = 1;
            for (requirements) |requirement|
                max_alignment = @max(max_alignment, requirement.alignment_words);
            const target = std.math.add(usize, lower_bound, max_alignment) catch
                return error.SizeOverflow;
            var candidate = try allocator.alloc(Placement, ordered.len);
            defer allocator.free(candidate);
            for (0..64) |index| {
                if (total_words <= target) break;
                @memcpy(ordered, requirements);
                std.mem.sort(Requirement, ordered, @as(u64, @intCast(index)) + 1, orderPerturbed);
                const candidate_words = try placeSorted(ordered, candidate);
                if (candidate_words < total_words) {
                    std.mem.swap([]Placement, &placements, &candidate);
                    total_words = candidate_words;
                }
            }
        }
        std.mem.sort(Placement, placements, {}, orderPlacementsById);
        return .{ .placements = placements, .total_words = total_words };
    }

    pub fn deinit(self: *Plan, allocator: std.mem.Allocator) void {
        allocator.free(self.placements);
        self.* = undefined;
    }

    pub fn clone(
        self: Plan,
        allocator: std.mem.Allocator,
    ) std.mem.Allocator.Error!Plan {
        return .{
            .placements = try allocator.dupe(Placement, self.placements),
            .total_words = self.total_words,
        };
    }

    pub fn placement(self: Plan, id: SlotId) runtime_error.Error!Placement {
        var low: usize = 0;
        var high = self.placements.len;
        while (low < high) {
            const middle = low + (high - low) / 2;
            const candidate = self.placements[middle];
            if (candidate.requirement.id < id) {
                low = middle + 1;
            } else {
                high = middle;
            }
        }
        if (low == self.placements.len or self.placements[low].requirement.id != id)
            return error.ArenaSlotMissing;
        return self.placements[low];
    }
};

pub const NativeArena = ArenaFor(context_module.ContextFor(native_api));

pub fn ArenaFor(comptime Context: type) type {
    return struct {
        const Self = @This();

        backing: Context.Buffer,
        plan: Plan,

        pub fn init(
            context: *Context,
            plan: *const Plan,
        ) runtime_error.Error!Self {
            if (plan.total_words == 0) return error.EmptyArenaPlan;
            return .{
                .backing = try context.allocate(plan.total_words),
                // Copy the slice descriptor, not the address of the caller's
                // Plan value. A proof transaction is returned by value, so a
                // retained pointer would become stale when that value moves.
                .plan = plan.*,
            };
        }

        pub fn initManaged(
            context: *Context,
            plan: *const Plan,
        ) runtime_error.Error!Self {
            if (plan.total_words == 0) return error.EmptyArenaPlan;
            if (comptime @hasDecl(Context, "allocateManaged")) {
                return .{
                    .backing = try context.allocateManaged(plan.total_words),
                    .plan = plan.*,
                };
            } else return error.InvalidState;
        }

        pub fn initPersistent(
            context: *Context,
            plan: *const Plan,
        ) runtime_error.Error!Self {
            if (plan.total_words == 0) return error.EmptyArenaPlan;
            return .{
                .backing = try context.allocatePersistent(plan.total_words),
                .plan = plan.*,
            };
        }

        pub fn initPersistentManaged(
            context: *Context,
            plan: *const Plan,
        ) runtime_error.Error!Self {
            if (plan.total_words == 0) return error.EmptyArenaPlan;
            if (comptime @hasDecl(Context, "allocatePersistentManaged")) {
                return .{
                    .backing = try context.allocatePersistentManaged(plan.total_words),
                    .plan = plan.*,
                };
            } else return error.InvalidState;
        }

        pub fn slice(
            self: *const Self,
            id: SlotId,
        ) runtime_error.Error!column.DeviceSlice(u32) {
            const placed = try self.plan.placement(id);
            const byte_offset = std.math.mul(
                usize,
                placed.offset_words,
                @sizeOf(u32),
            ) catch return error.SizeOverflow;
            return .{
                .address = std.math.add(
                    usize,
                    @intFromPtr(self.backing.pointer),
                    byte_offset,
                ) catch return error.SizeOverflow,
                .len = placed.requirement.words,
                .owner = self.backing.owner,
                .generation = self.backing.generation,
            };
        }

        pub fn sliceAs(
            self: *const Self,
            comptime F: type,
            id: SlotId,
        ) runtime_error.Error!column.DeviceSlice(F) {
            return (try self.slice(id)).cast(F);
        }

        /// Returns the exact allocation owned by this arena. Offset-addressed
        /// product kernels need the allocation base, but must not reconstruct
        /// it from an arbitrary slot or bypass context ownership checks.
        pub fn words(
            self: *const Self,
        ) column.DeviceSlice(u32) {
            return .{
                .address = @intFromPtr(self.backing.pointer),
                .len = self.plan.total_words,
                .owner = self.backing.owner,
                .generation = self.backing.generation,
            };
        }

        pub fn deinit(
            self: *Self,
            context: *Context,
        ) runtime_error.Error!void {
            try context.free(&self.backing);
            self.plan = undefined;
        }

        pub fn deinitPersistent(
            self: *Self,
            context: *Context,
        ) runtime_error.Error!void {
            try context.freePersistent(&self.backing);
            self.plan = undefined;
        }
    };
}

fn validateRequirement(requirement: Requirement) runtime_error.Error!void {
    if (requirement.words == 0 or
        requirement.alignment_words == 0 or
        !std.math.isPowerOfTwo(requirement.alignment_words) or
        lifetimeStart(requirement) > lifetimeEnd(requirement))
    {
        return error.InvalidArenaRequirement;
    }
}

fn orderRequirements(_: void, lhs: Requirement, rhs: Requirement) bool {
    if (lhs.words != rhs.words) return lhs.words > rhs.words;
    const lhs_lifetime = lifetimeEnd(lhs) - lifetimeStart(lhs);
    const rhs_lifetime = lifetimeEnd(rhs) - lifetimeStart(rhs);
    if (lhs_lifetime != rhs_lifetime) return lhs_lifetime > rhs_lifetime;
    return lhs.id < rhs.id;
}

fn orderPerturbed(seed: u64, lhs: Requirement, rhs: Requirement) bool {
    const lhs_score = @as(u128, lhs.words) * splitmix64(@as(u64, lhs.id) +% seed *% 10_007);
    const rhs_score = @as(u128, rhs.words) * splitmix64(@as(u64, rhs.id) +% seed *% 10_007);
    if (lhs_score != rhs_score) return lhs_score > rhs_score;
    return lhs.id < rhs.id;
}

fn splitmix64(input: u64) u64 {
    var value = input +% 0x9e3779b97f4a7c15;
    value = (value ^ (value >> 30)) *% 0xbf58476d1ce4e5b9;
    value = (value ^ (value >> 27)) *% 0x94d049bb133111eb;
    return value ^ (value >> 31);
}

fn placeSorted(requirements: []const Requirement, placements: []Placement) runtime_error.Error!usize {
    var total_words: usize = 0;
    for (requirements, 0..) |requirement, index| {
        const offset = try findOffset(requirement, placements[0..index]);
        const located = Placement{ .requirement = requirement, .offset_words = offset };
        placements[index] = located;
        total_words = @max(total_words, try located.endWords());
    }
    return total_words;
}

fn peakLiveWords(requirements: []const Requirement) runtime_error.Error!usize {
    var peak: usize = 0;
    for (0..telemetry.stage_count * 2) |point| {
        var live: usize = 0;
        for (requirements) |requirement| {
            if (lifetimeStart(requirement) <= point and
                point <= lifetimeEnd(requirement))
            {
                live = std.math.add(usize, live, requirement.words) catch
                    return error.SizeOverflow;
            }
        }
        peak = @max(peak, live);
    }
    return peak;
}

fn orderPlacementsById(_: void, lhs: Placement, rhs: Placement) bool {
    return lhs.requirement.id < rhs.requirement.id;
}

fn findOffset(
    requirement: Requirement,
    placed: []const Placement,
) runtime_error.Error!usize {
    var candidate: usize = 0;
    while (true) {
        candidate = std.mem.alignForward(
            usize,
            candidate,
            requirement.alignment_words,
        );
        const candidate_end = std.math.add(
            usize,
            candidate,
            requirement.words,
        ) catch return error.SizeOverflow;
        var blocker_end: usize = 0;
        for (placed) |other| {
            if (!lifetimesOverlap(requirement, other.requirement)) continue;
            const other_end = try other.endWords();
            if (candidate < other_end and other.offset_words < candidate_end) {
                blocker_end = @max(blocker_end, other_end);
            }
        }
        if (blocker_end == 0) return candidate;
        candidate = blocker_end;
    }
}

fn lifetimesOverlap(lhs: Requirement, rhs: Requirement) bool {
    return lifetimeStart(lhs) <= lifetimeEnd(rhs) and
        lifetimeStart(rhs) <= lifetimeEnd(lhs);
}

fn lifetimeStart(requirement: Requirement) usize {
    return requirement.live_from.index() * 2 + requirement.live_from_phase;
}

fn lifetimeEnd(requirement: Requirement) usize {
    return requirement.live_through.index() * 2 + requirement.live_through_phase;
}

test "arena aliases scratch only after its protocol lifetime ends" {
    const allocator = std.testing.allocator;
    var plan = try Plan.init(allocator, &.{
        .{
            .id = 1,
            .words = 1024,
            .live_from = .ingress,
            .live_through = .decommit,
        },
        .{
            .id = 2,
            .words = 512,
            .live_from = .oods,
            .live_through = .oods,
        },
        .{
            .id = 3,
            .words = 512,
            .live_from = .quotient,
            .live_through = .quotient,
        },
    });
    defer plan.deinit(allocator);

    const trace = try plan.placement(1);
    const oods = try plan.placement(2);
    const quotient = try plan.placement(3);
    try std.testing.expectEqual(@as(usize, 0), trace.offset_words);
    try std.testing.expectEqual(oods.offset_words, quotient.offset_words);
    try std.testing.expect(oods.offset_words >= 1024);
    try std.testing.expectEqual(@as(usize, 1536), plan.total_words);
}

test "arena aliases ordered work within one protocol stage" {
    const allocator = std.testing.allocator;
    var plan = try Plan.init(allocator, &.{
        .{ .id = 1, .words = 1024, .live_from = .trace_generation, .live_through = .trace_commit, .live_through_phase = 0 },
        .{ .id = 2, .words = 1024, .live_from = .trace_commit, .live_from_phase = 1, .live_through = .decommit },
        .{ .id = 3, .words = 1024, .live_from = .trace_commit, .live_through = .decommit },
    });
    defer plan.deinit(allocator);
    try std.testing.expectEqual((try plan.placement(1)).offset_words, (try plan.placement(2)).offset_words);
    try std.testing.expect((try plan.placement(3)).offset_words != (try plan.placement(1)).offset_words);
    try std.testing.expectEqual(@as(usize, 2048), plan.total_words);
}

test "arena preserves alignment and concurrent slot separation" {
    const allocator = std.testing.allocator;
    var plan = try Plan.init(allocator, &.{
        .{
            .id = 9,
            .words = 17,
            .alignment_words = 16,
            .live_from = .fri_commit,
            .live_through = .decommit,
        },
        .{
            .id = 4,
            .words = 31,
            .alignment_words = 8,
            .live_from = .fri_commit,
            .live_through = .decommit,
        },
    });
    defer plan.deinit(allocator);
    const lhs = try plan.placement(9);
    const rhs = try plan.placement(4);
    try std.testing.expectEqual(@as(usize, 0), lhs.offset_words % 16);
    try std.testing.expectEqual(@as(usize, 0), rhs.offset_words % 8);
    try std.testing.expect(
        try lhs.endWords() <= rhs.offset_words or
            try rhs.endWords() <= lhs.offset_words,
    );
}

test "arena rejects duplicate and malformed requirements" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(error.DuplicateArenaSlot, Plan.init(allocator, &.{
        .{
            .id = 1,
            .words = 1,
            .live_from = .ingress,
            .live_through = .ingress,
        },
        .{
            .id = 1,
            .words = 2,
            .live_from = .oods,
            .live_through = .oods,
        },
    }));
    try std.testing.expectError(error.InvalidArenaRequirement, Plan.init(allocator, &.{
        .{
            .id = 1,
            .words = 0,
            .alignment_words = 3,
            .live_from = .quotient,
            .live_through = .oods,
        },
    }));
}

test "arena materializes every slot from one context allocation" {
    const FakeContext = struct {
        pub const Buffer = struct {
            pointer: [*]u32,
            words: usize,
            owner: usize,
            generation: u64,
        };

        storage: [64]u32 = [_]u32{0} ** 64,
        allocations: usize = 0,
        frees: usize = 0,

        pub fn allocate(self: *@This(), words: usize) runtime_error.Error!Buffer {
            if (words > self.storage.len) return error.SizeOverflow;
            self.allocations += 1;
            return .{
                .pointer = &self.storage,
                .words = words,
                .owner = @intFromPtr(self),
                .generation = 1,
            };
        }

        pub fn free(self: *@This(), buffer: *Buffer) runtime_error.Error!void {
            if (buffer.owner != @intFromPtr(self)) return error.ContextMismatch;
            self.frees += 1;
            buffer.words = 0;
        }
    };

    const allocator = std.testing.allocator;
    var plan = try Plan.init(allocator, &.{
        .{
            .id = 1,
            .words = 16,
            .live_from = .ingress,
            .live_through = .proof_assembly,
        },
        .{
            .id = 2,
            .words = 8,
            .live_from = .oods,
            .live_through = .oods,
        },
    });
    defer plan.deinit(allocator);
    var context = FakeContext{};
    const FakeArena = ArenaFor(FakeContext);
    var arena = try FakeArena.init(&context, &plan);
    const whole = arena.words();
    const trace = try arena.slice(1);
    const scratch = try arena.slice(2);
    try std.testing.expectEqual(@as(usize, 1), context.allocations);
    try std.testing.expectEqual(plan.total_words, whole.len);
    try std.testing.expectEqual(
        @intFromPtr(arena.backing.pointer),
        whole.address,
    );
    try std.testing.expectEqual(arena.backing.owner, whole.owner);
    try std.testing.expectEqual(
        arena.backing.generation,
        whole.generation,
    );
    try std.testing.expectEqual(@as(usize, 16), trace.len);
    try std.testing.expectEqual(@as(usize, 8), scratch.len);
    try std.testing.expect(trace.owner == scratch.owner);
    try arena.deinit(&context);
    try std.testing.expectEqual(@as(usize, 1), context.frees);
}

test "arena plans clone without sharing placement ownership" {
    const allocator = std.testing.allocator;
    var plan = try Plan.init(allocator, &.{.{
        .id = 1,
        .words = 32,
        .live_from = .ingress,
        .live_through = .decommit,
    }});
    defer plan.deinit(allocator);
    var cloned = try plan.clone(allocator);
    defer cloned.deinit(allocator);
    try std.testing.expectEqual(plan.total_words, cloned.total_words);
    try std.testing.expectEqualSlices(
        Placement,
        plan.placements,
        cloned.placements,
    );
    try std.testing.expect(
        @intFromPtr(plan.placements.ptr) != @intFromPtr(cloned.placements.ptr),
    );
}
