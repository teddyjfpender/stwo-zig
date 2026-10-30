//! Canonical finite-family public reconstruction from independent admission and
//! proposed physical claims. No encoded offsets, producer capture or base proof.
const std = @import("std");
const E = @import("../prover/block_v7_execution_epoch_v1.zig");
const B = @import("block_v7_mixed_public_v1.zig");
pub const Native = struct { profile: *const @import("block_v7_native_fixed_profile_v1.zig").Owned, claims: B.Family(.native).Claims };
const MemoryComponent = @import("block_v7_memory_component_recursive_v1.zig");
pub const SeparateMemory = struct {
    ram: []const *const MemoryComponent.For(.ram).Profile.Owned,
    interval: *const MemoryComponent.For(.interval).Profile.Owned,
    range16: *const MemoryComponent.For(.range16).Profile.Owned,
    terminal: *const MemoryComponent.For(.terminal).Profile.Owned,
};
pub const Input = struct {
    epoch: E.Epoch,
    entries: []const E.Entry,
    natives: []const Native,
    callers: []const *const @import("block_v7_caller_joint_fixed_profile_v1.zig").Owned,
    active_callers: []const *const @import("block_v7_caller_family_v1.zig").Active.FixedProfile.Owned = &.{},
    program: *const @import("block_v7_program_fixed_profile_v1.zig").Owned,
    lookup: *const @import("block_v7_lookup_compact_fixed_profile_v1.zig").Owned,
    memory: ?*const @import("block_v7_memory_joint_fixed_profile_v1.zig").Owned = null,
    window_memory: ?*const @import("block_v7_memory_joint_fixed_profile_v1.zig").ForMode(true).Owned = null,
    separate_memory: ?SeparateMemory = null,
    pub fn callerCount(self: Input) !usize {
        if (self.callers.len != 0 and self.active_callers.len != 0) return error.InvalidV7MixedCallerMode;
        return std.math.add(usize, self.callers.len, self.active_callers.len);
    }
    pub fn count(self: Input) !usize {
        const memory_modes = @as(u32, @intFromBool(self.memory != null)) + @intFromBool(self.window_memory != null) + @intFromBool(self.separate_memory != null);
        if (memory_modes != 1) return error.InvalidV7MixedMemoryMode;
        const memory_count = if (self.separate_memory) |separate| try std.math.add(usize, separate.ram.len, 3) else 1;
        return std.math.add(usize, try std.math.add(usize, self.natives.len, try self.callerCount()), try std.math.add(usize, 2, memory_count));
    }
};
pub const Owned = struct {
    allocator: std.mem.Allocator,
    children: []B.Child,
    expected: []B.Expected,
    pub fn init(a: std.mem.Allocator, input: Input) !Owned {
        return initWhole(a, input, B.MAX_CHILDREN);
    }
    /// Whole-job metadata only. Direct proof frames remain bounded by64;
    /// batching does not turn any partial window into complete authority.
    pub fn initWhole(a: std.mem.Allocator, input: Input, max_entries: usize) !Owned {
        const total = try input.count();
        if (max_entries == 0 or max_entries >= 1 << 30 or total > max_entries or total != input.entries.len or input.natives.len == 0) return error.InvalidV7CompleteMixedRoster;
        try input.epoch.requireCompleteFamilies();
        if (input.epoch.counts[@intFromEnum(E.Family.caller_arithmetic)] != 0 or input.epoch.counts[@intFromEnum(E.Family.native)] != input.natives.len or input.epoch.counts[@intFromEnum(E.Family.caller_fused)] != try input.callerCount()) return error.InvalidV7CompleteMixedRoster;
        try input.epoch.require(input.epoch.statement, input.epoch.config, input.epoch.counts, input.entries, max_entries);
        const children = try a.alloc(B.Child, total);
        var done: usize = 0;
        errdefer {
            for (children[0..done]) |*child| child.deinit();
            a.free(children);
        }
        const expected = try a.alloc(B.Expected, total);
        errdefer a.free(expected);
        for (input.natives, 0..) |native, index| {
            if (native.profile.pin.index != index) return error.UntrustedV7MixedIndex;
            try sameEpoch(input, native.profile.epoch, native.profile.roster);
            const entry = try native.profile.pin.entry(a);
            expected[done] = try pin(input, .native, @intCast(index), native.profile.seal, entry);
            children[done] = .{ .index = @intCast(index), .value = .{ .native = try B.Family(.native).reconstruct(a, native.profile, native.claims) } };
            done += 1;
        }
        inline for (.{ B.Kind.caller_active, B.Kind.caller }) |kind| {
            const callers = if (kind == .caller_active) input.active_callers else input.callers;
            for (callers, 0..) |caller, index| {
                const proposal = caller.admitted.pin();
                if (proposal.index != index) return error.UntrustedV7MixedIndex;
                try sameEpoch(input, caller.admitted.epoch, caller.admitted.entries);
                const entry = try proposal.require(a, input.epoch, input.entries);
                expected[done] = try pin(input, kind, @intCast(index), caller.seal, entry);
                children[done] = .{ .index = @intCast(index), .value = @unionInit(B.Value, @tagName(kind), try B.Family(kind).reconstruct(a, &caller.admitted, &caller.arithmetic, &caller.claims)) };
                done += 1;
            }
        }
        try sameEpoch(input, input.program.input.policy.epoch, input.program.input.policy.entries);
        expected[done] = try pin(input, .program, 0, input.program.seal, try input.program.input.policy.entry());
        children[done] = .{ .index = 0, .value = .{ .program = try B.Family(.program).reconstruct(a, input.program) } };
        done += 1;
        try sameEpoch(input, input.lookup.input.policy.epoch, input.lookup.input.policy.entries);
        expected[done] = try pin(input, .lookup, 0, input.lookup.seal, try input.lookup.input.policy.entry());
        children[done] = .{ .index = 0, .value = .{ .lookup = try B.Family(.lookup).reconstruct(a, input.lookup) } };
        done += 1;
        if (input.memory) |memory| {
            if (input.epoch.counts[@intFromEnum(E.Family.memory_joint)] != 1) return error.InvalidV7MixedMemoryMode;
            try sameEpoch(input, memory.input.epoch, memory.input.roster);
            const memory_entry = try @import("../prover/block_v7_memory_joint_protocol_v1.zig").entry(memory.input.policy, &memory.layout, memory.input.roots);
            expected[done] = try pin(input, .memory, 0, memory.seal, memory_entry);
            children[done] = .{ .index = 0, .value = .{ .memory = try B.Family(.memory).reconstruct(a, memory) } };
            done += 1;
        } else if (input.window_memory) |memory| {
            if (input.epoch.counts[@intFromEnum(E.Family.window_memory_joint)] != 1) return error.InvalidV7MixedMemoryMode;
            try sameEpoch(input, memory.input.epoch, memory.input.roster);
            const memory_entry = try @import("../prover/block_v7_window_memory_joint_protocol_v1.zig").entry(memory.input.policy, &memory.layout, memory.input.roots);
            expected[done] = try pin(input, .window_memory, 0, memory.seal, memory_entry);
            children[done] = .{ .index = 0, .value = .{ .window_memory = try B.Family(.window_memory).reconstruct(a, memory) } };
            done += 1;
        } else if (input.separate_memory) |separate| {
            if (input.epoch.counts[@intFromEnum(E.Family.memory_joint)] != 0 or separate.ram.len == 0 or separate.ram.len != input.epoch.counts[@intFromEnum(E.Family.ram)]) return error.InvalidV7MixedMemoryMode;
            const Geometry = @import("../prover/block_v5_ram_lanes_protocol_v1.zig");
            const geometry = try a.alloc(Geometry.Claim, separate.ram.len);
            defer a.free(geometry);
            for (separate.ram, geometry, 0..) |ram, *claim, index| {
                if (ram.input.index != index) return error.UntrustedV7MixedIndex;
                claim.* = ram.input.geometry orelse return error.InvalidV7MemoryComponentGeometry;
                try sameEpoch(input, ram.input.epoch, ram.input.roster);
                try ram.validate();
                expected[done] = try pin(input, .ram, @intCast(index), ram.seal, try MemoryComponent.For(.ram).Profile.entry(ram.input));
                children[done] = .{ .index = @intCast(index), .value = .{ .ram = try B.Family(.ram).reconstruct(a, ram) } };
                done += 1;
            }
            try Geometry.admitSequence(geometry, geometry[0].total_events);
            inline for (.{ B.Kind.interval, B.Kind.range16, B.Kind.terminal }) |kind| {
                const profile = @field(separate, @tagName(kind));
                try profile.validate();
                try sameEpoch(input, profile.input.epoch, profile.input.roster);
                expected[done] = try pin(input, kind, 0, profile.seal, try MemoryComponent.For(@field(@import("air/block_v7_memory_composition_v1.zig").Family, @tagName(kind))).Profile.entry(profile.input));
                children[done] = .{ .index = 0, .value = @unionInit(B.Value, @tagName(kind), try B.Family(kind).reconstruct(a, profile)) };
                done += 1;
            }
        }
        const owned = Owned{ .allocator = a, .children = children, .expected = expected };
        try owned.requireSameWhole(children);
        return owned;
    }
    pub fn values(self: *const Owned) B.Values {
        return .{ .children = self.children };
    }
    pub fn requireSame(self: *const Owned, proposed: B.Values) !void {
        try proposed.requireRoster(self.expected);
        for (self.children, proposed.children) |expected, got| switch (expected.value) {
            inline else => |v, kind| try B.Family(kind).requireSameFrame(@field(got.value, @tagName(kind)), v),
        };
    }
    /// Bounds and validates one independently admitted canonical window.
    /// Its residuals are OPEN until complete global closure after reduction.
    pub fn window(self: *const Owned, first: usize, count: usize) !B.Values {
        if (count == 0 or count > B.MAX_CHILDREN or first > self.children.len or count > self.children.len - first) return error.InvalidV7MixedWindow;
        const result = B.Values{ .children = self.children[first..][0..count] };
        try result.requireRoster(self.expected[first..][0..count]);
        return result;
    }
    /// Validate all frames with exact global length, including ordering across
    /// bounded windows. No root or verification success is created here.
    pub fn requireSameWhole(self: *const Owned, proposed: []const B.Child) !void {
        if (proposed.len != self.children.len or self.expected.len != self.children.len or proposed.len == 0) return error.UntrustedV7MixedRoster;
        var first: usize = 0;
        while (first < proposed.len) {
            const count = @min(B.MAX_CHILDREN, proposed.len - first);
            if (first != 0) _ = try B.rosterDigest(self.expected[first - 1 .. first + 1]);
            try (B.Values{ .children = proposed[first..][0..count] }).requireRoster(self.expected[first..][0..count]);
            for (self.children[first..][0..count], proposed[first..][0..count]) |expected, got| switch (expected.value) {
                inline else => |v, kind| try B.Family(kind).requireSameFrame(@field(got.value, @tagName(kind)), v),
            };
            first += count;
        }
    }
    pub fn deinit(self: *Owned) void {
        for (self.children) |*child| child.deinit();
        self.allocator.free(self.children);
        self.allocator.free(self.expected);
        self.* = undefined;
    }
};
fn sameEpoch(input: Input, epoch: E.Epoch, entries: []const E.Entry) !void {
    if (!std.meta.eql(input.epoch, epoch) or entries.len != input.entries.len) return error.MixedV7Epochs;
    for (entries, input.entries) |got, want| if (!std.meta.eql(got, want)) return error.MixedV7Epochs;
}
fn pin(input: Input, kind: B.Kind, index: u32, template: [32]u8, entry: E.Entry) !B.Expected {
    try input.epoch.requireEntry(input.entries, entry);
    if (entry.index != index or entry.family != B.epochFamily(kind)) return error.UntrustedV7MixedIndex;
    return .{ .kind = kind, .index = index, .template = template, .epoch = input.epoch.digest, .entry = entry };
}
