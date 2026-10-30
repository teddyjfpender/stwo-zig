//! Variable-size, detached public proposal metadata for independent mixed-key
//! derivation. This owner carries no success receipt and proves nothing. All
//! claims must be authenticated by the final mixed root and global receiver.
const std = @import("std");
const Original = @import("../prover/block_v7_execution_receiver_v1.zig");
const Inputs = @import("block_v7_mixed_inputs_v1.zig");
const Initial = @import("../prover/block_v7_initial_intervals_v1.zig");
const Native = @import("block_v7_native_fixed_profile_v1.zig");
const Caller = @import("block_v7_caller_joint_fixed_profile_v1.zig");
const ActiveCaller = @import("block_v7_caller_family_v1.zig").Active.FixedProfile;
const Program = @import("block_v7_program_fixed_profile_v1.zig");
const Lookup = @import("block_v7_lookup_compact_fixed_profile_v1.zig");
const Memory = @import("block_v7_memory_joint_fixed_profile_v1.zig");
const WindowMemory = Memory.ForMode(true);
const Component = @import("block_v7_memory_component_recursive_v1.zig");
pub const Owned = struct {
    allocator: std.mem.Allocator,
    trusted: Original.Trusted,
    initialized: Initial.Owned,
    natives: []Inputs.Native,
    callers: []*const Caller.Owned,
    active_callers: []*const ActiveCaller.Owned,
    program: *Program.Owned,
    lookup: *Lookup.Owned,
    memory: ?*Memory.Owned = null,
    window_memory: ?*WindowMemory.Owned = null,
    separate_memory: ?Inputs.SeparateMemory = null,
    pub fn init(a: std.mem.Allocator, trusted: Original.Trusted, proposal: Original.Input) !*Owned {
        return initWhole(a, trusted, proposal, @import("block_v7_mixed_public_v1.zig").MAX_CHILDREN);
    }
    /// Bounded whole-job metadata for multiple direct windows. This does not
    /// raise a direct proof's64-child cap or authenticate a partial roster.
    pub fn initWhole(a: std.mem.Allocator, trusted: Original.Trusted, proposal: Original.Input, max_entries: usize) !*Owned {
        const memory_count: usize = switch (proposal.memory) {
            .joint, .window_joint => 1,
            .separate => |bundle| try std.math.add(usize, bundle.ram.len, 3),
        };
        if (proposal.callers.len != 0 and proposal.active_callers.len != 0) return error.InvalidV7MixedCallerMode;
        const caller_count = try std.math.add(usize, proposal.callers.len, proposal.active_callers.len);
        const count = try std.math.add(usize, try std.math.add(usize, proposal.natives.len, caller_count), try std.math.add(usize, 2, memory_count));
        if (max_entries == 0 or max_entries >= 1 << 30 or proposal.lookup != .compact or proposal.natives.len == 0 or count > max_entries) return error.InvalidV7MixedMetadata;
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        const elf = try a.dupe(u8, trusted.elf);
        errdefer a.free(elf);
        const window = if (trusted.window) |boundary| try boundary.cloneAlloc(a) else null;
        errdefer if (window) |boundary| {
            boundary.deinit();
            a.destroy(boundary);
        };
        var owned_trusted = trusted;
        owned_trusted.elf = elf;
        owned_trusted.window = window;
        self.initialized = try Original.deriveInitialization(a, owned_trusted, .{});
        errdefer self.initialized.deinit();
        const natives = try a.alloc(Inputs.Native, proposal.natives.len);
        errdefer a.free(natives);
        var native_count: usize = 0;
        errdefer for (natives[0..native_count]) |native| {
            @constCast(native.profile).deinit();
            a.free(native.claims.projection);
            a.free(native.claims.access);
        };
        for (proposal.natives, natives) |source, *native| {
            const profile = try Native.Owned.derive(a, source.pin, proposal.epoch, proposal.entries, .{});
            errdefer profile.deinit();
            const projection = try a.dupe(@TypeOf(source.proof.claims[0]), source.proof.claims);
            errdefer a.free(projection);
            const access = try a.dupe(@TypeOf(source.proof.memory_claims[0]), source.proof.memory_claims);
            native.* = .{ .profile = profile, .claims = .{ .projection = projection, .access = access } };
            native_count += 1;
        }
        const callers = try deriveCallers(false, a, proposal);
        errdefer freeCallers(a, callers);
        const active_callers = try deriveCallers(true, a, proposal);
        errdefer freeCallers(a, active_callers);
        const program = try Program.Owned.derive(a, .{ .policy = .{ .plan = proposal.program_plan, .expected_program_root = proposal.program_plan.program_root, .roots = proposal.program_roots, .epoch = proposal.epoch, .entries = proposal.entries }, .claim = proposal.program.claim }, .{});
        errdefer program.deinit();
        const compact = proposal.lookup.compact;
        const lookup = try Lookup.Owned.derive(a, .{ .policy = .{ .plan = proposal.lookup_plan, .layout = compact.layout, .roots = proposal.lookup_roots, .epoch = proposal.epoch, .entries = proposal.entries }, .claims = compact.proof.claims }, .{});
        errdefer lookup.deinit();
        const policy = @import("../prover/block_v7_execution_policy_v1.zig").Policy{ .initialized = &self.initialized, .program_root = proposal.program_plan.program_root.bytes, .terminal = trusted.terminal, .config = trusted.config, .window = window };
        var memory: ?*Memory.Owned = null;
        var window_memory: ?*WindowMemory.Owned = null;
        var separate: ?Inputs.SeparateMemory = null;
        switch (proposal.memory) {
            .joint => |proof| memory = try Memory.Owned.derive(a, .{ .policy = policy, .epoch = proposal.epoch, .roster = proposal.entries, .roots = proof.roots, .interval_log = proof.interval_log, .claims = proof.claims() }, .{}),
            .window_joint => |proof| window_memory = try WindowMemory.Owned.derive(a, .{ .policy = policy, .epoch = proposal.epoch, .roster = proposal.entries, .roots = proof.roots, .interval_log = proof.interval_log, .claims = proof.claims() }, .{}),
            .separate => |bundle| separate = try deriveSeparate(a, policy, proposal, bundle),
        }
        errdefer if (memory) |value| value.deinit();
        errdefer if (window_memory) |value| value.deinit();
        errdefer if (separate) |value| freeSeparate(a, value);
        // Preserve the stable address of initialized, which memory.policy owns
        // only as a borrowed pointer to this explicitly retained metadata.
        self.allocator = a;
        self.trusted = owned_trusted;
        self.natives = natives;
        self.callers = callers;
        self.active_callers = active_callers;
        self.program = program;
        self.lookup = lookup;
        self.memory = memory;
        self.window_memory = window_memory;
        self.separate_memory = separate;
        var canonical = try Inputs.Owned.initWhole(a, self.input(), max_entries);
        canonical.deinit();
        return self;
    }
    pub fn input(self: *const Owned) Inputs.Input {
        return .{ .epoch = self.program.input.policy.epoch, .entries = self.program.input.policy.entries, .natives = self.natives, .callers = self.callers, .active_callers = self.active_callers, .program = self.program, .lookup = self.lookup, .memory = self.memory, .window_memory = self.window_memory, .separate_memory = self.separate_memory };
    }
    pub fn deinit(self: *Owned) void {
        const a = self.allocator;
        if (self.memory) |memory| memory.deinit();
        if (self.window_memory) |memory| memory.deinit();
        if (self.separate_memory) |separate| freeSeparate(a, separate);
        self.lookup.deinit();
        self.program.deinit();
        freeCallers(a, self.callers);
        freeCallers(a, self.active_callers);
        for (self.natives) |native| {
            @constCast(native.profile).deinit();
            a.free(native.claims.projection);
            a.free(native.claims.access);
        }
        a.free(self.natives);
        self.initialized.deinit();
        if (self.trusted.window) |boundary| {
            @constCast(boundary).deinit();
            a.destroy(boundary);
        }
        a.free(self.trusted.elf);
        a.destroy(self);
    }
};

fn deriveSeparate(a: std.mem.Allocator, policy: @import("../prover/block_v7_execution_policy_v1.zig").Policy, proposal: Original.Input, bundle: *const @import("../prover/block_v7_memory_source_v1.zig").Bundle) !Inputs.SeparateMemory {
    const ram = try a.alloc(*const Component.For(.ram).Profile.Owned, bundle.ram.len);
    errdefer a.free(ram);
    var ready: usize = 0;
    errdefer for (ram[0..ready]) |item| @constCast(item).deinit();
    for (bundle.ram, ram, 0..) |item, *out, i| {
        out.* = try Component.For(.ram).Profile.Owned.derive(a, .{ .policy = policy, .epoch = proposal.epoch, .roster = proposal.entries, .index = @intCast(i), .row_log = item.geometry.row_log, .roots = item.proof.roots, .sums = item.proof.sums, .geometry = item.geometry }, .{});
        ready += 1;
    }
    const interval = try Component.For(.interval).Profile.Owned.derive(a, .{ .policy = policy, .epoch = proposal.epoch, .roster = proposal.entries, .index = 0, .row_log = bundle.interval_log, .roots = bundle.interval.roots, .sums = bundle.interval.sums }, .{});
    errdefer interval.deinit();
    const range16 = try Component.For(.range16).Profile.Owned.derive(a, .{ .policy = policy, .epoch = proposal.epoch, .roster = proposal.entries, .index = 0, .row_log = 16, .roots = bundle.range16.roots, .sums = bundle.range16.sums }, .{});
    errdefer range16.deinit();
    const terminal = try Component.For(.terminal).Profile.Owned.derive(a, .{ .policy = policy, .epoch = proposal.epoch, .roster = proposal.entries, .index = 0, .row_log = 4, .roots = bundle.terminal.roots, .sums = bundle.terminal.sums }, .{});
    return .{ .ram = ram, .interval = interval, .range16 = range16, .terminal = terminal };
}
fn freeSeparate(a: std.mem.Allocator, memory: Inputs.SeparateMemory) void {
    for (memory.ram) |item| @constCast(item).deinit();
    a.free(memory.ram);
    @constCast(memory.interval).deinit();
    @constCast(memory.range16).deinit();
    @constCast(memory.terminal).deinit();
}

fn deriveCallers(comptime active: bool, a: std.mem.Allocator, proposal: Original.Input) ![]*const @import("block_v7_caller_family_v1.zig").For(active).FixedProfile.Owned {
    const Profile = @import("block_v7_caller_family_v1.zig").For(active).FixedProfile;
    const sources = if (active) proposal.active_callers else proposal.callers;
    const result = try a.alloc(*const Profile.Owned, sources.len);
    errdefer a.free(result);
    var ready: usize = 0;
    errdefer for (result[0..ready]) |item| @constCast(item).deinit();
    for (sources, result) |source, *out| {
        out.* = try Profile.Owned.derive(a, .{ .pin = source.pin, .epoch = proposal.epoch, .entries = proposal.entries, .arithmetic = source.proof.arithmetic, .claims = source.proof.relations }, .{});
        ready += 1;
    }
    return result;
}
fn freeCallers(a: std.mem.Allocator, callers: anytype) void {
    for (callers) |caller| @constCast(caller).deinit();
    a.free(callers);
}
