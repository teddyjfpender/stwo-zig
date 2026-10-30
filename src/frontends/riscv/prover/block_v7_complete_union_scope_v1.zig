//! Independent admission for the finite one-window direct original STARK.
//! No original proof, producer receipt or recursively authenticated frame is
//! accepted here. The caller must subsequently verify the union STARK.
const std = @import("std");
const E = @import("block_v7_execution_epoch_v1.zig");
const Initial = @import("block_v7_initial_intervals_v1.zig");
const Image = @import("block_v7_program_image_v1.zig");
const Policy = @import("block_v7_execution_policy_v1.zig").Policy;
const Receiver = @import("block_v7_execution_receiver_v1.zig");
const Profile = @import("blake3_ethereum_sha_profile.zig");
const LP = @import("block_v5_native_lookup_plan_v1.zig");
pub const Input = struct {
    epoch: E.Epoch,
    entries: []const E.Entry,
    native: @import("block_v7_native_source_v1.zig").Pin,
    caller: @import("block_v7_caller_active_source_v1.zig").Pin,
    program_plan: @import("block_v5_program_table_v1.zig").Plan,
    program_roots: [2][32]u8,
    lookup_plan: LP.Plan,
    lookup_layout: @import("block_v7_lookup_compact_layout_v1.zig").Layout,
    lookup_roots: [2][32]u8,
    memory_roots: [2][32]u8,
    interval_log: u32,
};
pub const Owned = struct {
    a: std.mem.Allocator,
    initial: Initial.Owned,
    image: Image.Owned,
    policy: Policy,
    pub fn init(a: std.mem.Allocator, trusted: Receiver.Trusted, input: Input, limits: Receiver.Limits) !*Owned {
        var expected: E.Counts = @splat(0);
        inline for (.{ E.Family.native, E.Family.caller_fused, E.Family.program, E.Family.lookup, E.Family.memory_joint }) |family| expected[@intFromEnum(family)] = 1;
        if (!std.meta.eql(input.epoch.counts, expected) or input.entries.len != 5 or limits.max_segments < 1 or limits.max_entries < 5) return error.InvalidCompleteUnionRoster;
        try input.epoch.requireCompleteFamilies();
        const self = try a.create(Owned);
        errdefer a.destroy(self);
        self.a = a;
        self.initial = try Initial.Owned.derive(a, trusted.elf, trusted.elf_sha256, trusted.profile, limits.initial);
        errdefer self.initial.deinit();
        self.image = try Image.Owned.init(a, trusted.elf, &self.initial, limits.initial);
        errdefer self.image.deinit();
        self.policy = .{ .initialized = &self.initial, .program_root = self.image.root.bytes, .terminal = trusted.terminal, .config = trusted.config };
        try input.epoch.require(try self.policy.digest(), trusted.config, expected, input.entries, 5);
        const np = input.native;
        const cp = input.caller;
        if (trusted.profile != Profile.execution_profile or np.index != 0 or cp.index != 0 or cp.execution_index != 0 or np.template.execution_profile != trusted.profile or np.template.external_retirements != Profile.externalCount(cp.statement)) return error.UntrustedCompleteUnionWindow;
        try @import("block_v7_native_caller_union_proof_v1.zig").require(a, np, cp, input.epoch, input.entries);
        try self.policy.validateWindows(&.{.{ .shape = np.shape, .frame = np.frame, .external_retirements = np.template.external_retirements }});
        var demands: [6]u64 = @splat(0);
        try LP.addDemand(&demands, try LP.nativeDemand(np.shape, np.template.external_retirements));
        try LP.addDemand(&demands, try LP.sidecarMemoryDemand(np.expected_events));
        var schedule = try @import("block_v5_caller_fused_schedule_v1.zig").Schedule.init(a, cp.statement, cp.total_steps, cp.frame, 1);
        defer schedule.deinit();
        const demand = try @import("block_v5_memory_byte_demand_v1.zig").externalDemandForMode(cp.statement, schedule.memory, 1);
        try @import("block_v5_precompile_table_demand_v1.zig").add(a, &demands, cp.statement, cp.total_steps, trusted.config);
        try LP.addDemand(&demands, try LP.sidecarMemoryDemand(demand.event_count));
        const plan = LP.Plan{ .index = 0, .first_execution = 0, .execution_count = 1, .max_requests = demands };
        if (!std.meta.eql(plan, input.lookup_plan)) return error.UntrustedV7LookupDemand;
        if (!std.meta.eql(input.program_plan.program_root, self.image.root) or input.program_plan.leaves.len != self.image.leaves.len) return error.UntrustedV7ProgramImage;
        for (input.program_plan.leaves, self.image.leaves) |actual, expected_leaf| if (!std.meta.eql(actual, expected_leaf)) return error.UntrustedV7ProgramImage;
        return self;
    }
    pub fn deinit(self: *Owned) void {
        const a = self.a;
        self.image.deinit();
        self.initial.deinit();
        a.destroy(self);
    }
};
