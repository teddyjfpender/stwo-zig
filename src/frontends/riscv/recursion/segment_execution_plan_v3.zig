//! Two-pass sizing for a bounded leaf-local ELF campaign.
//!
//! The first pass supplies exact cycle counts for a V3 JobContext. The second
//! pass checks the same input, session policy and per-leaf sizes while a caller
//! constructs proofs. A plan is advisory: only verified proofs may authorize
//! the final statement and root.

const std = @import("std");
const profile_mod = @import("../isa/execution_profile.zig");
const result = @import("../runner/result.zig");
const session = @import("../runner/segment_session.zig");
const campaign = @import("segment_execution_campaign_v3.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Plan = struct {
    allocator: std.mem.Allocator,
    profile: profile_mod.ExecutionProfile,
    elf_sha256: [32]u8,
    input_sha256: [32]u8,
    stop_on_halt_flag: bool,
    strict_completion: bool,
    require_current_output_accesses: bool,
    x0_local_custody_version: u32,
    leaf_budget: usize,
    cycle_counts: []u32,
    summary: campaign.Summary,

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.cycle_counts);
        self.* = undefined;
    }

    pub fn validate(self: *const Plan) !void {
        if (self.leaf_budget == 0 or
            self.leaf_budget > @import("segment_leaf_local_authority_v3.zig").MAX_LEAF_CYCLES or
            self.cycle_counts.len == 0 or
            self.cycle_counts.len != self.summary.leaf_count)
            return error.InvalidCampaignPlan;
        var total: u64 = 0;
        for (self.cycle_counts) |count| {
            if (count == 0 or count > self.leaf_budget) return error.InvalidCampaignPlan;
            total = std.math.add(u64, total, count) catch
                return error.InvalidCampaignPlan;
        }
        if (total != self.summary.retired_cycles) return error.InvalidCampaignPlan;
    }
};

pub fn prepare(
    comptime profile: profile_mod.ExecutionProfile,
    allocator: std.mem.Allocator,
    elf: []const u8,
    options: session.SessionOptions,
    leaf_budget: usize,
    max_leaves: u32,
) !Plan {
    try requireUnhosted(options);
    var collector = Collector(profile){ .allocator = allocator };
    defer collector.counts.deinit(allocator);
    const summary = try campaign.run(
        profile,
        allocator,
        elf,
        options,
        leaf_budget,
        max_leaves,
        &collector,
    );
    const counts = try collector.counts.toOwnedSlice(allocator);
    errdefer allocator.free(counts);
    var plan: Plan = .{
        .allocator = allocator,
        .profile = profile,
        .elf_sha256 = digest(elf),
        .input_sha256 = digest(options.input),
        .stop_on_halt_flag = options.stop_on_halt_flag,
        .strict_completion = options.strict_completion,
        .require_current_output_accesses = options.require_current_output_accesses,
        .x0_local_custody_version = options.x0_local_custody_version,
        .leaf_budget = leaf_budget,
        .cycle_counts = counts,
        .summary = summary,
    };
    try plan.validate();
    return plan;
}

pub fn replay(
    comptime profile: profile_mod.ExecutionProfile,
    allocator: std.mem.Allocator,
    elf: []const u8,
    options: session.SessionOptions,
    plan: *const Plan,
    consumer: anytype,
) !campaign.Summary {
    try plan.validate();
    try requireUnhosted(options);
    if (plan.profile != profile or
        !std.mem.eql(u8, &plan.elf_sha256, &digest(elf)) or
        !std.mem.eql(u8, &plan.input_sha256, &digest(options.input)) or
        plan.stop_on_halt_flag != options.stop_on_halt_flag or
        plan.strict_completion != options.strict_completion or
        plan.require_current_output_accesses != options.require_current_output_accesses or
        plan.x0_local_custody_version != options.x0_local_custody_version)
        return error.CampaignPlanInputMismatch;

    var checked = ReplayConsumer(profile, @TypeOf(consumer)){
        .plan = plan,
        .consumer = consumer,
    };
    const summary = try campaign.run(
        profile,
        allocator,
        elf,
        options,
        plan.leaf_budget,
        @intCast(plan.cycle_counts.len),
        &checked,
    );
    if (checked.next != plan.cycle_counts.len or
        !std.meta.eql(summary, plan.summary))
        return error.CampaignPlanReplayMismatch;
    return summary;
}

fn Collector(comptime profile: profile_mod.ExecutionProfile) type {
    return struct {
        allocator: std.mem.Allocator,
        counts: std.ArrayList(u32) = .empty,

        pub fn onSegment(self: *@This(), leaf: *const session.ConfiguredSegmentResult(profile)) !void {
            const base = baseResult(profile, leaf);
            try self.counts.append(self.allocator, @intCast(base.cycle_count));
        }
    };
}

fn ReplayConsumer(comptime profile: profile_mod.ExecutionProfile, comptime Consumer: type) type {
    return struct {
        plan: *const Plan,
        consumer: Consumer,
        next: usize = 0,

        pub fn onSegment(self: *@This(), leaf: *const session.ConfiguredSegmentResult(profile)) !void {
            const base = baseResult(profile, leaf);
            if (self.next >= self.plan.cycle_counts.len or
                base.cycle_count != self.plan.cycle_counts[self.next])
                return error.CampaignPlanReplayMismatch;
            try self.consumer.onSegment(leaf);
            self.next += 1;
        }
    };
}

fn baseResult(
    comptime profile: profile_mod.ExecutionProfile,
    leaf: *const session.ConfiguredSegmentResult(profile),
) *const result.SegmentResult {
    return if (comptime profile == .rv32im_zkvm_v1) leaf else &leaf.base;
}

fn digest(bytes: []const u8) [32]u8 {
    var value: [32]u8 = undefined;
    Sha256.hash(bytes, &value, .{});
    return value;
}

fn requireUnhosted(options: session.SessionOptions) !void {
    // A host callback can inject data that is not represented by the ELF and
    // input digest. A later authority-bearing host transcript may relax this.
    if (options.host != null) return error.HostedCampaignPlanUnsupported;
}
