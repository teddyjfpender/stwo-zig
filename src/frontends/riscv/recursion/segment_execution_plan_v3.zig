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
const segment_v2 = @import("segment_statement_v2.zig");
const cpu = @import("../runner/cpu.zig");

const Sha256 = std.crypto.hash.sha2.Sha256;

/// Compact public boundary record for one planning pass. This is a
/// replay guard, not a proof or a substitute for the V3 AIR. The sparse word
/// arrays and execution trace remain owned by the runner and are never kept
/// across leaves.
pub const LeafRecord = struct {
    entry_cpu: cpu.Cpu,
    exit_cpu: cpu.Cpu,
    entry_memory: segment_v2.SnapshotDigest,
    exit_memory: segment_v2.SnapshotDigest,
    entry_register_clocks: [32]u32,
    exit_register_clocks: [32]u32,
    entry_memory_clock_id: segment_v2.Digest,
    exit_memory_clock_id: segment_v2.Digest,
    entry_memory_clock_count: usize,
    exit_memory_clock_count: usize,
    completion_reason: ?result.CompletionReason,
    completion_address: u32,
    completion_value: u32,
    completion_clock: u32,
    exit_code: ?u32,
    input_sha256: ?[32]u8,
    output_sha256: ?[32]u8,

    fn fromResult(leaf: *const result.SegmentResult) LeafRecord {
        return .{
            .entry_cpu = leaf.entry_cpu,
            .exit_cpu = leaf.exit_cpu,
            .entry_memory = segment_v2.snapshotDigest(leaf.rw_memory.words, .initial_word),
            .exit_memory = segment_v2.snapshotDigest(leaf.rw_memory.words, .final_word),
            .entry_register_clocks = leaf.entry_access_clocks.register_clocks,
            .exit_register_clocks = leaf.exit_access_clocks.register_clocks,
            .entry_memory_clock_id = segment_v2.memoryClockIdentity(leaf.entry_access_clocks.memory_clocks),
            .exit_memory_clock_id = segment_v2.memoryClockIdentity(leaf.exit_access_clocks.memory_clocks),
            .entry_memory_clock_count = leaf.entry_access_clocks.memory_clocks.len,
            .exit_memory_clock_count = leaf.exit_access_clocks.memory_clocks.len,
            .completion_reason = leaf.completion_reason,
            .completion_address = leaf.completion_address,
            .completion_value = leaf.completion_value,
            .completion_clock = leaf.completion_clock,
            .exit_code = leaf.exit_code,
            .input_sha256 = if (leaf.input) |input| digest(input) else null,
            .output_sha256 = if (leaf.output) |output| digest(output) else null,
        };
    }
};

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
    leaf_records: []LeafRecord,
    summary: campaign.Summary,

    pub fn deinit(self: *Plan) void {
        self.allocator.free(self.cycle_counts);
        self.allocator.free(self.leaf_records);
        self.* = undefined;
    }

    pub fn validate(self: *const Plan) !void {
        if (self.leaf_budget == 0 or
            self.leaf_budget > @import("segment_leaf_local_authority_v3.zig").MAX_LEAF_CYCLES or
            self.cycle_counts.len == 0 or
            self.cycle_counts.len != self.summary.leaf_count or
            self.leaf_records.len != self.cycle_counts.len)
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
    const elf_id = digest(elf);
    const input_id = digest(options.input);
    var collector = Collector(profile){ .allocator = allocator };
    defer collector.counts.deinit(allocator);
    defer collector.records.deinit(allocator);
    const summary = try campaign.run(
        profile,
        allocator,
        elf,
        options,
        leaf_budget,
        max_leaves,
        &collector,
    );
    if (!std.meta.eql(elf_id, digest(elf)) or
        !std.meta.eql(input_id, digest(options.input)))
        return error.CampaignSourceMutation;
    const counts = try collector.counts.toOwnedSlice(allocator);
    errdefer allocator.free(counts);
    const records = try collector.records.toOwnedSlice(allocator);
    errdefer allocator.free(records);
    var plan: Plan = .{
        .allocator = allocator,
        .profile = profile,
        .elf_sha256 = elf_id,
        .input_sha256 = input_id,
        .stop_on_halt_flag = options.stop_on_halt_flag,
        .strict_completion = options.strict_completion,
        .require_current_output_accesses = options.require_current_output_accesses,
        .x0_local_custody_version = options.x0_local_custody_version,
        .leaf_budget = leaf_budget,
        .cycle_counts = counts,
        .leaf_records = records,
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
    if (!std.meta.eql(plan.elf_sha256, digest(elf)) or
        !std.meta.eql(plan.input_sha256, digest(options.input)))
        return error.CampaignSourceMutation;
    if (checked.next != plan.cycle_counts.len or
        !std.meta.eql(summary, plan.summary))
        return error.CampaignPlanReplayMismatch;
    return summary;
}

fn Collector(comptime profile: profile_mod.ExecutionProfile) type {
    return struct {
        allocator: std.mem.Allocator,
        counts: std.ArrayList(u32) = .empty,
        records: std.ArrayList(LeafRecord) = .empty,

        pub fn onSegment(self: *@This(), leaf: *const session.ConfiguredSegmentResult(profile)) !void {
            const base = baseResult(profile, leaf);
            try self.counts.append(self.allocator, @intCast(base.cycle_count));
            try self.records.append(self.allocator, LeafRecord.fromResult(base));
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
                base.cycle_count != self.plan.cycle_counts[self.next] or
                !std.meta.eql(LeafRecord.fromResult(base), self.plan.leaf_records[self.next]))
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
    // Callback effects and failures are outside the ELF/input identity.
    // Admit observers only after they have a stable replay contract.
    if (options.host != null) return error.HostedCampaignPlanUnsupported;
    if (options.retirement_observer != null or
        options.pre_retirement_boundary_observer != null)
        return error.CampaignCallbackPlanUnsupported;
}
