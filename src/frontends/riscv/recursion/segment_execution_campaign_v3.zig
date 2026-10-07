//! Bounded, leaf-local execution of a real ELF with one live segment result.
//!
//! The caller consumes each owned trace before the next leaf is executed. This
//! is an execution source for V3 proving, not a recursive proof or publication.

const std = @import("std");
const profile_mod = @import("../isa/execution_profile.zig");
const result = @import("../runner/result.zig");
const session_mod = @import("../runner/segment_session.zig");
const max_v3_leaf_cycles = @import("segment_leaf_local_authority_v3.zig").MAX_LEAF_CYCLES;

pub const Summary = struct {
    leaf_count: u32,
    retired_cycles: u64,
    completion_reason: result.CompletionReason,
};

/// `consumer.onSegment(*const ConfiguredSegmentResult(profile))` may prove or
/// persist the leaf, including any profile-specific precompile sidecars.
/// Its error aborts the campaign before the next segment executes. The session
/// and all trace ownership are released on every exit path. Guest options such
/// as input, host, and halt policy are preserved; the V3 clock and ownership
/// modes are forced by this API.
pub fn run(
    comptime profile: profile_mod.ExecutionProfile,
    allocator: std.mem.Allocator,
    elf: []const u8,
    session_options: session_mod.SessionOptions,
    leaf_budget: usize,
    max_leaves: u32,
    consumer: anytype,
) !Summary {
    return runInternal(profile, allocator, elf, session_options, leaf_budget, max_leaves, null, consumer);
}

/// Replay a measured leaf schedule. The runner reserves only each leaf's
/// actual budget, which matters when the terminal leaf is much smaller than
/// the campaign's maximum. Each measured boundary remains exact.
pub fn runPlanned(
    comptime profile: profile_mod.ExecutionProfile,
    allocator: std.mem.Allocator,
    elf: []const u8,
    session_options: session_mod.SessionOptions,
    budgets: []const u32,
    consumer: anytype,
) !Summary {
    if (budgets.len == 0 or budgets.len > std.math.maxInt(u32))
        return error.InvalidCampaignBudgets;
    var maximum: usize = 0;
    for (budgets) |budget| {
        if (budget == 0 or budget > max_v3_leaf_cycles)
            return error.InvalidCampaignBudgets;
        maximum = @max(maximum, budget);
    }
    return runInternal(profile, allocator, elf, session_options, maximum, @intCast(budgets.len), budgets, consumer);
}

fn runInternal(
    comptime profile: profile_mod.ExecutionProfile,
    allocator: std.mem.Allocator,
    elf: []const u8,
    session_options: session_mod.SessionOptions,
    leaf_budget: usize,
    max_leaves: u32,
    planned_budgets: ?[]const u32,
    consumer: anytype,
) !Summary {
    if (leaf_budget == 0) return error.ZeroSegmentStepBudget;
    if (max_leaves == 0) return error.ZeroCampaignLeaves;
    if (leaf_budget > max_v3_leaf_cycles)
        return error.LeafBudgetExceedsLocalClock;

    var options = session_options;
    options.clock_frame = .leaf_local;
    options.trace_retention = .segment_owned;
    var session = try session_mod.ExecutionSession(profile).init(allocator, elf, options);
    defer session.deinit();

    var next: ?result.ContinuationToken = null;
    var total: u64 = 0;
    var count: u32 = 0;
    while (count < max_leaves) {
        const budget: usize = if (planned_budgets) |budgets|
            budgets[count]
        else
            leaf_budget;
        var segment = if (next) |token|
            try session.resumeSegment(token, budget)
        else
            try session.startSegment(budget);
        defer segment.deinit();

        const base: *const result.SegmentResult = if (comptime profile == .rv32im_zkvm_v1)
            &segment
        else
            &segment.base;
        const expected_first = std.math.add(u64, total, 1) catch
            return error.CampaignCycleOverflow;
        if (base.clock_frame != .leaf_local or
            base.segment_index != count or
            base.global_first_cycle != expected_first or
            base.cycle_count == 0 or
            base.cycle_count > budget or
            (base.continuation == null) != base.isComplete())
        {
            return error.InvalidCampaignSegment;
        }
        if (planned_budgets != null and
            (base.cycle_count != budget or
                (base.completion_reason != null and count + 1 != max_leaves)))
        {
            return error.CampaignBudgetScheduleMismatch;
        }
        // A consumer sees a complete, immutable leaf before its storage is
        // returned to the allocator. It never observes the next leaf in flight.
        try consumer.onSegment(&segment);
        total = std.math.add(u64, total, base.cycle_count) catch
            return error.CampaignCycleOverflow;
        count += 1;
        if (base.completion_reason) |reason| return .{
            .leaf_count = count,
            .retired_cycles = total,
            .completion_reason = reason,
        };
        next = base.continuation;
    }
    return error.CampaignLeafLimitReached;
}
