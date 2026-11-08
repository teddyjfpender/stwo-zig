//! Semantic attribution primitives for flat physical task graphs.
//!
//! This module allocates nothing. The recorder owns all slices and invokes
//! derivation only after every physical task has joined.

const std = @import("std");

/// The semantic relationship between a physical task and a registry
/// component. `exclusive` is reserved for lanes that execute exactly one
/// component, including graphs admitted through the v1-producer adapter.
pub const Role = enum {
    semantic_constraints,
    lookup_constraints,
    exclusive,
};

/// Half-open range into a graph's flat contribution slice. Event ranges must
/// form an exact contiguous partition in canonical event order.
pub const Range = struct {
    start: u32 = 0,
    len: u32 = 0,
};

/// Semantic work attributed to one component by one physical task lane.
///
/// Completion is exact when present. A never-started lane records zero, while
/// a started lane that failed or was cancelled records null because partial
/// completion is not reconstructed after failure.
pub const Contribution = struct {
    component_registry_index: u32 = 0,
    component_kind: []const u8 = "",
    role: Role = .exclusive,
    work_estimate: u64 = 0,
    planned_rows: u64 = 0,
    planned_tiles: u64 = 0,
    completed_rows: ?u64 = 0,
    completed_tiles: ?u64 = 0,
};

/// Semantic per-component totals derived from contributions at publication.
/// Physical run time remains exclusively event-owned and is intentionally not
/// attributed to components in a fused lane.
pub const ComponentWork = struct {
    component_registry_index: u32 = 0,
    component_kind: []const u8 = "",
    role: Role = .exclusive,
    task_count: u64 = 0,
    work_estimate: u64 = 0,
    planned_rows: u64 = 0,
    planned_tiles: u64 = 0,
    completed_rows: ?u64 = 0,
    completed_tiles: ?u64 = 0,
};

/// Fills storage already reserved by the compatibility API. `events` is
/// generic to keep task lifecycle authority in `task_profile.zig`.
pub fn synthesizeCompatibility(events: anytype, contributions: []Contribution) void {
    std.debug.assert(events.len == contributions.len);
    for (events, contributions, 0..) |*event, *contribution, index| {
        event.contribution_range = .{ .start = @intCast(index), .len = 1 };
        const completed_rows: ?u64 = if (!event.started)
            0
        else switch (event.terminal_status) {
            .completed => event.completed_rows,
            .failed, .cancelled => null,
        };
        const completed_tiles: ?u64 = if (!event.started)
            0
        else switch (event.terminal_status) {
            .completed => event.completed_tiles,
            .failed, .cancelled => null,
        };
        contribution.* = .{
            .component_registry_index = event.key.component_registry_index,
            .component_kind = event.component_kind,
            .role = .exclusive,
            .work_estimate = event.work_estimate,
            .planned_rows = event.planned_rows,
            .planned_tiles = event.planned_tiles,
            .completed_rows = completed_rows,
            .completed_tiles = completed_tiles,
        };
    }
}

/// Validates exact range coverage and derives every semantic aggregate in the
/// caller-reserved output. Output order is first appearance in event order.
pub fn deriveComponentWork(
    events: anytype,
    contributions: []const Contribution,
    component_work: []ComponentWork,
) !void {
    @memset(component_work, .{});
    var range_cursor: usize = 0;
    var component_count: usize = 0;

    for (events) |event| {
        const range_start: usize = @intCast(event.contribution_range.start);
        if (range_start != range_cursor) {
            return error.TaskProfileContributionRangeNotContiguous;
        }
        const range_len: usize = @intCast(event.contribution_range.len);
        const range_end = std.math.add(usize, range_start, range_len) catch
            return error.TaskProfileContributionRangeOutOfBounds;
        if (range_end > contributions.len) {
            return error.TaskProfileContributionRangeOutOfBounds;
        }
        const event_contributions = contributions[range_start..range_end];

        if (event_contributions.len != 1) {
            for (event_contributions) |contribution| {
                if (contribution.role == .exclusive) {
                    return error.TaskProfileExclusiveContributionNotExclusive;
                }
            }
        }

        for (event_contributions, 0..) |contribution, contribution_offset| {
            try validateCompletion(event, contribution);
            for (event_contributions[0..contribution_offset]) |prior| {
                if (prior.component_registry_index ==
                    contribution.component_registry_index)
                {
                    return error.TaskProfileDuplicateComponentContribution;
                }
            }

            const component = findComponent(
                component_work[0..component_count],
                contribution.component_registry_index,
            ) orelse blk: {
                if (component_count == component_work.len) {
                    return error.TaskProfileComponentWorkCountMismatch;
                }
                const fresh = &component_work[component_count];
                fresh.* = .{
                    .component_registry_index = contribution.component_registry_index,
                    .component_kind = contribution.component_kind,
                    .role = contribution.role,
                };
                component_count += 1;
                break :blk fresh;
            };
            if (!std.mem.eql(u8, component.component_kind, contribution.component_kind)) {
                return error.TaskProfileComponentKindDrift;
            }
            if (component.role != contribution.role) {
                return error.TaskProfileContributionRoleDrift;
            }
            component.task_count = try checkedAdd(component.task_count, 1);
            component.work_estimate = try checkedAdd(
                component.work_estimate,
                contribution.work_estimate,
            );
            component.planned_rows = try checkedAdd(
                component.planned_rows,
                contribution.planned_rows,
            );
            component.planned_tiles = try checkedAdd(
                component.planned_tiles,
                contribution.planned_tiles,
            );
            try addCompleted(&component.completed_rows, contribution.completed_rows);
            try addCompleted(&component.completed_tiles, contribution.completed_tiles);
        }
        range_cursor = range_end;
    }
    if (range_cursor != contributions.len) {
        return error.TaskProfileContributionRangeCoverageMismatch;
    }
    if (component_count != component_work.len) {
        return error.TaskProfileComponentWorkCountMismatch;
    }
}

fn validateCompletion(event: anytype, contribution: Contribution) !void {
    const rows = contribution.completed_rows;
    const tiles = contribution.completed_tiles;
    if (!event.started) {
        if (rows == null or rows.? != 0 or tiles == null or tiles.? != 0) {
            return error.TaskProfileContributionCompletionStateMismatch;
        }
    } else switch (event.terminal_status) {
        .completed => if (rows == null or tiles == null) {
            return error.TaskProfileContributionCompletionStateMismatch;
        },
        .failed, .cancelled => if (rows != null or tiles != null) {
            return error.TaskProfileContributionCompletionStateMismatch;
        },
    }
    if (rows) |completed| {
        if (completed > contribution.planned_rows) {
            return error.TaskProfileContributionCompletionExceedsPlan;
        }
    }
    if (tiles) |completed| {
        if (completed > contribution.planned_tiles) {
            return error.TaskProfileContributionCompletionExceedsPlan;
        }
    }
}

fn findComponent(
    components: []ComponentWork,
    component_registry_index: u32,
) ?*ComponentWork {
    for (components) |*component| {
        if (component.component_registry_index == component_registry_index) {
            return component;
        }
    }
    return null;
}

fn checkedAdd(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch
        return error.TaskProfileComponentWorkOverflow;
}

fn addCompleted(total: *?u64, amount: ?u64) !void {
    if (total.* == null or amount == null) {
        total.* = null;
        return;
    }
    total.* = try checkedAdd(total.*.?, amount.?);
}
