//! Pre-launch semantic-attribution planning for bounded task graphs.
//!
//! The only temporary allocation is an exact identity array used on the cold
//! profiled path to validate and count semantic components in O(C log C).
//! Publication remains allocation-free.

const std = @import("std");
const prover_api = @import("stwo_prover_api");
const task_context = @import("task_graph_context.zig");

const wire = prover_api.task_profile;

pub const Mode = enum {
    compatibility,
    semantic,
};

pub const Shape = struct {
    mode: Mode,
    reservation: wire.ReservationShape,
};

const Identity = struct {
    component_registry_index: u32,
    component_kind: []const u8,
    role: wire.ContributionRole,
    task_index: usize,
    work_estimate: u64,
    planned_rows: u64,
    planned_tiles: u64,
};

/// Determines one graph-wide attribution mode and validates every explicit
/// identity before any task can launch.
pub fn deriveShape(
    allocator: std.mem.Allocator,
    graph: anytype,
) !Shape {
    var semantic_tasks: usize = 0;
    var contribution_count: usize = 0;
    for (graph.slots[0..graph.count]) |slot| {
        if (slot.contributions) |plans| {
            semantic_tasks += 1;
            contribution_count = std.math.add(
                usize,
                contribution_count,
                plans.len,
            ) catch return error.TaskProfileContributionCountOverflow;
        }
    }
    if (semantic_tasks == 0) {
        return .{
            .mode = .compatibility,
            .reservation = .{
                .event_count = graph.count,
                .contribution_count = graph.count,
                .component_work_count = try validateCompatibility(graph),
            },
        };
    }
    if (semantic_tasks != graph.count) {
        return error.TaskProfileMixedAttributionModes;
    }
    if (contribution_count > std.math.maxInt(u32)) {
        return error.TaskProfileContributionCountOverflow;
    }

    const identities = try allocator.alloc(Identity, contribution_count);
    defer allocator.free(identities);
    var cursor: usize = 0;
    for (graph.slots[0..graph.count], 0..) |slot, task_index| {
        const plans = slot.contributions.?;
        if (plans.len != 1) {
            for (plans) |plan| {
                if (plan.role == .exclusive) {
                    return error.TaskProfileExclusiveContributionNotExclusive;
                }
            }
        }
        for (plans) |plan| {
            identities[cursor] = .{
                .component_registry_index = plan.component_registry_index,
                .component_kind = plan.component_kind,
                .role = plan.role,
                .task_index = task_index,
                .work_estimate = plan.work_estimate,
                .planned_rows = plan.planned_rows,
                .planned_tiles = plan.planned_tiles,
            };
            cursor += 1;
        }
    }
    std.debug.assert(cursor == identities.len);
    std.sort.heap(Identity, identities, {}, identityLessThan);

    var component_count: usize = 0;
    var previous: ?Identity = null;
    var work_estimate: u64 = 0;
    var planned_rows: u64 = 0;
    var planned_tiles: u64 = 0;
    for (identities) |identity| {
        if (previous) |prior| {
            if (identity.component_registry_index == prior.component_registry_index) {
                if (!std.mem.eql(u8, identity.component_kind, prior.component_kind)) {
                    return error.TaskProfileComponentKindDrift;
                }
                if (identity.role != prior.role) {
                    return error.TaskProfileContributionRoleDrift;
                }
                if (identity.task_index == prior.task_index) {
                    return error.TaskProfileDuplicateComponentContribution;
                }
                work_estimate = try checkedAdd(work_estimate, identity.work_estimate);
                planned_rows = try checkedAdd(planned_rows, identity.planned_rows);
                planned_tiles = try checkedAdd(planned_tiles, identity.planned_tiles);
            } else {
                component_count += 1;
                work_estimate = identity.work_estimate;
                planned_rows = identity.planned_rows;
                planned_tiles = identity.planned_tiles;
            }
        } else {
            component_count = 1;
            work_estimate = identity.work_estimate;
            planned_rows = identity.planned_rows;
            planned_tiles = identity.planned_tiles;
        }
        previous = identity;
    }
    return .{
        .mode = .semantic,
        .reservation = .{
            .event_count = graph.count,
            .contribution_count = contribution_count,
            .component_work_count = component_count,
        },
    };
}

/// Copies immutable plans into their final canonical flat ranges before
/// launch. Events remain task-id indexed until the join, but each already
/// carries the range it will own after canonical sorting.
pub fn initialize(
    graph: anytype,
    events: []wire.TaskEvent,
    contributions: []wire.Contribution,
) void {
    std.debug.assert(events.len == graph.count);
    var task_ids: [task_context.MAX_COMPONENT_TASKS]task_context.ComponentTaskId = undefined;
    for (task_ids[0..graph.count], 0..) |*id, index| id.* = @intCast(index);
    const Graph = @TypeOf(graph);
    const CanonicalOrder = struct {
        fn lessThan(
            context: Graph,
            lhs: task_context.ComponentTaskId,
            rhs: task_context.ComponentTaskId,
        ) bool {
            return context.slots[lhs].key.lessThan(context.slots[rhs].key);
        }
    };
    std.sort.heap(
        task_context.ComponentTaskId,
        task_ids[0..graph.count],
        graph,
        CanonicalOrder.lessThan,
    );

    var cursor: usize = 0;
    for (task_ids[0..graph.count]) |task_id| {
        const plans = graph.slots[task_id].contributions.?;
        events[task_id].contribution_range = .{
            .start = @intCast(cursor),
            .len = @intCast(plans.len),
        };
        for (plans, contributions[cursor..][0..plans.len]) |plan, *out| {
            out.* = .{
                .component_registry_index = plan.component_registry_index,
                .component_kind = plan.component_kind,
                .role = plan.role,
                .work_estimate = plan.work_estimate,
                .planned_rows = plan.planned_rows,
                .planned_tiles = plan.planned_tiles,
            };
        }
        cursor += plans.len;
    }
    std.debug.assert(cursor == contributions.len);
}

/// Completes semantic counters from joined event lifecycle authority.
pub fn finish(
    events: []const wire.TaskEvent,
    contributions: []wire.Contribution,
) void {
    for (events) |event| {
        const start: usize = @intCast(event.contribution_range.start);
        const len: usize = @intCast(event.contribution_range.len);
        for (contributions[start..][0..len]) |*contribution| {
            if (!event.started) {
                contribution.completed_rows = 0;
                contribution.completed_tiles = 0;
            } else switch (event.terminal_status) {
                .completed => {
                    contribution.completed_rows = contribution.planned_rows;
                    contribution.completed_tiles = contribution.planned_tiles;
                },
                .failed, .cancelled => {
                    contribution.completed_rows = null;
                    contribution.completed_tiles = null;
                },
            }
        }
    }
}

fn validateCompatibility(graph: anytype) !usize {
    var result: usize = 0;
    for (graph.slots[0..graph.count], 0..) |slot, index| {
        var seen = false;
        for (graph.slots[0..index]) |earlier| {
            if (earlier.key.component_registry_index ==
                slot.key.component_registry_index)
            {
                seen = true;
                break;
            }
        }
        if (seen) continue;
        result += 1;

        var work_estimate: u64 = 0;
        var planned_rows: u64 = 0;
        var planned_tiles: u64 = 0;
        for (graph.slots[0..graph.count]) |candidate| {
            if (candidate.key.component_registry_index !=
                slot.key.component_registry_index)
            {
                continue;
            }
            if (!std.mem.eql(u8, candidate.component_kind, slot.component_kind)) {
                return error.TaskProfileComponentKindDrift;
            }
            work_estimate = try checkedAdd(work_estimate, candidate.work_estimate);
            switch (candidate.work_unit) {
                .unspecified => {},
                .rows => planned_rows = try checkedAdd(
                    planned_rows,
                    candidate.planned_work_units,
                ),
                .tiles => planned_tiles = try checkedAdd(
                    planned_tiles,
                    candidate.planned_work_units,
                ),
            }
        }
    }
    return result;
}

fn checkedAdd(lhs: u64, rhs: u64) !u64 {
    return std.math.add(u64, lhs, rhs) catch
        error.TaskProfileComponentWorkOverflow;
}

fn identityLessThan(_: void, lhs: Identity, rhs: Identity) bool {
    if (lhs.component_registry_index != rhs.component_registry_index) {
        return lhs.component_registry_index < rhs.component_registry_index;
    }
    return lhs.task_index < rhs.task_index;
}
