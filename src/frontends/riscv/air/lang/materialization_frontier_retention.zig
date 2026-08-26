//! Deterministic Pareto maintenance and bounded frontier retention.
//!
//! Search owns proposal production and authentication. This private policy
//! helper owns only proposal ranking: Pareto updates, coordinate-minimum
//! preservation, and canonical proposal-digest ordering.

const std = @import("std");
const cost = @import("materialization_cost.zig");
const digest = @import("digest.zig");

const scenario_ranked_fields = .{
    "main_cells",
    "interaction_cells",
    "committed_cells",
    "main_bytes",
    "interaction_bytes",
    "committed_bytes",
};

pub fn rankedCoordinateCount(scenarios: usize) usize {
    return std.meta.fields(cost.CostVector).len + scenarios * scenario_ranked_fields.len;
}

pub fn updatePareto(
    allocator: std.mem.Allocator,
    stored: anytype,
    frontier: *std.ArrayList(usize),
    candidate: usize,
) std.mem.Allocator.Error!void {
    for (frontier.items) |index| {
        if (stored[index].proposal.report.dominates(&stored[candidate].proposal.report))
            return;
    }
    var write: usize = 0;
    for (frontier.items) |index| {
        if (stored[candidate].proposal.report.dominates(&stored[index].proposal.report))
            continue;
        frontier.items[write] = index;
        write += 1;
    }
    frontier.shrinkRetainingCapacity(write);
    try frontier.append(allocator, candidate);
}

pub fn selectRetained(
    allocator: std.mem.Allocator,
    stored: anytype,
    candidates: []const usize,
    limit: usize,
) std.mem.Allocator.Error![]usize {
    const sorted = try allocator.dupe(usize, candidates);
    errdefer allocator.free(sorted);
    sortByDigest(stored, sorted);
    if (sorted.len <= limit) return sorted;

    const chosen = try allocator.alloc(bool, sorted.len);
    defer allocator.free(chosen);
    @memset(chosen, false);
    inline for (std.meta.fields(cost.CostVector)) |field|
        chooseMinimum(stored, sorted, chosen, .{ .vector = field.name });
    if (sorted.len != 0) for (stored[sorted[0]].proposal.report.scenarios, 0..) |_, scenario| {
        inline for (scenario_ranked_fields) |field|
            chooseMinimum(stored, sorted, chosen, .{ .scenario = .{
                .index = scenario,
                .field = field,
            } });
    };

    var selected_count: usize = 0;
    for (chosen) |is_chosen| if (is_chosen) {
        selected_count += 1;
    };
    std.debug.assert(selected_count <= limit);
    for (chosen) |*is_chosen| {
        if (selected_count == limit) break;
        if (!is_chosen.*) {
            is_chosen.* = true;
            selected_count += 1;
        }
    }
    const result = try allocator.alloc(usize, limit);
    var cursor: usize = 0;
    for (sorted, chosen) |index, is_chosen| if (is_chosen) {
        result[cursor] = index;
        cursor += 1;
    };
    allocator.free(sorted);
    return result;
}

pub fn digestLess(lhs: digest.Digest, rhs: digest.Digest) bool {
    return std.mem.order(u8, &lhs, &rhs) == .lt;
}

const Coordinate = union(enum) {
    vector: []const u8,
    scenario: struct { index: usize, field: []const u8 },
};

fn chooseMinimum(
    stored: anytype,
    sorted: []const usize,
    chosen: []bool,
    coordinate: Coordinate,
) void {
    var best_position: usize = 0;
    var best = coordinateValue(&stored[sorted[0]].proposal.report, coordinate);
    for (sorted[1..], 1..) |index, position| {
        const value = coordinateValue(&stored[index].proposal.report, coordinate);
        if (value < best) {
            best = value;
            best_position = position;
        }
    }
    chosen[best_position] = true;
}

fn coordinateValue(report: *const cost.Report, coordinate: Coordinate) u64 {
    return switch (coordinate) {
        .vector => |field| inline for (std.meta.fields(cost.CostVector)) |candidate| {
            if (std.mem.eql(u8, field, candidate.name))
                break @field(report.vector, candidate.name);
        } else unreachable,
        .scenario => |item| inline for (scenario_ranked_fields) |candidate| {
            if (std.mem.eql(u8, item.field, candidate))
                break @field(report.scenarios[item.index], candidate);
        } else unreachable,
    };
}

fn sortByDigest(stored: anytype, indices: []usize) void {
    const Stored = std.meta.Child(@TypeOf(stored));
    const context: []const Stored = stored;
    std.mem.sort(usize, indices, context, struct {
        fn lessThan(items: []const Stored, lhs: usize, rhs: usize) bool {
            return digestLess(
                items[lhs].proposal.proposal_digest,
                items[rhs].proposal.proposal_digest,
            );
        }
    }.lessThan);
}
