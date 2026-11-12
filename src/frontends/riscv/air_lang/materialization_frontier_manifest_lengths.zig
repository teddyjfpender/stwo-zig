//! Checked section sizing for the canonical materialization-frontier wire.

const std = @import("std");

pub const Error = error{LengthLimitExceeded};

pub fn payloads(value: anytype, max_artifact_bytes: usize) Error![4]u32 {
    const identity = 32 + 1 + 2 + 8 + 8 + 4 +
        try mul(value.identity.roots.len, 4) + 1 +
        @as(usize, if (value.identity.gate == null) 0 else 4) + 32;
    const search: usize = 2 + 1 + 2 + 2 + 4 + 2 +
        1 + 2 + 2 + 32 + 4 + 4 + 4 + 1 + 32 + 32;
    const scenarios = 40 + 2 + try mul(value.scenarios.len, 9);
    var candidates: usize = 32 + 4 * 4 + 2 + 1 + 1 + 2;
    candidates = try add(candidates, try proposal(value.baseline));
    for (value.frontier) |item|
        candidates = try add(candidates, try proposal(item));
    return .{
        try bounded(identity, max_artifact_bytes),
        try bounded(search, max_artifact_bytes),
        try bounded(scenarios, max_artifact_bytes),
        try bounded(candidates, max_artifact_bytes),
    };
}

fn proposal(value: anytype) Error!usize {
    var result: usize = 32 + 32 + 1 + 2 + 32 + 1 + 1 + 4 + 13 * 8 + 2;
    if (value.provenance.removed != null) result += 4;
    if (value.provenance.added != null) result += 4;
    result = try add(
        result,
        try mul(value.selected_values.len, 4),
    );
    return add(
        result,
        try mul(value.scenario_costs.len, 6 * 8),
    );
}

fn bounded(value: usize, max_artifact_bytes: usize) Error!u32 {
    if (value > max_artifact_bytes) return error.LengthLimitExceeded;
    return @intCast(value);
}

fn add(lhs: usize, rhs: usize) Error!usize {
    return std.math.add(usize, lhs, rhs) catch error.LengthLimitExceeded;
}

fn mul(lhs: usize, rhs: usize) Error!usize {
    return std.math.mul(usize, lhs, rhs) catch error.LengthLimitExceeded;
}
