//! Proof-free row-0 control schedule for one detached parent child lane.
//! The prefix, PCS suffix and PCS/FRI checker use their production generators;
//! no child proof, recording or expected statement enters this recipe.
const std = @import("std");
const control = @import("air/control_witness.zig");
const child_mod = @import("detached_child_views_v1.zig");
const prefix = @import("detached_prefix_preparation_v1.zig");
const suffix = @import("detached_pcs_rows_v1.zig");
const checks = @import("detached_pcs_preparation_v1.zig");

pub fn lane(comptime family: child_mod.Family, allocator: std.mem.Allocator, key: anytype, verifier_id: u32) ![]control.Row {
    if (verifier_id != 1 and verifier_id != 2) return error.InvalidDetachedPrefixLane;
    const operations = try prefix.operationsFromKey(family, allocator, key);
    defer allocator.free(operations);
    const shape = try prefix.PrefixShape.fromOperations(operations);
    const head = try prefix.controlRowsFromOperations(allocator, operations, verifier_id);
    defer allocator.free(head);
    const pcs_operations = try prefix.initPcsOperationsFromKey(allocator, key);
    defer allocator.free(pcs_operations);
    const tail = try suffix.controlRowsFromOperations(allocator, pcs_operations, verifier_id, shape.operation_count);
    defer allocator.free(tail);
    const checker = try checks.controlRowsFromKey(allocator, key, verifier_id);
    defer allocator.free(checker);
    const total = try std.math.add(usize, try std.math.add(usize, head.len, tail.len), checker.len);
    const result = try allocator.alloc(control.Row, total);
    @memcpy(result[0..head.len], head);
    @memcpy(result[head.len..][0..tail.len], tail);
    @memcpy(result[head.len + tail.len ..], checker);
    return result;
}

pub fn pair(comptime family: child_mod.Family, allocator: std.mem.Allocator, keys: anytype) ![]control.Row {
    const left = try lane(family, allocator, keys[0], 1);
    defer allocator.free(left);
    const right = try lane(family, allocator, keys[1], 2);
    defer allocator.free(right);
    const total = try std.math.add(usize, left.len, right.len);
    const result = try allocator.alloc(control.Row, total);
    @memcpy(result[0..left.len], left);
    @memcpy(result[left.len..], right);
    return result;
}

pub fn testAgainstVerifiedChild(allocator: std.mem.Allocator, child: anytype) !void {
    const family = @typeInfo(@TypeOf(child)).pointer.child.FAMILY;
    for ([_]u32{ 1, 2 }) |verifier_id| {
        const fixed = try lane(family, allocator, child.key(), verifier_id);
        defer allocator.free(fixed);
        const head = try prefix.OwnedV1.init(allocator, child, verifier_id);
        defer head.deinit();
        const tail = try suffix.OwnedV1.init(allocator, child, head, verifier_id);
        defer tail.deinit();
        const checker = try checks.OwnedV1.init(allocator, child, verifier_id);
        defer checker.deinit();
        const expected = [_][]const control.Row{ head.view().control, tail.view().control, checker.view().control };
        var at: usize = 0;
        for (expected) |part| {
            try std.testing.expectEqualDeep(part, fixed[at..][0..part.len]);
            at += part.len;
        }
        try std.testing.expectEqual(fixed.len, at);
    }
}
