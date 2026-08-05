//! Allocation-failure transactions for multi-pool authoring finalizers.

const std = @import("std");
const functions = @import("functions.zig");
const hints = @import("hints.zig");
const ir = @import("ir.zig");
const source = @import("source.zig");
const types = @import("types.zig");
const validate = @import("validate.zig");

const Outcome = enum { failed, succeeded };
const max_failure_index = 256;

test "function declaration finalization is transactional under every allocation failure" {
    for (0..max_failure_index) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        const outcome: Outcome = blk: {
            var arena = ir.Arena.init(failing.allocator());
            defer arena.deinit();
            const generated = source.SourceSpan.generated();
            const input = arena.input("input", .felt, generated) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const outputs = [_]types.ValueId{input} ** 16;
            if (functions.add(
                &arena,
                "transaction.function",
                &.{input},
                &outputs,
                generated,
            )) |_| {
                try validate.validate(&arena);
                break :blk .succeeded;
            } else |err| {
                try expectInducedOutOfMemory(&failing, err);
                try std.testing.expectEqual(@as(usize, 0), arena.functions.items.len);
                try std.testing.expectEqual(@as(usize, 0), arena.function_inputs.items.len);
                try std.testing.expectEqual(@as(usize, 0), arena.function_outputs.items.len);
                try std.testing.expectEqual(@as(?types.FunctionId, null), arena.open_function);
                try validate.validate(&arena);
                break :blk .failed;
            }
        };
        try expectBalanced(&failing);
        if (outcome == .succeeded) {
            try std.testing.expect(!failing.has_induced_failure);
            return;
        }
    }
    return error.AllocationFailureSweepDidNotTerminate;
}

test "static call construction rolls every typed pool back on allocation failure" {
    for (0..max_failure_index) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        const outcome: Outcome = blk: {
            var arena = ir.Arena.init(failing.allocator());
            defer arena.deinit();
            const generated = source.SourceSpan.generated();
            const lhs = arena.input("lhs", .felt, generated) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const rhs = arena.input("rhs", .felt, generated) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const sum = arena.add(lhs, rhs, generated) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const callee = functions.add(
                &arena,
                "transaction.callee",
                &.{ lhs, rhs },
                &.{sum},
                generated,
            ) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const caller = functions.begin(
                &arena,
                "transaction.caller",
                &.{ lhs, rhs },
                generated,
            ) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const node_count = arena.nodes.items.len;
            const argument_count = arena.call_arguments.items.len;
            const output_count = arena.call_outputs.items.len;
            const call_count = arena.calls.items.len;

            if (functions.call(
                &arena,
                callee,
                &.{ lhs, rhs },
                .inline_expansion,
                generated,
            )) |_| {
                try functions.finish(&arena, caller, &.{});
                try validate.validate(&arena);
                break :blk .succeeded;
            } else |err| {
                try expectInducedOutOfMemory(&failing, err);
                try std.testing.expectEqual(node_count, arena.nodes.items.len);
                try std.testing.expectEqual(arena.nodes.items.len, arena.interned_nodes.count());
                try std.testing.expectEqual(argument_count, arena.call_arguments.items.len);
                try std.testing.expectEqual(output_count, arena.call_outputs.items.len);
                try std.testing.expectEqual(call_count, arena.calls.items.len);
                try functions.finish(&arena, caller, &.{});
                try validate.validate(&arena);
                break :blk .failed;
            }
        };
        try expectBalanced(&failing);
        if (outcome == .succeeded) {
            try std.testing.expect(!failing.has_induced_failure);
            return;
        }
    }
    return error.AllocationFailureSweepDidNotTerminate;
}

test "hint binding finalization rolls paths and records back together" {
    for (0..max_failure_index) |fail_index| {
        var failing = std.testing.FailingAllocator.init(
            std.testing.allocator,
            .{ .fail_index = fail_index },
        );
        const outcome: Outcome = blk: {
            var arena = ir.Arena.init(failing.allocator());
            defer arena.deinit();
            const generated = source.SourceSpan.generated();
            const input = arena.input("input", .felt, generated) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const active = arena.input("active", .bit, generated) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const hint_id = hints.add(
                &arena,
                .identity_felt,
                &.{input},
                active,
                generated,
            ) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const output = hints.outputs(&arena, hint_id).?[0];
            const root = arena.sub(output, input, generated) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const constraint = arena.assertZero(
                "transaction.hint",
                root,
                active,
                .hint_binding,
                generated,
            ) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const effect = arena.addEffect(
                .public_produce,
                &.{output},
                active,
                null,
                generated,
            ) catch |err| {
                try expectInducedOutOfMemory(&failing, err);
                break :blk .failed;
            };
            const node_count = arena.nodes.items.len;

            if (hints.bind(&arena, hint_id, &.{
                .{
                    .output_index = 0,
                    .target = .{ .constraint = constraint },
                    .path = &.{ output, root },
                },
                .{
                    .output_index = 0,
                    .target = .{ .effect = effect },
                    .path = &.{output},
                },
            })) |_| {
                try validate.validate(&arena);
                break :blk .succeeded;
            } else |err| {
                try expectInducedOutOfMemory(&failing, err);
                try std.testing.expectEqual(node_count, arena.nodes.items.len);
                try std.testing.expectEqual(arena.nodes.items.len, arena.interned_nodes.count());
                try std.testing.expectEqual(@as(usize, 0), arena.hint_bindings.items.len);
                try std.testing.expectEqual(@as(usize, 0), arena.hint_binding_values.items.len);
                try std.testing.expectEqual(
                    @as(?@import("program.zig").RefRange, null),
                    arena.hints.items[0].bindings,
                );
                break :blk .failed;
            }
        };
        try expectBalanced(&failing);
        if (outcome == .succeeded) {
            try std.testing.expect(!failing.has_induced_failure);
            return;
        }
    }
    return error.AllocationFailureSweepDidNotTerminate;
}

fn expectInducedOutOfMemory(
    failing: *std.testing.FailingAllocator,
    err: anyerror,
) !void {
    try std.testing.expect(err == error.OutOfMemory);
    try std.testing.expect(failing.has_induced_failure);
}

fn expectBalanced(failing: *const std.testing.FailingAllocator) !void {
    try std.testing.expectEqual(failing.allocated_bytes, failing.freed_bytes);
}
