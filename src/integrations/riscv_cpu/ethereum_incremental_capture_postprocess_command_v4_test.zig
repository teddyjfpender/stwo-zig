const std = @import("std");
const command =
    @import("ethereum_incremental_capture_postprocess_command_v4.zig");
const authority_tests =
    @import("ethereum_incremental_capture_postprocess_authority_v4_test.zig");
const recovery_tests =
    @import("ethereum_incremental_capture_raw_recovery_v4_test.zig");

comptime {
    _ = authority_tests;
    _ = recovery_tests;
}

test "fast V4 command distinguishes create and resumable unsealed custody" {
    const create = try command.OptionsV4.parse(&.{
        "--retained-materialization-result",
        "/tmp/materialization.json",
        "--publication-root-parent",
        "/tmp/custody",
        "--cold-workers",
        "8",
    });
    try std.testing.expectEqual(
        command.RootModeV4.create_under_parent,
        create.root_mode,
    );
    try std.testing.expectEqual(@as(usize, 8), create.cold_workers);

    const reopened = try command.OptionsV4.parse(&.{
        "--cold-workers",
        "1",
        "--publication-root",
        "/tmp/custody/ethereum-incremental-capture-v4",
        "--retained-materialization-result",
        "/tmp/materialization.json",
    });
    try std.testing.expectEqual(
        command.RootModeV4.reopen_unsealed,
        reopened.root_mode,
    );
    try std.testing.expectEqual(@as(usize, 1), reopened.cold_workers);
}

test "fast V4 command rejects ambiguous roots and unbounded workers" {
    try std.testing.expectError(error.DuplicateArgument, command.OptionsV4.parse(&.{
        "--publication-root",
        "/tmp/a",
        "--publication-root-parent",
        "/tmp/b",
        "--cold-workers",
        "2",
    }));
    try std.testing.expectError(
        error.InvalidColdWorkerCountV4,
        command.OptionsV4.parse(&.{
            "--retained-materialization-result",
            "/tmp/materialization.json",
            "--publication-root",
            "/tmp/a",
            "--cold-workers",
            "0",
        }),
    );
    try std.testing.expectError(
        error.InvalidColdWorkerCountV4,
        command.OptionsV4.parse(&.{
            "--retained-materialization-result",
            "/tmp/materialization.json",
            "--publication-root",
            "/tmp/a",
            "--cold-workers",
            "33",
        }),
    );
}

test "fast V4 command is raw-once then VM-free postprocess only" {
    try std.testing.expectEqual(@as(comptime_int, 1), command.VM_EXECUTION_COUNT);
    try std.testing.expect(!command.PRODUCTION_ACTIVE);
    try std.testing.expect(!command.PROOF_ADMISSIBLE);
    try std.testing.expect(command.RESUME_REQUIRES_TYPED_COLD_OPEN);
    try std.testing.expect(command.RAW_ONLY_RECOVERY_REPLAYS_COMPACT_TAPES);
    try std.testing.expect(!command.RAW_ONLY_REOPEN_VM_FALLBACK);
    try std.testing.expectEqual(
        @as(usize, 8),
        command.MAX_RECOVERY_REPLAY_WORKERS,
    );
}

test "parallel raw opens may complete out of order but mint order is exact" {
    const completion_order = [_]u32{ 12, 10, 13, 11 };
    try command.BatchOrderAuthorityV4.validateCompletionPermutation(
        10,
        &completion_order,
    );
    for (0..completion_order.len) |offset|
        try command.BatchOrderAuthorityV4.requireMintOrdinal(
            10,
            offset,
            @intCast(10 + offset),
        );

    try std.testing.expectError(
        error.InvalidIncrementalConcurrentOpenOrderV4,
        command.BatchOrderAuthorityV4.validateCompletionPermutation(
            10,
            &.{ 10, 11, 11, 13 },
        ),
    );
    try std.testing.expectError(
        error.IncrementalMintOrderMismatchV4,
        command.BatchOrderAuthorityV4.requireMintOrdinal(10, 1, 12),
    );
}

test "parallel raw open cleanup releases each moved owner exactly once" {
    const Slot = command.OwnedOptionalV4(CountedOwner);
    var release_count: usize = 0;
    var slots = [_]Slot{
        .{ .value = .{ .release_count = &release_count } },
        .{ .value = .{ .release_count = &release_count } },
        .{ .value = .{ .release_count = &release_count } },
    };
    var moved = try slots[1].take();
    moved.deinit();
    for (&slots) |*slot| slot.deinit();
    try std.testing.expectEqual(@as(usize, 3), release_count);
    for (&slots) |*slot| slot.deinit();
    try std.testing.expectEqual(@as(usize, 3), release_count);
}

const CountedOwner = struct {
    release_count: *usize,

    pub fn deinit(self: *CountedOwner) void {
        self.release_count.* += 1;
        self.* = undefined;
    }
};
