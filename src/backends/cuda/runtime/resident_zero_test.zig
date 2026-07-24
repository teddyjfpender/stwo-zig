//! Contract tests for stage-bound zeroing of resident arena ranges.

const std = @import("std");
const arena = @import("arena.zig");
const column = @import("column.zig");
const context = @import("context.zig");
const proof_transaction = @import("proof_transaction.zig");
const runtime_error = @import("error.zig");
const telemetry = @import("telemetry.zig");

test "context zeroes one exact resident range and records physical work" {
    const Fake = struct {
        var handle_word: u8 = 0;
        var stream_word: u8 = 0;
        var storage: [16]u32 = [_]u32{0xffff_ffff} ** 16;
        var memset_calls: usize = 0;
        var memset_bytes: usize = 0;
        var memset_destination: usize = 0;

        pub fn stwo_exec_context_create(out: *?*anyopaque) c_int {
            out.* = &handle_word;
            return 0;
        }

        pub fn stwo_exec_context_destroy(_: *anyopaque) c_int {
            return 0;
        }

        pub fn stwo_exec_context_stream(
            _: *anyopaque,
            out: *?*anyopaque,
        ) c_int {
            out.* = &stream_word;
            return 0;
        }

        pub fn stwo_exec_context_device(_: *anyopaque, out: *c_int) c_int {
            out.* = 0;
            return 0;
        }

        pub fn stwo_exec_context_lane_count(
            _: *anyopaque,
            out: *u32,
        ) c_int {
            out.* = 1;
            return 0;
        }
        pub fn stwo_exec_context_sync(_: *anyopaque) c_int {
            return 0;
        }

        pub fn stwo_exec_context_alloc_u32(
            _: *anyopaque,
            count: usize,
            out: *?[*]u32,
        ) c_int {
            if (count > storage.len) return 1;
            out.* = &storage;
            return 0;
        }

        pub fn stwo_exec_context_free_u32(
            _: *anyopaque,
            _: [*]u32,
        ) c_int {
            return 0;
        }

        pub fn stwo_exec_context_memset_async(
            _: *anyopaque,
            destination: *anyopaque,
            value: c_int,
            bytes: usize,
        ) c_int {
            if (value != 0) return 1;
            memset_calls += 1;
            memset_bytes += bytes;
            memset_destination = @intFromPtr(destination);
            const destination_bytes: [*]u8 = @ptrCast(destination);
            @memset(destination_bytes[0..bytes], 0);
            return 0;
        }
    };

    Fake.storage = [_]u32{0xffff_ffff} ** Fake.storage.len;
    Fake.memset_calls = 0;
    Fake.memset_bytes = 0;
    Fake.memset_destination = 0;

    const Context = context.ContextFor(Fake);
    var execution = try Context.open();
    const unavailable = column.DeviceSlice(u32){
        .address = @intFromPtr(&Fake.storage),
        .len = Fake.storage.len,
        .owner = @intFromPtr(execution.handle.?),
        .generation = 1,
    };
    try std.testing.expectError(
        error.StageNotActive,
        execution.zeroDeviceSlice(u32, unavailable),
    );

    try execution.beginStage(.ingress);
    const buffer = try execution.allocate(Fake.storage.len);
    const whole = column.DeviceSlice(u32){
        .address = @intFromPtr(buffer.pointer),
        .len = buffer.words,
        .owner = buffer.owner,
        .generation = buffer.generation,
    };
    try execution.endStage(.ingress);
    try std.testing.expectError(
        error.StageNotActive,
        execution.zeroDeviceSlice(u32, whole),
    );

    try execution.beginStage(.trace_generation);
    var oversized = whole;
    oversized.len += 1;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        execution.zeroDeviceSlice(u32, oversized),
    );
    try std.testing.expectError(
        error.SizeOverflow,
        execution.zeroDeviceSlice(u32, try whole.sub(whole.len, 0)),
    );
    var foreign = whole;
    foreign.owner += 1;
    try std.testing.expectError(
        error.InvalidDeviceAddress,
        execution.zeroDeviceSlice(u32, foreign),
    );

    const middle = try whole.sub(4, 6);
    try execution.zeroDeviceSlice(u32, middle);
    try std.testing.expectEqual(@as(usize, 1), Fake.memset_calls);
    try std.testing.expectEqual(@as(usize, 6 * @sizeOf(u32)), Fake.memset_bytes);
    try std.testing.expectEqual(middle.address, Fake.memset_destination);
    try std.testing.expectEqualSlices(
        u32,
        &([_]u32{0xffff_ffff} ** 4),
        Fake.storage[0..4],
    );
    try std.testing.expectEqualSlices(
        u32,
        &([_]u32{0} ** 6),
        Fake.storage[4..10],
    );
    try std.testing.expectEqualSlices(
        u32,
        &([_]u32{0xffff_ffff} ** 6),
        Fake.storage[10..16],
    );

    const counters = execution.counters;
    const stage = counters.stages[telemetry.Stage.trace_generation.index()];
    try std.testing.expectEqual(@as(u64, 24), counters.memset_bytes);
    try std.testing.expectEqual(@as(u64, 1), counters.memset_operations);
    try std.testing.expectEqual(@as(u64, 24), stage.memset_bytes);
    try std.testing.expectEqual(@as(u64, 1), stage.memset_operations);
    try std.testing.expectEqual(@as(u64, 1), counters.allocations);
    try std.testing.expectEqual(@as(u64, 0), counters.sync_calls);
    try std.testing.expectEqual(@as(u64, 0), counters.kernel_launches);
    try std.testing.expectEqual(@as(u64, 0), counters.cpu_fallback_attempts);
    try std.testing.expectEqual(@as(u64, 0), counters.cpu_fallbacks_completed);
    try std.testing.expectError(
        error.KernelPathUnused,
        execution.endStage(.trace_generation),
    );
    try execution.abort();
}

const FakeTransactionContext = struct {
    pub const Buffer = struct {
        pointer: [*]u32,
        words: usize,
        owner: usize,
        generation: u64,
    };

    var storage: [32]u32 = [_]u32{0} ** 32;
    active_stage: ?telemetry.Stage = null,
    backing_words: usize = 0,
    zero_calls: usize = 0,
    counters: telemetry.Counters = .{},
    free_memory_bytes: usize = 1024 * 1024 * 1024,

    pub fn allocate(
        self: *@This(),
        words: usize,
    ) runtime_error.Error!Buffer {
        if (self.active_stage != .ingress or words > storage.len)
            return error.AllocationOutsideIngress;
        self.backing_words = words;
        return .{
            .pointer = &storage,
            .words = words,
            .owner = 1,
            .generation = 1,
        };
    }

    pub fn deviceSlicePointer(
        self: *@This(),
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) runtime_error.Error![*]F {
        if (minimum == 0 or slice.len < minimum or
            slice.owner != 1 or slice.generation != 1)
        {
            return error.InvalidDeviceAddress;
        }
        const bytes = std.math.mul(usize, minimum, @sizeOf(F)) catch
            return error.SizeOverflow;
        const end = std.math.add(usize, slice.address, bytes) catch
            return error.SizeOverflow;
        const backing_start = @intFromPtr(&storage);
        const backing_bytes = std.math.mul(
            usize,
            self.backing_words,
            @sizeOf(u32),
        ) catch return error.SizeOverflow;
        const backing_end = std.math.add(
            usize,
            backing_start,
            backing_bytes,
        ) catch return error.SizeOverflow;
        if (slice.address < backing_start or end > backing_end)
            return error.InvalidDeviceAddress;
        return @ptrFromInt(slice.address);
    }

    pub fn uploadSlice(
        self: *@This(),
        comptime F: type,
        destination: anytype,
        source: []const F,
    ) runtime_error.Error!void {
        if (self.active_stage != .ingress)
            return error.HostWriteOutsideIngress;
        const pointer = try self.deviceSlicePointer(F, destination, source.len);
        @memcpy(pointer[0..source.len], source);
        const bytes = std.math.mul(usize, source.len, @sizeOf(F)) catch
            return error.SizeOverflow;
        self.counters.h2d(.ingress, bytes);
    }

    pub fn zeroDeviceSlice(
        self: *@This(),
        comptime F: type,
        destination: anytype,
    ) runtime_error.Error!void {
        if (self.active_stage == null) return error.StageNotActive;
        if (destination.len == 0) return error.SizeOverflow;
        const pointer = try self.deviceSlicePointer(
            F,
            destination,
            destination.len,
        );
        @memset(pointer[0..destination.len], 0);
        const bytes = std.math.mul(
            usize,
            destination.len,
            @sizeOf(F),
        ) catch return error.SizeOverflow;
        self.counters.memset(self.active_stage.?, bytes);
        self.zero_calls += 1;
    }

    pub fn memoryInfo(self: *@This()) runtime_error.Error!struct {
        free: usize,
        total: usize,
    } {
        return .{
            .free = self.free_memory_bytes,
            .total = 2 * 1024 * 1024 * 1024,
        };
    }
};

const FakeTransactionSession = struct {
    pub const FinishVerdict = u8;

    context: FakeTransactionContext = .{},
    next_stage: usize = 0,

    pub fn open(_: []const u32) runtime_error.Error!@This() {
        FakeTransactionContext.storage = [_]u32{0} **
            FakeTransactionContext.storage.len;
        return .{};
    }

    pub fn beginStage(
        self: *@This(),
        stage: telemetry.Stage,
    ) runtime_error.Error!void {
        if (self.context.active_stage != null or
            self.next_stage >= telemetry.all_stages.len or
            telemetry.all_stages[self.next_stage] != stage)
        {
            return error.StageOrderViolation;
        }
        self.context.active_stage = stage;
    }

    pub fn endStage(
        self: *@This(),
        stage: telemetry.Stage,
    ) runtime_error.Error!void {
        if (self.context.active_stage != stage)
            return error.StageOrderViolation;
        self.context.active_stage = null;
        self.next_stage += 1;
    }

    pub fn zeroResidentSlice(
        self: *@This(),
        comptime F: type,
        stage: telemetry.Stage,
        destination: anytype,
    ) runtime_error.Error!void {
        const active = self.context.active_stage orelse
            return error.StageNotActive;
        if (active != stage) return error.StageOrderViolation;
        try self.context.zeroDeviceSlice(F, destination);
    }

    pub fn abort(self: *@This()) runtime_error.Error!void {
        self.context.active_stage = null;
    }
};

test "transaction zeroes a proof bundle then uploads only its static header" {
    const Transaction = proof_transaction.TransactionFor(
        FakeTransactionSession,
    );
    const requirements = [_]arena.Requirement{
        .{
            .id = 1,
            .words = 16,
            .live_from = .ingress,
            .live_through = .proof_assembly,
        },
        .{
            .id = 2,
            .words = 4,
            .live_from = .trace_commit,
            .live_through = .trace_commit,
        },
    };
    var transaction = try Transaction.open(
        std.testing.allocator,
        &.{89},
        &requirements,
    );
    try transaction.zeroResidentSlice(u32, .ingress, 1, 0, 16);
    const header = [_]u32{ 0x5354_574f, 1, 16, 4 };
    try transaction.uploadResidentSlice(u32, 1, 0, &header);
    try std.testing.expectEqualSlices(
        u32,
        &header,
        FakeTransactionContext.storage[0..header.len],
    );
    try std.testing.expectEqualSlices(
        u32,
        &([_]u32{0} ** 12),
        FakeTransactionContext.storage[header.len..16],
    );
    const ingress = transaction.session.context.counters
        .stages[telemetry.Stage.ingress.index()];
    try std.testing.expectEqual(@as(u64, 64), ingress.memset_bytes);
    try std.testing.expectEqual(@as(u64, 1), ingress.memset_operations);
    try std.testing.expectEqual(@as(u64, 16), ingress.h2d_bytes);
    try std.testing.expectEqual(
        @as(u64, 16),
        transaction.session.context.counters.h2d_bytes,
    );
    try std.testing.expectError(
        error.StageOrderViolation,
        transaction.uploadResidentSlice(u32, 2, 0, &([_]u32{1} ** 4)),
    );
    try std.testing.expectError(
        error.StageOrderViolation,
        transaction.zeroResidentSlice(u32, .ingress, 2, 0, 4),
    );
    try std.testing.expectError(
        error.SizeOverflow,
        transaction.uploadResidentSlice(u32, 1, 15, &([_]u32{1} ** 2)),
    );
    try transaction.finishIngress();
    try std.testing.expectError(
        error.InvalidState,
        transaction.uploadResidentSlice(u32, 1, 0, &header),
    );
    try std.testing.expectError(
        error.InvalidState,
        transaction.upload(u32, 1, &([_]u32{0} ** 16)),
    );
    try std.testing.expectError(
        error.InvalidState,
        transaction.zeroResidentSlice(u32, .ingress, 1, 0, 16),
    );
    try transaction.abort();
}

test "transaction zero enforces stage, slot lifetime, and exact subrange" {
    const Transaction = proof_transaction.TransactionFor(
        FakeTransactionSession,
    );
    const requirements = [_]arena.Requirement{
        .{
            .id = 1,
            .words = 16,
            .live_from = .ingress,
            .live_through = .proof_assembly,
        },
        .{
            .id = 2,
            .words = 4,
            .live_from = .trace_commit,
            .live_through = .trace_commit,
        },
    };
    var transaction = try Transaction.open(
        std.testing.allocator,
        &.{89},
        &requirements,
    );
    try transaction.upload(
        u32,
        1,
        &.{ 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
    );
    try std.testing.expectError(
        error.InvalidState,
        transaction.zeroResidentSlice(u32, .trace_generation, 1, 4, 4),
    );
    try transaction.finishIngress();
    try std.testing.expectError(
        error.StageNotActive,
        transaction.zeroResidentSlice(u32, .trace_generation, 1, 4, 4),
    );

    try transaction.beginStage(.trace_generation);
    try std.testing.expectError(
        error.StageOrderViolation,
        transaction.zeroResidentSlice(u32, .trace_commit, 1, 4, 4),
    );
    try std.testing.expectError(
        error.StageOrderViolation,
        transaction.zeroResidentSlice(u32, .trace_generation, 2, 0, 4),
    );
    try std.testing.expectError(
        error.SizeOverflow,
        transaction.zeroResidentSlice(u32, .trace_generation, 1, 15, 2),
    );
    try std.testing.expectError(
        error.SizeOverflow,
        transaction.zeroResidentSlice(u32, .trace_generation, 1, 16, 0),
    );
    try transaction.zeroResidentSlice(u32, .trace_generation, 1, 4, 4);
    try std.testing.expectEqual(
        @as(usize, 1),
        transaction.session.context.zero_calls,
    );
    try std.testing.expectEqualSlices(
        u32,
        &.{ 1, 2, 3, 4, 0, 0, 0, 0, 9, 10, 11, 12, 13, 14, 15, 16 },
        FakeTransactionContext.storage[0..16],
    );
    try transaction.abort();
}
