//! Commitment-specific slab, stage, and alias policy checks.

const std = @import("std");
const column = @import("../column.zig");
const commitment = @import("commitment.zig").Native;
const common = @import("common.zig");
const field = @import("../../abi/field.zig");
const telemetry = @import("../telemetry.zig");

const owner: usize = 7;

const FakeContext = struct {
    stream_storage: u8 = 0,
    stream: *anyopaque = undefined,
    active_stage: ?telemetry.Stage = null,

    fn init(stage: telemetry.Stage) FakeContext {
        var result = FakeContext{};
        result.stream = &result.stream_storage;
        result.active_stage = stage;
        return result;
    }

    pub fn deviceSlicePointer(
        self: *@This(),
        comptime F: type,
        slice: anytype,
        minimum: usize,
    ) ![*]F {
        _ = self;
        if (slice.owner != owner or slice.len < minimum or
            slice.address == 0 or slice.address % @alignOf(F) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }

    pub fn requireStage(self: *@This(), expected: telemetry.Stage) !void {
        if (self.active_stage != expected) return error.StageOrderViolation;
    }
};

const FakeSession = struct {
    context: FakeContext,
    launches: usize = 0,

    fn init(stage: telemetry.Stage) FakeSession {
        return .{ .context = FakeContext.init(stage) };
    }

    pub fn recordOrdinaryKernel(
        self: *@This(),
        stage: telemetry.Stage,
        status: c_int,
    ) !void {
        if (status != 0) return error.CudaFailure;
        try self.context.requireStage(stage);
        self.launches += 1;
    }
};

fn viewAt(
    comptime F: type,
    address: usize,
    len: usize,
) column.DeviceSlice(F) {
    return .{ .address = address, .len = len, .owner = owner };
}

fn wordMatrix(
    address: usize,
    column_count: usize,
    stride_words: usize,
) common.WordMatrix {
    return .{
        .storage = viewAt(
            u32,
            address,
            column_count * stride_words,
        ),
        .column_stride_words = stride_words,
    };
}

test "commitment slabs reject invalid shapes, overflow, and aliases" {
    var session = FakeSession.init(.trace_commit);
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        commitment.progressiveAbsorb(
            &session,
            .trace_commit,
            16,
            0,
            wordMatrix(0x10000, 4, 15),
            viewAt(field.ProgressiveBlake2sState, 0x20000, 16),
        ),
    );
    try std.testing.expectError(
        error.SizeOverflow,
        commitment.progressiveAbsorb(
            &session,
            .trace_commit,
            16,
            std.math.maxInt(u32) - 2,
            wordMatrix(0x10000, 4, 16),
            viewAt(field.ProgressiveBlake2sState, 0x20000, 16),
        ),
    );
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        commitment.progressiveAbsorb(
            &session,
            .trace_commit,
            16,
            0,
            wordMatrix(0x10000, 4, 16),
            viewAt(field.ProgressiveBlake2sState, 0x10000, 16),
        ),
    );
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        commitment.progressiveFinalize(
            &session,
            .trace_commit,
            4,
            viewAt(field.ProgressiveBlake2sState, 0x30000, 16),
            viewAt(field.Blake2sHash, 0x30000, 16),
        ),
    );
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        commitment.layer(
            &session,
            .trace_commit,
            viewAt(field.Blake2sHash, 0x38000, 32),
            viewAt(field.Blake2sHash, 0x38000, 16),
            false,
        ),
    );

    session.context.active_stage = .fri_commit;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        commitment.friLeaves(
            &session,
            wordMatrix(0x40000, 3, 256),
            256,
            0,
            viewAt(field.Blake2sHash, 0x50000, 256),
        ),
    );
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        commitment.friLeaves(
            &session,
            wordMatrix(0x40000, 4, 256),
            256,
            0,
            viewAt(field.Blake2sHash, 0x40000, 256),
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), session.launches);
}
