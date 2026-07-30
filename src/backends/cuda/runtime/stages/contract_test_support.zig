//! Shared fake resident session and typed views for stage contract tests.

const field = @import("../../abi/field.zig");
const column = @import("../column.zig");
const telemetry = @import("../telemetry.zig");
const transform = @import("transform.zig");

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

    pub fn uploadSlice(
        self: *@This(),
        comptime F: type,
        destination: anytype,
        source: []const F,
    ) !void {
        try self.requireStage(.ingress);
        _ = try self.deviceSlicePointer(F, destination, source.len);
    }
};

pub const FakeSession = struct {
    context: FakeContext,
    launches: usize = 0,

    pub fn init(stage: telemetry.Stage) FakeSession {
        return .{ .context = FakeContext.init(stage) };
    }

    pub fn recordOrdinaryKernel(
        self: *@This(),
        stage: telemetry.Stage,
        status: c_int,
    ) !void {
        try self.recordOrdinaryKernels(stage, status, 1);
    }

    pub fn recordOrdinaryKernels(
        self: *@This(),
        stage: telemetry.Stage,
        status: c_int,
        count: u64,
    ) !void {
        if (status != 0) return error.CudaFailure;
        try self.context.requireStage(stage);
        self.launches += @intCast(count);
    }
};

pub fn view(comptime F: type, len: usize) column.DeviceSlice(F) {
    return .{ .address = 0x1000, .len = len, .owner = owner };
}

pub fn viewAt(
    comptime F: type,
    address: usize,
    len: usize,
) column.DeviceSlice(F) {
    return .{ .address = address, .len = len, .owner = owner };
}

pub fn words(len: usize) column.DeviceSlice(u32) {
    return view(u32, len);
}

pub fn wordMatrix(
    address: usize,
    column_count: usize,
    stride_words: usize,
) transform.WordMatrix {
    return .{
        .storage = .{
            .address = address,
            .len = column_count * stride_words,
            .owner = owner,
        },
        .column_stride_words = stride_words,
    };
}

pub fn secure(len: usize) column.DeviceSlice(field.SecureField) {
    return view(field.SecureField, len);
}

pub fn circles(len: usize) column.DeviceSlice(field.CirclePointBaseField) {
    return view(field.CirclePointBaseField, len);
}

pub fn secureCircles(len: usize) column.DeviceSlice(field.SecureCirclePoint) {
    return view(field.SecureCirclePoint, len);
}

pub fn hashes(len: usize) column.DeviceSlice(field.Blake2sHash) {
    return view(field.Blake2sHash, len);
}

pub fn states(len: usize) column.DeviceSlice(field.ProgressiveBlake2sState) {
    return view(field.ProgressiveBlake2sState, len);
}
