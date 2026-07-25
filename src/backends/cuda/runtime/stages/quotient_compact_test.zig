//! Focused compact mixed-height quotient runtime contracts.

const std = @import("std");
const field = @import("../../abi/field.zig");
const quotient_abi = @import("../../abi/stages/quotient.zig");
const column = @import("../column.zig");
const telemetry = @import("../telemetry.zig");
const common = @import("common.zig");
const quotient = @import("quotient.zig");

const owner: usize = 19;

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

fn outputAt(address: usize) quotient.CoordinateSlabs {
    return .{
        .c0 = matrixAt(address, 4, 256),
        .c1 = matrixAt(address + 0x10000, 4, 256),
        .c2 = matrixAt(address + 0x20000, 4, 256),
        .c3 = matrixAt(address + 0x30000, 4, 256),
    };
}

fn addressedOutputAt(
    address: usize,
) quotient.addressed.CoordinateColumns {
    return .{
        .c0 = viewAt(u32, address, 512),
        .c1 = viewAt(u32, address + 0x10000, 512),
        .c2 = viewAt(u32, address + 0x20000, 512),
        .c3 = viewAt(u32, address + 0x30000, 512),
    };
}

fn matrixAt(
    address: usize,
    columns: usize,
    stride_words: usize,
) common.WordMatrix {
    return .{
        .storage = viewAt(u32, address, columns * stride_words),
        .column_stride_words = stride_words,
    };
}

test "compact quotient admits mixed strides and dispatches without fallback" {
    var session = FakeSession.init(.ingress);
    const offsets = [_]u32{ 0, 1, 2, 3, 4 };
    const group_logs = [_]u32{ 8, 8, 8, 8 };
    const terms = [_]quotient_abi.BatchTermDescriptor{
        .{ .source_index = 0, .term_index = 0, .source_log_size = 8 },
        .{ .source_index = 1, .term_index = 1, .source_log_size = 7 },
        .{ .source_index = 2, .term_index = 2, .source_log_size = 8 },
        .{ .source_index = 3, .term_index = 3, .source_log_size = 7 },
    };
    const sources = [_]quotient_abi.CompactSourceDescriptor{
        .{ .offset_words = 0, .stride_words = 256, .log_size = 8 },
        .{ .offset_words = 256, .stride_words = 128, .log_size = 7 },
        .{ .offset_words = 384, .stride_words = 512, .log_size = 8 },
        .{ .offset_words = 896, .stride_words = 128, .log_size = 7 },
    };
    const topology = try quotient.prepareCompactNumeratorTopology(
        &session,
        &offsets,
        &terms,
        &sources,
        &group_logs,
        viewAt(u32, 0x10000, 5),
        viewAt(quotient_abi.BatchTermDescriptor, 0x11000, 4),
        viewAt(quotient_abi.CompactSourceDescriptor, 0x12000, 4),
        viewAt(u32, 0x13000, 4),
        256,
        1024,
        4,
    );

    session.context.active_stage = .quotient;
    try quotient.Native.accumulateCompact(
        &session,
        topology,
        viewAt(u32, 0x20000, 1024),
        viewAt(field.SecureField, 0x30000, 12),
        outputAt(0x40000),
    );
    try std.testing.expectEqual(@as(usize, 1), session.launches);
}

test "compact quotient rejects mismatched logs and extent overflow" {
    var session = FakeSession.init(.ingress);
    const offsets = [_]u32{ 0, 1 };
    const group_logs = [_]u32{8};
    const source = [_]quotient_abi.CompactSourceDescriptor{
        .{ .offset_words = 64, .stride_words = 256, .log_size = 8 },
    };
    const mismatched = [_]quotient_abi.BatchTermDescriptor{
        .{ .source_index = 0, .term_index = 0, .source_log_size = 7 },
    };
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        quotient.prepareCompactNumeratorTopology(
            &session,
            &offsets,
            &mismatched,
            &source,
            &group_logs,
            viewAt(u32, 0x10000, 2),
            viewAt(quotient_abi.BatchTermDescriptor, 0x11000, 1),
            viewAt(quotient_abi.CompactSourceDescriptor, 0x12000, 1),
            viewAt(u32, 0x13000, 1),
            256,
            320,
            1,
        ),
    );

    var undersized = source;
    undersized[0].stride_words = 255;
    const matched = [_]quotient_abi.BatchTermDescriptor{
        .{ .source_index = 0, .term_index = 0, .source_log_size = 8 },
    };
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        quotient.prepareCompactNumeratorTopology(
            &session,
            &offsets,
            &matched,
            &undersized,
            &group_logs,
            viewAt(u32, 0x10000, 2),
            viewAt(quotient_abi.BatchTermDescriptor, 0x11000, 1),
            viewAt(quotient_abi.CompactSourceDescriptor, 0x12000, 1),
            viewAt(u32, 0x13000, 1),
            256,
            320,
            1,
        ),
    );

    var out_of_bounds = source;
    out_of_bounds[0].offset_words = 65;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        quotient.prepareCompactNumeratorTopology(
            &session,
            &offsets,
            &matched,
            &out_of_bounds,
            &group_logs,
            viewAt(u32, 0x10000, 2),
            viewAt(quotient_abi.BatchTermDescriptor, 0x11000, 1),
            viewAt(quotient_abi.CompactSourceDescriptor, 0x12000, 1),
            viewAt(u32, 0x13000, 1),
            256,
            320,
            1,
        ),
    );

    var overflow = source;
    overflow[0].offset_words = std.math.maxInt(u64);
    try std.testing.expectError(
        error.SizeOverflow,
        quotient.prepareCompactNumeratorTopology(
            &session,
            &offsets,
            &matched,
            &overflow,
            &group_logs,
            viewAt(u32, 0x10000, 2),
            viewAt(quotient_abi.BatchTermDescriptor, 0x11000, 1),
            viewAt(quotient_abi.CompactSourceDescriptor, 0x12000, 1),
            viewAt(u32, 0x13000, 1),
            256,
            320,
            1,
        ),
    );
}

test "addressed quotient preserves two resident arenas without repacking" {
    var session = FakeSession.init(.ingress);
    const offsets = [_]u32{ 0, 1, 2 };
    const group_logs = [_]u32{ 8, 8 };
    const output_offsets = [_]u64{ 0, 256, 512 };
    const terms = [_]quotient_abi.BatchTermDescriptor{
        .{ .source_index = 0, .term_index = 0, .source_log_size = 8 },
        .{ .source_index = 1, .term_index = 1, .source_log_size = 7 },
    };
    const resident_sources = [_]common.Words{
        .{
            .address = 0x1_0000_0000,
            .len = 256,
            .owner = owner,
            .generation = 7,
        },
        .{
            .address = 0x2_0000_0000,
            .len = 128,
            .owner = owner,
            .generation = 11,
        },
    };
    const sources = [_]quotient_abi.AddressedSourceDescriptor{
        .{
            .address = resident_sources[0].address,
            .stride_words = 256,
            .log_size = 8,
        },
        .{
            .address = resident_sources[1].address,
            .stride_words = 128,
            .log_size = 7,
        },
    };
    const topology = try quotient.prepareAddressedNumeratorTopology(
        &session,
        &offsets,
        &terms,
        &sources,
        &resident_sources,
        &group_logs,
        &output_offsets,
        viewAt(u32, 0x10000, 3),
        viewAt(quotient_abi.BatchTermDescriptor, 0x11000, 2),
        viewAt(quotient_abi.AddressedSourceDescriptor, 0x12000, 2),
        viewAt(u32, 0x13000, 2),
        viewAt(u64, 0x14000, 3),
        256,
        2,
    );
    session.context.active_stage = .quotient;
    try quotient.addressed.Native.accumulate(
        &session,
        topology,
        viewAt(field.SecureField, 0x30000, 6),
        addressedOutputAt(0x40000),
    );
    try std.testing.expectEqual(@as(usize, 1), session.launches);

    var drifted = sources;
    drifted[1].address += 4;
    session.context.active_stage = .ingress;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        quotient.prepareAddressedNumeratorTopology(
            &session,
            &offsets,
            &terms,
            &drifted,
            &resident_sources,
            &group_logs,
            &output_offsets,
            viewAt(u32, 0x10000, 3),
            viewAt(quotient_abi.BatchTermDescriptor, 0x11000, 2),
            viewAt(quotient_abi.AddressedSourceDescriptor, 0x12000, 2),
            viewAt(u32, 0x13000, 2),
            viewAt(u64, 0x14000, 3),
            256,
            2,
        ),
    );
}
