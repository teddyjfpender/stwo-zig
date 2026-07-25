const std = @import("std");
const fixed = @import("fixed_tables.zig");
const telemetry = @import("../../telemetry.zig");

test "fixed-table binding accepts exact resident geometry" {
    var session = TestSession{};
    try fixed.OpsFor(TestApi).materialize(
        &session,
        .{
            .source_column_count = 2,
            .multiplicity_column_count = 3,
            .trace_output_count = 1,
            .lookup_output_count = 4,
            .row_count = 16,
        },
        .{
            .source_pointer_table = words(0x1000, 4),
            .multiplicity_pointer_table = words(0x1100, 6),
            .trace_multiplicity_columns = words(0x1200, 1),
            .trace_output_pointer_table = words(0x1300, 2),
            .lookup_descriptors = words(0x1400, 16),
            .lookup_output_pointer_table = words(0x1500, 8),
        },
    );
    try std.testing.expectEqual(@as(u64, 1), session.launches);
}

test "fixed-table binding rejects extent and alias drift" {
    const geometry = fixed.Geometry{
        .source_column_count = 0,
        .multiplicity_column_count = 1,
        .trace_output_count = 1,
        .lookup_output_count = 1,
        .row_count = 16,
    };
    const exact = fixed.Buffers{
        .source_pointer_table = words(0, 0),
        .multiplicity_pointer_table = words(0x1000, 2),
        .trace_multiplicity_columns = words(0x1100, 1),
        .trace_output_pointer_table = words(0x1200, 2),
        .lookup_descriptors = words(0x1300, 4),
        .lookup_output_pointer_table = words(0x1400, 2),
    };
    var session = TestSession{};
    var wrong = exact;
    wrong.lookup_descriptors.len -= 1;
    try std.testing.expectError(
        error.InvalidKernelDescriptor,
        fixed.OpsFor(TestApi).materialize(&session, geometry, wrong),
    );
    wrong = exact;
    wrong.lookup_output_pointer_table.address =
        wrong.trace_output_pointer_table.address;
    try std.testing.expectError(
        error.OverlappingDeviceRange,
        fixed.OpsFor(TestApi).materialize(&session, geometry, wrong),
    );
}

const TestApi = struct {
    pub fn stwo_fixed_table_materialize_on(
        _: ?[*]const u64,
        _: [*]const u64,
        _: [*]const u32,
        _: [*]const u64,
        _: u32,
        _: [*]const u32,
        _: [*]const u64,
        _: u32,
        _: u32,
        _: *anyopaque,
    ) c_int {
        return 0;
    }
};

const TestSession = struct {
    context: TestContext = .{},
    launches: u64 = 0,

    pub fn recordOrdinaryKernel(
        self: *TestSession,
        stage: telemetry.Stage,
        status: c_int,
    ) !void {
        if (stage != .trace_generation or status != 0)
            return error.InvalidState;
        self.launches += 1;
    }
};

const TestContext = struct {
    stream: *anyopaque = @ptrFromInt(1),

    pub fn requireStage(_: *TestContext, stage: telemetry.Stage) !void {
        if (stage != .trace_generation) return error.StageOrderViolation;
    }

    pub fn deviceSlicePointer(
        _: *TestContext,
        comptime T: type,
        slice: anytype,
        minimum: usize,
    ) ![*]T {
        if (slice.len < minimum or slice.address == 0 or
            slice.address % @alignOf(T) != 0)
        {
            return error.InvalidDeviceAddress;
        }
        return @ptrFromInt(slice.address);
    }
};

fn words(address: usize, len: usize) @import("../../column.zig").DeviceSlice(u32) {
    return .{
        .address = address,
        .len = len,
        .owner = 7,
        .generation = 11,
    };
}
