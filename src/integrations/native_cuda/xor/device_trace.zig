//! XOR-owned binding to the resident three-column CUDA trace primitive.

const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const native_trace = @import(
    "../../../backends/cuda/runtime/stages/trace.zig",
);
const geometry_mod = @import("geometry.zig");

pub const Buffers = struct {
    preprocessed: common.WordMatrix,
    main: common.WordMatrix,
};

pub fn generate(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !void {
    return generateWithApi(
        native_trace.Native,
        session,
        buffers,
        geometry,
    );
}

pub fn generateWithApi(
    comptime Api: type,
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !void {
    const row_count = @as(u32, @intCast(geometry.trace_rows));
    try Api.xor(
        session,
        buffers.preprocessed,
        buffers.main,
        row_count,
        geometry.statement.log_size,
        geometry.statement.log_step,
        @intCast(geometry.statement.offset),
    );
}

test "XOR device trace contributes only admitted statement geometry" {
    const std = @import("std");
    const pcs = @import("stwo_core").pcs;
    const Mock = struct {
        var calls: usize = 0;

        pub fn xor(
            _: anytype,
            preprocessed: common.WordMatrix,
            main: common.WordMatrix,
            row_count: u32,
            log_size: u32,
            log_step: u32,
            offset: u64,
        ) !void {
            try std.testing.expectEqual(@as(usize, 2 * 256), preprocessed.storage.len);
            try std.testing.expectEqual(@as(usize, 256), main.storage.len);
            try std.testing.expectEqual(@as(u32, 256), row_count);
            try std.testing.expectEqual(@as(u32, 8), log_size);
            try std.testing.expectEqual(@as(u32, 3), log_step);
            try std.testing.expectEqual(@as(u64, 0x1_0000_0005), offset);
            calls += 1;
        }
    };
    const geometry = try geometry_mod.admit(
        .{ .log_size = 8, .log_step = 3, .offset = 0x1_0000_0005 },
        pcs.PcsConfig.default(),
    );
    var token: u8 = 0;
    try generateWithApi(
        Mock,
        &token,
        .{
            .preprocessed = matrix(0x1000, 256, 2),
            .main = matrix(0x2000, 256, 1),
        },
        geometry,
    );
    try std.testing.expectEqual(@as(usize, 1), Mock.calls);
}

fn matrix(
    address: usize,
    stride: usize,
    columns: usize,
) common.WordMatrix {
    return .{
        .storage = .{
            .address = address,
            .len = stride * columns,
            .owner = 7,
            .generation = 11,
        },
        .column_stride_words = stride,
    };
}
