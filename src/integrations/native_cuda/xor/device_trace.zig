//! Exact XOR binding to the authenticated 7+4 resident witness kernel.

const common = @import(
    "../../../backends/cuda/runtime/stages/common.zig",
);
const exact_trace = @import(
    "../../../backends/cuda/runtime/traces/xor_logup.zig",
);
const geometry_mod = @import("geometry.zig");

pub const Buffers = exact_trace.Destinations;

pub fn generate(
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !void {
    return generateWithApi(exact_trace, session, buffers, geometry);
}

pub fn generateWithApi(
    comptime Api: type,
    session: anytype,
    buffers: Buffers,
    geometry: geometry_mod.Geometry,
) !void {
    try Api.generate(
        session,
        buffers,
        .{
            .log_size = geometry.statement.log_size,
            .log_step = geometry.statement.log_step,
            .offset = @intCast(geometry.statement.offset),
        },
    );
}

test "XOR device trace binds exact truth-table destinations and statement" {
    const std = @import("std");
    const Mock = struct {
        var calls: usize = 0;

        pub fn generate(
            _: anytype,
            destinations: exact_trace.Destinations,
            statement: exact_trace.Statement,
        ) !void {
            try std.testing.expectEqual(
                @as(usize, 7 * 256),
                destinations.preprocessed.storage.len,
            );
            try std.testing.expectEqual(
                @as(usize, 4 * 256),
                destinations.main.storage.len,
            );
            try std.testing.expectEqual(
                @as(usize, 7 * 256),
                destinations.relation_sources.storage.len,
            );
            try std.testing.expectEqual(@as(u32, 8), statement.log_size);
            try std.testing.expectEqual(@as(u32, 3), statement.log_step);
            try std.testing.expectEqual(
                @as(u64, 0x1_0000_0005),
                statement.offset,
            );
            calls += 1;
        }
    };
    const geometry = try geometry_mod.admit(
        .{ .log_size = 8, .log_step = 3, .offset = 0x1_0000_0005 },
        @import("stwo_core").pcs.PcsConfig.default(),
    );
    var token: u8 = 0;
    try generateWithApi(
        Mock,
        &token,
        .{
            .preprocessed = matrix(0x1000, 256, 7),
            .main = matrix(0x20_0000, 256, 4),
            .relation_sources = matrix(0x40_0000, 256, 7),
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
