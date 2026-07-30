//! Ingress-only binding of canonical Cairo multi-edge gather topology.

const std = @import("std");
const abi = @import("../../abi/stages/cairo_witness.zig");
const column = @import("../column.zig");
const common = @import("common.zig");
const runtime_error = @import("../error.zig");

pub const Descriptors = column.DeviceSlice(abi.MultiEdgeDescriptor);

pub const MultiEdgeTopology = struct {
    descriptors: Descriptors,
    edge_count: u32,
    input_width: u32,
    total_real_rows: u32,
    consumer_rows: u32,
    producer_word_count: usize,
    output_columns: u32,
    include_enabler: bool,
    include_iota: bool,
};

pub fn prepareMultiEdgeTopology(
    session: anytype,
    host_edges: []const abi.MultiEdgeDescriptor,
    device_edges: Descriptors,
    producer_word_count: usize,
    include_enabler: bool,
    include_iota: bool,
) runtime_error.Error!MultiEdgeTopology {
    try common.requireStage(session, .ingress);
    const edge_count = try common.count(host_edges.len);
    if (edge_count == 0 or producer_word_count == 0)
        return error.InvalidKernelDescriptor;
    const input_width = host_edges[0].words_per_instance;
    if (input_width == 0) return error.InvalidKernelDescriptor;

    var row_cursor: u64 = 0;
    for (host_edges) |edge| {
        row_cursor = try validateEdge(
            edge,
            input_width,
            row_cursor,
            producer_word_count,
        );
    }
    const total_real_rows: u32 = @intCast(row_cursor);
    const exact_device = try device_edges.sub(0, host_edges.len);
    try session.context.uploadSlice(
        abi.MultiEdgeDescriptor,
        exact_device,
        host_edges,
    );
    return .{
        .descriptors = exact_device,
        .edge_count = edge_count,
        .input_width = input_width,
        .total_real_rows = total_real_rows,
        .consumer_rows = try canonicalRows(total_real_rows),
        .producer_word_count = producer_word_count,
        .output_columns = try outputColumns(
            input_width,
            include_enabler,
            include_iota,
        ),
        .include_enabler = include_enabler,
        .include_iota = include_iota,
    };
}

fn validateEdge(
    edge: abi.MultiEdgeDescriptor,
    input_width: u32,
    row_cursor: u64,
    producer_word_count: usize,
) runtime_error.Error!u64 {
    if (edge.reserved != 0 or edge.producer_rows == 0 or
        edge.producer_rows % 16 != 0 or edge.instance_count == 0 or
        edge.words_per_instance != input_width or
        edge.destination_row_offset != @as(u32, @intCast(row_cursor)))
    {
        return error.InvalidKernelDescriptor;
    }
    const instance_words = std.math.mul(
        u64,
        edge.words_per_instance,
        edge.instance_count,
    ) catch return error.SizeOverflow;
    const source_word_end = std.math.add(
        u64,
        edge.word_base,
        instance_words,
    ) catch return error.SizeOverflow;
    const source_words = std.math.mul(
        u64,
        source_word_end,
        edge.producer_rows,
    ) catch return error.SizeOverflow;
    const arena_end = std.math.add(
        u64,
        edge.source_offset_words,
        source_words,
    ) catch return error.SizeOverflow;
    if (arena_end > @as(u64, producer_word_count))
        return error.InvalidKernelDescriptor;
    const destination_rows = std.math.mul(
        u64,
        edge.producer_rows,
        edge.instance_count,
    ) catch return error.SizeOverflow;
    const next = std.math.add(
        u64,
        row_cursor,
        destination_rows,
    ) catch return error.SizeOverflow;
    if (next > (@as(u64, 1) << 31)) return error.SizeOverflow;
    return next;
}

fn canonicalRows(real_rows: u32) runtime_error.Error!u32 {
    var rows: u32 = 16;
    while (rows < real_rows) {
        rows = std.math.mul(u32, rows, 2) catch
            return error.SizeOverflow;
    }
    return rows;
}

fn outputColumns(
    input_width: u32,
    include_enabler: bool,
    include_iota: bool,
) runtime_error.Error!u32 {
    const with_enabler = std.math.add(
        usize,
        input_width,
        @intFromBool(include_enabler),
    ) catch return error.SizeOverflow;
    return common.count(std.math.add(
        usize,
        with_enabler,
        @intFromBool(include_iota),
    ) catch return error.SizeOverflow);
}
