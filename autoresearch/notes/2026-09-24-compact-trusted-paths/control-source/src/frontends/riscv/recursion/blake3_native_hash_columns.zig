//! Owner for final native-parent hash columns and generated witness metadata.
const std = @import("std");
const M = @import("stwo_core").fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const frame = @import("air/blake3_frame_witness.zig");
const g = @import("air/blake3_g_call.zig");
const xor = @import("air/blake3_xor_call.zig");
const Layout = @import("blake3_native_hash_layout.zig").Layout;
pub const Owner = struct {
    allocator: std.mem.Allocator,
    layout: Layout,
    main: [2][]Column = @splat(&.{}),
    g_metadata: []@import("air/blake3_hash_metadata.zig").Row(g) = &.{},
    xor_metadata: []@import("air/blake3_hash_metadata.zig").Row(xor) = &.{},

    pub fn init(a: std.mem.Allocator, layout: Layout) !Owner {
        try layout.validateEmitted(layout.transcript, layout.paths);
        var self = Owner{ .allocator = a, .layout = layout };
        errdefer self.deinit();
        inline for (.{ g, xor }, 0..) |Air, i| {
            self.main[i] = try a.alloc(Column, Air.PHYSICAL_MAIN_COLUMN_COUNT);
            for (self.main[i]) |*column| column.* = .{ .log_size = layout.logs[i], .values = &.{} };
            for (self.main[i]) |*column| {
                const values = try a.alloc(M, @as(usize, 1) << @intCast(column.log_size));
                @memset(values, M.zero());
                column.values = values;
            }
        }
        self.g_metadata = try a.alloc(@import("air/blake3_hash_metadata.zig").Row(g), layout.total.g);
        self.xor_metadata = try a.alloc(@import("air/blake3_hash_metadata.zig").Row(xor), layout.total.xor);
        if (std.process.hasEnvVarConstant("STWO_RISCV_RECURSIVE_PARENT_PROFILE")) {
            const full_bytes = layout.total.g * @sizeOf(g.Row) + layout.total.xor * @sizeOf(xor.Row);
            const compact_bytes = std.mem.sliceAsBytes(self.g_metadata).len + std.mem.sliceAsBytes(self.xor_metadata).len;
            std.debug.print("BLAKE3_HASH_METADATA g_rows={d} xor_rows={d} full_row_bytes={d} compact_bytes={d} removed_bytes={d}\n", .{ layout.total.g, layout.total.xor, full_bytes, compact_bytes, full_bytes - compact_bytes });
        }
        return self;
    }
    pub fn deinit(self: *Owner) void {
        for (self.main) |columns| {
            for (columns) |column| self.allocator.free(column.values);
            self.allocator.free(columns);
        }
        self.allocator.free(self.g_metadata);
        self.allocator.free(self.xor_metadata);
        self.* = undefined;
    }
    pub fn view(self: *const Owner) !frame.MainColumns {
        var out: frame.MainColumns = .{
            .g_rows = .{ .columns = undefined, .metadata = self.g_metadata, .log_size = self.layout.logs[0] },
            .xor_rows = .{ .columns = undefined, .metadata = self.xor_metadata, .log_size = self.layout.logs[1] },
        };
        inline for (.{ "g_rows", "xor_rows" }, 0..) |name, i| {
            const dst = &@field(out, name);
            if (self.main[i].len != dst.columns.len) return error.InvalidNativeHashColumns;
            for (self.main[i], &dst.columns) |column, *values| {
                if (column.log_size != dst.log_size) return error.InvalidNativeHashColumns;
                // PCS descriptors expose const slices; this owner allocated the
                // storage and lends the only mutable emission views before transfer.
                values.* = @constCast(column.values);
            }
        }
        try out.validate(self.layout.total.g, self.layout.total.xor);
        return out;
    }
    pub fn transcript(self: *const Owner) !frame.MainColumns {
        return (try self.view()).slice(0, self.layout.transcript.g, 0, self.layout.transcript.xor);
    }
    pub fn paths(self: *const Owner) !frame.MainColumns {
        return (try self.view()).slice(self.layout.transcript.g, self.layout.paths.g, self.layout.transcript.xor, self.layout.paths.xor);
    }
};
