//! Allocation-free, independently reconstructed native PCS column geometry.
//! The immutable statement chooses every span. Received log arrays are checked
//! in order; no cached digest or array chooses a verifier mask.
const std = @import("std");
const Statement = @import("../air/statement.zig");
const Protocol = @import("block_v5_native_template_protocol_v3.zig");
const Frame = @import("block_v5_native_frame_v1.zig");
const Opcode = @import("../air/lookups/opcode_interaction.zig");

pub const Span = struct { log_size: u32, count: usize };
pub const Cursor = struct {
    shape: *const Statement.Blake3ExecutionStatement,
    tree: Protocol.ColumnTree,
    ordinal: usize = 0,
    frame: bool,

    pub fn init(shape: *const Statement.Blake3ExecutionStatement, external: u32, tree: Protocol.ColumnTree) !Cursor {
        try shape.validateBlake3ExecutionWithExternal(external);
        const is_frame = Frame.required(shape);
        if (is_frame) _ = try Frame.expected(shape, external);
        return .{ .shape = shape, .tree = tree, .frame = is_frame };
    }

    /// Borrows the same immutable statement used by independent admission.
    pub fn next(self: *Cursor) ?Span {
        if (self.frame) {
            if (self.ordinal != 0) return null;
            self.ordinal = 1;
            return .{ .log_size = Frame.LOG_SIZE, .count = switch (self.tree) {
                .fixed => Frame.FIXED_COLUMNS,
                .main => Frame.MAIN_COLUMNS,
                .interaction => Frame.INTERACTION_COLUMNS,
            } };
        }
        while (self.ordinal < self.shape.n_components + self.shape.n_infra) {
            const ordinal = self.ordinal;
            self.ordinal += 1;
            const span: Span = if (ordinal < self.shape.n_components) blk: {
                const desc = self.shape.component_descs[ordinal];
                break :blk .{ .log_size = desc.log_size, .count = switch (self.tree) {
                    .fixed => 2,
                    .main => desc.n_columns,
                    .interaction => Opcode.nColumns(desc.family),
                } };
            } else blk: {
                const desc = self.shape.infra_descs[ordinal - self.shape.n_components];
                break :blk .{ .log_size = desc.log_size, .count = switch (self.tree) {
                    .fixed => Statement.nPreprocessedColumnsForInfra(desc.kind),
                    .main => desc.n_columns,
                    .interaction => Statement.nInteractionColsForInfra(desc.kind),
                } };
            };
            if (span.count != 0) return span;
        }
        return null;
    }

    pub fn count(self: Cursor) !usize {
        var cursor = self;
        var result: usize = 0;
        while (cursor.next()) |span| result = try std.math.add(usize, result, span.count);
        return result;
    }

    pub fn write(self: Cursor, logs: []u32) !void {
        var cursor = self;
        var first: usize = 0;
        while (cursor.next()) |span| {
            if (span.count > logs.len - first) return error.UntrustedNativeColumnGeometry;
            @memset(logs[first..][0..span.count], span.log_size);
            first += span.count;
        }
        if (first != logs.len) return error.UntrustedNativeColumnGeometry;
    }

    pub fn require(self: Cursor, logs: []const u32) !void {
        var cursor = self;
        var first: usize = 0;
        while (cursor.next()) |span| {
            if (span.count > logs.len - first) return error.UntrustedNativeColumnGeometry;
            if (!std.mem.allEqual(u32, logs[first..][0..span.count], span.log_size))
                return error.UntrustedNativeColumnGeometry;
            first += span.count;
        }
        if (first != logs.len) return error.UntrustedNativeColumnGeometry;
    }

    pub fn allocate(self: Cursor, allocator: std.mem.Allocator) ![]u32 {
        const logs = try allocator.alloc(u32, try self.count());
        errdefer allocator.free(logs);
        try self.write(logs);
        return logs;
    }
};
