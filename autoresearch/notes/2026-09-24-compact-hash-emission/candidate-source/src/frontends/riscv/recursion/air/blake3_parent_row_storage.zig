//! Shared parent roster, retained columns and fail-atomic row storage.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const boundary = @import("blake3_boundary.zig");
const scalar = @import("scalar_wire_source.zig");
pub const selectors = @import("proof_kind.zig").ProofKind.segment_leaf.selectors();
pub const Airs = .{
    @import("blake3_g_call.zig"),                   @import("blake3_xor_call.zig"),        boundary,
    @import("qm31_mul_add_v1.zig"),                 @import("qm31_inv.zig"),               @import("linear_ops.zig"),
    @import("blake3_challenge_block.zig"),          @import("blake3_byte_route.zig"),      @import("blake3_query_mask.zig"),
    @import("blake3_private_word.zig"),             @import("blake3_field_bytes.zig"),     @import("qm31_pack_wire.zig"),
    scalar,                                         @import("blake3_path_select.zig"),     @import("blake3_retry_control.zig"),
    @import("blake3_counter_step.zig"),             @import("readonly_consistency.zig"),   @import("readonly_input.zig"),
    @import("detached_opening_accumulate4_v1.zig"), @import("native_pcs_opening4_v1.zig"),
};
pub fn Tuple(comptime list: bool) type {
    var types: [Airs.len]type = undefined;
    for (Airs, &types) |Air, *T| T.* = if (list) std.ArrayList(Air.Row) else []Air.Row;
    return std.meta.Tuple(&types);
}
/// Fixed schedule and proof-kind parameters, without redundant main placeholders.
pub fn FixedRow(comptime Air: type) type {
    return [Air.LOGICAL_INPUT_COUNT - Air.PHYSICAL_MAIN_COLUMN_COUNT]M;
}
pub fn compactFixed(comptime Air: type, row: Air.Row) FixedRow(Air) {
    return row[Air.PHYSICAL_MAIN_COLUMN_COUNT..].*;
}
pub fn FixedTuple(comptime list: bool) type {
    var types: [Airs.len]type = undefined;
    for (Airs, &types) |Air, *T| T.* = if (list) std.ArrayList(FixedRow(Air)) else []FixedRow(Air);
    return std.meta.Tuple(&types);
}
pub const Prepared = struct {
    allocator: std.mem.Allocator,
    main: [Airs.len][]Column,
    fixed: FixedTuple(false),
    input_count: usize,
    pub fn deinit(self: *Prepared) void {
        inline for (0..Airs.len) |i| {
            for (self.main[i]) |column| self.allocator.free(column.values);
            self.allocator.free(self.main[i]);
            self.allocator.free(self.fixed[i]);
        }
        self.* = undefined;
    }
    pub fn retainedBytes(self: *const Prepared) !usize {
        var total: usize = 0;
        inline for (Airs, 0..) |Air, i| {
            total = try std.math.add(usize, total, try std.math.mul(usize, self.fixed[i].len, @sizeOf(FixedRow(Air))));
            total = try std.math.add(usize, total, try std.math.mul(usize, self.main[i].len, @sizeOf(Column)));
            for (self.main[i]) |column| total = try std.math.add(usize, total, try std.math.mul(usize, column.values.len, @sizeOf(M)));
        }
        return total;
    }
};
pub const Builder = struct {
    a: std.mem.Allocator,
    rows: Tuple(true),
    fixed: FixedTuple(true),
    pub fn init(a: std.mem.Allocator) Builder {
        var self: Builder = .{ .a = a, .rows = undefined, .fixed = undefined };
        inline for (0..Airs.len) |i| {
            self.rows[i] = .empty;
            self.fixed[i] = .empty;
        }
        return self;
    }
    pub fn deinit(self: *Builder) void {
        inline for (0..Airs.len) |i| {
            self.rows[i].deinit(self.a);
            self.fixed[i].deinit(self.a);
        }
    }
    pub fn reserve(self: *Builder, comptime i: usize, count: usize) !void {
        if (!directCohort(i)) try self.rows[i].ensureTotalCapacityPrecise(self.a, count);
        try self.fixed[i].ensureTotalCapacityPrecise(self.a, count);
    }
    /// Main columns already exist; admit each generated fixed field independently.
    pub fn appendMetadata(self: *Builder, comptime i: usize, rows: []const FixedRow(Airs[i]), fixed: []const Airs[i].Row) !void {
        comptime std.debug.assert(i < 2);
        if (rows.len != fixed.len) return error.InvalidNativeParentRows;
        for (rows, fixed) |live, trusted| for (live, trusted[Airs[i].PHYSICAL_MAIN_COLUMN_COUNT..]) |actual, expected| {
            if (!actual.eql(expected)) return error.InvalidNativeParentRows;
        };
        try self.fixed[i].appendSlice(self.a, rows);
    }
    pub fn append(self: *Builder, comptime i: usize, rows: []const Airs[i].Row, fixed: []const Airs[i].Row) !void {
        if (rows.len != fixed.len) return error.InvalidNativeParentRows;
        for (rows, fixed) |live, trusted| for (live[Airs[i].PHYSICAL_MAIN_COLUMN_COUNT..], trusted[Airs[i].PHYSICAL_MAIN_COLUMN_COUNT..]) |actual, expected| {
            if (!actual.eql(expected)) return error.InvalidNativeParentRows;
        };
        if (!directCohort(i)) try self.rows[i].appendSlice(self.a, rows);
        try self.fixed[i].ensureUnusedCapacity(self.a, fixed.len);
        for (fixed) |row| self.fixed[i].appendAssumeCapacity(compactFixed(Airs[i], row));
    }
};
pub fn directCohort(comptime i: usize) bool {
    return i == 0 or i == 1 or i == 7;
}
