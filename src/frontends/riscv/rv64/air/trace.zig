//! Column-major bounded proof trace, in coset-natural bit-reversed circle order.
const std = @import("std");
const core = @import("stwo_core");
const M = core.fields.m31.M31;
const Q = core.fields.qm31.QM31;
const E = @import("evaluation.zig");
const L = E.L;
const R = @import("rows.zig");
const W = @import("witness.zig");
const S = @import("statement.zig");
const relation = @import("relations.zig");
pub const Column = @import("stwo_prover_engine").pcs.ColumnEvaluation;
pub const Trace = struct {
    allocator: std.mem.Allocator,
    log_size: u32,
    projection: @import("projection.zig").Projection,
    fixed: []M,
    main: []M,
    interaction: []M,

    pub fn init(a: std.mem.Allocator, public: S.Statement, metadata: S.Metadata, rows: ?[]const R.Main) !Trace {
        try metadata.validate(public);
        if (rows) |values| if (values.len != public.steps) return error.InvalidRv64Rows;
        const log = @max(5, std.math.log2_int_ceil(u32, public.steps));
        const size = @as(usize, 1) << @intCast(log);
        const projection = try @import("projection.zig").Projection.init(a, public, metadata, size);
        const fixed = try a.alloc(M, projection.fixed_count * size);
        errdefer a.free(fixed);
        const main = try a.alloc(M, if (rows != null) projection.main_count * size else 0);
        errdefer a.free(main);
        @memset(fixed, M.zero());
        @memset(main, M.zero());
        for (0..size) |i| {
            const row = try R.fixedRow(public, metadata, i, size);
            const physical = W.physical(i, log);
            for (projection.fixed_sources[0..projection.fixed_count], 0..) |source, column| fixed[column * size + physical] = row[source];
            if (rows) |values| if (i < values.len) {
                for (projection.main_sources[0..projection.main_count], 0..) |source, column| main[column * size + physical] = values[i][source];
            };
        }
        return .{ .allocator = a, .log_size = log, .projection = projection, .fixed = fixed, .main = main, .interaction = &.{} };
    }

    pub fn deinit(self: *Trace) void {
        self.releaseColumns();
        self.* = undefined;
    }
    pub fn releaseColumns(self: *Trace) void {
        self.allocator.free(self.fixed);
        self.allocator.free(self.main);
        self.allocator.free(self.interaction);
        self.fixed = &.{};
        self.main = &.{};
        self.interaction = &.{};
    }
    pub fn domainSize(self: *const Trace) usize {
        return @as(usize, 1) << @intCast(self.log_size);
    }
    pub fn fixedAt(self: *const Trace, index: usize) E.Fixed {
        var physical: [L.fixed.COUNT]Q = undefined;
        for (physical[0..self.projection.fixed_count], 0..) |*value, c| value.* = Q.fromBase(self.fixed[c * self.domainSize() + index]);
        return self.projection.inflateFixed(physical[0..self.projection.fixed_count]);
    }
    pub fn mainAt(self: *const Trace, index: usize) E.Main {
        var physical: [L.MAIN]Q = undefined;
        for (physical[0..self.projection.main_count], 0..) |*value, c| value.* = Q.fromBase(self.main[c * self.domainSize() + index]);
        return self.projection.inflateMain(physical[0..self.projection.main_count]);
    }
    pub fn columns(self: *const Trace, a: std.mem.Allocator, tree: u2) ![]Column {
        const storage = switch (tree) {
            0 => self.fixed,
            1 => self.main,
            2 => self.interaction,
            else => return error.InvalidRv64Tree,
        };
        const result = try a.alloc(Column, storage.len / self.domainSize());
        for (result, 0..) |*column, i| column.* = .{ .log_size = self.log_size, .values = storage[i * self.domainSize() ..][0..self.domainSize()] };
        return result;
    }
    pub fn generateInteraction(self: *Trace, challenges: relation.Challenges) !Q {
        if (self.interaction.len != 0 or self.main.len == 0) return error.InvalidRv64TracePhase;
        const storage = try self.allocator.alloc(M, self.domainSize() * L.INTERACTION);
        errdefer self.allocator.free(storage);
        @memset(storage, M.zero());
        var sum = Q.zero();
        for (0..self.domainSize()) |i| {
            const physical = W.physical(i, self.log_size);
            const fixed = self.fixedAt(physical);
            const main = self.mainAt(physical);
            const view = E.View{ .f = &fixed, .m = &main };
            for (0..4) |slot| {
                if (fixed[L.fixed.slot_start + slot].isZero()) continue;
                const before = try challenges.denominator(relation.tuple(view, slot, true)).inv();
                const after = try challenges.denominator(relation.tuple(view, slot, false)).inv();
                storeSecure(storage, self.domainSize(), physical, slot * 8, before);
                storeSecure(storage, self.domainSize(), physical, slot * 8 + 4, after);
                sum = sum.add(before).sub(after);
            }
            storeSecure(storage, self.domainSize(), physical, 32, sum);
        }
        self.interaction = storage;
        return sum;
    }
};
fn storeSecure(storage: []M, size: usize, row: usize, column: usize, value: Q) void {
    for (value.toM31Array(), 0..) |coordinate, i| storage[(column + i) * size + row] = coordinate;
}
