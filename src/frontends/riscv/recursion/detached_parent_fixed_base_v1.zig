//! Key-only fixed projections for the detached parent's transcript/control
//! rows. The evaluated parent and this recipe share the typed row converters;
//! no proof capture or expected statement enters this owner.
const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const child_mod = @import("detached_child_capture_v1.zig");
const cohort = @import("detached_parent_prepared_v1.zig");
const base_mod = @import("detached_parent_base_rows_v1.zig");
const fixed_control = @import("detached_parent_fixed_control_v1.zig");
const fixed_transcript = @import("detached_parent_fixed_transcript_v1.zig");
const prefix = @import("detached_prefix_preparation_v1.zig");
const suffix = @import("detached_pcs_rows_v1.zig");
const pcs = @import("detached_pcs_preparation_v1.zig");
const shared = @import("transcript_logical_rows_v1.zig");
const writer = @import("air/framework_device_interaction.zig");

const ROWS = [_]usize{ 0, 2, 3, 4, 5, 8, 9, 10 };

pub const OwnedV1 = struct {
    arena: std.heap.ArenaAllocator,
    rows: cohort.LogicalRowsV1,

    pub fn init(comptime family: child_mod.Family, allocator: std.mem.Allocator, keys: anytype) !OwnedV1 {
        var result = OwnedV1{ .arena = std.heap.ArenaAllocator.init(allocator), .rows = undefined };
        errdefer result.deinit();
        const a = result.arena.allocator();
        inline for (0..cohort.LOGICAL_ROWS.len) |index| result.rows[index] = &.{};
        const controls = try fixed_control.pair(family, a, keys);
        try result.appendConverted(0, controls);
        inline for (0..2) |index| {
            var lane = try fixed_transcript.OwnedV1.init(family, a, keys[index], index + 1);
            defer lane.deinit();
            try result.appendConverted(2, lane.binding);
            try result.appendConverted(3, lane.state);
            try result.appendConverted(4, lane.word);
            const head_payload = try result.reserve(5, lane.prefix_payload_count);
            for (lane.payload[0..lane.prefix_payload_count], head_payload) |source, *target|
                target.* = .{ M31.one(), source.value } ++ source.preprocessing.values() ++ .{ M31.zero(), M31.one() };
            try result.appendConverted(5, lane.payload[lane.prefix_payload_count..]);
            try result.appendConverted(8, lane.challenges);
            try result.appendConverted(9, lane.randomness);
            try result.appendLogical(10, lane.nonce);
        }
        return result;
    }

    pub fn deinit(self: *OwnedV1) void {
        self.arena.deinit();
        self.* = undefined;
    }

    fn Row(comptime row: usize) type {
        return [cohort.LOGICAL_ROWS[cohort.logicalIndex(row)].Air.LOGICAL_INPUT_COUNT]M31;
    }

    fn reserve(self: *OwnedV1, comptime row: usize, count: usize) ![]Row(row) {
        const index = cohort.logicalIndex(row);
        const prior = self.rows[index];
        const result = try self.arena.allocator().realloc(@constCast(prior), try std.math.add(usize, prior.len, count));
        self.rows[index] = result;
        return result[prior.len..];
    }

    fn appendConverted(self: *OwnedV1, comptime row: usize, values: anytype) !void {
        const destination = try self.reserve(row, values.len);
        for (values, destination) |source, *target| target.* = try shared.logicalRow(row, source);
    }

    fn appendLogical(self: *OwnedV1, comptime row: usize, values: []const Row(row)) !void {
        const destination = try self.reserve(row, values.len);
        @memcpy(destination, values);
    }

    /// Writes only this owner's row families into a complete Tree 0 destination.
    /// The caller must fill every remaining family before committing the tree.
    pub fn fillPreprocessedInto(self: *const OwnedV1, manifest: *const cohort.manifest_mod.Manifest, destination: [][]M31) !void {
        try manifest.validate();
        if (destination.len != manifest.total_preprocessed_columns) return error.DetachedParentDestinationMismatch;
        inline for (ROWS) |row| {
            const Air = cohort.LOGICAL_ROWS[cohort.logicalIndex(row)].Air;
            const placement = manifest.placements[row] orelse return error.DetachedParentManifestMismatch;
            if (placement.geometry.preprocessed_columns != Air.PREPROCESSED_COLUMN_COUNT or
                placement.preprocessed_offset + Air.PREPROCESSED_COLUMN_COUNT > destination.len or
                placement.geometry.log_size >= @bitSizeOf(usize)) return error.DetachedParentDestinationMismatch;
            const columns = destination[placement.preprocessed_offset..][0..Air.PREPROCESSED_COLUMN_COUNT];
            const height = @as(usize, 1) << @intCast(placement.geometry.log_size);
            if (self.rows[cohort.logicalIndex(row)].len > height) return error.DetachedParentDestinationMismatch;
            for (columns) |column| {
                if (column.len != height) return error.DetachedParentDestinationMismatch;
                @memset(column, M31.zero());
            }
            writer.writeColumns(Air, self.rows[cohort.logicalIndex(row)], placement.geometry.log_size, 0, columns);
        }
    }
};

pub fn testAgainstVerifiedChildren(comptime family: child_mod.Family, allocator: std.mem.Allocator, children: [2]*const child_mod.OwnedFor(family)) !void {
    var fixed = try OwnedV1.init(family, allocator, .{ children[0].key(), children[1].key() });
    defer fixed.deinit();
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const a = arena.allocator();
    var heads: [2]*const prefix.OwnedV1 = undefined;
    var tails: [2]*const suffix.OwnedV1 = undefined;
    var checks: [2]*const pcs.OwnedV1 = undefined;
    for (children, 0..) |child, index| {
        const lane: u32 = @intCast(index + 1);
        heads[index] = try prefix.OwnedV1.init(a, child, lane);
        tails[index] = try suffix.OwnedV1.init(a, child, heads[index], lane);
        checks[index] = try pcs.OwnedV1.init(a, child, lane);
    }
    const actual = try base_mod.OwnedV1.init(a, heads, tails, checks);
    const captured = actual.logicalRows();
    inline for (ROWS) |row| {
        const Air = cohort.LOGICAL_ROWS[cohort.logicalIndex(row)].Air;
        const index = cohort.logicalIndex(row);
        try std.testing.expectEqual(captured[index].len, fixed.rows[index].len);
        for (captured[index], fixed.rows[index]) |expected, candidate|
            try std.testing.expectEqualSlices(M31, expected[Air.PHYSICAL_MAIN_COLUMN_COUNT..], candidate[Air.PHYSICAL_MAIN_COLUMN_COUNT..]);
    }
}
