//! Backend-neutral sink contract for completed FRI quotient row tiles.

const std = @import("std");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;

const M31 = m31.M31;

pub const DEFAULT_TILE_ROWS: usize = 256;

pub const RowRange = struct {
    start: usize,
    end: usize,
};

/// Four quotient-coordinate slices for the absolute row range beginning at
/// `start`. The slices are borrowed only for the duration of `Writer.absorb`.
pub const QuotientTile = struct {
    start: usize,
    coordinates: [qm31.SECURE_EXTENSION_DEGREE][]const M31,

    pub fn len(self: QuotientTile) !usize {
        const tile_len = self.coordinates[0].len;
        if (tile_len == 0) return error.EmptyQuotientTile;
        for (self.coordinates[1..]) |coordinate| {
            if (coordinate.len != tile_len) return error.QuotientTileShapeMismatch;
        }
        return tile_len;
    }
};

/// Type-erased, worker-local leaf writer. Each writer is bound to one
/// disjoint shard before worker dispatch.
pub const Writer = struct {
    context: *anyopaque,
    absorb_fn: *const fn (*anyopaque, QuotientTile) anyerror!void,

    pub fn absorb(self: Writer, tile: QuotientTile) !void {
        return self.absorb_fn(self.context, tile);
    }
};

/// Factory used by quotient orchestration before and after worker dispatch.
/// `prepareWriter` is called in ascending worker/range order. `finishWriters`
/// is called only after all workers join without error.
pub const Factory = struct {
    context: *anyopaque,
    prepare_writer_fn: *const fn (*anyopaque, usize, RowRange) anyerror!Writer,
    finish_writers_fn: *const fn (*anyopaque, usize) anyerror!void,

    pub fn prepareWriter(self: Factory, worker: usize, range: RowRange) !Writer {
        return self.prepare_writer_fn(self.context, worker, range);
    }

    pub fn finishWriters(self: Factory, worker_count: usize) !void {
        return self.finish_writers_fn(self.context, worker_count);
    }
};

pub const ExecutionStats = struct {
    tile_pipeline_selected: bool,
    worker_count: usize,
    tile_row_limit: usize,
    tile_count: usize,
    peak_scratch_bytes_per_worker: usize,
    total_scratch_bytes: usize,
    bounded_numerator_tile_bytes_per_worker: usize,
    complete_column_combined_intermediate_bytes: usize,
    post_compute_leaf_pass_count: usize,
};

test "quotient tile validates coordinate shape" {
    const values = [_]M31{M31.one()} ** 2;
    const short = [_]M31{M31.one()};
    try std.testing.expectEqual(@as(usize, 2), try (QuotientTile{
        .start = 3,
        .coordinates = .{ &values, &values, &values, &values },
    }).len());
    try std.testing.expectError(error.EmptyQuotientTile, (QuotientTile{
        .start = 0,
        .coordinates = .{ &.{}, &.{}, &.{}, &.{} },
    }).len());
    try std.testing.expectError(error.QuotientTileShapeMismatch, (QuotientTile{
        .start = 0,
        .coordinates = .{ &values, &values, &values, &short },
    }).len());
}
