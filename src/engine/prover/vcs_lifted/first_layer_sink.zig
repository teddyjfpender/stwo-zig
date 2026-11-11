//! CPU leaf sink for quotient tiles in the first FRI commitment.

const std = @import("std");
const builtin = @import("builtin");
const m31 = @import("stwo_core").fields.m31;
const qm31 = @import("stwo_core").fields.qm31;
const work_pool = @import("../work_pool.zig");
const tile_sink = @import("../pcs/quotient_tile_sink.zig");

const M31 = m31.M31;

pub fn FirstLayerLeafSink(comptime H: type) type {
    return struct {
        layer_allocator: std.mem.Allocator,
        leaves: []H.Hash,
        writers: [work_pool.MAX_WORKERS]WriterState = undefined,
        writer_count: usize = 0,
        prepared_end: usize = 0,
        writers_finished: bool = false,

        const Self = @This();

        const WriterState = struct {
            leaves: []H.Hash,
            absolute_start: usize,
            next: usize,
            end: usize,

            fn absorbErased(context: *anyopaque, tile: tile_sink.QuotientTile) !void {
                const self: *WriterState = @ptrCast(@alignCast(context));
                const tile_len = try tile.len();
                const tile_end = std.math.add(usize, tile.start, tile_len) catch
                    return error.QuotientTileRangeOverflow;
                if (tile.start != self.next or tile_end > self.end) {
                    return error.QuotientTileRangeMismatch;
                }

                var row: usize = 0;
                if (comptime @hasDecl(H, "leafSeed") and
                    @hasDecl(H, "hashDirectM31LeavesWithSeed4"))
                {
                    const DirectColumn = struct { values: []const M31 };
                    var columns: [qm31.SECURE_EXTENSION_DEGREE]DirectColumn = undefined;
                    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                        columns[coordinate] = .{ .values = tile.coordinates[coordinate] };
                    }
                    const seed = H.leafSeed();
                    while (row + 4 <= tile_len) : (row += 4) {
                        const hashes = H.hashDirectM31LeavesWithSeed4(seed, &columns, row);
                        inline for (0..4) |lane| {
                            self.leaves[tile.start - self.absolute_start + row + lane] = hashes[lane];
                        }
                    }
                } else if (comptime @hasDecl(H, "leafSeed") and @hasDecl(H, "hashPackedLeavesWithSeed4")) {
                    const seed = H.leafSeed();
                    while (row + 4 <= tile_len) : (row += 4) {
                        var values: [4][qm31.SECURE_EXTENSION_DEGREE]M31 = undefined;
                        var packed_bytes: [4][qm31.SECURE_EXTENSION_DEGREE * @sizeOf(M31)]u8 = undefined;
                        var messages: [4][]const u8 = undefined;
                        for (0..4) |lane| {
                            inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                                values[lane][coordinate] = tile.coordinates[coordinate][row + lane];
                            }
                            if (builtin.cpu.arch.endian() == .little) {
                                messages[lane] = std.mem.sliceAsBytes(values[lane][0..]);
                            } else {
                                inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                                    const encoded = values[lane][coordinate].toBytesLe();
                                    const start = coordinate * @sizeOf(M31);
                                    @memcpy(packed_bytes[lane][start .. start + @sizeOf(M31)], encoded[0..]);
                                }
                                messages[lane] = packed_bytes[lane][0..];
                            }
                        }
                        const hashes = H.hashPackedLeavesWithSeed4(seed, &messages);
                        inline for (0..4) |lane| {
                            self.leaves[tile.start - self.absolute_start + row + lane] = hashes[lane];
                        }
                    }
                }
                while (row < tile_len) : (row += 1) {
                    var values: [qm31.SECURE_EXTENSION_DEGREE]M31 = undefined;
                    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
                        values[coordinate] = tile.coordinates[coordinate][row];
                    }
                    var hasher = H.defaultWithInitialState();
                    hasher.updateLeaf(values[0..]);
                    self.leaves[tile.start - self.absolute_start + row] = hasher.finalize();
                }
                self.next = tile_end;
            }
        };

        pub fn init(layer_allocator: std.mem.Allocator, leaf_count: usize) !Self {
            if (leaf_count == 0 or !std.math.isPowerOfTwo(leaf_count)) {
                return error.InvalidLeafCount;
            }
            return .{
                .layer_allocator = layer_allocator,
                .leaves = try layer_allocator.alloc(H.Hash, leaf_count),
            };
        }

        pub fn deinit(self: *Self) void {
            if (self.leaves.len != 0) self.layer_allocator.free(self.leaves);
            self.* = undefined;
        }

        pub fn factory(self: *Self) tile_sink.Factory {
            return .{
                .context = self,
                .prepare_writer_fn = prepareWriterErased,
                .finish_writers_fn = finishWritersErased,
            };
        }

        fn prepareWriterErased(
            context: *anyopaque,
            worker: usize,
            range: tile_sink.RowRange,
        ) !tile_sink.Writer {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.writers_finished or worker != self.writer_count or
                worker >= self.writers.len or range.start != self.prepared_end or
                range.end <= range.start or range.end > self.leaves.len)
            {
                return error.InvalidLeafWriterRange;
            }

            self.writers[worker] = .{
                .leaves = self.leaves[range.start..range.end],
                .absolute_start = range.start,
                .next = range.start,
                .end = range.end,
            };
            self.writer_count += 1;
            self.prepared_end = range.end;
            return .{
                .context = &self.writers[worker],
                .absorb_fn = WriterState.absorbErased,
            };
        }

        fn finishWritersErased(context: *anyopaque, worker_count: usize) !void {
            const self: *Self = @ptrCast(@alignCast(context));
            if (self.writers_finished or worker_count == 0 or
                worker_count != self.writer_count or self.prepared_end != self.leaves.len)
            {
                return error.IncompleteLeafLayer;
            }
            for (self.writers[0..worker_count]) |writer| {
                if (writer.next != writer.end) return error.IncompleteLeafLayer;
            }
            self.writers_finished = true;
        }

        /// Transfers the completed leaf allocation to the Merkle tree builder.
        pub fn takeLeaves(self: *Self) ![]H.Hash {
            if (!self.writers_finished) return error.IncompleteLeafLayer;
            const leaves = self.leaves;
            self.leaves = &.{};
            return leaves;
        }
    };
}

test "first layer sink enforces a complete ordered partition" {
    const H = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Sink = FirstLayerLeafSink(H);
    const allocator = std.testing.allocator;
    var sink = try Sink.init(allocator, 4);
    defer sink.deinit();
    const factory = sink.factory();

    var writer0 = try factory.prepareWriter(0, .{ .start = 0, .end = 2 });
    try std.testing.expectError(
        error.InvalidLeafWriterRange,
        factory.prepareWriter(1, .{ .start = 3, .end = 4 }),
    );
    var writer1 = try factory.prepareWriter(1, .{ .start = 2, .end = 4 });
    const values = [_]M31{ M31.fromCanonical(3), M31.fromCanonical(5) };
    try writer0.absorb(.{ .start = 0, .coordinates = .{ &values, &values, &values, &values } });
    try writer1.absorb(.{ .start = 2, .coordinates = .{ &values, &values, &values, &values } });
    try factory.finishWriters(2);

    const leaves = try sink.takeLeaves();
    defer allocator.free(leaves);
    try std.testing.expectEqual(@as(usize, 4), leaves.len);
}

test "first layer sink four-lane hashing matches scalar tails" {
    const H = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Sink = FirstLayerLeafSink(H);
    const allocator = std.testing.allocator;
    var sink = try Sink.init(allocator, 8);
    defer sink.deinit();
    const factory = sink.factory();
    var writer = try factory.prepareWriter(0, .{ .start = 0, .end = 8 });

    var values: [qm31.SECURE_EXTENSION_DEGREE][8]M31 = undefined;
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        for (0..8) |row| {
            values[coordinate][row] = M31.fromCanonical(@intCast(101 * coordinate + 7 * row + 3));
        }
    }
    var first_coordinates: [qm31.SECURE_EXTENSION_DEGREE][]const M31 = undefined;
    var final_coordinates: [qm31.SECURE_EXTENSION_DEGREE][]const M31 = undefined;
    inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
        first_coordinates[coordinate] = values[coordinate][0..7];
        final_coordinates[coordinate] = values[coordinate][7..8];
    }
    try writer.absorb(.{ .start = 0, .coordinates = first_coordinates });
    try writer.absorb(.{ .start = 7, .coordinates = final_coordinates });
    try factory.finishWriters(1);

    const leaves = try sink.takeLeaves();
    defer allocator.free(leaves);
    for (0..8) |row| {
        var row_values: [qm31.SECURE_EXTENSION_DEGREE]M31 = undefined;
        inline for (0..qm31.SECURE_EXTENSION_DEGREE) |coordinate| {
            row_values[coordinate] = values[coordinate][row];
        }
        var hasher = H.defaultWithInitialState();
        hasher.updateLeaf(row_values[0..]);
        const expected = hasher.finalize();
        try std.testing.expectEqualSlices(u8, expected[0..], leaves[row][0..]);
    }
}

test "first layer sink rejects incomplete and out of order tiles" {
    const H = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    const Sink = FirstLayerLeafSink(H);
    const allocator = std.testing.allocator;
    var sink = try Sink.init(allocator, 2);
    defer sink.deinit();
    const factory = sink.factory();
    var writer = try factory.prepareWriter(0, .{ .start = 0, .end = 2 });
    const value = [_]M31{M31.one()};
    try std.testing.expectError(error.QuotientTileRangeMismatch, writer.absorb(.{
        .start = 1,
        .coordinates = .{ &value, &value, &value, &value },
    }));
    try std.testing.expectError(error.IncompleteLeafLayer, factory.finishWriters(1));
}

fn allocateAndReleaseSink(allocator: std.mem.Allocator) !void {
    const H = @import("stwo_core").vcs_lifted.blake2_merkle.Blake2sMerkleHasher;
    var sink = try FirstLayerLeafSink(H).init(allocator, 8);
    defer sink.deinit();
}

test "first layer sink releases every failed allocation" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocateAndReleaseSink,
        .{},
    );
}
