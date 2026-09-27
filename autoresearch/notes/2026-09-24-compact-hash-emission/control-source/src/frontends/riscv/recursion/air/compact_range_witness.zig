//! Direct final-layout witness for experimental compact range providers.
//! Owns all output storage; source counters remain unchanged on every error.
const std = @import("std");
const core = @import("stwo_core");
const schema = @import("../../air/lookups/tables/schema.zig");
const counters = @import("../../air/lookups/tables/counter.zig");
const provider = @import("compact_range_provider.zig");
const M = core.fields.m31.M31;
const geometry = @import("compact_range_geometry.zig");
pub fn Owner(comptime kind: schema.Kind) type {
    const Air = provider.Provider(kind);
    return struct {
        allocator: std.mem.Allocator,
        storage: []M,
        columns: [Air.PHYSICAL_MAIN_COLUMN_COUNT][]M,
        byte_counts: []M,
        n_rows: usize,
        log_size: u32,
        pub fn deinit(self: *@This()) void {
            self.allocator.free(self.storage);
            self.allocator.free(self.byte_counts);
            self.* = undefined;
        }
        pub fn init(a: std.mem.Allocator, counter: *const counters.Counter) !@This() {
            return initShape(a, counter, null);
        }
        pub fn initAdmitted(a: std.mem.Allocator, counter: *const counters.Counter, plan: geometry.Plan, expected: [32]u8) !@This() {
            try plan.admit(expected);
            return initShape(a, counter, plan.shapes[try geometry.kindIndex(kind)]);
        }
        fn initShape(a: std.mem.Allocator, counter: *const counters.Counter, admitted: ?geometry.Shape) !@This() {
            if (counter.kind != kind or counter.values.len != schema.size(kind)) return error.InvalidTraceShape;
            var n_rows: usize = 0;
            for (counter.values) |value| {
                if (!value.isZero()) n_rows += 1;
            }
            // Match the packed AIR minimum while keeping empty-provider padding valid.
            const shape = try geometry.Shape.canonical(kind, n_rows);
            if (admitted) |expected| {
                if (!std.meta.eql(shape, expected)) return error.CompactRangeWitnessGeometryMismatch;
            }
            const log = shape.log_size;
            const size = @as(usize, 1) << @intCast(log);
            const storage = try a.alloc(M, try std.math.mul(usize, size, Air.PHYSICAL_MAIN_COLUMN_COUNT));
            errdefer a.free(storage);
            @memset(storage, M.zero());
            const byte_counts = try a.alloc(M, schema.size(.range_check_8_8));
            errdefer a.free(byte_counts);
            @memset(byte_counts, M.zero());
            var self = @This(){ .allocator = a, .storage = storage, .columns = undefined, .byte_counts = byte_counts, .n_rows = n_rows, .log_size = log };
            for (&self.columns, 0..) |*column, i| column.* = storage[i * size ..][0..size];
            var logical: usize = 0;
            for (counter.values, 0..) |multiplicity, table_row| {
                if (multiplicity.isZero()) continue;
                const tuple = try schema.tupleAt(kind, table_row);
                const row = try Air.logicalRow(tuple.slice(), multiplicity);
                const dst = core.utils.bitReverseIndex(core.utils.cosetIndexToCircleDomainIndex(logical, log), log);
                for (self.columns, row) |column, value| column[dst] = value;
                const lo = row[if (kind == .range_check_20) 1 else 0].toU32();
                const hi = row[if (kind == .range_check_20 or kind == .range_check_8_11) 2 else 1].toU32();
                const byte_index = lo | (hi << 8);
                byte_counts[byte_index] = byte_counts[byte_index].sub(M.one());
                logical += 1;
            }
            std.debug.assert(logical == n_rows);
            byte_counts[0] = byte_counts[0].sub(M.fromCanonical(@intCast(size - n_rows)));
            return self;
        }
    };
}
