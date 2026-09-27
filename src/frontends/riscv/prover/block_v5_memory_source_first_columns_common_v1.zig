//! Shared typed source-page owner kernel. The schema independently selects
//! exact census/grammar/codec; no shape relabeling or proof authority is added.
const std = @import("std");
const core = @import("stwo_core");
const Placement = @import("../air/block/memory_component_trace.zig");

pub fn ForSchema(comptime Schema: type) type {
    return struct {
        //! Real prechallenge source witness cells, one canonical chunk per row.
        //! Fixed and main arrays are column-major in canonical physical circle order.
        //! They are witnesses/commitment inputs, never a source-verification receipt.
        const M = core.fields.m31.M31;
        const First = Schema.Protocol;
        const Source = Schema.Source;
        const Stream = Schema.Stream;
        const Eq = Schema.Equations;
        pub const FIXED = struct {
            pub const active = 0;
            pub const physical_ordinal = 1; // four LE16 limbs
            pub const kind = 5;
            pub const stream_or_edit = 6;
            pub const local_ordinal = 7; // four LE16 limbs
            pub const height = 11;
            pub const first = 12;
            pub const last = 13;
            pub const domain_last = 14;
        };
        pub const writeBits = Schema.writeBits;
        pub fn fixedAt(admitted: *const Source.Admitted, page: First.Page, logical: usize) ![First.FIXED_COUNT]M {
            return Schema.fixedAt(admitted, page, logical);
        }
        pub const Columns = struct {
            allocator: std.mem.Allocator,
            page: First.Page,
            fixed: []M,
            main: []M,
            written: u32 = 0,
            // Plain independently admitted metadata, never an image/file owner.
            compact_admission: if (@hasDecl(Schema, "CompactCodec")) Source.Admitted else void,
            pub fn init(a: std.mem.Allocator, admitted: *const Source.Admitted, plan: First.Plan, page: First.Page, limits: First.Limits) !Columns {
                try plan.require(admitted, limits);
                if (!std.meta.eql(page, try plan.page(page.index))) return error.InvalidSourceFirstPage;
                const row_count = @as(usize, 1) << @intCast(page.row_log);
                const fixed = try a.alloc(M, try std.math.mul(usize, row_count, First.FIXED_COUNT));
                errdefer a.free(fixed);
                const main = try a.alloc(M, try std.math.mul(usize, row_count, First.MAIN_COUNT));
                errdefer a.free(main);
                @memset(main, M.zero());
                for (0..row_count) |logical| {
                    const physical = Placement.committedRow(logical, page.row_log);
                    const values = try fixedAt(admitted, page, logical);
                    for (values, 0..) |v, column| fixed[column * row_count + physical] = v;
                }
                return .{ .allocator = a, .page = page, .fixed = fixed, .main = main, .compact_admission = if (@hasDecl(Schema, "CompactCodec")) admitted.* else {} };
            }
            pub fn deinit(self: *Columns) void {
                self.allocator.free(self.main);
                self.allocator.free(self.fixed);
                self.* = undefined;
            }
            pub fn rows(self: *const Columns) usize {
                return @as(usize, 1) << @intCast(self.page.row_log);
            }
            pub fn fixedColumn(self: *const Columns, column: usize) []const M {
                return self.fixed[column * self.rows() ..][0..self.rows()];
            }
            pub fn mainColumn(self: *const Columns, column: usize) []const M {
                return self.main[column * self.rows() ..][0..self.rows()];
            }
            pub fn append(self: *Columns, admitted: *const Source.Admitted, chunk: Stream.Chunk) !void {
                if (self.written >= self.page.chunks or !std.meta.eql(chunk.kind, try Stream.kindAt(admitted, self.page.first_chunk + self.written))) return error.UntrustedSourceFirstChunk;
                var bits: [First.MAIN_COUNT]M = undefined;
                writeBits(chunk.witness, &bits);
                const physical = Placement.committedRow(self.written, self.page.row_log);
                for (bits, 0..) |v, column| self.main[column * self.rows() + physical] = v;
                self.written += 1;
            }
            pub fn witness(self: *const Columns, logical: u32) !Eq.Witness {
                if (self.written != self.page.chunks or logical >= self.page.chunks) return error.InvalidSourceFirstRow;
                const physical = Placement.committedRow(logical, self.page.row_log);
                var bits: [First.MAIN_COUNT]M = undefined;
                for (&bits, 0..) |*v, column| v.* = self.main[column * self.rows() + physical];
                return Schema.restoreBits(&bits);
            }
            /// Local immutability guard only. This digest NEVER grants proof authority;
            /// genuine proof input routing must use the actual retained PCS main tree.
            pub fn snapshot(self: *const Columns) [32]u8 {
                var hash = std.crypto.hash.sha2.Sha256.init(.{});
                hash.update("source-first-private-cells/guard/v1\x00");
                for ([_][]const M{ self.fixed, self.main }) |cells| for (cells) |v| {
                    var bytes: [4]u8 = undefined;
                    std.mem.writeInt(u32, &bytes, v.toU32(), .little);
                    hash.update(&bytes);
                };
                return hash.finalResult();
            }
        };
    };
}
