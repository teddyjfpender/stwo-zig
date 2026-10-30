//! Finite complete/nonterminal layouts; old placement is unchanged.
pub fn ForMode(comptime window: bool) type {
    return struct {
        //! Finite original memory-provider roster in three shared commitment trees.
        //! This layout is metadata only; neither its digest nor a proposed claim is a
        //! verifier-success receipt. Original equations retain their separate domains.
        const std = @import("std");
        const core = @import("stwo_core");
        const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
        const Ram = if (window) @import("block_v7_window_ram_component_v1.zig").Spec else @import("block_v7_ram_component_v1.zig").Spec;
        const Provider = @import("block_v7_provider_component_v1.zig");
        pub const VERSION: u32 = if (window) 1 else 2;
        pub const TREE_COUNT: usize = 3;
        pub const SPLIT: u32 = 2;
        pub const Family = enum(u32) { ram, interval, range16, terminal };
        pub const Part = struct {
            family: Family,
            index: u32,
            log: u32,
            offset: [TREE_COUNT]u32,
            width: [TREE_COUNT]u32,
            claim_offset: u32,
            claim_count: u32,
        };
        pub const Limits = struct { max_shards: usize = 4096, max_columns: usize = 1 << 20, max_claims: usize = 1 << 18, max_row_log: u32 = 24 };
        pub const Layout = struct {
            allocator: std.mem.Allocator,
            parts: []Part,
            columns: [TREE_COUNT]u32,
            claims: u32,
            digest: [32]u8,
            pub fn init(a: std.mem.Allocator, ram: []const Geometry.Claim, interval_log: u32, limits: Limits) !Layout {
                if (ram.len == 0 or ram.len > limits.max_shards or interval_log < 1 or interval_log > limits.max_row_log or limits.max_row_log > 24) return error.InvalidV7JointGeometry;
                try Geometry.admitSequence(ram, ram[0].total_events);
                const parts = try a.alloc(Part, try std.math.add(usize, ram.len, if (window) 2 else 3));
                errdefer a.free(parts);
                var columns: [3]u32 = @splat(0);
                var claims: u32 = 0;
                for (ram, parts[0..ram.len], 0..) |g, *part, i| {
                    if (g.row_log < 1 or g.row_log > limits.max_row_log) return error.InvalidV7JointGeometry;
                    part.* = try append(Ram, .ram, @intCast(i), g.row_log, &columns, &claims, limits);
                }
                inline for ((if (window) [_]Provider.Kind{ .interval, .range16 } else [_]Provider.Kind{ .interval, .range16, .terminal }), 0..) |kind, i| {
                    const S = Provider.For(kind);
                    part: {
                        const log: u32 = switch (kind) {
                            .interval => interval_log,
                            .range16 => 16,
                            .terminal => 4,
                        };
                        if (log > limits.max_row_log) return error.InvalidV7JointGeometry;
                        parts[ram.len + i] = try append(S, @field(Family, @tagName(kind)), 0, log, &columns, &claims, limits);
                        break :part;
                    }
                }
                var ch = core.channel.blake3.Channel{};
                ch.mixU32s(&.{ if (window) @as(u32, 0x4237574c) else @as(u32, 0x42374a4c), VERSION, TREE_COUNT, SPLIT, @intCast(ram.len) });
                ch.mixU32s(&columns);
                ch.mixU32s(&.{claims});
                for (ram) |g| g.mix(&ch);
                for (parts) |part| {
                    ch.mixU32s(&.{ @intFromEnum(part.family), part.index, part.log, part.claim_offset, part.claim_count });
                    ch.mixU32s(&part.offset);
                    ch.mixU32s(&part.width);
                }
                return .{ .allocator = a, .parts = parts, .columns = columns, .claims = claims, .digest = ch.digestBytes() };
            }
            pub fn deinit(self: *Layout) void {
                self.allocator.free(self.parts);
                self.* = undefined;
            }
            pub fn logs(self: Layout, a: std.mem.Allocator, tree: usize) ![]u32 {
                if (tree >= TREE_COUNT) return error.InvalidV7JointTree;
                const result = try a.alloc(u32, self.columns[tree]);
                errdefer a.free(result);
                var at: usize = 0;
                for (self.parts) |part| {
                    if (part.offset[tree] != at or part.width[tree] > result.len - at) return error.InvalidV7JointPlacement;
                    @memset(result[at..][0..part.width[tree]], part.log);
                    at += part.width[tree];
                }
                if (at != result.len) return error.InvalidV7JointPlacement;
                return result;
            }
        };
        fn append(comptime S: type, family: Family, index: u32, log: u32, columns: *[3]u32, claims: *u32, limits: Limits) !Part {
            comptime std.debug.assert(S.EXPANSION_BITS == SPLIT);
            const widths = [3]u32{ S.FIXED_COUNT, S.MAIN_COUNT, S.INTERACTION_COUNT };
            const part = Part{ .family = family, .index = index, .log = log, .offset = columns.*, .width = widths, .claim_offset = claims.*, .claim_count = (S.INTERACTION_COUNT / 4) };
            for (columns, widths) |*count, width| {
                count.* = try std.math.add(u32, count.*, width);
                if (count.* > limits.max_columns) return error.V7JointColumnLimit;
            }
            claims.* = try std.math.add(u32, claims.*, (S.INTERACTION_COUNT / 4));
            if (claims.* > limits.max_claims) return error.V7JointClaimLimit;
            return part;
        }
    };
}
