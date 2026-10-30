//! Shared physical memory-claim algebra after proof authentication. This
//! closes providers and counts; the transition bus remains open to execution.
const std = @import("std");
const Q = @import("stwo_core").fields.qm31.QM31;
const T = @import("block_v7_memory_trace_v1.zig");
const Geometry = @import("block_v5_ram_lanes_protocol_v1.zig");
pub const RamClaim = struct { geometry: Geometry.Claim, sums: [@import("block_v7_ram_component_v1.zig").PLANES]Q };
pub const Claims = struct { ram: []const RamClaim, interval: [2]Q, range16: [2]Q, terminal: [1]Q };
pub const Open = struct { transition: Q, event_count: u64 };
pub fn close(claims: Claims) !Open {
    if (claims.ram.len == 0) return error.InvalidV7JointClaims;
    var transition = claims.terminal[0];
    var link = Q.zero();
    var initialization = claims.interval[0];
    var range = claims.range16[0];
    var first_count: u64 = 0;
    var range_count: u64 = 0;
    for (claims.ram) |item| {
        transition = transition.add(item.sums[0]);
        link = link.add(item.sums[1]);
        initialization = initialization.add(item.sums[2]);
        for (item.sums[3..27]) |sum| range = range.add(sum);
        const f = try T.natural(item.sums[27]);
        const r = try T.natural(item.sums[28]);
        if (f > item.geometry.events or r > @as(u64, item.geometry.events) * 24) return error.InvalidV7MemoryCensus;
        first_count = try std.math.add(u64, first_count, f);
        range_count = try std.math.add(u64, range_count, r);
    }
    if (!link.isZero() or !initialization.isZero() or !range.isZero() or first_count != try T.natural(claims.interval[1]) or range_count != try T.natural(claims.range16[1])) return error.UnclosedV7MemoryRelations;
    const events = claims.ram[0].geometry.total_events;
    if (events < @import("block_v7_terminal_protocol_v1.zig").READS) return error.InvalidV7MemoryCensus;
    return .{ .transition = transition, .event_count = events - @import("block_v7_terminal_protocol_v1.zig").READS };
}
