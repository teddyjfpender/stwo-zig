//! One range16/byte-pair census for independently fixed endpoint prefixes.
//! Positive bounded request multiplicities may share the canonical provider;
//! per-cohort CPU/register/RAM closure is not aggregated by this helper.
const std = @import("std");
const Range = @import("block_v8_endpoint_range_provider_v1.zig");
const T = @import("block_v7_memory_trace_v1.zig");
pub const Owned = Range.Owned;
pub const production_active = false;
pub fn init(a: std.mem.Allocator, matrices: []const T.Matrix, counts: []const u32, limits: Range.Limits) !Owned {
    return initForProfile(a, matrices, counts, limits, .compact_v1);
}
pub fn initForProfile(a: std.mem.Allocator, matrices: []const T.Matrix, counts: []const u32, limits: Range.Limits, profile: @import("block_v8_endpoint_group_layout_v1.zig").Profile) !Owned {
    if (matrices.len == 0 or matrices.len != counts.len or matrices.len > @import("block_v8_endpoint_group_layout_v1.zig").maxMembers(profile)) return error.InvalidEndpointGroupRanges;
    var total: u64 = 0;
    for (counts) |count| total = try std.math.add(u64, total, count);
    const request = try Range.requests(total);
    if (request.endpoints > limits.max_endpoints) return error.EndpointRangeResourceLimit;
    var merged = try Owned.init(a, matrices[0], counts[0], limits);
    errdefer merged.deinit();
    if (matrices.len > 1 and try std.math.add(usize, merged.owned_bytes, merged.construction_peak_bytes) > limits.max_live_bytes) return error.EndpointRangeResourceLimit;
    for (matrices[1..], counts[1..]) |matrix, count| {
        var current = try Owned.init(a, matrix, count, limits);
        defer current.deinit();
        for (@constCast(merged.range16.columns[2].values), current.range16.columns[2].values) |*value, addend| value.* = value.add(addend);
        for (merged.byte_counter.values, current.byte_counter.values) |*value, addend| value.* = value.add(addend);
        merged.construction_peak_bytes = @max(merged.construction_peak_bytes, try std.math.add(usize, merged.owned_bytes, current.construction_peak_bytes));
    }
    merged.counts = request;
    return merged;
}
