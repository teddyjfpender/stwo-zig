//! Production global_stage allocation envelope. Existing MAIN/FIXED owners
//! are observed by the physical endpoint; this lists only additional growth.
//! Every optional immutable miss is conservatively charged as a separate cold
//! allocation. This is a GPU bound and does not certify host preparation/RSS.
const std = @import("std");
const A = @import("global_admission.zig");
const Prefix = @import("prefix_plan.zig");
pub const Input = struct {
    log: u32,
    fixed_columns: usize,
    main_columns: usize,
    host_fixed_columns: usize,
    parameters: usize,
    pairs: usize,
    groups: usize,
};
pub const Plan = struct {
    temporary: A.Footprint,
    output: A.Footprint,
    /// Output, cached forward twiddle, and every cold FIXED column surviving join.
    retained: A.Footprint,
    /// source, parameters, output, numerators, scan/claims/status, twiddle,
    /// then one possible immutable upload per nonresident FIXED column.
    allocation_count: usize,
};
fn mul(a: u64, b: u64) !u64 {
    return std.math.mul(u64, a, b);
}
pub fn init(input: Input) !Plan {
    if (input.log < 5 or input.log > 27 or input.fixed_columns == 0 or input.main_columns == 0 or input.host_fixed_columns > input.fixed_columns or input.parameters == 0 or input.parameters > 65536 or input.pairs == 0 or input.pairs > 1280 or input.groups == 0 or input.groups > 2) return error.InvalidNativeInteractionCost;
    const rows = @as(u64, 1) << @intCast(input.log);
    const scan = try Prefix.Plan.init(input.log);
    const columns = try std.math.add(u64, input.fixed_columns, input.main_columns);
    const output = try mul(try mul(8, try std.math.add(u64, input.pairs, input.groups)), rows);
    const sizes = [_]u64{
        try mul(try mul(columns, rows), 4),
        try mul(input.parameters, 32),
        try mul(output, 4),
        try mul(try mul(try mul(input.pairs, 8), rows), 4),
        try mul(try std.math.add(u64, scan.scratch_words, try std.math.add(u64, try mul(input.groups, 8), 1)), 4),
        // precomputeM31's forward tower is root_coset.size() = rows/2.
        try mul(rows / 2, 4),
    };
    var temporary = try A.Footprint.allocations(sizes);
    const fixed_upload = try A.Footprint.allocation(try mul(rows, 4));
    // Job.run obtains this tower through service.immutableWords, not a
    // temporary lease. It survives even when all FIXED columns are warm.
    var retained = try (try A.Footprint.allocation(try mul(output, 4))).add(try A.Footprint.allocation(sizes[5]));
    for (0..input.host_fixed_columns) |_| {
        temporary = try temporary.add(fixed_upload);
        retained = try retained.add(fixed_upload);
    }
    return .{ .temporary = temporary, .output = try A.Footprint.allocation(try mul(output, 4)), .retained = retained, .allocation_count = sizes.len + input.host_fixed_columns };
}
test "native interaction separately rounds every possible immutable FIXED miss" {
    const input = Input{ .log = 18, .fixed_columns = 3, .main_columns = 5, .host_fixed_columns = 3, .parameters = 7, .pairs = 2, .groups = 1 };
    const cold = try init(input);
    var warm_input = input;
    warm_input.host_fixed_columns = 0;
    const warm = try init(warm_input);
    const each = try A.Footprint.allocation((@as(u64, 1) << 18) * 4);
    try std.testing.expectEqual(try warm.temporary.add(try each.add(try each.add(each))), cold.temporary);
    try std.testing.expectEqual(@as(usize, 9), cold.allocation_count);
    try std.testing.expectEqual(@as(usize, 6), warm.allocation_count);
    try std.testing.expectEqual(cold.output, warm.output);
    try std.testing.expectEqual(try warm.output.add(try A.Footprint.allocation((@as(u64, 1) << 17) * 4)), warm.retained);
    try std.testing.expectEqual(try warm.retained.add(try each.add(try each.add(each))), cold.retained);
}
test "native interaction rejects unsupported geometry and arithmetic overflow" {
    var input = Input{ .log = 18, .fixed_columns = 1, .main_columns = 1, .host_fixed_columns = 1, .parameters = 1, .pairs = 1, .groups = 1 };
    input.log = 28;
    try std.testing.expectError(error.InvalidNativeInteractionCost, init(input));
    input.log = 18;
    input.main_columns = std.math.maxInt(usize);
    try std.testing.expectError(error.Overflow, init(input));
}

test "CPU log20 global interaction retains cold two-MiB forward twiddle" {
    const p = try init(.{ .log = 20, .fixed_columns = 3, .main_columns = 37, .host_fixed_columns = 3, .parameters = 7, .pairs = 2, .groups = 1 });
    // Output and each four-MiB FIXED plane consume large buckets. The cached
    // rows/2 forward twiddle is the otherwise-missing surviving small lease.
    try std.testing.expectEqual(@as(u64, 0), p.output.small);
    try std.testing.expectEqual(@as(u64, 2 << 20), p.retained.small);
    try std.testing.expect(p.temporary.contains(p.retained));
}
