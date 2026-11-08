//! Allocation/lifetime envelope of the production gkr_stage adapter, including
//! the original fraction planes kept by device_binding_runtime. This does not
//! describe the distinct, experimental native_gkr_stage implementation.
const std = @import("std");
const A = @import("global_admission.zig");
const Prefix = @import("prefix_plan.zig");
pub const Item = struct { facts: u64, offsets: u64, public: u64, parameters: u64 };
pub const Input = struct {
    cells: u64,
    twiddles: u64,
    workspace: u64,
    relation_count: u32,
    items: []const Item,
    publish_coefficients: bool,
    binding_state_words: u64,
    /// FixedProvider may allocate one concatenated immutable forest on a miss.
    cold_fixed_words: u64 = 0,
};
pub const Plan = struct { projection: A.Footprint, traversal: A.Footprint, peak: A.Footprint, retained: A.Footprint };
pub const Binding = struct { project: A.Footprint, finalize: A.Footprint, park: A.Footprint, projection_owner: A.Footprint, coefficient_owner: A.Footprint };
fn words(n: u64) !A.Footprint {
    if (n == 0) return error.InvalidNativeGkrAllocation;
    return A.Footprint.allocation(try std.math.mul(u64, n, 4));
}
pub fn init(input: Input) !Plan {
    if (input.cells == 0 or input.twiddles == 0 or input.items.len == 0 or input.items.len > 128 or input.relation_count == 0 or input.relation_count > 31) return error.InvalidNativeGkrAllocation;
    var common: A.Footprint = .{};
    for ([_]u64{ 9, 16, 16, 310 * 8, 1, 3 + 2 * @as(u64, input.relation_count) }) |n| common = try common.add(try words(n));
    var fractions: A.Footprint = .{};
    for (input.items) |item| {
        for ([_]u64{ try std.math.mul(u64, item.offsets, 2), item.public, try std.math.mul(u64, item.parameters, 8) }) |n| common = try common.add(try words(n));
        const numerator = try words(item.facts);
        const denominator = try words(try std.math.mul(u64, item.facts, 8));
        fractions = try fractions.add(try numerator.add(denominator));
    }
    var retained: A.Footprint = .{};
    if (input.cold_fixed_words != 0) retained = try retained.add(try words(input.cold_fixed_words));
    if (input.publish_coefficients) retained = try retained.add(try words(input.cells));
    const projected = try retained.add(try common.add(fractions));
    // Decoded MAIN/FIXED and twiddles are joined/freed before workspace.
    const projection = try projected.add(try (try words(input.cells)).add(try words(input.twiddles)));
    var traversal = projected;
    if (input.workspace != 0) traversal = try traversal.add(try words(input.workspace));
    if (input.binding_state_words != 0) {
        const state = try words(input.binding_state_words);
        traversal = try traversal.add(state);
        retained = try retained.add(try fractions.add(state));
    }
    return .{ .projection = projection, .traversal = traversal, .peak = projection.max(traversal), .retained = retained };
}
/// Additional allocations of Call.project/finalize and park. Original
/// fractions, saved state and an existing projection are in the live snapshot.
pub fn binding(rows: u64, max_log: u32) !Binding {
    if (max_log < 1 or max_log > 27 or rows < @as(u64, 1) << @intCast(max_log)) return error.InvalidNativeGkrAllocation;
    const projection = try words(try std.math.mul(u64, rows, 8));
    const coefficients = try words(try std.math.mul(u64, rows, 16));
    const metadata = try A.Footprint.allocations([_]u64{ 260 * 8 * 4, 22 * 8 * 4, 22 * 16 * 4, 9 * 4, 4 });
    const prefix = try Prefix.Plan.init(max_log);
    const fft_scan = try A.Footprint.allocations([_]u64{ (@as(u64, 1) << @intCast(max_log - 1)) * 4, try std.math.mul(u64, prefix.scratch_words, 4), 8 * 4 });
    const tree_words = try std.math.mul(u64, (@as(u64, 2) << @intCast(max_log)) - 1, 8);
    return .{ .project = try metadata.add(projection), .finalize = try (try metadata.add(coefficients)).add(fft_scan), .park = try words(tree_words), .projection_owner = projection, .coefficient_owner = coefficients };
}
test "production GKR rounds planes separately and retires decoded columns before tree" {
    const input = Input{ .cells = 1 << 20, .twiddles = 1 << 17, .workspace = 1 << 24, .relation_count = 10, .items = &.{.{ .facts = 1 << 19, .offsets = 12, .public = 304, .parameters = 15 }}, .publish_coefficients = false, .binding_state_words = 2580, .cold_fixed_words = 1 << 18 };
    const p = try init(input);
    const decoded = try (try words(input.cells)).add(try words(input.twiddles));
    const workspace = try (try words(input.workspace)).add(try words(input.binding_state_words));
    try std.testing.expectEqual(p.projection.large - decoded.large + workspace.large, p.traversal.large);
    try std.testing.expectEqual(p.projection.small - decoded.small + workspace.small, p.traversal.small);
    // Arena classes have independent peaks: decoded twiddles raise the small
    // peak during projection while the traversal workspace raises large.
    try std.testing.expectEqual(p.traversal.large, p.peak.large);
    try std.testing.expectEqual(p.projection.small, p.peak.small);
    var replay = input;
    replay.workspace = 0;
    replay.binding_state_words = 0; // Existing saved state is in endpoint snapshot.
    const r = try init(replay);
    try std.testing.expectEqual(r.projection, r.peak);
}
test "production GKR refuses zero-sized ABI allocations and overflow" {
    var input = Input{ .cells = 32, .twiddles = 16, .workspace = 64, .relation_count = 10, .items = &.{.{ .facts = 32, .offsets = 0, .public = 304, .parameters = 15 }}, .publish_coefficients = false, .binding_state_words = 0 };
    try std.testing.expectError(error.InvalidNativeGkrAllocation, init(input));
    input.items = &.{.{ .facts = std.math.maxInt(u64), .offsets = 1, .public = 304, .parameters = 15 }};
    try std.testing.expectError(error.Overflow, init(input));
}
