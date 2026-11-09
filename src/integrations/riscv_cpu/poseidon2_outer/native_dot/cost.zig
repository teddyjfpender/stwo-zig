//! Source-fed geometry model only, not an implemented new circuit roster.
//! QM31 widths are the actual OM31-field P2 values (12/8/16), not the
//! legacy QM31-field circuit evaluator's 8 interaction columns.
const std = @import("std");
const KeyAuthority = @import("../native_omul/authority.zig");
const Native = @import("../native_omul/census.zig");
const Layout = @import("../layout.zig");
const Row = @import("row.zig");
pub const Input = struct {
    original_raw: [6]u64,
    numerator_qm31_rows: u64,
    terms: u64,
    empty_dots: u64 = 0,
};
pub const Cost = struct {
    original: Native.Census,
    remaining_generic: Native.Census,
    dot_rows: usize,
    dot_log: u32,
    dot_main_cells: u64,
    dot_fixed_cells: u64,
    dot_interaction_cells: u64,
    candidate_main_cells: u64,
    candidate_fixed_cells: u64,
    candidate_interaction_cells: u64,
    candidate_total_native_cells: u64,
    native_cells_saved: u64,
    main_interaction_cells_saved: u64,
    new_main_opening_masks: usize = Row.MAIN + 8,
    new_interaction_opening_masks: usize = Row.INTER + 8,
    new_fixed_columns: usize = Row.FIXED,
    new_main_interaction_width: usize = Row.MAIN + Row.INTER,
    original_key_tree_widths: [3]usize = .{ KeyAuthority.FIXED_COUNT, KeyAuthority.MAIN_COUNT, KeyAuthority.INTER_COUNT },
    candidate_key_tree_widths: [3]usize = .{ KeyAuthority.FIXED_COUNT + Row.FIXED, KeyAuthority.MAIN_COUNT + Row.MAIN, KeyAuthority.INTER_COUNT + Row.INTER },
    original_max_log: u32,
    candidate_max_log: u32,
    promoted_or_measured_prover_speedup: bool = false,
};
pub fn derive(input: Input) !Cost {
    if (input.numerator_qm31_rows > input.original_raw[1]) return error.NativeDotRemovalExceedsSource;
    const before = try Native.derive(input.original_raw[0..5].*, std.math.cast(usize, input.original_raw[5]) orelse return error.NativeDotCostOverflow);
    var raw = input.original_raw[0..5].*;
    raw[1] -= input.numerator_qm31_rows;
    const after = try Native.derive(raw, std.math.cast(usize, input.original_raw[5]) orelse return error.NativeDotCostOverflow);
    const dot_raw = try std.math.add(u64, input.terms, input.empty_dots);
    const rows = try std.math.ceilPowerOfTwo(usize, @max(16, std.math.cast(usize, dot_raw) orelse return error.NativeDotCostOverflow));
    const main = try std.math.mul(u64, rows, Row.MAIN);
    const fixed = try std.math.mul(u64, rows, Row.FIXED);
    const inter = try std.math.mul(u64, rows, Row.INTER);
    const main_cells = try std.math.add(u64, after.main_cells, main);
    const fixed_cells = try std.math.add(u64, after.fixed_cells, fixed);
    const inter_cells = try std.math.add(u64, after.interaction_cells, inter);
    const total = try std.math.add(u64, main_cells, try std.math.add(u64, fixed_cells, inter_cells));
    const old_main_inter = try std.math.add(u64, before.main_cells, before.interaction_cells);
    const new_main_inter = try std.math.add(u64, main_cells, inter_cells);
    if (total > before.total_native_cells or new_main_inter > old_main_inter) return error.NativeDotPaddingRegression;
    var original_max: u32 = 0;
    var candidate_max: u32 = @intCast(std.math.log2_int(usize, rows));
    for (before.logs, after.logs) |old_log, new_log| {
        original_max = @max(original_max, old_log);
        candidate_max = @max(candidate_max, new_log);
    }
    return .{ .original_max_log = original_max, .candidate_max_log = candidate_max, .original = before, .remaining_generic = after, .dot_rows = rows, .dot_log = @intCast(std.math.log2_int(usize, rows)), .dot_main_cells = main, .dot_fixed_cells = fixed, .dot_interaction_cells = inter, .candidate_main_cells = main_cells, .candidate_fixed_cells = fixed_cells, .candidate_interaction_cells = inter_cells, .candidate_total_native_cells = total, .native_cells_saved = before.total_native_cells - total, .main_interaction_cells_saved = old_main_inter - new_main_inter };
}
test "OP native dot isolated source fed costs use actual OM31 widths and observed rows" {
    try std.testing.expectEqual(@as(u32, 16), Layout.FACTS[1].classic_interaction);
    const c = try derive(.{ .original_raw = .{ 36418, 4809612, 2522, 80066, 65536, 174158 }, .numerator_qm31_rows = 2259648, .terms = 566208 });
    try std.testing.expectEqual(@as(u32, 23), c.original.logs[1]);
    try std.testing.expectEqual(@as(u32, 22), c.remaining_generic.logs[1]);
    try std.testing.expectEqual(@as(u32, 20), c.dot_log);
    try std.testing.expectEqual(@as(u64, 415756288), c.original.total_native_cells);
    try std.testing.expectEqual(@as(u64, 318238720), c.candidate_total_native_cells);
    try std.testing.expectEqual(@as(u64, 97517568), c.native_cells_saved);
    try std.testing.expectEqual(@as(usize, 57), c.new_main_opening_masks + c.new_interaction_opening_masks);
}

test "OP native dot isolated cost report uses pinned source-only counter results" {
    const output = std.posix.getenv("STWO_OP_DOT_COST_OUTPUT") orelse return error.SkipZigTest;
    const Record = struct { ordinal: usize, observed_qm31_rows: u64, terms: u64, cost: Cost };
    const rows = [_]Record{
        .{ .ordinal = 3, .observed_qm31_rows = 2259648, .terms = 566208, .cost = try derive(.{ .original_raw = .{ 36418, 4809612, 2522, 80066, 65536, 174158 }, .numerator_qm31_rows = 2259648, .terms = 566208 }) },
        .{ .ordinal = 20, .observed_qm31_rows = 2104704, .terms = 527184, .cost = try derive(.{ .original_raw = .{ 35736, 4554842, 2474, 76886, 65536, 167853 }, .numerator_qm31_rows = 2104704, .terms = 527184 }) },
    };
    const bytes = try std.json.Stringify.valueAlloc(std.testing.allocator, rows, .{ .whitespace = .indent_2 });
    defer std.testing.allocator.free(bytes);
    var file = try std.fs.cwd().createFile(output, .{});
    defer file.close();
    try file.writeAll(bytes);
}
