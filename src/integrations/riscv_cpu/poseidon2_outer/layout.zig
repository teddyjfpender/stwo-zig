//! New named Poseidon2 circuit roster. These constants do not change M6.
const std = @import("std");
const Core = @import("stwo_core");
const M = Core.fields.m31.M31;
pub const WIDTH = 24;
pub const SBOXES = 8 * WIDTH + 22;
pub const INPUT = 0;
pub const TEMPORARY = INPUT + WIDTH;
pub const OUTPUT = TEMPORARY + 2 * SBOXES;
pub const MAIN_COLUMNS = OUTPUT + WIDTH; // 476
pub const INPUT_ID = 0;
pub const OUTPUT_ID = INPUT_ID + WIDTH;
pub const OUTPUT_USES = OUTPUT_ID + WIDTH;
pub const ENABLED = OUTPUT_USES + WIDTH;
pub const FIXED_COLUMNS = ENABLED + 1; // 73
pub const CONSTRAINTS = 2 * SBOXES + WIDTH; // 452, degree <=3
pub const PORTS = 2 * WIDTH;
pub const MAX_DEGREE = 3;
pub const CLASSIC_INTERACTION_COLUMNS = PORTS / 2 * 8; // 192 M31
pub const GKR_INTERACTION_COLUMNS = 16;
pub const Row = [MAIN_COLUMNS]M;
pub const Fixed = [FIXED_COLUMNS]M;
pub const Gate = struct { inputs: [WIDTH]u32, outputs: [WIDTH]u32 };
/// Source-owned whole-circuit usage census. A proof/witness cannot supply it.
pub const SourceUsage = struct { counts: []const u32, max_per_wire: u32, max_total: u64 };
pub const ValidatedUsage = struct { source: SourceUsage };
pub fn validateUsage(usage: SourceUsage) !ValidatedUsage {
    if (usage.counts.len == 0 or usage.counts.len >= Core.fields.m31.Modulus or usage.max_per_wire >= Core.fields.m31.Modulus or usage.max_total >= Core.fields.m31.Modulus) return error.InvalidPoseidonSourceUsage;
    var total: u64 = 0;
    for (usage.counts) |count| {
        if (count > usage.max_per_wire) return error.InvalidPoseidonSourceUsage;
        total = try std.math.add(u64, total, count);
    }
    if (total > usage.max_total) return error.InvalidPoseidonSourceUsage;
    return .{ .source = usage };
}
pub fn fixedFor(gate: Gate, usage: SourceUsage) !Fixed {
    return fixedForValidated(gate, try validateUsage(usage));
}
/// Only a source-validated whole-graph usage census may enter this O(ports) path.
pub fn fixedForValidated(gate: Gate, checked: ValidatedUsage) !Fixed {
    const usage = checked.source;
    var out: Fixed = @splat(M.zero());
    for (gate.inputs, gate.outputs, 0..) |input, output, i| {
        if (input >= usage.counts.len or output == 0 or output >= usage.counts.len) return error.InvalidPoseidonPortAddress;
        for (gate.outputs[0..i]) |previous| if (previous == output) return error.AliasedPoseidonOutput;
        out[INPUT_ID + i] = M.fromCanonical(input);
        out[OUTPUT_ID + i] = M.fromCanonical(output);
        out[OUTPUT_USES + i] = M.fromCanonical(usage.counts[output]);
    }
    out[ENABLED] = M.one();
    return out;
}
pub fn paddingFixed() Fixed {
    return @splat(M.zero());
}

pub const Component = enum(u8) { eq, qm31_ops, m31_to_u32, poseidon2_m31_w24, range_check_16 };
pub const COMPONENTS = 5;
pub const Facts = struct { main: u32, fixed: u32, classic_interaction: u32, degree: u32 };
pub const FACTS = [COMPONENTS]Facts{
    .{ .main = 4, .fixed = 2, .classic_interaction = 8, .degree = 2 },
    .{ .main = 12, .fixed = 8, .classic_interaction = 16, .degree = 3 },
    .{ .main = 4, .fixed = 3, .classic_interaction = 24, .degree = 3 },
    .{ .main = MAIN_COLUMNS, .fixed = FIXED_COLUMNS, .classic_interaction = CLASSIC_INTERACTION_COLUMNS, .degree = MAX_DEGREE },
    .{ .main = 1, .fixed = 1, .classic_interaction = 8, .degree = 2 },
};
pub const Census = struct { rows: [COMPONENTS]u64, main_cells: u64, fixed_cells: u64, interaction_cells: u64, total_trace_cells: u64, poseidon_hybrid: bool, production_qualified: bool = false };
/// Concrete source count/padding model, not a physical allocation estimate.
/// The sequence table is charged at all2^16 rows; no XOR tables survive.
pub fn census(raw: [COMPONENTS]u64, poseidon_hybrid: bool) !Census {
    var out = Census{ .rows = undefined, .main_cells = 0, .fixed_cells = 0, .interaction_cells = 0, .total_trace_cells = 0, .poseidon_hybrid = poseidon_hybrid };
    for (raw, FACTS, 0..) |count, fact, i| {
        const rows = if (i == @intFromEnum(Component.range_check_16)) @max(@as(u64, 1) << 16, try std.math.ceilPowerOfTwo(u64, @max(16, count))) else try std.math.ceilPowerOfTwo(u64, @max(16, count));
        out.rows[i] = rows;
        out.main_cells = try std.math.add(u64, out.main_cells, try std.math.mul(u64, rows, fact.main));
        out.fixed_cells = try std.math.add(u64, out.fixed_cells, try std.math.mul(u64, rows, fact.fixed));
        const inter = if (poseidon_hybrid and i == @intFromEnum(Component.poseidon2_m31_w24)) GKR_INTERACTION_COLUMNS else fact.classic_interaction;
        out.interaction_cells = try std.math.add(u64, out.interaction_cells, try std.math.mul(u64, rows, inter));
    }
    out.total_trace_cells = try std.math.add(u64, out.main_cells, try std.math.add(u64, out.fixed_cells, out.interaction_cells));
    return out;
}
test "new Poseidon roster pins degree3 geometry and source-owned fanout" {
    try std.testing.expectEqual(@as(usize, 476), MAIN_COLUMNS);
    try std.testing.expectEqual(@as(usize, 73), FIXED_COLUMNS);
    var uses: [64]u32 = @splat(1);
    var gate: Gate = undefined;
    for (&gate.inputs, &gate.outputs, 0..) |*input, *output, i| {
        input.* = @intCast(i);
        output.* = @intCast(24 + i);
    }
    const fixed = try fixedFor(gate, .{ .counts = &uses, .max_per_wire = 2, .max_total = 128 });
    try std.testing.expectEqual(@as(u32, 1), fixed[ENABLED].v);
    uses[33] = 3;
    try std.testing.expectError(error.InvalidPoseidonSourceUsage, fixedFor(gate, .{ .counts = &uses, .max_per_wire = 2, .max_total = 128 }));
    const c = try census(.{ 0, 0, 0, 40, 0 }, true);
    try std.testing.expectEqual(@as(u64, 64), c.rows[@intFromEnum(Component.poseidon2_m31_w24)]);
}
