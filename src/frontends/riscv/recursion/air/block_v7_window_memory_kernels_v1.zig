//! Nonterminal RAM composition extends the exact original 161 equations with
//! two snapshot-delta recurrences. Old public offsets stay stable; the delta
//! sums are appended and use the independently drawn Word.initial challenge.
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const F = @import("block_v5_ram_lanes_composition_v1.zig").Field;
const Base = @import("block_v7_memory_composition_v1.zig");
const Ram = @import("../../prover/block_v7_window_ram_component_v1.zig");
const R = @import("../../prover/block_v7_memory_relations_v1.zig");
const Halt = @import("../../prover/block_v7_halt_algebra_v1.zig");
const Geometry = @import("../../prover/block_v5_ram_lanes_protocol_v1.zig");
const Air = @import("../../air/block/word_memory_lanes_v1.zig");
pub const Family = Base.Family;
pub const relation_pair_indices = [5]usize{ 47, 48, 52, 51, 49 };
pub fn Spec(comptime family: Family) type {
    return if (family == .ram) Ram.Spec else Base.Spec(family);
}
pub fn planes(comptime family: Family) usize {
    return if (family == .ram) Ram.PLANES else Base.planes(family);
}
pub fn publicCount(comptime family: Family) usize {
    return Base.publicCount(family) + @as(usize, if (family == .ram) 2 else 0);
}
pub fn ramPublic(claim: Geometry.Claim, sums: [31]Q, halt: Halt.Constants(Q)) ![publicCount(.ram)]Q {
    var result: [publicCount(.ram)]Q = undefined;
    const original = try Base.ramPublic(claim, sums[0..29].*, halt);
    @memcpy(result[0..original.len], &original);
    @memcpy(result[original.len..], sums[29..31]);
    return result;
}
fn wrap(comptime n: usize, values: [n]S) [n]F {
    var out: [n]F = undefined;
    for (&out, values) |*value, symbol| value.* = .{ .symbol = symbol };
    return out;
}
pub fn accumulate(comptime family: Family, row_log: u32, max_log: u32, fixed: [Spec(family).FIXED_COUNT]S, row: [Spec(family).MAIN_COUNT]S, prior: [Spec(family).MAIN_COUNT]S, current: [Spec(family).INTERACTION_COUNT]S, previous: [Spec(family).INTERACTION_COUNT]S, public: [publicCount(family)]S, relations: [10]S, randomness: S, seed: S, accumulated: *S) !void {
    if (family != .ram) return Base.accumulate(family, row_log, max_log, fixed, row, prior, current, previous, public, relations[0..8].*, randomness, seed, accumulated);
    try Base.accumulate(.ram, row_log, max_log, fixed, row, prior, current[0..116].*, previous[0..116].*, public[0..84].*, relations[0..8].*, randomness, seed, accumulated);
    const fields = wrap(Spec(.ram).FIXED_COUNT, fixed);
    var lanes: Air.Algebra(F).Fixed = undefined;
    for (&lanes, 0..) |*lane, i| {
        const cells = fields[i * 12 ..][0..12];
        lane.* = .{ .active = cells[0], .first = cells[1], .last = cells[2], .domain_last = cells[3], .ordinal = cells[4..8].*, .previous_ordinal = cells[8..12].*, .global_first = cells[1].mul(.{ .symbol = public[60] }), .global_last = cells[2].mul(.{ .symbol = public[61] }) };
    }
    var delta: R.Relation(F, 5) = undefined;
    delta.z = .{ .symbol = relations[8] };
    var power = F.one();
    for (&delta.powers) |*item| {
        item.* = power;
        power = power.mul(.{ .symbol = relations[9] });
    }
    const inverse_size = S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(row_log)).inv());
    const normalized = [2]F{
        .{ .symbol = public[84].mul(inverse_size) },
        .{ .symbol = public[85].mul(inverse_size) },
    };
    const equations = Ram.deltaEquations(F, lanes, wrap(88, row), wrap(8, current[116..124].*), wrap(8, previous[116..124].*), delta, normalized);
    var cache: G.DenominatorCache = @splat(null);
    const denominator = try G.quotientDenominator(row_log, max_log, G.pointFromSeed(seed), &cache);
    for (equations) |equation| G.accumulate(accumulated, randomness, equation.symbol, denominator);
}
