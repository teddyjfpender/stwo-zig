//! Exact v7 memory composition kernels. All endpoints and physical sums are
//! circuit inputs; no captured witness or received claim chooses fixed code.
//! This is the equation seam, not transcript/PCS or recursive admission.
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Recorder = @import("composition_graph_recorder.zig");
const S = Recorder.Scalar;
const F = @import("block_v5_ram_lanes_composition_v1.zig").Field;
const R = @import("../../prover/block_v7_memory_relations_v1.zig");
const Ram = @import("../../prover/block_v7_ram_component_v1.zig");
const Halt = @import("../../prover/block_v7_halt_algebra_v1.zig");
const Provider = @import("../../prover/block_v7_provider_component_v1.zig");
const Geometry = @import("../../prover/block_v5_ram_lanes_protocol_v1.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const Air = @import("../../air/block/word_memory_lanes_v1.zig");
pub const Family = enum { ram, interval, range16, terminal };
pub fn Spec(comptime family: Family) type {
    return switch (family) {
        .ram => Ram.Spec,
        .interval => Provider.For(.interval),
        .range16 => Provider.For(.range16),
        .terminal => Provider.For(.terminal),
    };
}
pub fn planes(comptime family: Family) usize {
    return if (family == .ram) Ram.PLANES else Spec(family).PLANES;
}
pub fn publicCount(comptime family: Family) usize {
    return if (family == .ram) 66 + Halt.PUBLIC_COUNT else planes(family);
}
// The complete epoch has Universal47, Word5, then interval1 challenge pairs.
// These offsets select transition/link/interval/range16, in kernel order.
pub const relation_pair_indices = [4]usize{ 47, 48, 52, 51 };
comptime {
    if (@import("universal_challenges.zig").RELATION_COUNT != 47)
        @compileError("V7 memory challenge ports require an explicit epoch migration");
}
pub const RamPublic = struct {
    pub const sums = 0;
    pub const prior = 29;
    pub const first = 38;
    pub const last = 49;
    pub const global_first = 60;
    pub const global_last = 61;
    pub const prior_ordinal = 62;
    pub const halt = 66;
};
pub fn ramPublic(claim: Geometry.Claim, sums: [29]Q, halt: Halt.Constants(Q)) ![publicCount(.ram)]Q {
    try claim.validate();
    _ = try R.normalize(29, sums, claim.rowCapacity());
    var out: [publicCount(.ram)]Q = undefined;
    @memcpy(out[0..29], &sums);
    const prior = if (claim.preceding) |p| Word.endpointTuple(p) else @as([9]M, @splat(M.zero()));
    for (out[29..38], prior) |*v, x| v.* = Q.fromBase(x);
    for (out[38..49], Word.transitionTuple(claim.first)) |*v, x| v.* = Q.fromBase(x);
    for (out[49..60], Word.transitionTuple(claim.last)) |*v, x| v.* = Q.fromBase(x);
    out[60] = Q.fromBase(M.fromCanonical(@intFromBool(claim.first_event == 0)));
    out[61] = Q.fromBase(M.fromCanonical(@intFromBool(claim.first_event + claim.events == claim.total_events)));
    const ordinal = if (claim.first_event == 0) 0 else claim.first_event - 1;
    for (out[62..66], 0..) |*v, i| v.* = Q.fromBase(M.fromCanonical(@intCast((ordinal >> @intCast(16 * i)) & 65535)));
    @memcpy(out[66..68], &halt.address);
    for (halt.clocks, 0..) |clock, i| @memcpy(out[68 + 4 * i ..][0..4], &clock);
    return out;
}
fn wrap(comptime n: usize, values: [n]S) [n]F {
    var out: [n]F = undefined;
    for (&out, values) |*v, x| v.* = .{ .symbol = x };
    return out;
}
fn challenges(values: [8]S) R.Challenges(F) {
    var out: R.Challenges(F) = undefined;
    inline for (.{ "transition", "link", "interval", "range16" }, 0..) |name, i| {
        @field(out, name).z = .{ .symbol = values[2 * i] };
        var power = F.one();
        for (&@field(out, name).powers) |*p| {
            p.* = power;
            power = power.mul(.{ .symbol = values[2 * i + 1] });
        }
    }
    return out;
}
pub fn recordEquation(comptime family: Family, builder: *Recorder.Builder, row_log: u32, fixed: [Spec(family).FIXED_COUNT]S, row: [Spec(family).MAIN_COUNT]S, prior_row: [Spec(family).MAIN_COUNT]S, current: [Spec(family).INTERACTION_COUNT]S, previous: [Spec(family).INTERACTION_COUNT]S, public: [publicCount(family)]S, relation_inputs: [8]S, randomness: S, seed: S, chunks: [4]S) !void {
    var accumulated = S.zero();
    try accumulate(family, row_log, row_log, fixed, row, prior_row, current, previous, public, relation_inputs, randomness, seed, &accumulated);
    const point = Recorder.pointFromSeed(seed);
    const reconstructed = try Recorder.reconstructSplitComposition(&chunks, point, row_log + Spec(family).EXPANSION_BITS, Spec(family).EXPANSION_BITS);
    try builder.constrainZero(reconstructed.sub(accumulated));
}
/// Joint proofs carry one Horner accumulator through every original component,
/// using the global maximum log for each component's coset denominator. Callers
/// reconstruct and constrain the single final split composition once.
pub fn accumulate(comptime family: Family, row_log: u32, max_log: u32, fixed: [Spec(family).FIXED_COUNT]S, row: [Spec(family).MAIN_COUNT]S, prior_row: [Spec(family).MAIN_COUNT]S, current: [Spec(family).INTERACTION_COUNT]S, previous: [Spec(family).INTERACTION_COUNT]S, public: [publicCount(family)]S, relation_inputs: [8]S, randomness: S, seed: S, accumulated: *S) !void {
    @setEvalBranchQuota(500000);
    if (row_log == 0 or row_log > max_log or max_log > 24) return error.InvalidV7CompositionGeometry;
    const f = wrap(Spec(family).FIXED_COUNT, fixed);
    const ch = challenges(relation_inputs);
    var norm: [planes(family)]F = undefined;
    const inverse_size = S.fromBase(try M.fromCanonical(@as(u32, 1) << @intCast(row_log)).inv());
    for (&norm, public[0..planes(family)]) |*v, x| v.* = .{ .symbol = x.mul(inverse_size) };
    const equations = if (family == .ram) blk: {
        var fixed_lanes: Air.Algebra(F).Fixed = undefined;
        for (&fixed_lanes, 0..) |*lane, i| {
            const cells = f[i * 12 ..][0..12];
            lane.* = .{ .active = cells[0], .first = cells[1], .last = cells[2], .domain_last = cells[3], .ordinal = cells[4..8].*, .previous_ordinal = cells[8..12].*, .global_first = cells[1].mul(.{ .symbol = public[60] }), .global_last = cells[2].mul(.{ .symbol = public[61] }) };
        }
        // Bind the incoming link inverse inside the circuit. For the first
        // shard use denominator1 and weight0, avoiding an unused random inverse.
        const incoming_weight = S.one().sub(public[60]);
        const denominator = ch.link.combineSecure(wrap(13, public[62..66].* ++ public[29..38].*)).symbol;
        const safe_denominator = incoming_weight.mul(denominator).add(public[60]);
        const incoming = F{ .symbol = incoming_weight.mul(safe_denominator.inverse()) };
        var halt = Halt.Constants(F){ .address = wrap(2, public[66..68].*), .clocks = undefined };
        for (&halt.clocks, 0..) |*clock, i| clock.* = wrap(4, public[68 + 4 * i ..][0..4].*);
        break :blk Ram.equations(F, wrap(9, public[29..38].*), wrap(11, public[38..49].*), wrap(11, public[49..60].*), halt, fixed_lanes, wrap(Ram.Spec.MAIN_COUNT, row), wrap(Ram.Spec.MAIN_COUNT, prior_row), wrap(Ram.Spec.INTERACTION_COUNT, current), wrap(Ram.Spec.INTERACTION_COUNT, previous), ch, incoming, norm);
    } else Spec(family).equations(F, f, wrap(Spec(family).MAIN_COUNT, row), wrap(Spec(family).INTERACTION_COUNT, current), wrap(Spec(family).INTERACTION_COUNT, previous), ch, norm);
    const point = Recorder.pointFromSeed(seed);
    var cache: Recorder.DenominatorCache = @splat(null);
    const denominator = try Recorder.quotientDenominator(row_log, max_log, point, &cache);
    for (equations) |equation| Recorder.accumulate(accumulated, randomness, equation.symbol, denominator);
}
