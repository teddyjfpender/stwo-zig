//! Exact117 lane equations, sharing canonical generic AIR and symbolic public
//! endpoints/census. Neither received metadata nor concrete state enters setup.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Recorder = @import("composition_graph_recorder.zig");
const S = Recorder.Scalar;
const Air = @import("../../air/block/word_memory_lanes_v1.zig");
const Trace = @import("../../air/block/word_memory_lanes_trace_v1.zig");
const Word = @import("../../prover/block_v5_word_memory_protocol_v1.zig");
const Spec = @import("../../prover/block_v5_ram_lanes_component_v1.zig").Spec;
const Interaction = @import("../../prover/block_v5_ram_lanes_interaction_v1.zig");
const Admission = @import("../../prover/block_v5_ram_lanes_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_ram_lanes_recursive_capture_v1.zig");
pub const Prepared = @import("blake3_execution_composition.zig").Prepared;
const Source = @import("blake3_execution_composition.zig").Source;
pub const RELATION_COUNT = @import("universal_challenges.zig").RELATION_COUNT + 5;
pub const PUBLIC_COUNT: usize = 61;
pub const PublicLayout = struct {
    pub const normalized = 0;
    pub const prior = 23;
    pub const first = 32;
    pub const last = 43;
    pub const global_first = 54;
    pub const global_last = 55;
    pub const boundary_fraction = 56;
    pub const final_fraction = 57;
    pub const incoming_fraction = 58;
    pub const boundary_count = 59;
    pub const final_count = 60;
};
pub fn publicInputs(a: std.mem.Allocator, pin: @import("../../prover/block_v5_ram_lanes_proof_v1.zig").Pin, sums: Interaction.Claim, sealed: [32]u8) ![PUBLIC_COUNT]Q {
    try pin.validate();
    if (sums.range_count != pin.request_count) return error.UntrustedV5RamLanesRangeCensus;
    var channel = @import("../../prover/block_v5_universal_channel_v1.zig").init(sealed);
    const challenges = try Word.Challenges.drawFromChannel(a, &channel);
    const endpoints = try Interaction.publicEndpoints(pin.claim, &challenges);
    var result: [PUBLIC_COUNT]Q = undefined;
    // Public normalized values are independently derived from exact received
    // sums/counts and the admitted ACTUAL physical row capacity.
    const normalized = try Interaction.normalize(sums, pin.claim);
    @memcpy(result[0..23], &normalized);
    const prior = if (pin.claim.preceding) |value| Word.endpointTuple(value) else @as([9]M, @splat(M.zero()));
    for (result[23..32], prior) |*out, value| out.* = Q.fromBase(value);
    for (result[32..43], Word.transitionTuple(pin.claim.first)) |*out, value| out.* = Q.fromBase(value);
    for (result[43..54], Word.transitionTuple(pin.claim.last)) |*out, value| out.* = Q.fromBase(value);
    result[54] = Q.fromBase(M.fromCanonical(@intFromBool(pin.claim.first_event == 0)));
    result[55] = Q.fromBase(M.fromCanonical(@intFromBool(pin.claim.first_event + pin.claim.events == pin.claim.total_events)));
    result[56] = endpoints.legacy.boundary_fraction[0];
    result[57] = endpoints.legacy.final_fraction[0];
    result[58] = endpoints.incoming_fraction;
    result[59] = endpoints.legacy.boundary_count[0];
    result[60] = endpoints.legacy.final_count[0];
    return result;
}
pub const Field = struct {
    symbol: S,
    pub fn zero() Field {
        return .{ .symbol = S.zero() };
    }
    pub fn one() Field {
        return .{ .symbol = S.one() };
    }
    pub fn splat(value: Q) Field {
        return .{ .symbol = S.fromSecure(value) };
    }
    pub fn add(self: Field, other: Field) Field {
        return .{ .symbol = self.symbol.add(other.symbol) };
    }
    pub fn sub(self: Field, other: Field) Field {
        return .{ .symbol = self.symbol.sub(other.symbol) };
    }
    pub fn mul(self: Field, other: Field) Field {
        return .{ .symbol = self.symbol.mul(other.symbol) };
    }
    pub fn neg(self: Field) Field {
        return .{ .symbol = self.symbol.neg() };
    }
    pub fn fromPartialEvals(values: [4]Field) Field {
        var partials: [4]S = undefined;
        for (&partials, values) |*out, value| out.* = value.symbol;
        return .{ .symbol = Recorder.fromPartialEvals(partials) };
    }
};
fn wrapped(comptime n: usize, values: [n]S) [n]Field {
    var result: [n]Field = undefined;
    for (&result, values) |*out, value| out.* = .{ .symbol = value };
    return result;
}
fn Relation(comptime n: usize) type {
    return struct {
        z: Field,
        powers: [n]Field,
        fn init(z: S, alpha: S) @This() {
            var powers: [n]Field = undefined;
            var power = Field.one();
            for (&powers) |*out| {
                out.* = power;
                power = power.mul(.{ .symbol = alpha });
            }
            return .{ .z = .{ .symbol = z }, .powers = powers };
        }
        pub fn combineSecure(self: @This(), values: [n]Field) Field {
            return @import("../../air/relation_challenges.zig").combineGeneric(Field, self.z, self.powers, values);
        }
    };
}
/// This entry is shared by actual capture lowering and arbitrary-OODS parity
/// fixtures. Every dynamic input must be created BEFORE builder.activate().
pub fn recordEquation(builder: *Recorder.Builder, row_log: u32, fixed: [24]S, row: [54]S, previous_row: [54]S, current: [92]S, previous: [92]S, public: [PUBLIC_COUNT]S, challenges: [10]S, randomness: S, seed: S, chunks: [4]S) !void {
    @setEvalBranchQuota(400000);
    var fixed_lanes: Air.Algebra(Field).Fixed = undefined;
    const f = wrapped(24, fixed);
    for (&fixed_lanes, 0..) |*out, lane| {
        const cells = f[lane * Trace.FixedLayout.len ..][0..Trace.FixedLayout.len];
        out.* = .{ .active = cells[0], .first = cells[1], .last = cells[2], .domain_last = cells[3], .ordinal = cells[4..8].*, .previous_ordinal = cells[8..12].*, .global_first = cells[1].mul(.{ .symbol = public[54] }), .global_last = cells[2].mul(.{ .symbol = public[55] }) };
    }
    const r = wrapped(54, row);
    const p = wrapped(54, previous_row);
    const rows: Air.Algebra(Field).Row = .{ r[0..27].*, r[27..54].* };
    const prior_rows: Air.Algebra(Field).Row = .{ p[0..27].*, p[27..54].* };
    const prior = wrapped(9, public[23..32].*);
    const first = wrapped(11, public[32..43].*);
    const last = wrapped(11, public[43..54].*);
    const elements = .{ .transition = Relation(11).init(challenges[0], challenges[1]), .link = Relation(13).init(challenges[2], challenges[3]), .initial = Relation(5).init(challenges[4], challenges[5]), .endpoint = Relation(9).init(challenges[6], challenges[7]), .range16 = Relation(1).init(challenges[8], challenges[9]) };
    const endpoints = Interaction.EndpointConstants(Field){ .legacy = .{ .prior = prior, .boundary_fraction = .{ .{ .symbol = public[56] }, Field.zero() }, .final_fraction = .{ .{ .symbol = public[57] }, Field.zero() }, .boundary_count = .{ .{ .symbol = public[59] }, Field.zero() }, .final_count = .{ .{ .symbol = public[60] }, Field.zero() } }, .incoming_fraction = .{ .symbol = public[58] } };
    const equations = Air.Algebra(Field).constraintsWithEndpoints(prior, first, last, fixed_lanes, rows, prior_rows) ++ Interaction.Algebra(Field).constraintsPrepared(&elements, &endpoints, fixed_lanes, rows, prior_rows, wrapped(92, current), wrapped(92, previous), wrapped(23, public[0..23].*));
    const point = Recorder.pointFromSeed(seed);
    var cache: Recorder.DenominatorCache = @splat(null);
    const denominator = try Recorder.quotientDenominator(row_log, row_log, point, &cache);
    var accumulated = S.zero();
    for (equations) |equation| Recorder.accumulate(&accumulated, randomness, equation.symbol, denominator);
    const reconstructed = try Recorder.reconstructSplitComposition(&chunks, point, row_log + Spec.EXPANSION_BITS, Spec.EXPANSION_BITS);
    try builder.constrainZero(reconstructed.sub(accumulated));
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = Recorder.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Source) = .empty;
    if (capture.proof.sampled_points.len != 4) return error.InvalidRamRecursiveSamples;
    const widths = [_]usize{ 24, 54, 92, 16 };
    var offsets: [4][92]usize = undefined;
    var cursor: usize = 0;
    for (capture.proof.sampled_points, widths, 0..) |columns, width, tree| {
        if (columns.len != width) return error.InvalidRamRecursiveSamples;
        for (columns, 0..) |points, column| {
            const wanted: usize = if (tree == 2 or (tree == 1 and Spec.PREVIOUS_MAIN_MASK[column])) 2 else 1;
            if (points.len != wanted) return error.InvalidRamRecursiveSamples;
            offsets[tree][column] = cursor;
            cursor = try std.math.add(usize, cursor, wanted);
        }
    }
    if (cursor != capture.proof.sampled_values.len) return error.InvalidRamRecursiveSamples;
    const samples = try temp.alloc(S, cursor);
    for (samples, capture.proof.sampled_values, 0..) |*symbol, value, index| symbol.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(index) }, value);
    var challenge_symbols: [10]S = undefined;
    var draw: u32 = 0;
    for (capture.challenges.universal_prefix.elements) |element| {
        _ = try input(&builder, temp, &inputs, &sources, .{ .challenge = draw }, element.z);
        _ = try input(&builder, temp, &inputs, &sources, .{ .challenge = draw + 1 }, element.alpha);
        draw += 2;
    }
    inline for (.{ "transition", "link", "initial", "endpoint", "range16" }, 0..) |field, index| {
        const element = @field(capture.challenges, field);
        challenge_symbols[2 * index] = try input(&builder, temp, &inputs, &sources, .{ .challenge = draw }, element.z);
        challenge_symbols[2 * index + 1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = draw + 1 }, element.alpha);
        draw += 2;
    }
    if (draw != 2 * RELATION_COUNT) return error.InvalidRamRecursiveChallenges;
    const randomness = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    const public_values = try publicInputs(temp, admitted.pin, capture.receipt.sums, admitted.sealed.digest);
    var public: [PUBLIC_COUNT]S = undefined;
    for (&public, public_values, 0..) |*symbol, value, index| symbol.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(index) }, value);
    var fixed: [24]S = undefined;
    for (&fixed, 0..) |*out, column| out.* = samples[offsets[0][column]];
    var main: [54]S = undefined;
    var prior_main: [54]S = @splat(S.zero());
    for (&main, 0..) |*out, column| {
        out.* = samples[offsets[1][column]];
        if (Spec.PREVIOUS_MAIN_MASK[column]) prior_main[column] = samples[offsets[1][column] + 1];
    }
    var current: [92]S = undefined;
    var previous: [92]S = undefined;
    for (&current, &previous, 0..) |*now, *prior_value, column| {
        now.* = samples[offsets[2][column]];
        prior_value.* = samples[offsets[2][column] + 1];
    }
    try builder.activate();
    var active = true;
    defer if (active) builder.deactivate();
    var chunks: [4]S = undefined;
    for (&chunks, 0..) |*chunk, index| {
        var partials: [4]S = undefined;
        for (&partials, 0..) |*limb, coordinate| limb.* = samples[offsets[3][4 * index + coordinate]];
        chunk.* = Recorder.fromPartialEvals(partials);
    }
    try recordEquation(&builder, admitted.pin.claim.row_log, fixed, main, prior_main, current, previous, public, challenge_symbols, randomness, seed, chunks);
    builder.deactivate();
    active = false;
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const values = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, values);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = values, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(builder: *Recorder.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Source), source: Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
