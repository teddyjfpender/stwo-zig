//! All six shipped signed-multiplicity table equations in native component
//! order. Public claims are exact inputs; no normalization or reduced table AIR.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const r = @import("composition_graph_recorder.zig");
const S = r.Scalar;
const tables = @import("../../air/lookups/tables/mod.zig");
const Assembly = @import("../../prover/block_v5_native_lookup_assembly_v1.zig");
const Admission = @import("../../prover/block_v5_native_lookup_recursive_admission_v1.zig");
const Capture = @import("../../prover/block_v5_native_lookup_recursive_capture_v1.zig");
const shared = @import("blake3_execution_composition.zig");
pub const Prepared = shared.Prepared;
const Source = shared.Source;
pub const FIXED_COLUMNS: usize = 20;
pub const MAIN_COLUMNS: usize = 6;
pub const INTERACTION_COLUMNS: usize = 24;
pub const COMPOSITION_COLUMNS: usize = 8;
pub const COMPOSITION_LOG: u32 = 21;
pub const MASK_LOG: u32 = 20;
comptime {
    if (Assembly.Count != 6 or tables.interaction.N_COLUMNS != 4 or
        @import("../../air/lookups/tables/layout.zig").N_CONSTRAINTS != 1)
        @compileError("lookup recursion v1 requires the complete original six singleton table AIRs");
    var fixed_count: usize = 0;
    var max_log: u32 = 0;
    for (0..Assembly.Count) |index| {
        const kind: tables.schema.Kind = @enumFromInt(index);
        fixed_count += 1 + tables.schema.arity(kind);
        max_log = @max(max_log, tables.schema.logSize(kind));
    }
    if (fixed_count != FIXED_COLUMNS or max_log != MASK_LOG or core.verifier_types.COMPOSITION_LOG_SPLIT != 1)
        @compileError("lookup recursion v1 table or composition geometry changed");
}
fn Element(comptime n: usize) type {
    return struct {
        source: *const r.ChallengeSet.Element,
        pub fn combine(self: @This(), values: [n]S) S {
            var result = S.zero();
            for (values, self.source.alpha_powers[0..n]) |value, power| result = result.add(power.mul(value));
            return result.sub(self.source.z);
        }
    };
}
/// Same original denominatorWith field interface; only six exact domains are
/// consumed by table AIR. Every scalar operation belongs to the active DAG.
const Relations = struct {
    registers_state: Element(2),
    memory_access: Element(7),
    program_access: Element(5),
    merkle: Element(4),
    poseidon2: Element(16),
    poseidon2_io: Element(32),
    bitwise: Element(4),
    range_check_20: Element(1),
    range_check_8_11: Element(2),
    range_check_8_8_4: Element(3),
    range_check_8_8: Element(2),
    range_check_m31: Element(2),
    fn init(challenges: *const r.ChallengeSet) Relations {
        var result: Relations = undefined;
        inline for (std.meta.fields(Relations)) |field| @field(result, field.name) = .{ .source = challenges.get(@field(@import("../../air/lang/relation.zig").Domain, field.name)) };
        return result;
    }
};
pub fn recordEquation(builder: *r.Builder, fixed: [FIXED_COLUMNS]S, main: [MAIN_COLUMNS]S, current: [INTERACTION_COLUMNS]S, previous: [INTERACTION_COLUMNS]S, claims: [Assembly.Count]S, challenges: *const r.ChallengeSet, randomness: S, seed: S, chunks: [2]S) !void {
    const point = r.pointFromSeed(seed);
    var cache: r.DenominatorCache = @splat(null);
    const relations = Relations.init(challenges);
    var accumulated = S.zero();
    var at: usize = 0;
    for (0..Assembly.Count) |index| {
        const kind: tables.schema.Kind = @enumFromInt(index);
        const width = tables.schema.arity(kind);
        const equation = try @import("../../air/lookups/tables/equations.zig").evaluateGeneric(S, kind, fixed[at + 1 ..][0..width], main[index], r.fromPartialEvals(current[4 * index ..][0..4].*), r.fromPartialEvals(previous[4 * index ..][0..4].*), fixed[at], claims[index], &relations);
        const denominator = try r.quotientDenominator(tables.schema.logSize(kind), MASK_LOG, point, &cache);
        r.accumulate(&accumulated, randomness, equation, denominator);
        at += width + 1;
    }
    if (at != FIXED_COLUMNS) return error.InvalidLookupRecursiveGeometry;
    try builder.constrainZero((try r.reconstructSplitComposition(&chunks, point, COMPOSITION_LOG, 1)).sub(accumulated));
}
pub fn prepare(a: std.mem.Allocator, admitted: *const Admission.Prepared, capture: *const Capture.VerifiedCapture, expected: [32]u8) !Prepared {
    try capture.validate(admitted, expected);
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const temp = arena.allocator();
    var builder = r.Builder.init(a);
    defer builder.deinit();
    var inputs: std.ArrayList(Q) = .empty;
    var sources: std.ArrayList(Source) = .empty;
    if (capture.proof.sampled_points.len != 4) return error.InvalidLookupRecursiveSamples;
    const widths = [_]usize{ FIXED_COLUMNS, MAIN_COLUMNS, INTERACTION_COLUMNS, COMPOSITION_COLUMNS };
    var offsets: [4][INTERACTION_COLUMNS]usize = undefined;
    var cursor: usize = 0;
    for (capture.proof.sampled_points, widths, 0..) |columns, width, tree| {
        if (columns.len != width) return error.InvalidLookupRecursiveSamples;
        for (columns, 0..) |points, column| {
            if (points.len != (if (tree == 2) @as(usize, 2) else 1)) return error.InvalidLookupRecursiveSamples;
            offsets[tree][column] = cursor;
            cursor = try std.math.add(usize, cursor, points.len);
        }
    }
    if (cursor != capture.proof.sampled_values.len) return error.InvalidLookupRecursiveSamples;
    const samples = try temp.alloc(S, cursor);
    for (samples, capture.proof.sampled_values, 0..) |*symbol, value, index| symbol.* = try input(&builder, temp, &inputs, &sources, .{ .sample = @intCast(index) }, value);
    var draws: [@import("universal_challenges.zig").RELATION_COUNT][2]S = undefined;
    for (&draws, capture.relations.elements, 0..) |*pair, element, index| {
        pair[0] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * index) }, element.z);
        pair[1] = try input(&builder, temp, &inputs, &sources, .{ .challenge = @intCast(2 * index + 1) }, element.alpha);
    }
    const randomness = try input(&builder, temp, &inputs, &sources, .composition, capture.proof.composition_randomness);
    const seed = try input(&builder, temp, &inputs, &sources, .oods, capture.proof.oods_seed);
    var claims: [Assembly.Count]S = undefined;
    for (&claims, capture.receipt.claims, 0..) |*claim, value, index| claim.* = try input(&builder, temp, &inputs, &sources, .{ .public_input = @intCast(index) }, value);
    var fixed: [FIXED_COLUMNS]S = undefined;
    var main: [MAIN_COLUMNS]S = undefined;
    var current: [INTERACTION_COLUMNS]S = undefined;
    var previous: [INTERACTION_COLUMNS]S = undefined;
    for (&fixed, 0..) |*value, index| value.* = samples[offsets[0][index]];
    for (&main, 0..) |*value, index| value.* = samples[offsets[1][index]];
    for (&current, &previous, 0..) |*value, *prior, index| {
        value.* = samples[offsets[2][index]];
        prior.* = samples[offsets[2][index] + 1];
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var chunks: [2]S = undefined;
    for (&chunks, 0..) |*chunk, index| {
        var limbs: [4]S = undefined;
        for (&limbs, 0..) |*limb, coordinate| limb.* = samples[offsets[3][4 * index + coordinate]];
        chunk.* = r.fromPartialEvals(limbs);
    }
    const challenges = try r.ChallengeSet.init(draws);
    try recordEquation(&builder, fixed, main, current, previous, claims, &challenges, randomness, seed, chunks);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    const evaluated = try temp.alloc(Q, circuit.nodes.len);
    try circuit.evaluateInto(inputs.items, evaluated);
    var result = Prepared{ .arena = arena, .circuit = circuit, .inputs = inputs.items, .sources = sources.items, .values = evaluated, .key_id = expected, .capture_seal = capture.seal, .seal = undefined };
    result.seal = result.identity();
    return result;
}
fn input(builder: *r.Builder, a: std.mem.Allocator, inputs: *std.ArrayList(Q), sources: *std.ArrayList(Source), source: Source, value: Q) !S {
    const symbol = try builder.input();
    try inputs.append(a, value);
    try sources.append(a, source);
    return symbol.value;
}
