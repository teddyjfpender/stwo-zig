//! Replays the exact dense/sparse equations symbolically. All six physical sums
//! and all relation draws are graph inputs; no witness value selects fixed code.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const M = core.fields.m31.M31;
const Profile = @import("../block_v7_lookup_compact_fixed_profile_v1.zig");
const A = @import("../../prover/block_v7_lookup_compact_algebra_v1.zig");
const L = @import("../../prover/block_v7_lookup_compact_layout_v1.zig");
const R = @import("../../prover/block_v7_memory_relations_v1.zig");
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const F = @import("block_v5_ram_lanes_composition_v1.zig").Field;
const Source = @import("blake3_execution_composition.zig").Source;
pub const RELATION_COUNT = 53;
pub const Compiled = struct {
    allocator: std.mem.Allocator,
    circuit: G.Circuit,
    sources: []Source,
    pub fn deinit(self: *Compiled) void {
        self.circuit.deinit();
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};
fn input(b: *G.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const symbol = try b.input();
    try sources.append(a, source);
    return symbol.value;
}
pub fn compile(a: std.mem.Allocator, profile: *const Profile.Owned) !Compiled {
    try profile.validate();
    if (profile.shape.split != 2 or profile.shape.composition_log != profile.shape.mask_log + 2 or profile.columns[3].len != 16) return error.InvalidCompactLookupCompositionShape;
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const scratch = arena.allocator();
    var b = G.Builder.init(a);
    defer b.deinit();
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(a);
    const samples = try scratch.alloc(S, try profile.sampleCount());
    var offsets: [4][]usize = undefined;
    var cursor: usize = 0;
    var col: usize = 0;
    for (&offsets, profile.columns) |*tree, logs| {
        tree.* = try scratch.alloc(usize, logs.len);
        for (tree.*) |*offset| {
            offset.* = cursor;
            for (0..profile.shape.layouts[col].sampleCount()) |_| {
                samples[cursor] = try input(&b, a, &sources, .{ .sample = @intCast(cursor) });
                cursor += 1;
            }
            col += 1;
        }
    }
    if (cursor != samples.len or col != profile.shape.layouts.len) return error.InvalidCompactLookupCompositionSamples;
    var relations: [RELATION_COUNT][2]S = undefined;
    for (&relations, 0..) |*pair, i| for (pair, 0..) |*v, j| {
        v.* = try input(&b, a, &sources, .{ .challenge = @intCast(2 * i + j) });
    };
    const random = try input(&b, a, &sources, .composition);
    const seed = try input(&b, a, &sources, .oods);
    var public: [6]S = undefined;
    for (&public, 0..) |*v, i| v.* = try input(&b, a, &sources, .{ .public_input = @intCast(i) });
    try b.activate();
    var active = true;
    defer if (active) b.deactivate();
    var accumulated = S.zero();
    inline for (0..6) |i| {
        const kind: A.Schema.Kind = @enumFromInt(i);
        const domain = @field(@import("../../air/lang/relation.zig").Domain, @tagName(kind));
        inline for (.{ A.Mode.dense, A.Mode.sparse }) |mode| if (profile.input.policy.layout.parts[i].mode == mode) {
            try recordPart(kind, mode, profile.shape.mask_log, profile.input.policy.layout.parts[i], offsets, samples, public[i], relations[@intFromEnum(domain)], random, seed, &accumulated);
        };
    }
    var chunks: [4]S = undefined;
    for (&chunks, 0..) |*chunk, i| {
        var limbs: [4]S = undefined;
        for (&limbs, 0..) |*limb, j| limb.* = samples[offsets[3][4 * i + j]];
        chunk.* = G.fromPartialEvals(limbs);
    }
    const reconstructed = try G.reconstructSplitComposition(&chunks, G.pointFromSeed(seed), profile.shape.composition_log, profile.shape.split);
    try b.constrainZero(reconstructed.sub(accumulated));
    b.deactivate();
    active = false;
    var circuit = try b.finish();
    errdefer circuit.deinit();
    return .{ .allocator = a, .circuit = circuit, .sources = try sources.toOwnedSlice(a) };
}
pub fn recordPart(comptime kind: A.Schema.Kind, comptime mode: A.Mode, max_log: u32, part: L.Part, offsets: [4][]const usize, samples: []const S, claim: S, pair: [2]S, random: S, seed: S, acc: *S) !void {
    @setEvalBranchQuota(500000);
    const Spec = A.For(kind, mode);
    if (!std.meta.eql(part.width, [3]u32{ Spec.FIXED_COUNT, Spec.MAIN_COUNT, Spec.INTERACTION_COUNT }) or part.claim_count != 1) return error.InvalidCompactLookupCompositionPlacement;
    var fixed: [Spec.FIXED_COUNT]F = undefined;
    var main: [Spec.MAIN_COUNT]F = undefined;
    var current: [4]F = undefined;
    var previous: [4]F = undefined;
    for (&fixed, 0..) |*v, i| v.* = .{ .symbol = samples[offsets[0][part.offset[0] + i]] };
    for (&main, 0..) |*v, i| v.* = .{ .symbol = samples[offsets[1][part.offset[1] + i]] };
    for (&current, &previous, 0..) |*v, *p, i| {
        const at = offsets[2][part.offset[2] + i];
        v.* = .{ .symbol = samples[at] };
        p.* = .{ .symbol = samples[at + 1] };
    }
    var relation: R.Relation(F, A.Schema.arity(kind)) = undefined;
    relation.z = .{ .symbol = pair[0] };
    var power = F.one();
    for (&relation.powers) |*v| {
        v.* = power;
        power = power.mul(.{ .symbol = pair[1] });
    }
    const inverse_size = S.fromBase(try M.fromCanonical(@as(u32, 1) << @as(u5, @intCast(part.log))).inv());
    const norm = F{ .symbol = claim.mul(inverse_size) };
    const equations = Spec.equations(F, fixed, main, current, previous, relation, norm);
    var cache: G.DenominatorCache = @splat(null);
    const denominator = try G.quotientDenominator(part.log, max_log, G.pointFromSeed(seed), &cache);
    for (equations) |equation| G.accumulate(acc, random, equation.symbol, denominator);
}
