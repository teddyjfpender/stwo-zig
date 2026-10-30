//! Joined original composition uses the original symbolic equation kernels,
//! one global sample map and one Horner accumulator. This compiler alone is
//! not recursive publication authority; global/public closure is separate.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const Source = @import("blake3_execution_composition.zig").Source;
const Multi = @import("../../prover/block_v7_multi_union_proof_v1.zig").ForMode(true);
const Profile = @import("../block_v7_union_fixed_profile_v1.zig").ForMode(true);
const Native = @import("block_v6_partitioned_composition_v1.zig");
const Memory = @import("block_v7_window_memory_kernels_v1.zig");
const MemoryCompiler = @import("block_v7_memory_joint_composition_mode_v1.zig").ForMode(true);
const Lookup = @import("../../prover/block_v7_lookup_compact_algebra_v1.zig");
pub const Compiled = struct {
    allocator: std.mem.Allocator,
    circuit: G.Circuit,
    sources: []Source,
    pub const global_closure_complete = false;
    pub fn deinit(self: *Compiled) void {
        self.circuit.deinit();
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};
const Samples = struct {
    offsets: [][]usize,
    lengths: [][]usize,
    values: []S,
    fn init(a: std.mem.Allocator, b: *G.Builder, sources: *std.ArrayList(Source), profile: *const Profile.Owned) !Samples {
        const offsets = try a.alloc([]usize, profile.shape.columns.len);
        const lengths = try a.alloc([]usize, offsets.len);
        var count: usize = 0;
        for (profile.shape.layouts) |layout| count = try std.math.add(usize, count, layout.sampleCount());
        const values = try a.alloc(S, count);
        var cursor: usize = 0;
        var flat: usize = 0;
        for (offsets, lengths, profile.shape.columns) |*off, *len, columns| {
            off.* = try a.alloc(usize, columns.len);
            len.* = try a.alloc(usize, columns.len);
            for (off.*, len.*) |*start, *n| {
                start.* = cursor;
                n.* = profile.shape.layouts[flat].sampleCount();
                for (0..n.*) |_| {
                    values[cursor] = try input(b, a, sources, .{ .sample = @intCast(cursor) });
                    cursor += 1;
                }
                flat += 1;
            }
        }
        if (cursor != values.len or flat != profile.shape.layouts.len) return error.InvalidUnionCompositionSamples;
        return .{ .offsets = offsets, .lengths = lengths, .values = values };
    }
    fn at(self: Samples, tree: usize, column: usize, sample: usize) !S {
        if (tree >= self.offsets.len or column >= self.offsets[tree].len or sample >= self.lengths[tree][column]) return error.InvalidUnionCompositionSamples;
        return self.values[self.offsets[tree][column] + sample];
    }
};
const Mapped = struct {
    samples: Samples,
    map: []const usize,
    fixed_start: usize,
    fixed_count: usize,
    pub fn at(self: Mapped, tree: usize, column: usize, sample: usize) !S {
        if (tree >= self.map.len or (tree == 0 and column >= self.fixed_count)) return error.InvalidUnionCompositionPlacement;
        return self.samples.at(self.map[tree], if (tree == 0) self.fixed_start + column else column, sample);
    }
    fn offsets4(self: Mapped) ![4][]const usize {
        if (self.map.len != 3) return error.InvalidUnionCompositionPlacement;
        return .{ self.samples.offsets[0][self.fixed_start..][0..self.fixed_count], self.samples.offsets[self.map[1]], self.samples.offsets[self.map[2]], &.{} };
    }
};
fn input(b: *G.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const value = try b.input();
    try sources.append(a, source);
    return value.value;
}
pub fn publicValues(a: std.mem.Allocator, profile: *const Profile.Owned, components: *const Multi.AdmittedComponents, claims: *const Multi.Claims) ![]Q {
    var out: std.ArrayList(Q) = .empty;
    errdefer out.deinit(a);
    const i = components.context.input;
    for (components.context.natives, i.natives, claims.native) |n, pin, claim| {
        const values = try @import("block_v7_native_composition_v1.zig").publicInputsForSource(a, pin, n.component.layout.slots, n.component.slots, claim.claims, claim.access);
        defer a.free(values);
        try out.appendSlice(a, values);
    }
    for (claims.callers, 0..) |*claim, index| {
        const values = try @import("block_v7_union_caller_composition_v1.zig").publicValues(a, profile, index, claim);
        defer a.free(values);
        try out.appendSlice(a, values);
    }
    try out.append(a, claims.program);
    try out.appendSlice(a, &claims.lookup);
    const halt = try components.scope.policy.window.?.nonhaltConstants();
    for (claims.ram) |ram| try out.appendSlice(a, &try Memory.ramPublic(ram.geometry, ram.sums, halt));
    try out.appendSlice(a, &claims.interval);
    try out.appendSlice(a, &claims.range16);
    return out.toOwnedSlice(a);
}
pub fn compile(a: std.mem.Allocator, profile: *const Profile.Owned, claims: *const Multi.Claims) !Compiled {
    try profile.validateAgainst(claims);
    var components = try Multi.AdmittedComponents.init(a, profile.statement.trusted, profile.statement.input, claims, profile.limits.original);
    defer components.deinit();
    return compileFromComponents(a, profile, claims, &components);
}
/// Structural kernel compilation; only the typed independent admission owner
/// may nominate these components as its source policy. No key is issued here.
pub fn compileFromComponents(a: std.mem.Allocator, profile: *const Profile.Owned, claims: *const Multi.Claims, components: *const Multi.AdmittedComponents) !Compiled {
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    const values = try publicValues(t, profile, components, claims);
    var b = G.Builder.init(a);
    defer b.deinit();
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(a);
    // Samples uses the temporary arena, while graph/source ownership is a.
    var sample_sources: std.ArrayList(Source) = .empty;
    const samples = try Samples.init(t, &b, &sample_sources, profile);
    try sources.appendSlice(a, sample_sources.items);
    const draws = try t.alloc([2]S, try @import("block_v7_union_caller_draws_v1.zig").pairCount(claims.callers.len));
    for (draws, 0..) |*pair, index| {
        for (pair, 0..) |*v, half| v.* = try input(&b, a, &sources, .{ .challenge = @intCast(2 * index + half) });
    }
    const public = try t.alloc(S, values.len);
    for (public, 0..) |*v, index| v.* = try input(&b, a, &sources, .{ .public_input = @intCast(index) });
    const random = try input(&b, a, &sources, .composition);
    const seed = try input(&b, a, &sources, .oods);
    var union_points = try (core.air.components.Components{ .components = components.handles(), .n_preprocessed_columns = profile.shape.columns[0].len }).maskPoints(t, core.circle.SECURE_FIELD_CIRCLE_GEN, profile.shape.mask_log, false);
    defer union_points.deinitDeep(t);
    try b.activate();
    defer if (b.active) b.deactivate();
    var accumulated = S.zero();
    var fixed_start: usize = 0;
    var at: usize = 0;
    const i = profile.statement.input;
    for (components.context.natives, i.natives, components.scope.sources[0..i.natives.len], components.scope.placement.parts[0..i.natives.len]) |n, pin, source, part| {
        const mapped = Mapped{ .samples = samples, .map = part.mapping(), .fixed_start = fixed_start, .fixed_count = source.logs[0].len };
        const count = try Native.publicCount(n.component.layout.slots.len, n.component.slots.len);
        const context = Native.EquationContext{ .shape = pin.shape, .external_retirements = pin.template.external_retirements, .register_custody_mode = 1, .projections = n.component.layout.slots, .slots = n.component.slots, .tree_count = source.tree_count };
        _ = try Native.recordEquations(context, mapped, public[at..][0..count], draws[0..47].*, flattenWord(draws[0..53].*), random, G.pointFromSeed(seed), profile.shape.mask_log, &accumulated);
        at += count;
        fixed_start += source.logs[0].len;
    }
    for (claims.callers, 0..) |*caller, index| {
        const source_index = i.natives.len + index;
        const source = components.scope.sources[source_index];
        const mapped = Mapped{ .samples = samples, .map = components.scope.placement.parts[source_index].mapping(), .fixed_start = fixed_start, .fixed_count = source.logs[0].len };
        at += try @import("block_v7_union_caller_composition_v1.zig").record(t, &b, profile, index, caller, mapped, &union_points, public[at..], draws, random, G.pointFromSeed(seed), &accumulated);
        fixed_start += source.logs[0].len;
    }
    const base = i.natives.len + i.callers.len;
    {
        const mapped = Mapped{ .samples = samples, .map = components.scope.placement.parts[base].mapping(), .fixed_start = fixed_start, .fixed_count = components.scope.sources[base].logs[0].len };
        try program(t, i, mapped, public[at], draws[0..47].*, random, seed, profile.shape.mask_log, &accumulated);
        at += 1;
        fixed_start += mapped.fixed_count;
    }
    {
        const mapped = Mapped{ .samples = samples, .map = components.scope.placement.parts[base + 1].mapping(), .fixed_start = fixed_start, .fixed_count = components.scope.sources[base + 1].logs[0].len };
        const offsets = try mapped.offsets4();
        inline for (0..6) |kind_index| {
            const kind: Lookup.Schema.Kind = @enumFromInt(kind_index);
            const domain = @field(@import("../../air/lang/relation.zig").Domain, @tagName(kind));
            inline for (.{ Lookup.Mode.dense, Lookup.Mode.sparse }) |mode| if (i.lookup_layout.parts[kind_index].mode == mode) try @import("block_v7_lookup_compact_composition_v1.zig").recordPart(kind, mode, profile.shape.mask_log, i.lookup_layout.parts[kind_index], offsets, samples.values, public[at + kind_index], draws[@intFromEnum(domain)], random, seed, &accumulated);
        }
        at += 6;
        fixed_start += mapped.fixed_count;
    }
    {
        const mapped = Mapped{ .samples = samples, .map = components.scope.placement.parts[base + 2].mapping(), .fixed_start = fixed_start, .fixed_count = components.scope.sources[base + 2].logs[0].len };
        const offsets = try mapped.offsets4();
        var relations: [10]S = undefined;
        for (Memory.relation_pair_indices, 0..) |pair, index| @memcpy(relations[2 * index ..][0..2], &draws[pair]);
        for (components.context.memory.?.layout.parts) |part| switch (part.family) {
            inline else => |family| {
                const f = @field(Memory.Family, @tagName(family));
                const count = comptime Memory.publicCount(f);
                try MemoryCompiler.recordPart(f, profile.shape.mask_log, part, offsets, samples.values, public[at..][0..count].*, relations, random, seed, &accumulated);
                at += count;
            },
        };
    }
    if (at != public.len) return error.InvalidUnionCompositionPublicFrame;
    const chunks = try t.alloc(S, core.verifier_types.compositionChunkCount(profile.shape.split) orelse return error.InvalidUnionCompositionGeometry);
    for (chunks, 0..) |*chunk, index| {
        var limbs: [4]S = undefined;
        for (&limbs, 0..) |*limb, half| limb.* = try samples.at(profile.trace_count, 4 * index + half, 0);
        chunk.* = G.fromPartialEvals(limbs);
    }
    try b.constrainZero((try G.reconstructSplitComposition(chunks, G.pointFromSeed(seed), profile.shape.composition_log, profile.shape.split)).sub(accumulated));
    b.deactivate();
    var circuit = try b.finish();
    errdefer circuit.deinit();
    return .{ .allocator = a, .circuit = circuit, .sources = try sources.toOwnedSlice(a) };
}
fn flattenWord(draws: [53][2]S) [10]S {
    var word: [10]S = undefined;
    for (draws[47..52], 0..) |pair, index| @memcpy(word[2 * index ..][0..2], &pair);
    return word;
}
fn program(a: std.mem.Allocator, i: Multi.Input, samples: Mapped, claim: S, draws: [47][2]S, random: S, seed: S, mask_log: u32, accumulated: *S) !void {
    const Original = @import("../../prover/block_v5_program_table_proof_v1.zig");
    var definition = try Original.Air.build(a);
    defer definition.deinit();
    const relation = try @import("universal_relation_binding.zig").Binding(Original.Air).authenticate(&definition);
    const drawn = try i.epoch.draw(a);
    const manifest = Original.Roster.Manifest{ .log_sizes = .{i.program_plan.log_size} };
    const component = try Original.Roster.Component(Original.Air).init(&definition, relation, &manifest, .program, i.program_plan.log_size, .{}, &drawn.word.universal_prefix, Q.zero());
    var fixed: [6]S = undefined;
    var current: [4]S = undefined;
    var previous: [4]S = undefined;
    for (&fixed, 0..) |*v, index| v.* = try samples.at(0, index, 0);
    for (&current, &previous, 0..) |*v, *p, index| {
        v.* = try samples.at(2, index, 1);
        p.* = try samples.at(2, index, 0);
    }
    const challenges = try G.ChallengeSet.init(draws);
    try @import("block_v5_program_table_composition_v1.zig").accumulate(&component, fixed, current, previous, claim, &challenges, random, G.pointFromSeed(seed), mask_log, accumulated);
}
pub fn prepare(a: std.mem.Allocator, profile: *const Profile.Owned, capture: *const Multi.VerifiedCapture) !@import("blake3_execution_composition.zig").Prepared {
    if (!std.meta.eql(capture.closed.statement, profile.policy) or !std.meta.eql(capture.closed.epoch, profile.statement.input.epoch.digest)) return error.UntrustedUnionCompositionCapture;
    var compiled = try compile(a, profile, &capture.claims);
    var owns_graph = true;
    defer if (owns_graph) compiled.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const t = arena.allocator();
    var components = try Multi.AdmittedComponents.init(t, profile.statement.trusted, profile.statement.input, &capture.claims, profile.limits.original);
    defer components.deinit();
    const public = try publicValues(t, profile, &components, &capture.claims);
    var challenge_values: std.ArrayList(Q) = .empty;
    const epoch = profile.statement.input.epoch;
    const base_draws = try @import("block_v7_memory_joint_inputs_mode_v1.zig").ForMode(true).challenges(t, epoch);
    try challenge_values.appendSlice(t, &base_draws);
    for (profile.statement.input.callers) |pin| {
        const caller = try @import("../../prover/block_v7_caller_active_source_v1.zig").draw(t, epoch, try pin.require(t, epoch, profile.statement.input.entries));
        try challenge_values.appendSlice(t, &caller.relations.draws());
    }
    const draws = challenge_values.items;
    const inputs = try t.alloc(Q, compiled.sources.len);
    for (inputs, compiled.sources) |*value, source| value.* = switch (source) {
        .sample => |index| if (index < capture.proof.sampled_values.len) capture.proof.sampled_values[index] else return error.InvalidUnionCompositionSamples,
        .public_input => |index| if (index < public.len) public[index] else return error.InvalidUnionCompositionPublicFrame,
        .challenge => |index| if (index < draws.len) draws[index] else return error.InvalidUnionCompositionChallenge,
        .composition => capture.proof.composition_randomness,
        .oods => capture.proof.oods_seed,
        else => return error.InvalidUnionCompositionSource,
    };
    const values = try t.alloc(Q, compiled.circuit.nodes.len);
    try compiled.circuit.evaluateInto(inputs, values);
    const sources = try t.dupe(Source, compiled.sources);
    var result = @import("blake3_execution_composition.zig").Prepared{ .arena = arena, .circuit = compiled.circuit, .inputs = inputs, .sources = sources, .values = values, .key_id = profile.seal, .capture_seal = capture.final_channel.digestBytes(), .seal = undefined };
    result.seal = result.identity();
    a.free(compiled.sources);
    owns_graph = false;
    return result;
}
