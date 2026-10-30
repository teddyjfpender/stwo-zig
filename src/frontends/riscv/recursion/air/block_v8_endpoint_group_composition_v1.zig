//! Exact dynamic Group composition. Original typed Native, halt, endpoint,
//! provider, ROM and lookup kernels are reused; no alternate AIR equations.
const std = @import("std");
const core = @import("stwo_core");
const G = @import("composition_graph_recorder.zig");
const S = G.Scalar;
const Q = core.fields.qm31.QM31;
const Source = @import("blake3_execution_composition.zig").Source;
const Profile = @import("../block_v8_endpoint_group_profile_v1.zig");
const Original = @import("../../prover/block_v8_endpoint_group_proof_v1.zig");
const H = @import("block_v8_endpoint_recursive_composition_v1.zig").For(.local_open);
const Native = @import("block_v6_partitioned_composition_v1.zig");
const Endpoint = @import("../../prover/block_v8_ram_endpoint_component_v1.zig");
const Provider = @import("../../prover/block_v8_endpoint_range_provider_v1.zig").Spec;
const Lookup = @import("../../prover/block_v7_lookup_compact_algebra_v1.zig");
const Closure = @import("block_v8_endpoint_group_closure_v1.zig");
pub const Compiled = H.Compiled;
pub fn publicValues(a: std.mem.Allocator, p: *const Profile.Owned) ![]Q {
    var out: std.ArrayList(Q) = .empty;
    errdefer out.deinit(a);
    for (p.claims.members) |member| {
        try out.appendNTimes(a, Q.zero(), 8);
        for (member.native) |claim| try out.append(a, claim.sum);
        try out.appendSlice(a, &member.endpoint);
    }
    try out.appendSlice(a, &p.claims.endpoint_range);
    try out.append(a, p.claims.program);
    try out.appendSlice(a, &p.claims.lookup);
    try Closure.appendPublic(a, p, &out);
    return out.toOwnedSlice(a);
}
fn input(b: *G.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const value = try b.input();
    try sources.append(a, source);
    return value.value;
}
pub fn compile(a: std.mem.Allocator, p: *const Profile.Owned) !Compiled {
    try p.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const t = arena.allocator();
    var builder = G.Builder.init(a);
    defer builder.deinit();
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(a);
    var sample_sources: std.ArrayList(Source) = .empty;
    const samples = try H.Samples.init(t, &builder, &sample_sources, p);
    try sources.appendSlice(a, sample_sources.items);
    var draws: [53][2]S = undefined;
    for (&draws, 0..) |*pair, i| {
        for (pair, 0..) |*value, half| value.* = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * i + half) });
    }
    const public_values = try publicValues(t, p);
    const public = try t.alloc(S, public_values.len);
    for (public, 0..) |*value, i| value.* = try input(&builder, a, &sources, .{ .public_input = @intCast(i) });
    const random = try input(&builder, a, &sources, .composition);
    const seed = try input(&builder, a, &sources, .oods);
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var accumulated = S.zero();
    var count: usize = 0;
    var fixed_start: usize = 0;
    var at: usize = 0;
    const offsets = try t.alloc(usize, p.layout.n);
    // Match the original component roster: ALL native members, then ALL
    // endpoints, then the three shared providers.
    for (p.context.members, p.statement.input.members, p.claims.members, 0..) |member, metadata, claims, i| {
        offsets[i] = at;
        const mapped = H.Mapped{ .samples = samples, .map = &p.layout.native(i), .fixed_start = fixed_start, .fixed_count = member.native.?.fixed.len };
        const n = 8 + claims.native.len;
        count += try Native.recordEquationsWithInterstitial(.{ .shape = metadata.shape, .external_retirements = 0, .register_custody_mode = 1, .projections = member.native.?.layout.slots, .slots = &.{}, .tree_count = 3 }, mapped, public[at..][0..n], draws[0..47].*, H.flattenWord(draws), random, G.pointFromSeed(seed), p.shape.mask_log, &accumulated, H.GuardRecorder{ .guards = member.native.?.guards, .gaps = &.{}, .gap_sums = &.{}, .range16 = H.symbolicRelation(1, draws[48]) });
        at += n + Endpoint.PLANES;
        fixed_start += mapped.fixed_count;
    }
    for (p.statement.input.members, p.scope.member, 0..) |metadata, member, i| {
        const mapped = H.Mapped{ .samples = samples, .map = &p.layout.endpoint(i), .fixed_start = fixed_start, .fixed_count = Endpoint.Spec.FIXED_COUNT };
        const port = offsets[i] + 8 + p.claims.members[i].native.len;
        count += try H.endpoint(mapped, try @import("../../prover/block_v8_native_endpoint_local_source_v1.zig").endpointLog(metadata.endpoint_count), p.shape.mask_log, member.endpoint_policy, draws, public[port..][0..Endpoint.PLANES].*, random, seed, &accumulated);
        fixed_start += mapped.fixed_count;
    }
    {
        const mapped = H.Mapped{ .samples = samples, .map = &p.layout.range(), .fixed_start = fixed_start, .fixed_count = Provider.FIXED_COUNT };
        try H.provider(mapped, p.shape.mask_log, draws, public[at..][0..Provider.PLANES].*, random, seed, &accumulated);
        count += Provider.CONSTRAINT_COUNT;
        at += Provider.PLANES;
        fixed_start += mapped.fixed_count;
    }
    {
        const mapped = H.Mapped{ .samples = samples, .map = &p.layout.program(), .fixed_start = fixed_start, .fixed_count = p.context.program.?.fixed_columns.len };
        try H.program(t, p, mapped, public[at], draws[0..47].*, random, seed, p.shape.mask_log, &accumulated);
        for (p.context.program.?.verifiers) |component| count += component.nConstraints();
        at += 1;
        fixed_start += mapped.fixed_count;
    }
    {
        const mapped = H.Mapped{ .samples = samples, .map = &p.layout.lookup(), .fixed_start = fixed_start, .fixed_count = p.context.lookup.?.fixed_columns.len };
        const flat = try mapped.offsets4();
        inline for (0..6) |kind_index| {
            const kind: Lookup.Schema.Kind = @enumFromInt(kind_index);
            const domain = @field(@import("../../air/lang/relation.zig").Domain, @tagName(kind));
            inline for (.{ Lookup.Mode.dense, Lookup.Mode.sparse }) |mode| if (p.statement.input.lookup_layout.parts[kind_index].mode == mode) try @import("block_v7_lookup_compact_composition_v1.zig").recordPart(kind, mode, p.shape.mask_log, p.statement.input.lookup_layout.parts[kind_index], flat, samples.values, public[at + kind_index], draws[@intFromEnum(domain)], random, seed, &accumulated);
        }
        for (p.context.lookup.?.verifiers) |component| count += component.nConstraints();
        at += 6;
        fixed_start += mapped.fixed_count;
    }
    if (count != p.constraint_count or fixed_start != p.shape.columns[0].len) return error.InvalidGroupCompositionRoster;
    const chunks = try t.alloc(S, core.verifier_types.compositionChunkCount(p.shape.split) orelse return error.InvalidGroupCompositionGeometry);
    for (chunks, 0..) |*chunk, i| {
        var limbs: [4]S = undefined;
        for (&limbs, 0..) |*limb, half| limb.* = try samples.at(p.layout.traces(), 4 * i + half, 0);
        chunk.* = G.fromPartialEvals(limbs);
    }
    try builder.constrainZero((try G.reconstructSplitComposition(chunks, G.pointFromSeed(seed), p.shape.composition_log, p.shape.split)).sub(accumulated));
    try Closure.record(t, &builder, p, public[0..at], public[at..], draws);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    return .{ .allocator = a, .circuit = circuit, .sources = try sources.toOwnedSlice(a) };
}
pub fn prepare(a: std.mem.Allocator, p: *const Profile.Owned, capture: *const Original.VerifiedCapture) !@import("blake3_execution_composition.zig").Prepared {
    try p.requireCapture(capture);
    var compiled = try compile(a, p);
    var owns_graph = true;
    defer if (owns_graph) compiled.deinit();
    var arena = std.heap.ArenaAllocator.init(a);
    errdefer arena.deinit();
    const t = arena.allocator();
    const public = try publicValues(t, p);
    const draws = try @import("block_v7_memory_joint_inputs_mode_v1.zig").ForMode(true).challenges(t, p.scope.epoch);
    const inputs = try t.alloc(Q, compiled.sources.len);
    for (inputs, compiled.sources) |*value, source| value.* = switch (source) {
        .sample => |i| if (i < capture.proof.sampled_values.len) capture.proof.sampled_values[i] else return error.InvalidGroupCompositionSample,
        .public_input => |i| if (i < public.len) public[i] else return error.InvalidGroupCompositionPublic,
        .challenge => |i| if (i < draws.len) draws[i] else return error.InvalidGroupCompositionChallenge,
        .composition => capture.proof.composition_randomness,
        .oods => capture.proof.oods_seed,
        else => return error.InvalidGroupCompositionSource,
    };
    const values = try t.alloc(Q, compiled.circuit.nodes.len);
    try compiled.circuit.evaluateInto(inputs, values);
    const sources = try t.dupe(Source, compiled.sources);
    var result = @import("blake3_execution_composition.zig").Prepared{ .arena = arena, .circuit = compiled.circuit, .inputs = inputs, .sources = sources, .values = values, .key_id = p.seal, .capture_seal = capture.final_channel.digestBytes(), .seal = undefined };
    result.seal = result.identity();
    a.free(compiled.sources);
    owns_graph = false;
    return result;
}
