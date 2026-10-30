//! Exact original ROM equation with v7's public epoch challenge inputs.
const std = @import("std");
const core = @import("stwo_core");
const Q = core.fields.qm31.QM31;
const Profile = @import("../block_v7_program_fixed_profile_v1.zig");
const Original = @import("../../prover/block_v5_program_table_proof_v1.zig");
const R = @import("composition_graph_recorder.zig");
const S = R.Scalar;
const Source = @import("blake3_execution_composition.zig").Source;
pub const Compiled = struct {
    allocator: std.mem.Allocator,
    circuit: R.Circuit,
    sources: []Source,
    pub fn deinit(self: *Compiled) void {
        self.circuit.deinit();
        self.allocator.free(self.sources);
        self.* = undefined;
    }
};
fn input(builder: *R.Builder, a: std.mem.Allocator, sources: *std.ArrayList(Source), source: Source) !S {
    const symbol = try builder.input();
    try sources.append(a, source);
    return symbol.value;
}
pub fn compile(a: std.mem.Allocator, profile: *const Profile.Owned) !Compiled {
    try profile.validate();
    var arena = std.heap.ArenaAllocator.init(a);
    defer arena.deinit();
    const temp = arena.allocator();
    var definition = try Original.Air.build(temp);
    defer definition.deinit();
    const relation = try @import("universal_relation_binding.zig").Binding(Original.Air).authenticate(&definition);
    const drawn = try profile.input.policy.epoch.draw(temp);
    const manifest = Original.Roster.Manifest{ .log_sizes = .{profile.input.policy.plan.log_size} };
    const component = try Original.Roster.Component(Original.Air).init(&definition, relation, &manifest, .program, profile.input.policy.plan.log_size, .{}, &drawn.word.universal_prefix, Q.zero());
    var builder = R.Builder.init(a);
    defer builder.deinit();
    var sources: std.ArrayList(Source) = .empty;
    defer sources.deinit(a);
    const Samples = @import("block_v5_caller_arithmetic_composition_v1.zig").Samples;
    var samples = Samples{ .offsets = undefined, .layouts = undefined, .values = undefined };
    const values = try temp.alloc(S, try profile.sampleCount());
    var cursor: usize = 0;
    var flat: usize = 0;
    for (profile.columns, 0..) |columns, tree| {
        samples.offsets[tree] = try temp.alloc(usize, columns.len);
        samples.layouts[tree] = try temp.alloc(@import("../sample_point_layout.zig").Layout, columns.len);
        for (columns, 0..) |_, col| {
            const layout = profile.shape.layouts[flat];
            samples.offsets[tree][col] = cursor;
            samples.layouts[tree][col] = layout;
            for (0..layout.sampleCount()) |_| {
                values[cursor] = try input(&builder, a, &sources, .{ .sample = @intCast(cursor) });
                cursor += 1;
            }
            flat += 1;
        }
    }
    samples.values = values;
    // Keep the exact 106 exported epoch operands contiguous for the shared
    // challenge linker; ROM equations consume only the original first 47 pairs.
    var draws: [53][2]S = undefined;
    for (&draws, 0..) |*pair, i| for (pair, 0..) |*value, j| {
        value.* = try input(&builder, a, &sources, .{ .challenge = @intCast(2 * i + j) });
    };
    const randomness = try input(&builder, a, &sources, .composition);
    const seed = try input(&builder, a, &sources, .oods);
    const claim = try input(&builder, a, &sources, .{ .public_input = 0 });
    var fixed: [6]S = undefined;
    var current: [4]S = undefined;
    var previous: [4]S = undefined;
    for (&fixed, 0..) |*value, i| value.* = try samples.at(0, i, 0);
    for (&current, &previous, 0..) |*value, *prior, i| {
        value.* = try samples.at(2, i, 0);
        prior.* = try samples.at(2, i, -1);
    }
    try builder.activate();
    defer if (builder.active) builder.deactivate();
    var chunks: [4]S = undefined;
    for (&chunks, 0..) |*chunk, i| {
        var limbs: [4]S = undefined;
        for (&limbs, 0..) |*limb, j| limb.* = try samples.at(3, 4 * i + j, 0);
        chunk.* = R.fromPartialEvals(limbs);
    }
    const challenges = try R.ChallengeSet.init(draws[0..47].*);
    try @import("block_v5_program_table_composition_v1.zig").recordEquation(&builder, &component, fixed, current, previous, claim, &challenges, randomness, seed, chunks);
    builder.deactivate();
    var circuit = try builder.finish();
    errdefer circuit.deinit();
    return .{ .allocator = a, .circuit = circuit, .sources = try sources.toOwnedSlice(a) };
}
