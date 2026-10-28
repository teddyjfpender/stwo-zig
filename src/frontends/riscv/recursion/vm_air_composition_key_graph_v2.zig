//! Canonical VM composition graph compiled from authenticated geometry alone.
//! Dynamic sampled values, claims, relation draws, and roots are inputs to
//! this graph; none is accepted while constructing its key-owned nodes.
const std = @import("std");
const core = @import("stwo_core");
const graph = @import("air/composition_circuit.zig");
const circuit = @import("vm_air_composition_circuit.zig");
const geometry_mod = @import("vm_composition_base_geometry_v2.zig");
const lookup = @import("../air/lang/lookup_physical_manifest_v2.zig");
const selected_lookup = @import("vm_selected_lookup_compiler_v2.zig");
const relations_mod = @import("../air/relation_challenges.zig");
const transcript = @import("../air/transcript/claims.zig");
const base_graph = @import("ethereum_vm_composition_graph_base_v2.zig");
const support = @import("ethereum_vm_composition_graph_support_v2.zig");
const program = @import("ethereum_vm_composition_program_v2.zig");
const profile_mod = @import("vm_air_profile_v2.zig");
const key_profile = @import("detached_native_vm_profile_from_key_v1.zig");
const descriptors_mod = @import("detached_segment_authority_boundary_v1.zig");
const Scalar = support.Scalar;

pub const Owned = struct {
    builder: support.Builder,
    input_profile: graph.InputProfile,
    graph_digest: [32]u8,

    pub fn deinit(self: *Owned) void {
        self.builder.deinit();
        self.* = undefined;
    }

    pub fn lane(self: *const Owned) graph.VmLane {
        return .{
            .circuit_id = circuit.CIRCUIT_ID,
            .graph = .{
                .nodes = self.builder.nodes.items,
                .outputs = self.builder.outputs.items,
                .identity_digest = self.graph_digest,
            },
            .profile = self.input_profile,
            .bindings = self.builder.bindings.items,
        };
    }
};

pub fn build(
    allocator: std.mem.Allocator,
    profile: *const profile_mod.ProfileV2,
    manifest: *const lookup.Manifest,
    selected: *const selected_lookup.CompilerV2,
    geometry: *const geometry_mod.GeometryV2,
) !Owned {
    try profile.validate();
    try selected.validateAgainstManifest(manifest);
    try geometry.validateAgainst(profile);
    if (!std.mem.eql(u8, &selected.profile_identity, &profile.identity_digest) or
        !std.mem.eql(u8, &selected.authenticated_statement_identity, &profile.lookup_statement_identity) or
        !std.mem.eql(u8, &selected.activation_identity, &profile.lookup_activation_identity))
        return error.InvalidKeyGraphAuthority;
    const input_profile = graph.InputProfile{
        .sampled_value_count = geometry.sampled_value_count,
        .claimed_sum_count = profile.input_profile.claimed_sum_count,
        .relation_challenge_count = relations_mod.RELATION_COUNT,
        .transcript_claimed_sum_count = transcript.COMPONENT_COUNT,
        .vm_statement_root_count = 2,
        .vm_native_continuation_roots = true,
    };
    var builder = support.Builder.init(allocator);
    errdefer builder.deinit();
    try builder.reserve(try graph.vmInputCount(input_profile), profile.air_instruction_count + transcript.COMPONENT_COUNT + 1);
    circuit.installBuilder(&builder);
    defer circuit.uninstallBuilder();

    const selector = try builder.input(.segment_selector);
    const sampled = try allocator.alloc(Scalar, input_profile.sampled_value_count);
    defer allocator.free(sampled);
    for (sampled, 0..) |*value, index|
        value.* = try support.secureInput(&builder, .sampled_value, @intCast(index));
    const claims = try allocator.alloc(Scalar, input_profile.claimed_sum_count);
    defer allocator.free(claims);
    for (claims, 0..) |*value, index|
        value.* = try support.secureInput(&builder, .claimed_sum, @intCast(index));
    var aggregates: [transcript.COMPONENT_COUNT]Scalar = undefined;
    for (&aggregates, 0..) |*value, index|
        value.* = try support.secureInput(&builder, .transcript_claimed_sum, @intCast(index));
    var draws: [relations_mod.RELATION_COUNT][2]Scalar = undefined;
    for (&draws, 0..) |*pair, index| {
        pair[0] = try support.challengeInput(&builder, @intCast(index), 0);
        pair[1] = try support.challengeInput(&builder, @intCast(index), 4);
    }
    const randomness = try support.scalarInput(&builder, .composition_randomness);
    const seed = try support.scalarInput(&builder, .oods_point);
    const native_roots = [2]Scalar{
        try builder.input(.{ .native_continuation_root = 0 }),
        try builder.input(.{ .native_continuation_root = 1 }),
    };
    try program.bindTranscriptAggregates(&builder, selector, profile, null, claims, &aggregates);
    const relations = circuit.GraphRelations.init(draws);
    var layout = try support.SampleLayoutV2.init(allocator, geometry, null, sampled);
    defer layout.deinit();
    const point = support.pointFromSeed(seed);
    var denominators: [31]?Scalar = .{null} ** 31;
    const recorded = try base_graph.record(.legacy_role_filtered_v1, profile, manifest, selected, &layout, claims, &relations, native_roots, point, randomness, profile.max_log_degree_bound, &denominators);
    const composition = try support.reconstructComposition(&layout, point, profile.composition_log_degree_bound, profile.composition_log_split);
    try builder.constrainZero(selector.mul(composition.sub(recorded.accumulation)));
    try builder.check();
    return .{
        .builder = builder,
        .input_profile = input_profile,
        .graph_digest = graph.computeGraphDigest(builder.nodes.items, builder.outputs.items),
    };
}

/// Complete graph-only path from the leaf key's native descriptors and the
/// canonical PCS configuration. It never constructs a proof-bearing statement.
pub fn buildFromDescriptors(
    allocator: std.mem.Allocator,
    descriptors: descriptors_mod.DescriptorsV1,
    pcs_config: core.pcs.PcsConfig,
) !Owned {
    var profile = try key_profile.derive(allocator, descriptors, pcs_config);
    defer profile.deinit();
    const manifest = lookup.Manifest.native();
    const authenticated = try lookup.AuthenticatedStatement.initFromComponents(descriptors.components, &manifest);
    const selected = try selected_lookup.CompilerV2.initFromGeometry(
        allocator,
        .{ .components = descriptors.components, .infrastructure = descriptors.infrastructure },
        &manifest,
        &authenticated,
        &profile,
    );
    var geometry = try geometry_mod.GeometryV2.init(allocator, &profile);
    defer geometry.deinit();
    return build(allocator, &profile, &manifest, &selected, &geometry);
}

test "q193 VM graph is rebuilt from key descriptors without proof data" {
    const allocator = std.testing.allocator;
    const descriptors = @import("tests/q193_native_census_fixture.zig").DESCRIPTORS;
    var owner = try buildFromDescriptors(allocator, descriptors, @import("protocol.zig").PCS_CONFIG);
    defer owner.deinit();
    const expected_hex = "94fcde4244a3ca3f4ecd81a861257f05a68d7ff1ca23b3e1c80cb470a0d7df40";
    var expected: [32]u8 = undefined;
    _ = try std.fmt.hexToBytes(&expected, expected_hex);
    try std.testing.expectEqualDeep(expected, owner.lane().graph.identity_digest);
}
