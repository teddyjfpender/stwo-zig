//! Narrow compile and mutation gate for the partial V3 link proof manifest.
const std = @import("std");
const subject = @import("recursion/air/segment_leaf_wrapper_link_manifest_v3.zig");
const program_mod = @import("recursion/ethereum_leaf_link_program_v1.zig");
const source_air = @import("recursion/air/ethereum_leaf_link_source_v1.zig");
const projection_air = @import("recursion/air/ethereum_leaf_link_projection_v1.zig");
const arithmetic_air = @import("recursion/air/ethereum_leaf_link_arithmetic_v1.zig");
const relation_binding = @import("recursion/air/universal_relation_binding.zig");
const universal = @import("recursion/air/universal_challenges.zig");
const QM31 = @import("stwo_core").fields.qm31.QM31;

test "V3 link extension manifest pins typed geometry but refuses publication" {
    var program = try program_mod.ProgramV1.init(std.testing.allocator);
    defer program.deinit();
    const original = try subject.Manifest.build(std.testing.allocator, &program);
    try original.validateAgainst(&program);
    try checkAdapter(source_air, subject.SourceAdapter, .link_source, &original);
    try checkAdapter(projection_air, subject.ProjectionAdapter, .link_projection, &original);
    try checkAdapter(arithmetic_air, subject.ArithmeticAdapter, .link_arithmetic, &original);
    try std.testing.expectEqual(@as(u32, 4), (try original.placement(.link_arithmetic)).geometry.log_size);
    try std.testing.expectError(error.V3WrapperProofUnavailable, original.requireCompleteWrapperProof());
    var changed = original;
    changed.placements[subject.keyIndex(.link_arithmetic)].?.geometry.semantic_digest[0] ^= 1;
    try std.testing.expectError(error.InvalidV3LinkManifest, changed.validate());
    changed = original;
    changed.placements[subject.keyIndex(.link_source)].?.geometry.log_size += 1;
    try std.testing.expectError(error.InvalidV3LinkManifest, changed.validateAgainst(&program));
}

fn checkAdapter(comptime Air: type, comptime Adapter: type, comptime key: subject.ComponentKey, manifest: *const subject.Manifest) !void {
    var definition = try Air.build(std.testing.allocator);
    defer definition.deinit();
    const plan = try relation_binding.Binding(Air).authenticate(&definition);
    const relations = universal.UniversalRelations.dummy();
    const placement = try manifest.placement(key);
    const component = try Adapter.init(
        &definition,
        plan,
        manifest,
        key,
        placement.geometry.log_size,
        .{},
        &relations,
        QM31.zero(),
    );
    try std.testing.expectEqual(
        @as(usize, placement.geometry.direct_constraints) + placement.geometry.interaction_batches,
        component.nConstraints(),
    );
    _ = try component.binding(manifest);
}
