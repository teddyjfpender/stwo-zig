const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const backend = @import("typed_poseidon2_degree5_backend.zig");
const candidate_mod = @import("typed_poseidon2_degree_bounded_candidate.zig");
const component_mod = @import("typed_poseidon2_degree5_component.zig");
const relations_mod = @import("../relation_challenges.zig");

test "degree-five backend export covers the exact direct and lookup relation" {
    var candidate = try candidate_mod.Candidate.init(
        std.testing.allocator,
        .degree5,
    );
    defer candidate.deinit();
    const relations = relations_mod.Relations.dummy();
    const component = try component_mod.Component.init(
        &candidate,
        8,
        193,
        3,
        4,
        11,
        17,
        &relations,
        .{ QM31.zero(), QM31.zero() },
    );

    const capability = backend.capability().base_lookup_polynomial_v1;
    const prover_component = backend.asProverComponent(&component);
    try std.testing.expect(prover_component.backend_composition_capability != null);
    const exported = try capability.export_capabilities(&component);
    try exported.validate(component_mod.CONSTRAINTS);
    try std.testing.expectEqual(@as(usize, 4), exported.base_partition_count);
    try std.testing.expectEqual(@as(usize, 227), exported.lookup_constraints.start);
    try std.testing.expectEqual(@as(usize, 2), exported.lookup_constraints.count);
    try std.testing.expectEqual(@as(u32, 8), exported.lookup.trace_log_size);
    try std.testing.expectEqual(@as(usize, 239), exported.lookup.main_column_count);
    try std.testing.expectEqual(@as(usize, 8), exported.lookup.interaction_column_count);

    var covered: usize = 0;
    for (exported.base_partitions[0..exported.base_partition_count]) |partition| {
        try std.testing.expectEqual(covered, partition.constraints.start);
        covered += partition.constraints.count;
        var program = try partition.capability.export_program(
            &component,
            std.testing.allocator,
        );
        defer program.deinit();
        try std.testing.expectEqual(@as(usize, 240), program.column_count);
        try std.testing.expectEqual(partition.constraints.count, program.roots.len);
        try std.testing.expectEqual(
            candidate.direct_program.nodes().len + 5,
            program.nodes.len,
        );
    }
    try std.testing.expectEqual(@as(usize, 227), covered);

    var lookups = try exported.lookup.export_program(
        &component,
        std.testing.allocator,
    );
    defer lookups.deinit();
    try std.testing.expectEqual(@as(usize, 239), lookups.column_count);
    try std.testing.expectEqual(@as(usize, 4), lookups.entries.len);
    try std.testing.expectEqual(@as(usize, 2), lookups.batchCount());
    try std.testing.expectEqual(@as(usize, 8), 4 * lookups.batchCount());

    const parameters = try exported.lookup.export_parameters(
        &component,
        std.testing.allocator,
    );
    defer std.testing.allocator.free(parameters);
    try std.testing.expectEqual(lookups.parameterCount(), parameters.len);
}

test "degree-five backend export rejects noncanonical partitions" {
    var candidate = try candidate_mod.Candidate.init(
        std.testing.allocator,
        .degree5,
    );
    defer candidate.deinit();
    try std.testing.expectError(
        error.InvalidCandidateBackendProgram,
        backend.exportDirectProgram(
            std.testing.allocator,
            &candidate,
            .{ .start = 226, .count = 2 },
        ),
    );
    try std.testing.expectError(
        error.InvalidCandidateBackendProgram,
        backend.exportDirectProgram(
            std.testing.allocator,
            &candidate,
            .{ .start = 0, .count = 0 },
        ),
    );
}
