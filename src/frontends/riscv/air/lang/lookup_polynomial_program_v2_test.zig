const std = @import("std");
const stwo_core = @import("stwo_core");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prepared_v2 = @import("stwo_prover_engine").air.lookup_polynomial_v2;
const subject = @import("lookup_polynomial_program_v2.zig");
const selected_batching = @import("lookup_batch_execution.zig");
const runtime_program = @import("../extract/runtime_program.zig");
const entry = @import("../lookups/entry.zig");
const opcode_component = @import("../lookups/opcode_component.zig");
const opcode_entries = @import("../lookups/opcode_entries.zig");
const relations_mod = @import("../relation_challenges.zig");
const trace = @import("../../runner/trace.zig");

const M31 = stwo_core.fields.m31.M31;
const QM31 = stwo_core.fields.qm31.QM31;

test "lookup polynomial v2: every selected family lowers into exact authenticated authority" {
    var selected_batches: usize = 0;
    var selected_columns: usize = 0;
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var plan = try selected_batching.FamilyPlan.initNativeV1(
            std.testing.allocator,
            family,
        );
        defer plan.deinit();
        var program = try subject.lowerSelected(std.testing.allocator, &plan);
        defer program.deinit();

        const authority = try program.authority();
        try program.validateAgainst(&authority);
        try std.testing.expectEqual(
            plan.selection.program_digest,
            authority.component_identity,
        );
        try std.testing.expectEqual(
            plan.selection.plan_digest,
            authority.partition_identity,
        );
        try std.testing.expectEqual(
            @as(usize, plan.selection.event_count),
            program.entries.len,
        );
        try std.testing.expectEqual(plan.batchCount(), program.batchCount());
        try std.testing.expectEqual(
            @as(usize, plan.selection.score.interaction_columns),
            program.interactionColumnCount(),
        );
        try std.testing.expectEqual(
            plan.selection.score.maximum_interaction_degree,
            program.layout.maximum_interaction_degree,
        );
        try std.testing.expectEqual(
            plan.selection.policy.maximum_interaction_degree,
            program.layout.degree_cap,
        );
        for (program.event_degrees, 0..) |event, ordinal|
            try std.testing.expectEqual(@as(u32, @intCast(ordinal)), event.ordinal);
        selected_batches += program.batchCount();
        selected_columns += program.interactionColumnCount();
    }
    try std.testing.expectEqual(@as(usize, 137), selected_batches);
    try std.testing.expectEqual(@as(usize, 548), selected_columns);
}

test "lookup polynomial v2: uniform selections retain exact v1 program and layout" {
    var uniform_families: usize = 0;
    var selected_families: usize = 0;
    for (0..trace.N_FAMILIES) |family_index| {
        const family: trace.OpcodeFamily = @enumFromInt(family_index);
        var plan = try selected_batching.FamilyPlan.initNativeV1(
            std.testing.allocator,
            family,
        );
        defer plan.deinit();
        var selected = try subject.lowerSelected(std.testing.allocator, &plan);
        defer selected.deinit();
        var legacy = try runtime_program.buildLookups(
            std.testing.allocator,
            family,
        );
        defer legacy.deinit();

        const selected_parameter_count = try selected.parameterCount();
        try std.testing.expectEqual(
            legacy.parameterCount() - legacy.batchCount() + selected.batchCount(),
            selected_parameter_count,
        );
        if (selected.isExactUniformV1(&legacy)) {
            uniform_families += 1;
            try std.testing.expectEqual(
                opcode_entries.batchCount(family),
                selected.batchCount(),
            );
        } else {
            selected_families += 1;
            try std.testing.expect(
                selected.batchCount() < opcode_entries.batchCount(family),
            );
        }
    }
    try std.testing.expectEqual(@as(usize, 14), uniform_families);
    try std.testing.expectEqual(@as(usize, 3), selected_families);
}

test "lookup polynomial v2: layout coverage degree capacity and identities fail closed" {
    var plan = try selected_batching.FamilyPlan.initNativeV1(
        std.testing.allocator,
        .div,
    );
    defer plan.deinit();
    var program = try subject.lowerSelected(std.testing.allocator, &plan);
    defer program.deinit();
    const authority = try program.authority();

    const format_version = program.layout.format_version;
    program.layout.format_version +%= 1;
    try std.testing.expectError(error.InvalidLayoutVersion, program.validate());
    program.layout.format_version = format_version;

    const component_identity = program.layout.component_identity;
    program.layout.component_identity = .{0} ** 32;
    try std.testing.expectError(error.InvalidComponentIdentity, program.validate());
    program.layout.component_identity = component_identity;

    const partition_identity = program.layout.partition_identity;
    program.layout.partition_identity = .{0} ** 32;
    try std.testing.expectError(error.InvalidPartitionIdentity, program.validate());
    program.layout.partition_identity = partition_identity;

    const column_count = program.layout.column_count;
    program.layout.column_count = 0;
    try std.testing.expectError(error.InvalidColumnCapacity, program.validate());
    program.layout.column_count = column_count;

    program.layout.entry_count -= 1;
    try std.testing.expectError(error.InvalidEntryCount, program.validate());
    program.layout.entry_count += 1;

    program.layout.batch_count -= 1;
    try std.testing.expectError(error.InvalidBatchCount, program.validate());
    program.layout.batch_count += 1;

    program.layout.interaction_column_count -=
        prover_component.LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES;
    try std.testing.expectError(
        error.InvalidInteractionCapacity,
        program.validate(),
    );
    program.layout.interaction_column_count +=
        prover_component.LOOKUP_POLYNOMIAL_LAYOUT_V2_INTERACTION_COORDINATES;

    const degree_cap = program.layout.degree_cap;
    program.layout.degree_cap = 0;
    try std.testing.expectError(error.InvalidDegreeCap, program.validate());
    program.layout.degree_cap = degree_cap;

    program.layout.maximum_interaction_degree += 1;
    try std.testing.expectError(error.InvalidMaximumDegree, program.validate());
    program.layout.maximum_interaction_degree -= 1;

    program.event_degrees[1].ordinal = 0;
    try std.testing.expectError(error.InvalidEventOrder, program.validate());
    program.event_degrees[1].ordinal = 1;

    const numerator_degree = program.event_degrees[0].numerator_degree;
    program.event_degrees[0].numerator_degree =
        prover_component.LOOKUP_POLYNOMIAL_LAYOUT_V2_MAXIMUM_DEGREE + 1;
    try std.testing.expectError(error.InvalidEventDegree, program.validate());
    program.event_degrees[0].numerator_degree = numerator_degree;

    program.batches[0].first_entry = 1;
    try std.testing.expectError(error.InvalidBatchCoverage, program.validate());
    program.batches[0].first_entry = 0;

    const first_width = program.batches[0].entry_count;
    program.batches[0].entry_count = 0;
    try std.testing.expectError(error.InvalidBatchWidth, program.validate());
    program.batches[0].entry_count = first_width;

    program.batches[0].interaction_degree += 1;
    try std.testing.expectError(error.InvalidBatchDegree, program.validate());
    program.batches[0].interaction_degree -= 1;

    program.layout.layout_identity[0] ^= 1;
    try std.testing.expectError(error.InvalidLayoutIdentity, program.validate());
    program.layout.layout_identity[0] ^= 1;

    const first_arity = program.entries[0].arity;
    program.entries[0].arity = 0;
    try std.testing.expectError(error.InvalidEntry, program.validate());
    program.entries[0].arity = first_arity;

    const node_index = firstDerivedNode(program.nodes);
    const node = program.nodes[node_index];
    program.nodes[node_index].lhs = @intCast(node_index);
    try std.testing.expectError(error.InvalidNode, program.validate());
    program.nodes[node_index] = node;

    program.program_identity[0] ^= 1;
    try std.testing.expectError(error.InvalidProgramIdentity, program.validate());
    program.program_identity[0] ^= 1;

    var wrong_component = component_identity;
    wrong_component[0] ^= 1;
    var wrong_authority = authority;
    wrong_authority.component_identity = wrong_component;
    try std.testing.expectError(
        error.InvalidComponentIdentity,
        program.validateAgainst(&wrong_authority),
    );
    var wrong_partition = partition_identity;
    wrong_partition[0] ^= 1;
    wrong_authority = authority;
    wrong_authority.partition_identity = wrong_partition;
    try std.testing.expectError(
        error.InvalidPartitionIdentity,
        program.validateAgainst(&wrong_authority),
    );

    // A self-consistent re-seal still cannot substitute a different selected
    // partition for the caller's pinned plan identity.
    program.layout.partition_identity[0] ^= 1;
    program.layout.layout_identity = program.layout.identityDigest(
        program.event_degrees,
        program.batches,
    );
    try program.seal();
    try program.validate();
    try std.testing.expectError(
        error.InvalidPartitionIdentity,
        program.validateAgainst(&authority),
    );
}

test "lookup polynomial v2: lowering is deterministic and owns its plan projection" {
    var plan = try selected_batching.FamilyPlan.initNativeV1(
        std.testing.allocator,
        .mul,
    );
    defer plan.deinit();
    var first = try subject.lowerSelected(std.testing.allocator, &plan);
    defer first.deinit();
    var second = try subject.lowerSelected(std.testing.allocator, &plan);
    defer second.deinit();

    try std.testing.expectEqual(first.layout.layout_identity, second.layout.layout_identity);
    try std.testing.expectEqual(first.program_identity, second.program_identity);
    try std.testing.expectEqualSlices(
        prover_component.LookupPolynomialEventDegreeV2,
        first.event_degrees,
        second.event_degrees,
    );
    try std.testing.expectEqualSlices(
        prover_component.LookupPolynomialBatchV2,
        first.batches,
        second.batches,
    );

    const first_ordinal = first.event_degrees[0].ordinal;
    plan.events[0].ordinal = 99;
    try std.testing.expectEqual(first_ordinal, first.event_degrees[0].ordinal);
}

test "lookup polynomial v2: prepared capability matches exact v1 uniform evaluation" {
    try preparedDifferential(.lui, true);
}

test "lookup polynomial v2: prepared capability matches selected reference evaluation" {
    try preparedDifferential(.div, false);
}

test "lookup polynomial v2: capability identity degree capacity and resources fail closed" {
    var plan = try selected_batching.FamilyPlan.initNativeV1(
        std.testing.allocator,
        .div,
    );
    defer plan.deinit();
    var program = try subject.lowerSelected(std.testing.allocator, &plan);
    defer program.deinit();
    const authority = try program.authority();
    const relations = relations_mod.Relations.dummy();
    var claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    fillClaims(claims[0..plan.batchCount()]);
    const component = try opcode_component.OpcodeLookupComponent.initSelectedProverV2(
        &plan,
        authority,
        5,
        0,
        0,
        0,
        &relations,
        claims[0..plan.batchCount()],
    );
    const prover = component.asProverComponent();
    const capability = try selectedCapability(prover);

    var wrong_identity = capability;
    var wrong_identity_authority = capability.authority.*;
    wrong_identity_authority.program_identity[0] ^= 1;
    wrong_identity.authority = &wrong_identity_authority;
    try std.testing.expectError(
        error.InvalidProgramIdentity,
        prepared_v2.PreparedCapability.init(
            std.testing.allocator,
            prover.ctx,
            wrong_identity,
            component.nConstraints(),
        ),
    );

    var wrong_degree = capability;
    var wrong_degree_authority = capability.authority.*;
    wrong_degree_authority.maximum_interaction_degree += 1;
    wrong_degree.authority = &wrong_degree_authority;
    try std.testing.expectError(
        error.InvalidAuthorityGeometry,
        prepared_v2.PreparedCapability.init(
            std.testing.allocator,
            prover.ctx,
            wrong_degree,
            component.nConstraints(),
        ),
    );

    var wrong_capacity = capability;
    wrong_capacity.interaction_column_count += 4;
    try std.testing.expectError(
        error.InvalidCapabilityGeometry,
        prepared_v2.PreparedCapability.init(
            std.testing.allocator,
            prover.ctx,
            wrong_capacity,
            component.nConstraints(),
        ),
    );
    try std.testing.expectError(
        error.InvalidCapabilityGeometry,
        prepared_v2.PreparedCapability.init(
            std.testing.allocator,
            prover.ctx,
            capability,
            component.nConstraints() + 1,
        ),
    );

    try std.testing.expectError(
        error.InvalidPreparedCapacity,
        prepared_v2.evaluatorScratchBytes(
            prepared_v2.MAX_PROGRAM_NODES + 1,
            1,
            1,
        ),
    );
    try std.testing.expectError(
        error.ResourceReservationOverflow,
        prepared_v2.evaluatorScratchBytes(std.math.maxInt(usize), 1, 1),
    );
    try std.testing.expectError(
        error.ResourceReservationOverflow,
        prepared_v2.capabilityResidentBytes(
            &program,
            std.math.maxInt(usize),
            1,
        ),
    );

    program.layout.column_count = @intCast(prepared_v2.MAX_MAIN_COLUMNS + 1);
    program.layout.layout_identity = program.layout.identityDigest(
        program.event_degrees,
        program.batches,
    );
    try program.seal();
    const oversized_authority = try program.authority();
    const parameters = try capability.export_parameters(
        prover.ctx,
        std.testing.allocator,
    );
    defer std.testing.allocator.free(parameters);
    try std.testing.expectError(
        error.InvalidPreparedCapacity,
        prepared_v2.PreparedEvaluator.init(
            std.testing.allocator,
            &program,
            &oversized_authority,
            parameters,
        ),
    );
}

test "lookup polynomial v2: prepared scratch construction is allocation-failure clean" {
    var plan = try selected_batching.FamilyPlan.initNativeV1(
        std.testing.allocator,
        .mul,
    );
    defer plan.deinit();
    var program = try subject.lowerSelected(std.testing.allocator, &plan);
    defer program.deinit();
    const authority = try program.authority();
    const relations = relations_mod.Relations.dummy();
    var claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    fillClaims(claims[0..plan.batchCount()]);
    const component = try opcode_component.OpcodeLookupComponent.initSelectedProverV2(
        &plan,
        authority,
        5,
        0,
        0,
        0,
        &relations,
        claims[0..plan.batchCount()],
    );
    const prover = component.asProverComponent();
    const capability = try selectedCapability(prover);
    const parameters = try capability.export_parameters(
        prover.ctx,
        std.testing.allocator,
    );
    defer std.testing.allocator.free(parameters);
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        preparedAllocationFailureCase,
        .{ &program, &authority, parameters },
    );
}

fn firstDerivedNode(nodes: []const prover_component.BasePolynomialNode) usize {
    for (nodes, 0..) |node, index| switch (node.op) {
        .add, .sub, .mul, .neg => return index,
        .constant, .column => {},
    };
    unreachable;
}

fn preparedDifferential(
    family: trace.OpcodeFamily,
    expect_uniform_v1: bool,
) !void {
    var plan = try selected_batching.FamilyPlan.initNativeV1(
        std.testing.allocator,
        family,
    );
    defer plan.deinit();
    var authority_program = try subject.lowerSelected(
        std.testing.allocator,
        &plan,
    );
    defer authority_program.deinit();
    const authority = try authority_program.authority();
    const relations = relations_mod.Relations.dummy();
    var claims = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    fillClaims(claims[0..plan.batchCount()]);
    const component = try opcode_component.OpcodeLookupComponent.initSelectedProverV2(
        &plan,
        authority,
        5,
        0,
        0,
        0,
        &relations,
        claims[0..plan.batchCount()],
    );
    const prover = component.asProverComponent();
    const capability = try selectedCapability(prover);
    var prepared = try prepared_v2.PreparedCapability.init(
        std.testing.allocator,
        prover.ctx,
        capability,
        component.nConstraints(),
    );
    defer prepared.deinit();

    try std.testing.expectEqual(
        @as(usize, 0),
        prepared_v2.EVALUATE_ROW_ALLOCATION_COUNT,
    );
    try std.testing.expect(prepared.resources().shared_resident_bytes > 0);
    try std.testing.expectEqual(
        authority.program_identity,
        prepared.program.program_identity,
    );

    const n_main = trace.nColumnsForFamily(family);
    const n_batches = plan.batchCount();
    var main = [_]M31{M31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    var secure_main = [_]QM31{QM31.zero()} ** trace.MAX_FAMILY_COLUMNS;
    for (main[0..n_main], secure_main[0..n_main], 0..) |*base, *secure, index| {
        base.* = M31.fromU64(index * 65_537 + 19);
        secure.* = QM31.fromBase(base.*);
    }
    var current = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    var previous = [_]QM31{QM31.zero()} ** entry.MAX_BATCHES;
    for (current[0..n_batches], previous[0..n_batches], 0..) |
        *current_value,
        *previous_value,
        index,
    | {
        current_value.* = QM31.fromU32Unchecked(
            @intCast(index + 101),
            @intCast(index + 211),
            @intCast(index + 307),
            @intCast(index + 401),
        );
        previous_value.* = QM31.fromU32Unchecked(
            @intCast(index + 17),
            @intCast(index + 29),
            @intCast(index + 43),
            @intCast(index + 59),
        );
    }
    const selector = M31.one();
    const actual = try prepared.evaluator.evaluateRow(
        main[0..n_main],
        current[0..n_batches],
        previous[0..n_batches],
        selector,
    );
    const selected_reference = try component.evaluateRow(
        secure_main[0..n_main],
        current[0..n_batches],
        previous[0..n_batches],
        QM31.fromBase(selector),
    );
    try expectConstraintsEqual(
        selected_reference.values[0..selected_reference.len],
        actual,
    );

    if (expect_uniform_v1) {
        const compatibility = try opcode_component.OpcodeLookupComponent.initVerifier(
            family,
            5,
            0,
            0,
            0,
            &relations,
            claims[0..n_batches],
        );
        const legacy_reference = try compatibility.evaluateRow(
            secure_main[0..n_main],
            current[0..n_batches],
            previous[0..n_batches],
            QM31.fromBase(selector),
        );
        try expectConstraintsEqual(
            legacy_reference.values[0..legacy_reference.len],
            actual,
        );
        try std.testing.expectEqual(
            opcode_entries.batchCount(family),
            n_batches,
        );
    } else {
        try std.testing.expect(n_batches < opcode_entries.batchCount(family));
    }
}

fn selectedCapability(
    component: prover_component.ComponentProver,
) !prover_component.LookupPolynomialCapabilityV2 {
    const capability = component.backend_composition_capability orelse
        return error.MissingSelectedV2Capability;
    return switch (capability) {
        .lookup_polynomial_v2 => |selected| selected,
        else => error.UnexpectedSelectedV2Capability,
    };
}

fn fillClaims(claims: []QM31) void {
    for (claims, 0..) |*claim, index| {
        claim.* = QM31.fromU32Unchecked(
            @intCast(index + 701),
            @intCast(index + 809),
            @intCast(index + 907),
            @intCast(index + 1_009),
        );
    }
}

fn expectConstraintsEqual(expected: []const QM31, actual: []const QM31) !void {
    try std.testing.expectEqual(expected.len, actual.len);
    for (expected, actual) |want, got|
        try std.testing.expect(want.eql(got));
}

fn preparedAllocationFailureCase(
    allocator: std.mem.Allocator,
    program: *const prover_component.OwnedLookupPolynomialProgramV2,
    authority: *const prover_component.LookupPolynomialAuthorityV2,
    parameters: []const QM31,
) !void {
    var prepared = try prepared_v2.PreparedEvaluator.init(
        allocator,
        program,
        authority,
        parameters,
    );
    defer prepared.deinit();
}
