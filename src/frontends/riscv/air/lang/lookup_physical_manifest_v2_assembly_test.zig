const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const subject = @import("lookup_physical_manifest_v2.zig");
const fixture = @import("lookup_physical_manifest_v2_test.zig");
const statement_mod = @import("../statement.zig");
const relations_mod = @import("../relation_challenges.zig");
const proof_finalize = @import("../../prover/proof_finalize.zig");
const verifier = @import("../../prover/verifier.zig");
const proof_workspace = @import("../../prover/proof_workspace.zig");

test "lookup polynomial v2: authenticated prover and verifier construction share physical authority" {
    const allocator = std.testing.allocator;
    var manifest = subject.Manifest.native();
    var statement = fixture.canonicalStatement();
    const authenticated = try subject.AuthenticatedStatement.init(
        &statement,
        &manifest,
    );
    const claim = try allocator.create(statement_mod.RiscVInteractionClaim);
    defer allocator.destroy(claim);
    claim.initZeroInto();
    claim.n_components = statement.n_components;
    claim.n_infra = 0;
    const relations = relations_mod.Relations.dummy();

    const prover_workspace = try proof_workspace.ProofWorkspace.create(allocator);
    defer prover_workspace.destroy(allocator);
    prover_workspace.statement = statement;
    const prover_components = try proof_finalize.assembleAuthenticatedLookupV2(
        prover_workspace,
        &relations,
        claim,
        authenticated.opcode_main_columns,
        authenticated.opcode_interaction_columns,
        &manifest,
        &authenticated,
    );
    try std.testing.expectEqual(@as(usize, 34), prover_components.len);
    for (statement.component_descs[0..statement.n_components], 0..) |
        descriptor,
        index,
    | {
        const physical = manifest.entryForFamily(descriptor.family);
        const component = &prover_workspace.components.opcode_lookup[index];
        try std.testing.expectEqual(
            @as(usize, physical.detailed_claim_count),
            component.nConstraints(),
        );
        try std.testing.expectEqual(
            @as(usize, physical.interaction_column_count),
            component.interactionColumnCount(),
        );
        const capability = component.asProverComponent()
            .backend_composition_capability orelse
            return error.MissingAuthenticatedV2Capability;
        switch (capability) {
            .lookup_polynomial_v2 => |value| {
                try std.testing.expectEqualDeep(
                    physical.lookup_authority,
                    value.authority.*,
                );
                try std.testing.expectEqual(
                    @as(usize, physical.interaction_column_count),
                    value.interaction_column_count,
                );
            },
            else => return error.WrongAuthenticatedV2Capability,
        }
    }

    const verifier_workspace =
        try proof_workspace.VerificationWorkspace.create(allocator);
    defer verifier_workspace.destroy(allocator);
    const verifier_components =
        try verifier.assembleComponentsAuthenticatedLookupV2(
            verifier_workspace,
            &statement,
            claim,
            &relations,
            authenticated.opcode_main_columns,
            authenticated.opcode_interaction_columns,
            &manifest,
            &authenticated,
        );
    try std.testing.expectEqual(prover_components.len, verifier_components.len);
    for (0..statement.n_components) |index| {
        try std.testing.expectEqual(
            prover_workspace.components.opcode_lookup[index].nConstraints(),
            verifier_workspace.components.opcode_lookup[index].nConstraints(),
        );
    }
}

test "lookup polynomial v2: failed admission is atomic and V1 stays the default" {
    const allocator = std.testing.allocator;
    var manifest = subject.Manifest.native();
    var statement = fixture.canonicalStatement();
    const authenticated = try subject.AuthenticatedStatement.init(
        &statement,
        &manifest,
    );
    const claim = try allocator.create(statement_mod.RiscVInteractionClaim);
    defer allocator.destroy(claim);
    claim.initZeroInto();
    claim.n_components = statement.n_components;
    claim.n_infra = 0;
    const relations = relations_mod.Relations.dummy();

    const rejected_workspace =
        try proof_workspace.ProofWorkspace.create(allocator);
    defer rejected_workspace.destroy(allocator);
    rejected_workspace.statement = statement;
    var wrong_activation = authenticated;
    wrong_activation.activation_identity[0] ^= 1;
    try std.testing.expectError(
        error.InvalidActivationIdentity,
        proof_finalize.assembleAuthenticatedLookupV2(
            rejected_workspace,
            &relations,
            claim,
            authenticated.opcode_main_columns,
            authenticated.opcode_interaction_columns,
            &manifest,
            &wrong_activation,
        ),
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        rejected_workspace.components.active().len,
    );

    const compatibility_workspace =
        try proof_workspace.ProofWorkspace.create(allocator);
    defer compatibility_workspace.destroy(allocator);
    compatibility_workspace.statement = statement;
    const compatibility_components = try proof_finalize.assemble(
        compatibility_workspace,
        &relations,
        claim,
        statement.nMainColumns(),
        statement.nInteractionColumns(),
    );
    try std.testing.expectEqual(@as(usize, 34), compatibility_components.len);
    for (0..statement.n_components) |index| {
        const capability = compatibility_workspace.components
            .opcode_lookup[index].asProverComponent()
            .backend_composition_capability orelse
            return error.MissingCompatibilityCapability;
        switch (capability) {
            .lookup_polynomial_v1 => {},
            else => return error.V1DefaultChanged,
        }
    }
    try std.testing.expectEqual(
        @as(u32, 620),
        statement.nInteractionColumns(),
    );
}

comptime {
    // Construction has no allocator parameter: the physical manifest removes
    // the planner/arena allocation seam from both registry directions.
    _ = prover_component.LookupPolynomialCapabilityV2;
}
