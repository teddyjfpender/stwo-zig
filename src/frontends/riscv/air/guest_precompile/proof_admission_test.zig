const std = @import("std");
const component_order = @import("../component_order.zig");
const lookup_table_schema = @import("../lookups/tables/schema.zig");
const merkle_node = @import("../memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const public_data = @import("../public_data.zig");
const base_statement = @import("../statement.zig");
const artifact = @import("artifact_identity.zig");
const support = @import("main_trace_test_support.zig");
const proof_admission = @import("proof_admission.zig");
const extension_statement = @import("statement.zig");
const statement_validation = @import("../../prover/statement_validation.zig");

test "guest proof admission composes base rows with authenticated retirements" {
    const core = admittedCore(1);
    const extension = try extension_statement.ExtensionStatement.canonical(&core, 1);
    const identity = try artifact.Identity.canonical(&core, &extension);

    const reconstructed = try proof_admission.canonical(
        &core,
        &extension,
        .proof,
    );
    try std.testing.expect(std.meta.eql(identity, reconstructed));
    try proof_admission.validate(&core, &extension, identity, .proof);

    // The unchanged base profile continues to require one opcode-family row
    // for every retirement and therefore rejects this same core geometry.
    try std.testing.expectError(
        error.InvalidStatement,
        statement_validation.validate(core, .proof),
    );
}

test "guest proof admission accepts the canonical zero-call profile" {
    const core = admittedCore(0);
    const extension = try extension_statement.ExtensionStatement.canonical(&core, 0);
    const identity = try proof_admission.canonical(&core, &extension, .proof);
    try proof_admission.validate(&core, &extension, identity, .proof);
}

test "guest proof admission rejects row coefficient and artifact drift" {
    const core = admittedCore(2);
    const extension = try extension_statement.ExtensionStatement.canonical(&core, 2);
    const identity = try artifact.Identity.canonical(&core, &extension);

    var wrong_rows = core;
    wrong_rows.component_descs[0].n_rows += 1;
    try std.testing.expectError(
        error.CallCountMismatch,
        proof_admission.validate(&wrong_rows, &extension, identity, .proof),
    );

    var wrong_certificate = extension;
    wrong_certificate.admission.memory_relation_terms += 1;
    try std.testing.expectError(
        error.AdmissionCertificateMismatch,
        proof_admission.validate(&core, &wrong_certificate, identity, .proof),
    );

    var wrong_artifact = identity;
    wrong_artifact.statement_digest[0] ^= 1;
    try std.testing.expectError(
        error.StatementDigestMismatch,
        proof_admission.validate(&core, &extension, wrong_artifact, .proof),
    );

    try std.testing.expectError(
        error.InvalidStatement,
        statement_validation.validateWithRetirementSupplement(core, .proof, .{
            .rows = extension.counts.n_guest,
            .extra_memory_terms_per_row = proof_admission.extra_memory_terms_per_guest_row,
            .expected_memory_relation_terms = extension.admission.memory_relation_terms - 1,
        }),
    );
}

fn admittedCore(n_guest: u32) base_statement.RiscVStatement {
    var core = support.coreFixture(n_guest);
    core.public_data.completion = public_data.Completion.canonicalSelfLoop(
        core.final_pc,
    );
    const clock_update = core.infra_descs[2];
    core.infra_descs[2] = .{
        .kind = .merkle,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = merkle_node.N_MAIN_COLUMNS,
    };
    core.infra_descs[3] = .{
        .kind = .poseidon2,
        .log_size = 4,
        .n_rows = 0,
        .n_columns = poseidon2_air.N_MAIN_COLUMNS,
    };
    core.infra_descs[4] = clock_update;
    var index: usize = 5;
    for (component_order.lookupTables()) |kind| {
        core.infra_descs[index] = .{
            .kind = base_statement.infraKindForTable(kind),
            .log_size = lookup_table_schema.logSize(kind),
            .n_rows = @intCast(lookup_table_schema.size(kind)),
            .n_columns = 1,
        };
        index += 1;
    }
    core.n_infra = @intCast(index);
    return core;
}
