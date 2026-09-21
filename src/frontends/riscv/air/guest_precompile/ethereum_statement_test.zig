const std = @import("std");
const component_order = @import("../component_order.zig");
const lookup_table_schema = @import("../lookups/tables/schema.zig");
const merkle_node = @import("../memory_commitment/merkle_node.zig");
const poseidon2_air = @import("../memory_commitment/poseidon2_air.zig");
const public_data = @import("../public_data.zig");
const base_statement = @import("../statement.zig");
const support = @import("main_trace_test_support.zig");
const statement = @import("ethereum_statement.zig");
const admission = @import("ethereum_proof_admission.zig");

test "Ethereum statement: heterogeneous retirement authority admits exactly" {
    const core = admittedCore(2);
    const extension = try statement.Statement.canonical(
        &core,
        1,
        1,
        shapes(1),
    );
    try admission.validate(&core, &extension, .proof);
    try std.testing.expectEqual(@as(u64, 88), extension.admission.extra_memory_terms);

    var wrong = extension;
    wrong.admission.extra_memory_terms += 1;
    try std.testing.expectError(
        error.AdmissionCertificateMismatch,
        admission.validate(&core, &wrong, .proof),
    );
    wrong = extension;
    wrong.counts.signer_calls += 1;
    try std.testing.expectError(
        error.CallCountMismatch,
        admission.validate(&core, &wrong, .proof),
    );
}

test "Ethereum statement: component order and signer count are fail closed" {
    const core = admittedCore(2);
    var extension = try statement.Statement.canonical(&core, 1, 1, shapes(1));
    const temporary = extension.components[0];
    extension.components[0] = extension.components[1];
    extension.components[1] = temporary;
    try std.testing.expectError(
        error.ComponentOrderMismatch,
        extension.validate(&core),
    );

    var wrong_shapes = shapes(1);
    wrong_shapes.recovery.n_rows = 2;
    try std.testing.expectError(
        error.CallCountMismatch,
        statement.Statement.canonical(&core, 1, 1, wrong_shapes),
    );
}

fn shapes(signer_calls: u32) statement.SecpShapes {
    const singleton = statement.Shape{ .log_size = 1, .n_rows = 1 };
    return .{
        .product_base = singleton,
        .product_scalar = singleton,
        .linear_base = singleton,
        .linear_scalar = singleton,
        .point = singleton,
        .split = singleton,
        .scalar = singleton,
        .table = singleton,
        .recovery = .{ .log_size = 1, .n_rows = signer_calls },
        .byte = .{ .log_size = 8, .n_rows = 256 },
        .recovery_caller = .{ .log_size = 1, .n_rows = signer_calls },
    };
}

fn admittedCore(external_retirements: u32) base_statement.RiscVStatement {
    var core = support.coreFixture(external_retirements);
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
