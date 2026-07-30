const std = @import("std");
const ir = @import("proof_program.zig");

const Fixture = struct {
    columns: [4]ir.TraceColumn = .{
        .{
            .id = 0,
            .component = 7,
            .ordinal = 0,
            .log_rows = 8,
            .role = .main,
        },
        .{
            .id = 1,
            .component = 7,
            .ordinal = 1,
            .log_rows = 8,
            .role = .main,
        },
        .{
            .id = 2,
            .component = 7,
            .ordinal = 2,
            .log_rows = 8,
            .role = .interaction,
        },
        .{
            .id = 3,
            .component = 7,
            .ordinal = 3,
            .log_rows = 8,
            .role = .composition,
        },
    },
    constraints: [1]ir.ConstraintProgram = .{.{
        .id = 0,
        .component = 7,
        .expression = ir.identityDigest("generic-native-constraint"),
        .constraint_count = 3,
        .max_degree_log = 2,
    }},
    commitments: [4]ir.CommitmentTree = .{
        tree(0, .preprocessed, 0, 0),
        tree(1, .main, 0, 2),
        tree(2, .interaction, 2, 1),
        tree(3, .composition, 3, 1),
    },
    barriers: [1]ir.TranscriptBarrier = .{.{
        .ordinal = 0,
        .node = 1,
        .phase = 0,
        .kind = .challenge,
        .value_count = 1,
    }},
    fri_layers: [1]ir.FriLayer = .{.{
        .tree_id = 0,
        .evaluation_log_rows = 9,
        .fold_step = 1,
        .cumulative_fold = 0,
        .log_rows_per_leaf = 9,
    }},
    buffers: [1]ir.Buffer = .{.{
        .id = 9,
        .words = 256,
        .alignment_words = 8,
        .live_from = .ingress,
        .live_through = .decommit,
        .storage = .request_local,
        .immutable = true,
    }},
    nodes: [2]ir.Node = .{
        node(0, .trace_generation, .trace_generation, 0, 0),
        node(1, .commitment, .trace_commit, 0, 1),
    },
    dependencies: [1]u32 = .{0},

    fn description(
        self: *const Fixture,
        native_contract: ?ir.NativeAirContract,
    ) ir.Description {
        return .{
            .identity = .{
                .frontend = .native,
                .air = ir.identityDigest("generic-native-air"),
                .statement = ir.identityDigest("generic-native-statement"),
                .protocol = ir.identityDigest("generic-native-protocol"),
            },
            .native_air_contract = native_contract,
            .trace_columns = &self.columns,
            .constraints = &self.constraints,
            .commitments = &self.commitments,
            .transcript = &self.barriers,
            .quotient = .{
                .term_count = 3,
                .group_count = 1,
                .evaluation_log_rows = 9,
                .composition_degree_log = 2,
            },
            .fri_layers = &self.fri_layers,
            .buffers = &self.buffers,
            .nodes = &self.nodes,
            .dependency_ids = &self.dependencies,
        };
    }
};

fn contract() ir.NativeAirContract {
    return .{
        .geometry = .{
            .component = 7,
            .log_rows = 8,
            .preprocessed_columns = 0,
            .main_columns = 2,
            .interaction_columns = 1,
        },
        .ingress = .{
            .recipe_identity = ir.identityDigest("materialized-host-trace"),
            .layout_abi_identity = ir.identityDigest("m31-column-major-v1"),
            .element_count = 3 * 256,
        },
        .statement = .{
            .transcript_recipe_identity = ir.identityDigest(
                "statement-transcript-v1",
            ),
            .public_input_abi_identity = ir.identityDigest(
                "public-input-abi-v1",
            ),
            .public_input_words = 3,
        },
        .sampling = .{
            .recipe_identity = ir.identityDigest("oods-sampling-v1"),
            .mask_layout_identity = ir.identityDigest("mask-layout-v1"),
            .mask_point_count = 3,
        },
        .constraint_parameters = .{
            .identity = ir.identityDigest("constraint-parameter-abi-v1"),
            .statement_words = 3,
            .challenge_words = 8,
            .parameter_words = 11,
        },
    };
}

fn tree(
    id: u32,
    role: ir.CommitmentRole,
    first_column: u32,
    column_count: u32,
) ir.CommitmentTree {
    return .{
        .id = id,
        .role = role,
        .first_column = first_column,
        .column_count = column_count,
        .evaluation_log_rows = 9,
        .log_rows_per_leaf = 9,
        .retain_openings = column_count != 0,
    };
}

fn node(
    id: u32,
    kind: ir.OperationKind,
    stage: ir.Stage,
    dependency_first: u32,
    dependency_count: u32,
) ir.Node {
    return .{
        .id = id,
        .kind = kind,
        .stage = stage,
        .dependencies = .{
            .first = dependency_first,
            .count = dependency_count,
        },
        .parallelism = .component,
        .graph_candidate = true,
        .work = .{
            .bytes_read = 256,
            .bytes_written = 256,
            .field_operations = 64,
            .hash_compressions = 32,
            .minimum_launches = 1,
        },
    };
}

test "generic Native AIR binds every executable recipe into program identity" {
    const allocator = std.testing.allocator;
    const fixture = Fixture{};
    const base_contract = contract();
    var base = try ir.ProofProgram.init(
        allocator,
        fixture.description(base_contract),
    );
    defer base.deinit(allocator);

    inline for (.{
        "ingress recipe",
        "ingress ABI",
        "statement recipe",
        "public input ABI",
        "sampling recipe",
        "mask layout",
        "constraint ABI",
    }, 0..) |label, index| {
        var changed_contract = base_contract;
        const changed = ir.identityDigest(label);
        switch (index) {
            0 => changed_contract.ingress.recipe_identity = changed,
            1 => changed_contract.ingress.layout_abi_identity = changed,
            2 => changed_contract.statement.transcript_recipe_identity = changed,
            3 => changed_contract.statement.public_input_abi_identity = changed,
            4 => changed_contract.sampling.recipe_identity = changed,
            5 => changed_contract.sampling.mask_layout_identity = changed,
            6 => changed_contract.constraint_parameters.identity = changed,
            else => unreachable,
        }
        var candidate = try ir.ProofProgram.init(
            allocator,
            fixture.description(changed_contract),
        );
        defer candidate.deinit(allocator);
        try std.testing.expect(!std.mem.eql(
            u8,
            &base.program_digest,
            &candidate.program_digest,
        ));
        try std.testing.expect(!std.mem.eql(
            u8,
            &base.semantic_digest,
            &candidate.semantic_digest,
        ));
    }
}

test "generic Native AIR rejects geometry and component substitution" {
    const allocator = std.testing.allocator;
    const fixture = Fixture{};

    var wrong_geometry = contract();
    wrong_geometry.geometry.interaction_columns = 0;
    wrong_geometry.ingress.element_count = 2 * 256;
    try std.testing.expectError(
        error.InvalidNativeAir,
        ir.ProofProgram.init(
            allocator,
            fixture.description(wrong_geometry),
        ),
    );

    var foreign = fixture;
    foreign.constraints[0].component = 8;
    try std.testing.expectError(
        error.InvalidNativeAir,
        ir.ProofProgram.init(
            allocator,
            foreign.description(contract()),
        ),
    );
}

test "generic Native AIR permits an omitted zero-width interaction tree" {
    const allocator = std.testing.allocator;
    var zero_interaction = Fixture{};
    zero_interaction.columns[2] = .{
        .id = 2,
        .component = 7,
        .ordinal = 2,
        .log_rows = 8,
        .role = .composition,
    };
    zero_interaction.commitments = .{
        tree(0, .preprocessed, 0, 0),
        tree(1, .main, 0, 2),
        tree(2, .composition, 2, 1),
        tree(3, .fri, 0, 0),
    };
    var zero_interaction_contract = contract();
    zero_interaction_contract.geometry.interaction_columns = 0;
    zero_interaction_contract.ingress.element_count = 2 * 256;
    var zero_description = zero_interaction.description(
        zero_interaction_contract,
    );
    zero_description.trace_columns = zero_interaction.columns[0..3];
    zero_description.commitments = zero_interaction.commitments[0..3];
    var accepted = try ir.ProofProgram.init(allocator, zero_description);
    defer accepted.deinit(allocator);

    var fixture = Fixture{};
    fixture.commitments[0].role = .fri;
    try std.testing.expectError(
        error.InvalidNativeAir,
        ir.ProofProgram.init(
            allocator,
            fixture.description(contract()),
        ),
    );
}

test "resource policy changes full identity but not proof semantics" {
    const allocator = std.testing.allocator;
    const base_fixture = Fixture{};
    var base = try ir.ProofProgram.init(
        allocator,
        base_fixture.description(contract()),
    );
    defer base.deinit(allocator);

    var resource_fixture = base_fixture;
    resource_fixture.buffers[0].words *= 2;
    resource_fixture.buffers[0].live_from = .trace_generation;
    resource_fixture.nodes[0].graph_candidate = false;
    resource_fixture.nodes[0].work.bytes_written *= 2;
    resource_fixture.nodes[1].dependencies.count = 0;
    resource_fixture.commitments[1].retain_openings = false;
    var resource_changed = try ir.ProofProgram.init(
        allocator,
        resource_fixture.description(contract()),
    );
    defer resource_changed.deinit(allocator);

    try std.testing.expectEqualSlices(
        u8,
        &base.semantic_digest,
        &resource_changed.semantic_digest,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &base.program_digest,
        &resource_changed.program_digest,
    ));
}

test "proof-semantic changes alter semantic and full identity" {
    const allocator = std.testing.allocator;
    const base_fixture = Fixture{};
    var base = try ir.ProofProgram.init(
        allocator,
        base_fixture.description(contract()),
    );
    defer base.deinit(allocator);

    var semantic_fixture = base_fixture;
    semantic_fixture.constraints[0].expression =
        ir.identityDigest("changed-constraint");
    var changed = try ir.ProofProgram.init(
        allocator,
        semantic_fixture.description(contract()),
    );
    defer changed.deinit(allocator);
    try std.testing.expect(!std.mem.eql(
        u8,
        &base.semantic_digest,
        &changed.semantic_digest,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &base.program_digest,
        &changed.program_digest,
    ));

    var changed_contract = contract();
    changed_contract.sampling.mask_layout_identity =
        ir.identityDigest("changed-mask");
    var changed_sampling = try ir.ProofProgram.init(
        allocator,
        base_fixture.description(changed_contract),
    );
    defer changed_sampling.deinit(allocator);
    try std.testing.expect(!std.mem.eql(
        u8,
        &base.semantic_digest,
        &changed_sampling.semantic_digest,
    ));

    inline for (0..5) |index| {
        var changed_abi_contract = contract();
        switch (index) {
            0 => changed_abi_contract.statement.public_input_words += 1,
            1 => changed_abi_contract.sampling.mask_point_count += 1,
            2 => changed_abi_contract.constraint_parameters.statement_words += 1,
            3 => changed_abi_contract.constraint_parameters.challenge_words += 1,
            4 => changed_abi_contract.constraint_parameters.parameter_words += 1,
            else => unreachable,
        }
        var changed_abi = try ir.ProofProgram.init(
            allocator,
            base_fixture.description(changed_abi_contract),
        );
        defer changed_abi.deinit(allocator);
        try std.testing.expect(!std.mem.eql(
            u8,
            &base.semantic_digest,
            &changed_abi.semantic_digest,
        ));
    }

    var changed_geometry_fixture = base_fixture;
    for (&changed_geometry_fixture.columns) |*column| column.log_rows += 1;
    var changed_geometry_contract = contract();
    changed_geometry_contract.geometry.log_rows += 1;
    changed_geometry_contract.ingress.element_count *= 2;
    var changed_geometry = try ir.ProofProgram.init(
        allocator,
        changed_geometry_fixture.description(changed_geometry_contract),
    );
    defer changed_geometry.deinit(allocator);
    try std.testing.expect(!std.mem.eql(
        u8,
        &base.semantic_digest,
        &changed_geometry.semantic_digest,
    ));
}
