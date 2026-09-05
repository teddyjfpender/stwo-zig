const std = @import("std");

const artifact = @import("recursive_node_artifact_v1.zig");
const manifest_mod = @import("recursive_common_wrapper_manifest_v1.zig");
const padding = @import("recursive_common_wrapper_padding_v1.zig");
const registry = @import("recursive_circuit_registry_v1.zig");

test "common wrapper target requires three cold geometries and never squeezes" {
    var geometries = try fixtureGeometries();
    const target = try fixtureManifest(&geometries);
    try target.validateSelfConsistency();
    try std.testing.expect(!target.production_activation);
    try std.testing.expect(!manifest_mod.PADDING_PARITY_AVAILABLE);
    try std.testing.expect(manifest_mod.CANDIDATE_TARGET_ONLY);
    try std.testing.expectEqual(
        @as(u16, 36),
        target.component_count,
    );
    try std.testing.expectEqual(
        @as(u8, 2),
        target.padded_component_log_sizes[0],
    );

    // A self-consistent larger wrapper is not squeezed into the V1 target.
    geometries[1].active_component_log_sizes[0] = 3;
    geometries[1].padded_component_log_sizes[0] = 3;
    geometries[1].trace_log_size = 3;
    geometries[1] = try registry.AuthenticatedGeometryV1.seal(
        geometries[1],
    );
    try std.testing.expectError(
        error.InvalidCommonWrapperTarget,
        fixtureManifest(&geometries),
    );
}

test "common wrapper role contracts keep one fold and lease atomicity" {
    inline for (comptime std.enums.values(manifest_mod.WrapperRoleV1)) |role| {
        const contract = manifest_mod.RoleInputContractV1.canonical(role);
        try contract.validate();
    }

    const fold = manifest_mod.RoleInputContractV1.canonical(
        manifest_mod.COMMON_FOLD_ROLE,
    );
    try std.testing.expectEqual(
        manifest_mod.RoleInputKindV1.ordered_registered_children,
        fold.input_kind,
    );
    try std.testing.expectEqual(@as(u8, 2), fold.live_child_lease_count);
    try std.testing.expectEqual(
        manifest_mod.LeaseConsumptionV1.both_or_neither,
        fold.lease_consumption,
    );
    try std.testing.expect(fold.success_reports_consumed_handles);
    try std.testing.expect(!fold.native_input_proof_required);

    const pair = manifest_mod.OrderedChildCircuitPairV1{
        .left = .real_leaf_wrapper,
        .right = .common_fold,
    };
    try std.testing.expectEqualDeep(
        [2]manifest_mod.WrapperRoleV1{
            .ethereum_incremental_leaf_wrapper_v4,
            manifest_mod.COMMON_FOLD_ROLE,
        },
        pair.registryRoles(),
    );

    var mutation = fold;
    mutation.success_reports_consumed_handles = false;
    try std.testing.expectError(
        error.InvalidCommonWrapperContract,
        mutation.validate(),
    );

    const status = manifest_mod.currentAuthorityStatus();
    try status.validate();
    try std.testing.expectEqual(
        manifest_mod.MissingAuthorityV1.ethereum_incremental_leaf_cold_wrapper,
        status.first_missing,
    );
    try std.testing.expect(!status.proof_bearing_empty_cold_wrapper_available);
    try std.testing.expect(!status.common_fold_cold_wrapper_available);

    const reuse = manifest_mod.commonFoldReuseStatus();
    try reuse.validate();
    try std.testing.expectEqual(@as(u16, 36), reuse.universal_component_count);
    try std.testing.expect(reuse.verifier_statement_words_published);
    try std.testing.expect(!reuse.complete_parent_stark_verified);
    try std.testing.expect(!reuse.authenticated_common_wrapper_available);
}

test "padding AIR enforces prefix count and every inactive column family" {
    const geometries = try fixtureGeometries();
    const target = try fixtureManifest(&geometries);
    const contract = try padding.ComponentContractV1.init(
        &target,
        .ethereum_incremental_leaf_wrapper_v4,
        0,
        2,
        1,
        1,
        1,
        1,
        1,
    );
    var fixture = TraceFixture.valid();
    var sink = TestSink{};
    const tally = try recordTrace(&sink, &target, &contract, &fixture);
    try std.testing.expectEqual(@as(usize, 4), tally.active_boolean);
    try std.testing.expectEqual(@as(usize, 3), tally.active_monotone);
    try std.testing.expectEqual(@as(usize, 1), tally.active_exact_count);
    try std.testing.expectEqual(@as(usize, 4), tally.inactive_main_zero);
    try std.testing.expectEqual(@as(usize, 28), tally.total());

    fixture = TraceFixture.valid();
    fixture.active_mask = scalarArray4(.{ 1, 0, 1, 0 });
    try std.testing.expectError(
        error.Unsatisfied,
        recordTrace(&sink, &target, &contract, &fixture),
    );

    inline for (.{
        "main",
        "interaction",
        "composition",
        "claim",
        "binding",
    }) |field_name| {
        fixture = TraceFixture.valid();
        @field(fixture, field_name)[3] = scalar(7);
        try std.testing.expectError(
            error.Unsatisfied,
            recordTrace(&sink, &target, &contract, &fixture),
        );
    }

    const wrong_count = try padding.ComponentContractV1.init(
        &target,
        .ethereum_incremental_leaf_wrapper_v4,
        0,
        3,
        1,
        1,
        1,
        1,
        1,
    );
    fixture = TraceFixture.valid();
    try std.testing.expectError(
        error.Unsatisfied,
        recordTrace(&sink, &target, &wrong_count, &fixture),
    );
}

test "NodePublic AIR binds all words identities digest and role authority" {
    const geometries = try fixtureGeometries();
    const target = try fixtureManifest(&geometries);
    const owner = try padding.ComponentContractV1.init(
        &target,
        .canonical_empty_field_v2,
        padding.NODE_PUBLIC_OWNER_COMPONENT,
        2,
        1,
        1,
        1,
        1,
        1,
    );
    var sink = TestSink{};
    var input = validNodePublicInput();
    const derivation = MockDerivationOwner{ .expected = &input.published };
    const tally = try padding.recordNodePublicBinding(
        &sink,
        &target,
        .canonical_empty_field_v2,
        &owner,
        &derivation,
        &input,
    );
    try std.testing.expectEqual(
        @as(usize, artifact.STATEMENT_WORD_COUNT),
        input.published.statement_words.len,
    );
    try std.testing.expectEqual(@as(usize, 560), tally.node_public_equality);
    try std.testing.expectEqual(@as(usize, 1152), tally.identity_byte_range);
    try std.testing.expectEqual(@as(usize, 4), tally.identity_nonzero);
    try std.testing.expectEqual(@as(usize, 25), tally.digest_nonzero);
    try std.testing.expectEqual(@as(usize, 554), tally.role_derivation);

    input = validNodePublicInput();
    input.derived.statement_words[artifact.STATEMENT_WORD_COUNT - 1] = scalar(9);
    try expectNodePublicUnsatisfied(&sink, &target, &owner, &input);

    input = validNodePublicInput();
    input.derived.output_identity_bytes[0] = scalar(2);
    try expectNodePublicUnsatisfied(&sink, &target, &owner, &input);

    input = validNodePublicInput();
    input.derived.subtree_digest[0] = scalar(2);
    try expectNodePublicUnsatisfied(&sink, &target, &owner, &input);

    input = validNodePublicInput();
    input.aux.identity_bits[0][0][0] = scalar(2);
    try expectNodePublicUnsatisfied(&sink, &target, &owner, &input);

    input = validNodePublicInput();
    const bad_derivation = BadDerivationOwner{};
    try std.testing.expectError(
        error.InvalidNodePublicConstraintShape,
        padding.recordNodePublicBinding(
            &sink,
            &target,
            .canonical_empty_field_v2,
            &owner,
            &bad_derivation,
            &input,
        ),
    );

    const non_owner = try padding.ComponentContractV1.init(
        &target,
        .canonical_empty_field_v2,
        1,
        2,
        1,
        1,
        1,
        1,
        1,
    );
    try std.testing.expectError(
        error.InvalidComponentPaddingContract,
        padding.recordNodePublicBinding(
            &sink,
            &target,
            .canonical_empty_field_v2,
            &non_owner,
            &derivation,
            &input,
        ),
    );
}

const TestScalar = struct {
    value: i128,

    pub fn add(self: TestScalar, other: TestScalar) TestScalar {
        return .{ .value = self.value + other.value };
    }

    pub fn sub(self: TestScalar, other: TestScalar) TestScalar {
        return .{ .value = self.value - other.value };
    }

    pub fn mul(self: TestScalar, other: TestScalar) TestScalar {
        return .{ .value = self.value * other.value };
    }
};

const TestSink = struct {
    pub fn zero(_: *TestSink) TestScalar {
        return scalar(0);
    }

    pub fn one(_: *TestSink) TestScalar {
        return scalar(1);
    }

    pub fn constantU64(_: *TestSink, value: u64) TestScalar {
        return .{ .value = @intCast(value) };
    }

    pub fn constrainZero(_: *TestSink, value: TestScalar) !void {
        if (value.value != 0) return error.Unsatisfied;
    }
};

const TraceFixture = struct {
    active_mask: [4]TestScalar,
    main: [4]TestScalar,
    interaction: [4]TestScalar,
    composition: [4]TestScalar,
    claim: [4]TestScalar,
    binding: [4]TestScalar,

    fn valid() TraceFixture {
        return .{
            .active_mask = scalarArray4(.{ 1, 1, 0, 0 }),
            .main = scalarArray4(.{ 2, 3, 0, 0 }),
            .interaction = scalarArray4(.{ 4, 5, 0, 0 }),
            .composition = scalarArray4(.{ 6, 7, 0, 0 }),
            .claim = scalarArray4(.{ 8, 9, 0, 0 }),
            .binding = scalarArray4(.{ 10, 11, 0, 0 }),
        };
    }
};

fn recordTrace(
    sink: *TestSink,
    target: *const manifest_mod.ManifestV1,
    contract: *const padding.ComponentContractV1,
    fixture: *const TraceFixture,
) !padding.ConstraintTallyV1 {
    const main_columns = [1][]const TestScalar{&fixture.main};
    const interaction_columns = [1][]const TestScalar{&fixture.interaction};
    const composition_columns = [1][]const TestScalar{&fixture.composition};
    const claim_columns = [1][]const TestScalar{&fixture.claim};
    const binding_columns = [1][]const TestScalar{&fixture.binding};
    const input = padding.TraceInputV1(TestScalar){
        .active_mask = &fixture.active_mask,
        .main_columns = &main_columns,
        .interaction_weight_columns = &interaction_columns,
        .composition_columns = &composition_columns,
        .claim_columns = &claim_columns,
        .binding_columns = &binding_columns,
    };
    return padding.recordTracePadding(
        sink,
        target,
        .ethereum_incremental_leaf_wrapper_v4,
        contract,
        input,
    );
}

fn validNodePublicInput() padding.NodePublicInputV1(TestScalar) {
    var public = zeroNodePublic();
    public.format_version = scalar(artifact.FORMAT_VERSION);
    public.schema_version = scalar(artifact.SCHEMA_VERSION);
    for (&public.statement_words, 0..) |*word, index|
        word.* = scalar(index + 1);
    public.statement_identity_bytes[0] = scalar(1);
    public.node_authority_bytes[0] = scalar(1);
    public.subtree_sha256_bytes[0] = scalar(1);
    public.subtree_digest[0] = scalar(1);
    public.output_identity_bytes[0] = scalar(1);

    var aux = zeroNodePublicAux();
    for (0..padding.IDENTITY_FIELD_COUNT) |identity|
        aux.identity_bits[identity][0][0] = scalar(1);
    aux.identity_nonzero_inverses = [_]TestScalar{scalar(1)} **
        padding.IDENTITY_FIELD_COUNT;
    aux.digest_nonzero_flags[0] = scalar(1);
    aux.digest_word_inverses[0] = scalar(1);
    aux.digest_any_inverse = scalar(1);
    return .{ .published = public, .derived = public, .aux = aux };
}

fn zeroNodePublic() padding.NodePublicScalarsV1(TestScalar) {
    return .{
        .format_version = scalar(0),
        .schema_version = scalar(0),
        .reserved = [_]TestScalar{scalar(0)} ** 4,
        .statement_words = [_]TestScalar{scalar(0)} **
            artifact.STATEMENT_WORD_COUNT,
        .statement_identity_bytes = [_]TestScalar{scalar(0)} **
            padding.IDENTITY_BYTE_COUNT,
        .node_authority_bytes = [_]TestScalar{scalar(0)} **
            padding.IDENTITY_BYTE_COUNT,
        .subtree_sha256_bytes = [_]TestScalar{scalar(0)} **
            padding.IDENTITY_BYTE_COUNT,
        .subtree_digest = [_]TestScalar{scalar(0)} **
            artifact.DIGEST_WORD_COUNT,
        .output_identity_bytes = [_]TestScalar{scalar(0)} **
            padding.IDENTITY_BYTE_COUNT,
    };
}

fn zeroNodePublicAux() padding.NodePublicAuxV1(TestScalar) {
    return .{
        .identity_bits = [_][padding.IDENTITY_BYTE_COUNT][
            padding.IDENTITY_BIT_COUNT
        ]TestScalar{[_][padding.IDENTITY_BIT_COUNT]TestScalar{
            [_]TestScalar{scalar(0)} ** padding.IDENTITY_BIT_COUNT,
        } ** padding.IDENTITY_BYTE_COUNT} ** padding.IDENTITY_FIELD_COUNT,
        .identity_nonzero_inverses = [_]TestScalar{scalar(0)} **
            padding.IDENTITY_FIELD_COUNT,
        .digest_nonzero_flags = [_]TestScalar{scalar(0)} **
            artifact.DIGEST_WORD_COUNT,
        .digest_word_inverses = [_]TestScalar{scalar(0)} **
            artifact.DIGEST_WORD_COUNT,
        .digest_any_inverse = scalar(0),
    };
}

fn expectNodePublicUnsatisfied(
    sink: *TestSink,
    target: *const manifest_mod.ManifestV1,
    contract: *const padding.ComponentContractV1,
    input: *const padding.NodePublicInputV1(TestScalar),
) !void {
    const derivation = MockDerivationOwner{ .expected = &input.published };
    try std.testing.expectError(
        error.Unsatisfied,
        padding.recordNodePublicBinding(
            sink,
            target,
            .canonical_empty_field_v2,
            contract,
            &derivation,
            input,
        ),
    );
}

const MockDerivationOwner = struct {
    expected: *const padding.NodePublicScalarsV1(TestScalar),

    pub fn recordNodePublicDerivation(
        self: *const MockDerivationOwner,
        sink: *TestSink,
        derived: *const padding.NodePublicScalarsV1(TestScalar),
    ) !padding.RoleDerivationTallyV1 {
        var count: usize = 0;
        try constrainDerived(sink, derived.format_version, self.expected.format_version, &count);
        try constrainDerived(sink, derived.schema_version, self.expected.schema_version, &count);
        try constrainDerivedArray(sink, &derived.reserved, &self.expected.reserved, &count);
        try constrainDerivedArray(
            sink,
            &derived.statement_words,
            &self.expected.statement_words,
            &count,
        );
        try constrainDerivedArray(
            sink,
            &derived.statement_identity_bytes,
            &self.expected.statement_identity_bytes,
            &count,
        );
        try constrainDerivedArray(
            sink,
            &derived.node_authority_bytes,
            &self.expected.node_authority_bytes,
            &count,
        );
        try constrainDerivedArray(
            sink,
            &derived.subtree_sha256_bytes,
            &self.expected.subtree_sha256_bytes,
            &count,
        );
        try constrainDerivedArray(
            sink,
            &derived.subtree_digest,
            &self.expected.subtree_digest,
            &count,
        );
        try constrainDerivedArray(
            sink,
            &derived.output_identity_bytes,
            &self.expected.output_identity_bytes,
            &count,
        );
        return .{
            .statement_word_count = artifact.STATEMENT_WORD_COUNT,
            .identity_field_count = padding.IDENTITY_FIELD_COUNT,
            .digest_word_count = artifact.DIGEST_WORD_COUNT,
            .source_constraint_count = count,
        };
    }
};

const BadDerivationOwner = struct {
    pub fn recordNodePublicDerivation(
        _: *const BadDerivationOwner,
        _: *TestSink,
        _: *const padding.NodePublicScalarsV1(TestScalar),
    ) !padding.RoleDerivationTallyV1 {
        return .{
            .statement_word_count = artifact.STATEMENT_WORD_COUNT - 1,
            .identity_field_count = padding.IDENTITY_FIELD_COUNT,
            .digest_word_count = artifact.DIGEST_WORD_COUNT,
            .source_constraint_count = 1,
        };
    }
};

fn constrainDerivedArray(
    sink: *TestSink,
    actual: anytype,
    expected: anytype,
    count: *usize,
) !void {
    for (actual, expected) |actual_value, expected_value|
        try constrainDerived(sink, actual_value, expected_value, count);
}

fn constrainDerived(
    sink: *TestSink,
    actual: TestScalar,
    expected: TestScalar,
    count: *usize,
) !void {
    try sink.constrainZero(actual.sub(expected));
    count.* += 1;
}

fn fixtureManifest(
    geometries: *const [manifest_mod.ROLE_COUNT]registry.AuthenticatedGeometryV1,
) !manifest_mod.ManifestV1 {
    var owned: [manifest_mod.ROLE_COUNT]manifest_mod.testing.OwnedColdWrapperGeometryV1 = undefined;
    for (&owned, geometries) |*destination, geometry|
        destination.* = try .init(geometry);
    return manifest_mod.ManifestV1.derive(.{
        owned[0].lease(),
        owned[1].lease(),
        owned[2].lease(),
    });
}

fn fixtureGeometries() ![manifest_mod.ROLE_COUNT]registry.AuthenticatedGeometryV1 {
    var result: [manifest_mod.ROLE_COUNT]registry.AuthenticatedGeometryV1 = undefined;
    for (&result, 0..) |*geometry, ordinal| {
        var active = [_]u8{0} ** registry.MAX_COMPONENT_COUNT;
        var padded = [_]u8{0} ** registry.MAX_COMPONENT_COUNT;
        var preprocessed = [_]u8{0} **
            registry.MAX_PREPROCESSED_COLUMN_COUNT;
        @memset(active[0..manifest_mod.COMPONENT_COUNT], if (ordinal == 2) 2 else 1);
        @memset(padded[0..manifest_mod.COMPONENT_COUNT], 2);
        @memset(preprocessed[0..2], 2);
        geometry.* = try registry.AuthenticatedGeometryV1.seal(.{
            .role = @enumFromInt(ordinal),
            .authenticated_padding = true,
            .component_count = manifest_mod.COMPONENT_COUNT,
            .preprocessed_column_count = 2,
            .trace_log_size = 2,
            .active_component_log_sizes = active,
            .padded_component_log_sizes = padded,
            .preprocessed_column_log_sizes = preprocessed,
            .circuit_identity_sha256 = fixtureIdentity(@intCast(10 + ordinal)),
            .program_identity_sha256 = fixtureIdentity(@intCast(20 + ordinal)),
            .profile_identity_sha256 = fixtureIdentity(@intCast(30 + ordinal)),
            .padding_layout_identity_sha256 = fixtureIdentity(40),
            .preprocessed_root = fixtureDigest(@intCast(50 + ordinal)),
            .pcs = registry.PcsConfigV1.secureTemporalParent(),
            .output_abi = registry.OutputAbiV1.nodePublic(),
            .proof_shape = try fixtureProofShape(),
            .authority_identity_sha256 = undefined,
        });
    }
    return result;
}

fn fixtureProofShape() !registry.FixedProofShapeV3 {
    var tree_logs = [_][registry.MAX_TREE_COLUMN_COUNT]u8{
        [_]u8{0} ** registry.MAX_TREE_COLUMN_COUNT,
    } ** registry.FIXED_PROOF_TREE_COUNT;
    var sample_counts = [_][registry.MAX_TREE_COLUMN_COUNT]u8{
        [_]u8{0} ** registry.MAX_TREE_COLUMN_COUNT,
    } ** registry.FIXED_PROOF_TREE_COUNT;
    tree_logs[0][0] = 3;
    tree_logs[0][1] = 3;
    tree_logs[1][0] = 3;
    tree_logs[2][0] = 3;
    tree_logs[3][0] = 3;
    sample_counts[0][0] = 1;
    sample_counts[0][1] = 1;
    sample_counts[1][0] = 1;
    sample_counts[2][0] = 1;
    sample_counts[3][0] = 1;
    var fri_fold_widths = [_]u8{0} ** registry.MAX_FRI_LAYER_COUNT;
    var fri_path_depths = [_]u8{0} ** registry.MAX_FRI_LAYER_COUNT;
    fri_fold_widths[0] = 4;
    fri_path_depths[0] = 3;
    return registry.FixedProofShapeV3.seal(.{
        .maximum_merkle_depth = 3,
        .claimed_sum_count = manifest_mod.COMPONENT_COUNT,
        .fri_layer_count = 1,
        .query_count = 193,
        .maximum_fold_width = 4,
        .column_log_degree = 2,
        .sampled_value_count = 5,
        .queried_value_count = 5 * 193,
        .trace_path_count = 4 * 193,
        .trace_sibling_count = 12 * 193,
        .fri_value_count = 4 * 193,
        .fri_sibling_count = 3 * 193,
        .last_layer_coefficient_count = 1,
        .tree_column_counts = .{ 2, 1, 1, 1 },
        .tree_column_log_sizes = tree_logs,
        .tree_column_sample_counts = sample_counts,
        .fri_layer_fold_widths = fri_fold_widths,
        .fri_layer_path_depths = fri_path_depths,
        .table_layout_identity_sha256 = fixtureIdentity(41),
        .identity_sha256 = undefined,
    });
}

fn scalar(value: anytype) TestScalar {
    return .{ .value = @intCast(value) };
}

fn scalarArray4(values: [4]i32) [4]TestScalar {
    return .{
        scalar(values[0]),
        scalar(values[1]),
        scalar(values[2]),
        scalar(values[3]),
    };
}

fn fixtureIdentity(seed: u32) [32]u8 {
    var result: [32]u8 = undefined;
    var word: [4]u8 = undefined;
    std.mem.writeInt(u32, &word, seed, .little);
    for (0..8) |index| @memcpy(result[index * 4 ..][0..4], &word);
    return result;
}

fn fixtureDigest(seed: u32) [artifact.DIGEST_WORD_COUNT]u32 {
    return [_]u32{seed + 1} ** artifact.DIGEST_WORD_COUNT;
}
