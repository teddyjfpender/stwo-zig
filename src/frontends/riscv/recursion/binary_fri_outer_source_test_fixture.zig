//! Focused shard of binary_fri_outer_source_test.zig; import that suite facade.

const dependency_0 = @import("binary_fri_outer_source_test_capture_fixture.zig");

const Bundle = dependency_0.Bundle;
const CaptureFixture = dependency_0.CaptureFixture;
const M31 = dependency_0.M31;
const Prepared = dependency_0.Prepared;
const QM31 = dependency_0.QM31;
const Source = dependency_0.Source;
const air = dependency_0.air;
const authority = dependency_0.authority;
const buildFullComposition = dependency_0.buildFullComposition;
const fixture_mod = dependency_0.fixture_mod;
const source_mod = dependency_0.source_mod;
const std = dependency_0.std;
const testPoseidonPartials = dependency_0.testPoseidonPartials;
const testPoseidonTotal = dependency_0.testPoseidonTotal;

test "R-015 binary FRI source admits exact verifier-owned child captures" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    try fixture.source.validate();
    try std.testing.expectEqualSlices(
        u32,
        &.{ 10, 13, 4, 12, 15, 13, 11, 10, 11, 16 },
        &fixture.source.friLogSizes(),
    );
    try std.testing.expectError(
        error.MissingCompositionAuthority,
        fixture.source.requireCompositionAuthorities(),
    );
}

test "R-015 prepared and bundle identities exclude process addresses" {
    var fixture = try Fixture.initFull(std.testing.allocator);
    defer fixture.deinit();

    // A shallow immutable view has identical semantic authority and borrowed
    // storage but a deliberately distinct source-object address. Operational
    // capabilities remain address-bound; proof-visible identities must not.
    var equivalent_source = fixture.source;
    try equivalent_source.validate();
    try std.testing.expect(
        @intFromPtr(&fixture.source) != @intFromPtr(&equivalent_source),
    );

    const original_authority = try fixture.source.prepareAuthority();
    const equivalent_authority = try equivalent_source.prepareAuthority();
    try std.testing.expect(original_authority.source != equivalent_authority.source);
    try std.testing.expectEqual(
        original_authority.source_authority_digest,
        equivalent_authority.source_authority_digest,
    );
    try std.testing.expectEqual(
        original_authority.identity_digest,
        equivalent_authority.identity_digest,
    );
    try original_authority.validateFor(&fixture.source);
    try equivalent_authority.validateFor(&equivalent_source);
    try std.testing.expectError(
        error.SourceAuthorityMismatch,
        original_authority.validateFor(&equivalent_source),
    );

    var original_bundle = try Bundle.init(
        std.testing.allocator,
        &fixture.source,
    );
    defer original_bundle.deinit();
    var equivalent_bundle = try Bundle.init(
        std.testing.allocator,
        &equivalent_source,
    );
    defer equivalent_bundle.deinit();
    try std.testing.expectEqual(
        original_bundle.authority_seal,
        equivalent_bundle.authority_seal,
    );
}

test "R-015 binary FRI source rejects substitution mutations and stale seals" {
    var fixture = try Fixture.init(std.testing.allocator);
    defer fixture.deinit();

    const left_capture = fixture.source.children[0].capture;
    fixture.source.children[0].capture = fixture.source.children[1].capture;
    try std.testing.expectError(
        error.CaptureTranscriptMismatch,
        fixture.source.validate(),
    );
    fixture.source.children[0].capture = left_capture;

    const original_query = fixture.capture_children[1].capture.raw_queries[0];
    @constCast(fixture.capture_children[1].capture.raw_queries)[0] =
        original_query.add(M31.one());
    try std.testing.expectError(error.InvalidQuerySchedule, fixture.source.validate());
    @constCast(fixture.capture_children[1].capture.raw_queries)[0] = original_query;

    fixture.source.source_authority_digest[0] ^= 1;
    try std.testing.expectError(error.SourceAuthorityMismatch, fixture.source.validate());
    fixture.source.source_authority_digest[0] ^= 1;
    try fixture.source.validate();
}

test "R-015 binary FRI rows 18--19 use the admitted composition graph" {
    var fixture = try Fixture.initFull(std.testing.allocator);
    defer fixture.deinit();
    try fixture.source.requireFullBundleAuthority();
    const logs = try fixture.source.compositionLogSizes();

    var workspace_meter = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{},
    );
    var workspace = try Source.CompositionWorkspace.init(
        workspace_meter.allocator(),
        &fixture.source,
    );
    defer workspace.deinit();
    try std.testing.expectEqual(
        source_mod.ROWS_18_19_WORKSPACE_HEAP_ALLOCATIONS,
        workspace_meter.alloc_index,
    );
    var preprocessed = try Tree.init(
        std.testing.allocator,
        logs,
        source_mod.COMPOSITION_PREPROCESSED_COLUMNS_PER_ROW,
    );
    defer preprocessed.deinit();
    var main = try Tree.init(
        std.testing.allocator,
        logs,
        source_mod.COMPOSITION_MAIN_COLUMNS_PER_ROW,
    );
    defer main.deinit();
    try fixture.source.fillCompositionPreprocessedInto(
        &workspace,
        preprocessed.columns,
    );
    try fixture.source.fillCompositionMainInto(&workspace, main.columns);
    try std.testing.expect(preprocessed.anyNonZero());
    try std.testing.expect(main.anyNonZero());
    const preprocessed_permuted = try expectCommittedScatter(
        preprocessed.columns,
        &workspace.preprocessed_columns,
    );
    const main_permuted = try expectCommittedScatter(
        main.columns,
        &workspace.main_columns,
    );
    // This must exercise a genuinely moved, unequal payload; otherwise a
    // future memcpy regression could satisfy the parity loop accidentally.
    try std.testing.expect(preprocessed_permuted or main_permuted);

    const hot_before = workspace_meter.alloc_index;
    try fixture.source.fillCompositionPreprocessedInto(
        &workspace,
        preprocessed.columns,
    );
    try fixture.source.fillCompositionMainInto(&workspace, main.columns);
    try std.testing.expectEqual(
        source_mod.ROWS_18_19_REUSED_HOT_HEAP_ALLOCATIONS,
        workspace_meter.alloc_index - hot_before,
    );

    const sentinel = M31.fromCanonical(6_181);
    main.fill(sentinel);
    const values = @constCast(
        fixture.source.children[0].composition.?.evaluation.values,
    );
    const original = values[0];
    values[0] = original.add(QM31.one());
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        fixture.source.fillCompositionMainInto(&workspace, main.columns),
    );
    values[0] = original;
    try main.expectFilled(sentinel);

    const original_column = main.columns[1];
    main.columns[1] = main.columns[0];
    try std.testing.expectError(
        error.DestinationAlias,
        fixture.source.fillCompositionMainInto(&workspace, main.columns),
    );
    main.columns[1] = original_column;
    try main.expectFilled(sentinel);
}

test "R-015 V3 recorder lanes reuse rows 18--19 and reject lane mutations" {
    var fixture = try Fixture.initFull(std.testing.allocator);
    defer fixture.deinit();

    var lanes: [source_mod.CHILD_COUNT]air.composition_circuit.RecursionLane =
        undefined;
    var evaluations: [source_mod.CHILD_COUNT]air.verifier_arithmetic_lowering.Evaluation =
        undefined;
    for (fixture.source.children, 0..) |child, child_index| {
        const composition_authority = child.composition.?;
        const profile = child.trusted_composition_profile.?;
        lanes[child_index] = .{
            .verifier_id = composition_authority.verifier_id,
            .circuit_id = composition_authority.circuit_id,
            .statement_scope = if (child_index == source_mod.LEFT_CHILD)
                source_mod.LEFT_COMPOSITION_STATEMENT_SCOPE
            else
                source_mod.RIGHT_COMPOSITION_STATEMENT_SCOPE,
            .graph = composition_authority.graph,
            .profile = profile.input_profile,
            .bindings = profile.input_bindings,
        };
        evaluations[child_index] = composition_authority.evaluation;
    }

    var rows = try source_mod.CompositionRowsAuthority
        .initFromAuthenticatedRecorderLanes(
        std.testing.allocator,
        &fixture.pair.vm_plan,
        &fixture.pair.recursion_plans[0],
        @intCast(fixture.source.children[0].capture.sampled_values.len),
        lanes,
        evaluations,
    );
    defer rows.deinit();
    try rows.validateAuthenticatedRecorderLanes(evaluations);
    try std.testing.expectEqualDeep(
        fixture.source.composition_rows.?.log_sizes,
        rows.log_sizes,
    );

    const values = @constCast(evaluations[0].values);
    const original = values[0];
    values[0] = original.add(QM31.one());
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        rows.validateAuthenticatedRecorderLanes(evaluations),
    );
    values[0] = original;

    var swapped = lanes;
    std.mem.swap(
        air.composition_circuit.RecursionLane,
        &swapped[0],
        &swapped[1],
    );
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        source_mod.CompositionRowsAuthority.initFromAuthenticatedRecorderLanes(
            std.testing.allocator,
            &fixture.pair.vm_plan,
            &fixture.pair.recursion_plans[0],
            @intCast(fixture.source.children[0].capture.sampled_values.len),
            swapped,
            evaluations,
        ),
    );

    var detached = evaluations;
    detached[1].circuit_identity[0] ^= 1;
    try std.testing.expectError(
        error.CompositionAuthorityMismatch,
        source_mod.CompositionRowsAuthority.initFromAuthenticatedRecorderLanes(
            std.testing.allocator,
            &fixture.pair.vm_plan,
            &fixture.pair.recursion_plans[0],
            @intCast(fixture.source.children[0].capture.sampled_values.len),
            lanes,
            detached,
        ),
    );
}

pub const Fixture = struct {
    allocator: std.mem.Allocator,
    /// `Source` borrows both authorities. Keep them at stable addresses across
    /// the by-value fixture return; optimized builds are free to move the
    /// `Fixture` itself.
    pair: *fixture_mod.HonestFixture,
    prepared: *Prepared,
    capture_children: [2]*CaptureFixture,
    source: Source,

    pub fn init(allocator: std.mem.Allocator) !Fixture {
        return initMode(allocator, false);
    }

    pub fn initWithComposition(allocator: std.mem.Allocator) !Fixture {
        return initMode(allocator, true);
    }

    pub fn initFull(allocator: std.mem.Allocator) !Fixture {
        return initModeWithFullComposition(allocator);
    }

    fn initMode(allocator: std.mem.Allocator, with_composition: bool) !Fixture {
        const pair = try allocator.create(fixture_mod.HonestFixture);
        errdefer allocator.destroy(pair);
        pair.* = try fixture_mod.HonestFixture.init(allocator);
        errdefer pair.deinit();
        try fixture_mod.installAuthenticatedMerkleWires(pair);
        const plans = [2]*const air.verifier_schedule.Plan{
            &pair.recursion_plans[0],
            &pair.recursion_plans[1],
        };
        const prepared = try allocator.create(Prepared);
        errdefer allocator.destroy(prepared);
        prepared.* = try Prepared.init(
            allocator,
            .sealed_candidate,
            &pair.vm_plan,
            plans,
            &pair.transcript_preprocessing,
            &pair.statement_preprocessing,
            &pair.semantics,
            &pair.validation_workspace,
            pair.pair_inputs,
            pair.children(),
        );
        errdefer prepared.deinit();
        const left_capture = try allocator.create(CaptureFixture);
        errdefer allocator.destroy(left_capture);
        left_capture.* = try CaptureFixture.init(
            allocator,
            pair.wires[0],
            &prepared.executions[0],
        );
        errdefer left_capture.deinit();
        const right_capture = try allocator.create(CaptureFixture);
        errdefer allocator.destroy(right_capture);
        right_capture.* = try CaptureFixture.init(
            allocator,
            pair.wires[1],
            &prepared.executions[1],
        );
        errdefer right_capture.deinit();
        const capture_children = [2]*CaptureFixture{ left_capture, right_capture };
        var composition_profiles = [2]?source_mod.TrustedCompositionProfileV1{
            null,
            null,
        };
        var composition_authorities = [2]?source_mod.VerifiedChildCompositionAuthority{
            null,
            null,
        };
        if (with_composition) for (capture_children, 0..) |capture_child, child_index| {
            const graph = capture_child.capture.circuit.graph();
            const partials = testPoseidonPartials(pair, child_index);
            const poseidon_total = testPoseidonTotal(pair, child_index);
            const profile = try source_mod.TrustedCompositionProfileV1.seal(
                pair.shape.air_program_id,
                @intCast(501 + child_index),
                capture_child.capture.circuit.identity_digest,
                graph.identity_digest,
            );
            composition_profiles[child_index] = profile;
            composition_authorities[child_index] =
                try source_mod.VerifiedChildCompositionAuthority.authenticate(
                    profile,
                    child_index,
                    prepared.authority.children[child_index],
                    pair.shape,
                    capture_child.capture.circuit.identity_digest,
                    graph,
                    .{
                        .circuit_identity = capture_child.capture.evaluation.circuit_identity,
                        .values = capture_child.capture.evaluation.values,
                    },
                    partials,
                    poseidon_total,
                );
        };
        var source = try Source.init(
            allocator,
            prepared,
            pair.pair_inputs.root_pin,
            &pair.vm_plan,
            plans,
            .{
                .{
                    .shape = pair.shape,
                    .wire = pair.wires[0],
                    .capture = &capture_children[0].capture,
                    .composition = composition_authorities[0],
                    .trusted_composition_profile = composition_profiles[0],
                },
                .{
                    .shape = pair.shape,
                    .wire = pair.wires[1],
                    .capture = &capture_children[1].capture,
                    .composition = composition_authorities[1],
                    .trusted_composition_profile = composition_profiles[1],
                },
            },
        );
        errdefer source.deinit();
        return .{
            .allocator = allocator,
            .pair = pair,
            .prepared = prepared,
            .capture_children = capture_children,
            .source = source,
        };
    }

    fn initModeWithFullComposition(allocator: std.mem.Allocator) !Fixture {
        const pair = try allocator.create(fixture_mod.HonestFixture);
        errdefer allocator.destroy(pair);
        pair.* = try fixture_mod.HonestFixture.init(allocator);
        errdefer pair.deinit();
        try fixture_mod.installAuthenticatedMerkleWires(pair);
        const plans = [2]*const air.verifier_schedule.Plan{
            &pair.recursion_plans[0],
            &pair.recursion_plans[1],
        };
        const prepared = try allocator.create(Prepared);
        errdefer allocator.destroy(prepared);
        prepared.* = try Prepared.init(
            allocator,
            .sealed_candidate,
            &pair.vm_plan,
            plans,
            &pair.transcript_preprocessing,
            &pair.statement_preprocessing,
            &pair.semantics,
            &pair.validation_workspace,
            pair.pair_inputs,
            pair.children(),
        );
        errdefer prepared.deinit();
        const left_capture = try allocator.create(CaptureFixture);
        errdefer allocator.destroy(left_capture);
        left_capture.* = try CaptureFixture.init(
            allocator,
            pair.wires[0],
            &prepared.executions[0],
        );
        errdefer left_capture.deinit();
        const right_capture = try allocator.create(CaptureFixture);
        errdefer allocator.destroy(right_capture);
        right_capture.* = try CaptureFixture.init(
            allocator,
            pair.wires[1],
            &prepared.executions[1],
        );
        errdefer right_capture.deinit();
        const capture_children = [2]*CaptureFixture{ left_capture, right_capture };

        var composition_profiles: [2]?source_mod.TrustedCompositionProfileV1 = .{
            null,
            null,
        };
        var composition_authorities: [2]?source_mod.VerifiedChildCompositionAuthority = .{
            null,
            null,
        };
        for (capture_children, 0..) |capture_child, child_index| {
            const built = try buildFullComposition(
                capture_child.arena.allocator(),
                pair,
                prepared,
                capture_child,
                child_index,
            );
            composition_profiles[child_index] = built.profile;
            composition_authorities[child_index] =
                try source_mod.VerifiedChildCompositionAuthority.authenticate(
                    built.profile,
                    child_index,
                    prepared.authority.children[child_index],
                    pair.shape,
                    built.graph.identity_digest,
                    built.graph,
                    built.evaluation,
                    built.poseidon2_partials,
                    built.poseidon2_roster_total,
                );
        }
        var source = try Source.init(
            allocator,
            prepared,
            pair.pair_inputs.root_pin,
            &pair.vm_plan,
            plans,
            .{
                .{
                    .shape = pair.shape,
                    .wire = pair.wires[0],
                    .capture = &capture_children[0].capture,
                    .composition = composition_authorities[0],
                    .trusted_composition_profile = composition_profiles[0],
                },
                .{
                    .shape = pair.shape,
                    .wire = pair.wires[1],
                    .capture = &capture_children[1].capture,
                    .composition = composition_authorities[1],
                    .trusted_composition_profile = composition_profiles[1],
                },
            },
        );
        errdefer source.deinit();
        return .{
            .allocator = allocator,
            .pair = pair,
            .prepared = prepared,
            .capture_children = capture_children,
            .source = source,
        };
    }

    pub fn deinit(self: *Fixture) void {
        self.source.deinit();
        self.capture_children[1].deinit();
        self.allocator.destroy(self.capture_children[1]);
        self.capture_children[0].deinit();
        self.allocator.destroy(self.capture_children[0]);
        self.prepared.deinit();
        self.allocator.destroy(self.prepared);
        self.pair.deinit();
        self.allocator.destroy(self.pair);
        self.* = undefined;
    }
};

pub const Tree = struct {
    allocator: std.mem.Allocator,
    columns: [][]M31,
    storage: []M31,

    pub fn init(
        allocator: std.mem.Allocator,
        log_sizes: anytype,
        column_counts: anytype,
    ) !Tree {
        var total_columns: usize = 0;
        var total_storage: usize = 0;
        for (log_sizes, column_counts) |log_size, count| {
            total_columns += count;
            total_storage += count * (@as(usize, 1) << @intCast(log_size));
        }
        const columns = try allocator.alloc([]M31, total_columns);
        errdefer allocator.free(columns);
        const storage = try allocator.alloc(M31, total_storage);
        errdefer allocator.free(storage);
        @memset(storage, M31.zero());
        var column_at: usize = 0;
        var storage_at: usize = 0;
        for (log_sizes, column_counts) |log_size, count| {
            const rows = @as(usize, 1) << @intCast(log_size);
            for (0..count) |_| {
                columns[column_at] = storage[storage_at..][0..rows];
                column_at += 1;
                storage_at += rows;
            }
        }
        return .{ .allocator = allocator, .columns = columns, .storage = storage };
    }

    pub fn deinit(self: *Tree) void {
        self.allocator.free(self.storage);
        self.allocator.free(self.columns);
        self.* = undefined;
    }

    pub fn fill(self: *Tree, value: M31) void {
        @memset(self.storage, value);
    }

    pub fn anyNonZero(self: *const Tree) bool {
        for (self.storage) |value| if (!value.isZero()) return true;
        return false;
    }

    pub fn expectFilled(self: *const Tree, value: M31) !void {
        for (self.storage) |actual| try std.testing.expect(actual.eql(value));
    }
};

pub fn expectCommittedScatter(destination: [][]M31, source: anytype) !bool {
    try std.testing.expectEqual(source.len, destination.len);
    var observed_nontrivial_permutation = false;
    for (destination, source) |published, logical| {
        try std.testing.expectEqual(logical.len, published.len);
        try std.testing.expect(logical.len != 0);
        try std.testing.expect(std.math.isPowerOfTwo(logical.len));
        const log_size: u32 = @intCast(std.math.log2_int(usize, logical.len));
        for (logical, 0..) |value, logical_row| {
            const committed = air.framework_interaction.committedRow(
                logical_row,
                log_size,
            );
            try std.testing.expect(published[committed].eql(value));
            if (committed != logical_row and
                !logical[committed].eql(value))
            {
                observed_nontrivial_permutation = true;
            }
        }
    }
    return observed_nontrivial_permutation;
}
