//! Failure, transcript-boundary, and ownership tests for real split PCS state.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const pcs_core = @import("stwo_core").pcs;
const ColumnEvaluation = @import("stwo_prover_engine").pcs.ColumnEvaluation;
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const types = @import("../types.zig");
const production = @import("../main_trace_plan_execution_production.zig");
const aggregation_fixture = @import("../../aggregation/test_fixture.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const split_leaf_prepare = @import("split_leaf_prepare.zig");
const split_leaf_statement = @import("split_leaf_statement.zig");
const split_provider_finish = @import("split_provider_finish.zig");
const subject = @import("split_pcs_prepare.zig");

const FakeEngine = struct {
    pub const Hasher = struct {
        pub const Hash = [32]u8;
    };
    pub const Channel = types.Channel;
    pub const Scheme = struct {
        values: [subject.tree_count][32]u8 = undefined,
        count: usize = 0,

        pub fn roots(
            self: *Scheme,
            allocator: std.mem.Allocator,
        ) !pcs_core.TreeVec([32]u8) {
            const values = try allocator.dupe([32]u8, self.values[0..self.count]);
            return pcs_core.TreeVec([32]u8).initOwned(values);
        }
    };

    var commit_calls: usize = 0;
    var fail_commit_index: ?usize = null;

    fn reset() void {
        commit_calls = 0;
        fail_commit_index = null;
    }

    pub fn init(_: std.mem.Allocator, _: pcs_core.PcsConfig) !Scheme {
        return .{};
    }

    pub fn deinit(_: *Scheme, _: std.mem.Allocator) void {}

    pub fn commitWithBacking(
        scheme: *Scheme,
        allocator: std.mem.Allocator,
        columns: []ColumnEvaluation,
        maybe_backings: ?[][]M31,
        _: anytype,
        channel: *Channel,
    ) !void {
        const backings = maybe_backings orelse
            return error.FakeEngineRequiresOwnedBacking;
        const root = hashColumns(columns);
        allocator.free(columns);
        for (backings) |backing| allocator.free(backing);
        allocator.free(backings);

        const call_index = commit_calls;
        commit_calls += 1;
        if (fail_commit_index == call_index)
            return error.InjectedCommitFailure;
        if (scheme.count >= scheme.values.len) return error.TooManyFakeTrees;
        scheme.values[scheme.count] = root;
        scheme.count += 1;
        mixDigest(channel, root);
    }

    pub fn flushPendingCommit(
        _: *Scheme,
        _: std.mem.Allocator,
        _: *Channel,
    ) !void {}
};

fn hashColumns(columns: []const ColumnEvaluation) [32]u8 {
    var hash = std.crypto.hash.blake2.Blake2s256.init(.{});
    for (columns) |column| {
        var log_bytes: [4]u8 = undefined;
        std.mem.writeInt(u32, &log_bytes, column.log_size, .little);
        hash.update(&log_bytes);
        for (column.values) |value| {
            const bytes = value.toBytesLe();
            hash.update(&bytes);
        }
    }
    var result: [32]u8 = undefined;
    hash.final(&result);
    return result;
}

fn mixDigest(channel: anytype, digest: [32]u8) void {
    var words: [8]u32 = undefined;
    for (&words, 0..) |*word, index| {
        const start = index * @sizeOf(u32);
        word.* = std.mem.readInt(
            u32,
            digest[start..][0..@sizeOf(u32)],
            .little,
        );
    }
    channel.mixU32s(&words);
}

const test_config = pcs_core.PcsConfig{
    .pow_bits = 0,
    .fri_config = .{
        .log_blowup_factor = 1,
        .log_last_layer_degree_bound = 0,
        .n_queries = 3,
        .fold_step = 1,
    },
};

const Authorities = struct {
    accepted: aggregation_types.AcceptedProtocolV1,
    caller: split_leaf_prepare.CallerPrepareAuthorityV1,
    provider: split_leaf_prepare.ProviderPrepareAuthorityV1,
};

fn authorities(
    count: u32,
    job_marker: u8,
    protocol_marker: u8,
) !Authorities {
    const accepted = aggregation_types.AcceptedProtocolV1{
        .proof_protocol_digest = aggregation_fixture.digest(protocol_marker),
        .relation_registry_digest = aggregation_fixture.digest(protocol_marker +% 1),
    };
    return .{
        .accepted = accepted,
        .caller = try split_leaf_prepare.CallerPrepareAuthorityV1.canonical(
            accepted,
            aggregation_fixture.digest(job_marker),
            aggregation_fixture.digest(0xc1),
            count,
        ),
        .provider = try split_leaf_prepare.ProviderPrepareAuthorityV1.canonical(
            accepted,
            aggregation_fixture.digest(job_marker),
            aggregation_fixture.digest(0xc2),
            count,
        ),
    };
}

const BaseOwner = struct {
    allocator: std.mem.Allocator,
    value: production.MainCommitment,

    fn init(
        allocator: std.mem.Allocator,
        core: anytype,
        marker: u32,
    ) !BaseOwner {
        const columns = try allocator.alloc(ColumnEvaluation, core.nMainColumns());
        var initialized: usize = 0;
        errdefer {
            for (columns[0..initialized]) |column| allocator.free(column.values);
            allocator.free(columns);
        }
        for (core.component_descs[0..core.n_components]) |descriptor| {
            try appendColumns(
                allocator,
                columns,
                &initialized,
                descriptor.log_size,
                descriptor.n_columns,
                marker,
            );
        }
        for (core.infra_descs[0..core.n_infra]) |descriptor| {
            try appendColumns(
                allocator,
                columns,
                &initialized,
                descriptor.log_size,
                descriptor.n_columns,
                marker,
            );
        }
        if (initialized != columns.len) return error.InvalidTestBaseGeometry;
        return .{
            .allocator = allocator,
            .value = .{
                .destination_policy = .independent_columns,
                .columns = columns,
                .backing = null,
            },
        };
    }

    fn deinit(self: *BaseOwner) void {
        self.value.deinit(self.allocator);
        self.* = undefined;
    }
};

fn appendColumns(
    allocator: std.mem.Allocator,
    columns: []ColumnEvaluation,
    cursor: *usize,
    log_size: u32,
    count: u32,
    marker: u32,
) !void {
    const domain = @as(usize, 1) << @intCast(log_size);
    for (0..count) |_| {
        const values = try allocator.alloc(M31, domain);
        for (values, 0..) |*value, row| {
            value.* = M31.fromCanonical(@intCast(
                (marker +% @as(u32, @intCast(cursor.* * 131 + row))) %
                    (aggregation_types.M31_MODULUS - 1),
            ));
        }
        columns[cursor.*] = .{ .log_size = log_size, .values = values };
        cursor.* += 1;
    }
}

const Pair = struct {
    accepted: aggregation_types.AcceptedProtocolV1,
    caller: subject.PreparedCallerPcsV1(FakeEngine),
    provider: subject.PreparedProviderPcsV1(FakeEngine),

    fn deinit(self: *Pair) void {
        self.provider.deinit();
        self.caller.deinit();
        self.* = undefined;
    }
};

fn preparePair(
    allocator: std.mem.Allocator,
    count: usize,
    job_marker: u8,
    protocol_marker: u8,
    base_marker: u32,
) !Pair {
    var core = support.coreFixture(@intCast(count));
    const extension = try guest_statement.ExtensionStatement.canonical(
        &core,
        @intCast(count),
    );
    var logs = try support.logsFixture(allocator, count);
    defer logs.deinit();
    const authority = try authorities(
        @intCast(count),
        job_marker,
        protocol_marker,
    );
    var caller_shadow = try split_leaf_prepare.prepareCaller(
        allocator,
        authority.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    var caller_shadow_owned = true;
    defer if (caller_shadow_owned) caller_shadow.deinit();
    var provider_shadow = try split_leaf_prepare.prepareProvider(
        allocator,
        authority.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    var provider_shadow_owned = true;
    defer if (provider_shadow_owned) provider_shadow.deinit();
    var base = try BaseOwner.init(allocator, &core, base_marker);
    var base_owned = true;
    defer if (base_owned) base.deinit();

    base_owned = false;
    caller_shadow_owned = false;
    var caller = try subject.prepareCaller(
        FakeEngine,
        allocator,
        test_config,
        &core,
        &extension,
        &base.value,
        &caller_shadow,
        null,
    );
    errdefer caller.deinit();
    provider_shadow_owned = false;
    const provider = try subject.prepareProvider(
        FakeEngine,
        allocator,
        test_config,
        &core,
        &extension,
        &provider_shadow,
        null,
    );
    return .{
        .accepted = authority.accepted,
        .caller = caller,
        .provider = provider,
    };
}

fn identities(
    comptime role: aggregation_types.LeafRole,
    prepared: anytype,
) !split_leaf_statement.VerifierOwnedLeafIdentitiesV1 {
    return .{
        .protocol = try split_leaf_statement.VerifierOwnedProtocolIdentityV1.canonical(
            prepared.authority.accepted_protocol,
        ),
        .artifact = .{
            .role = role,
            .air_artifact_digest = prepared.authority.air_artifact_digest,
            .preprocessed_root = prepared.roots[subject.tree0_index],
            .component = prepared.authority.component,
        },
    };
}

test "real PCS state retains exactly two roots and zero local shared draws" {
    FakeEngine.reset();
    var pair = try preparePair(std.testing.allocator, 17, 0x18, 0xa1, 0x1020_3040);
    defer pair.deinit();
    try pair.caller.validate();
    try pair.provider.validate();

    try std.testing.expect(subject.PREPARES_REAL_PCS_ROOTS);
    try std.testing.expect(subject.RETAINS_REAL_PCS_SCHEME);
    try std.testing.expect(!subject.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expect(!subject.CALL_COMMITMENT_IS_AIR_PROVED);
    try std.testing.expect(!subject.CAN_FINISH_STARK);
    try std.testing.expect(!subject.CREATES_WORK_POOL);
    try std.testing.expectEqual(@as(usize, 4), FakeEngine.commit_calls);
    try std.testing.expectEqual(
        @as(usize, component_registry.provider_main_columns),
        pair.provider.ownership.tree1_columns,
    );
    try std.testing.expectEqual(
        @as(usize, component_registry.caller_layout.main_columns),
        pair.caller.ownership.tree1_columns - 34,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        pair.caller.ownership.commitment_source_plan_cell_copies,
    );
    try std.testing.expectEqual(
        @as(usize, 0),
        pair.provider.ownership.commitment_source_plan_cell_copies,
    );
    try std.testing.expectEqual(
        subject.caller_relation_source_columns * pair.caller.relation_source.domain_size,
        pair.caller.ownership.relation_source_capture_cell_copies,
    );
    try std.testing.expectEqual(
        subject.provider_relation_source_columns * pair.provider.relation_source.domain_size,
        pair.provider.ownership.relation_source_capture_cell_copies,
    );
    try std.testing.expectEqual(
        pair.caller.ownership.tree0_cells + pair.caller.ownership.tree1_cells,
        pair.caller.ownership.backend_source_detach_copy_upper_bound_cells,
    );
    try std.testing.expectEqual(
        pair.provider.ownership.tree0_cells + pair.provider.ownership.tree1_cells,
        pair.provider.ownership.backend_source_detach_copy_upper_bound_cells,
    );
    try std.testing.expectEqual(@as(usize, 0), pair.caller.ownership.local_shared_challenge_draws);
    try std.testing.expectEqual(@as(usize, 0), pair.provider.ownership.local_shared_challenge_draws);
}

test "caller Tree-1 root covers every base column before its 286-column role block" {
    FakeEngine.reset();
    var first = try preparePair(std.testing.allocator, 1, 0x18, 0xa1, 0x1020_3040);
    defer first.deinit();
    var changed = try preparePair(std.testing.allocator, 1, 0x18, 0xa1, 0x1020_3041);
    defer changed.deinit();

    try std.testing.expect(!aggregation_hash.eql(
        first.caller.roots[subject.tree1_index],
        changed.caller.roots[subject.tree1_index],
    ));
    try std.testing.expect(aggregation_hash.eql(
        first.provider.roots[subject.tree1_index],
        changed.provider.roots[subject.tree1_index],
    ));
    try std.testing.expect(!aggregation_hash.eql(
        first.caller.descriptor.leaf_statement_digest,
        changed.caller.descriptor.leaf_statement_digest,
    ));
}

test "retained provider projection is exactly enabled input and output without widening" {
    FakeEngine.reset();
    var pair = try preparePair(std.testing.allocator, 17, 0x18, 0xa1, 0x1020_3040);
    defer pair.deinit();
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();
    const source = &pair.provider.relation_source;

    try std.testing.expectEqual(@as(usize, 33), source.columnCount());
    try std.testing.expectEqual(
        @as(usize, 33) * source.domain_size,
        pair.provider.ownership.retained_relation_source_cells,
    );
    for (0..source.domain_size) |logical_row| {
        const committed = @import("../../air/guest_precompile/main_trace.zig")
            .committedRow(logical_row, source.log_size);
        const active = M31.fromCanonical(@intFromBool(logical_row < 17));
        try std.testing.expect(source.column(0)[committed].eql(active));
        if (logical_row < 17) {
            const record = logs.calls.records()[logical_row];
            for (0..16) |lane| {
                try std.testing.expect(source.column(1 + lane)[committed].eql(
                    M31.fromCanonical(record.input[lane]),
                ));
                try std.testing.expect(source.column(17 + lane)[committed].eql(
                    M31.fromCanonical(record.output[lane]),
                ));
            }
        } else {
            for (1..33) |column_index| {
                try std.testing.expect(source.column(column_index)[committed].isZero());
            }
        }
    }
}

test "provider Tree-2 owner is allocation-failure atomic" {
    FakeEngine.reset();
    var pair = try preparePair(std.testing.allocator, 1, 0x18, 0xa1, 0x1020_3040);
    defer pair.deinit();
    const Barrier = subject.ManifestBarrierV1(FakeEngine);
    const barrier = try Barrier.create(
        std.testing.allocator,
        pair.accepted,
        &pair.caller,
        &pair.provider,
    );
    defer barrier.deinit();
    const relations = try @import("split_component_assembly.zig")
        .bindSessionGuestRelation(
        &barrier.session,
        @import("../../air/guest_precompile/relation_challenges.zig")
            .Poseidon2V1Relations.dummy(),
    );
    const Check = struct {
        fn run(
            allocator: std.mem.Allocator,
            source: *const subject.ProviderRelationSourceV1,
            component: component_registry.Descriptor,
            bound_relations: *const @TypeOf(relations),
        ) !void {
            var owner = try split_provider_finish.ProviderInteractionOwnerV1.init(
                allocator,
                source,
                component,
                bound_relations,
            );
            defer owner.deinit();
        }
    };
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        Check.run,
        .{
            &pair.provider.relation_source,
            pair.provider.authority.component,
            &relations,
        },
    );
}

test "manifest barrier derives once then both leaves bind the same shared pair without a draw" {
    FakeEngine.reset();
    var pair = try preparePair(std.testing.allocator, 17, 0x18, 0xa1, 0x1020_3040);
    defer pair.deinit();
    const Barrier = subject.ManifestBarrierV1(FakeEngine);
    const barrier = try Barrier.create(
        std.testing.allocator,
        pair.accepted,
        &pair.caller,
        &pair.provider,
    );
    defer barrier.deinit();
    const caller_id = try identities(.core_request, &pair.caller);
    const provider_id = try identities(.poseidon2_provider, &pair.provider);
    const caller_draws = pair.caller.channel.n_draws;
    const provider_draws = pair.provider.channel.n_draws;
    const caller_binding = try pair.caller.bindSession(
        &barrier.session,
        &caller_id,
    );
    const provider_binding = try pair.provider.bindSession(
        &barrier.session,
        &provider_id,
    );

    try std.testing.expectEqual(caller_binding, provider_binding);
    try std.testing.expectEqual(caller_draws, pair.caller.channel.n_draws);
    try std.testing.expectEqual(provider_draws, pair.provider.channel.n_draws);
    try std.testing.expectEqual(subject.CommitmentPhaseV1.session_bound, pair.caller.phase);
    try std.testing.expectEqual(subject.CommitmentPhaseV1.session_bound, pair.provider.phase);
    try std.testing.expectError(
        error.PcsSessionAlreadyBound,
        pair.caller.bindSession(&barrier.session, &caller_id),
    );
}

test "barrier and finish reject swapped protocol cross-session and mutated roots before channel change" {
    FakeEngine.reset();
    var first = try preparePair(std.testing.allocator, 1, 0x18, 0xa1, 0x1020_3040);
    defer first.deinit();
    var second = try preparePair(std.testing.allocator, 1, 0x19, 0xa1, 0x1020_3040);
    defer second.deinit();
    const Barrier = subject.ManifestBarrierV1(FakeEngine);

    var wrong_protocol = first.accepted;
    wrong_protocol.proof_protocol_digest[0] ^= 1;
    try std.testing.expectError(
        error.PairProtocolMismatch,
        Barrier.create(
            std.testing.allocator,
            wrong_protocol,
            &first.caller,
            &first.provider,
        ),
    );

    const first_barrier = try Barrier.create(
        std.testing.allocator,
        first.accepted,
        &first.caller,
        &first.provider,
    );
    defer first_barrier.deinit();
    const second_barrier = try Barrier.create(
        std.testing.allocator,
        second.accepted,
        &second.caller,
        &second.provider,
    );
    defer second_barrier.deinit();

    const caller_id = try identities(.core_request, &first.caller);
    const provider_id = try identities(.poseidon2_provider, &first.provider);
    const pristine_caller_channel = first.caller.channel;
    try std.testing.expectError(
        error.PcsSessionDescriptorMismatch,
        first.caller.bindSession(&second_barrier.session, &caller_id),
    );
    try std.testing.expectEqual(pristine_caller_channel, first.caller.channel);
    try std.testing.expectEqual(subject.CommitmentPhaseV1.commitments_frozen, first.caller.phase);

    const pristine_provider_channel = first.provider.channel;
    try std.testing.expectError(
        error.ArtifactRoleMismatch,
        first.provider.bindSession(&first_barrier.session, &caller_id),
    );
    try std.testing.expectEqual(pristine_provider_channel, first.provider.channel);
    try std.testing.expectEqual(subject.CommitmentPhaseV1.commitments_frozen, first.provider.phase);

    first.caller.roots[subject.tree1_index][0] ^= 1;
    try std.testing.expectError(error.PreparedPcsRootMismatch, first.caller.validate());
    first.caller.roots[subject.tree1_index][0] ^= 1;
    _ = provider_id;
}

test "pre-requested cancellation consumes caller inputs without entering the engine" {
    FakeEngine.reset();
    const allocator = std.testing.allocator;
    var core = support.coreFixture(1);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(allocator, 1);
    defer logs.deinit();
    const authority = try authorities(1, 0x18, 0xa1);
    var shadow = try split_leaf_prepare.prepareCaller(
        allocator,
        authority.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    var base = try BaseOwner.init(allocator, &core, 0x1020_3040);
    var cancellation = subject.CancellationTokenV1{};
    cancellation.request();
    try std.testing.expectError(
        error.SplitPcsPreparationCancelled,
        subject.prepareCaller(
            FakeEngine,
            allocator,
            test_config,
            &core,
            &extension,
            &base.value,
            &shadow,
            &cancellation,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), FakeEngine.commit_calls);
}

test "each injected PCS commit failure consumes the transaction and leaks nothing" {
    for (0..subject.tree_count) |fail_index| {
        FakeEngine.reset();
        FakeEngine.fail_commit_index = fail_index;
        var counter = std.testing.FailingAllocator.init(std.testing.allocator, .{});
        const allocator = counter.allocator();
        var core = support.coreFixture(1);
        const extension = try guest_statement.ExtensionStatement.canonical(&core, 1);
        var logs = try support.logsFixture(std.testing.allocator, 1);
        defer logs.deinit();
        const authority = try authorities(1, 0x18, 0xa1);
        var shadow = try split_leaf_prepare.prepareCaller(
            allocator,
            authority.caller,
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
        );
        var base = try BaseOwner.init(allocator, &core, 0x1020_3040);
        try std.testing.expectError(
            error.InjectedCommitFailure,
            subject.prepareCaller(
                FakeEngine,
                allocator,
                test_config,
                &core,
                &extension,
                &base.value,
                &shadow,
                null,
            ),
        );
        try std.testing.expectEqual(counter.allocated_bytes, counter.freed_bytes);
    }
}

fn allocationFailureCase(allocator: std.mem.Allocator) !void {
    FakeEngine.reset();
    var core = support.coreFixture(1);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 1);
    var logs = try support.logsFixture(std.testing.allocator, 1);
    defer logs.deinit();
    const authority = try authorities(1, 0x18, 0xa1);
    var shadow = try split_leaf_prepare.prepareProvider(
        allocator,
        authority.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    var shadow_owned = true;
    defer if (shadow_owned) shadow.deinit();
    shadow_owned = false;
    var prepared = try subject.prepareProvider(
        FakeEngine,
        allocator,
        test_config,
        &core,
        &extension,
        &shadow,
        null,
    );
    defer prepared.deinit();
}

test "provider prepare releases every allocation failure" {
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        allocationFailureCase,
        .{},
    );
}
