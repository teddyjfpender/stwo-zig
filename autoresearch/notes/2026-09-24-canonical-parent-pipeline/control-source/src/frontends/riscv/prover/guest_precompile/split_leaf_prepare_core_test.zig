//! Parallel ownership, manifest-barrier, and failure evidence for R-008.
//! Core split-leaf preparation and barrier tests.

const std = @import("std");
const M31 = @import("stwo_core").fields.m31.M31;
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const call_buffer = @import("../../runner/guest_precompile/call_buffer.zig");
const opcode_trace = @import("../opcode_trace.zig");
const aggregation_fixture = @import("../../aggregation/test_fixture.zig");
const aggregation_hash = @import("../../aggregation/hash.zig");
const aggregation_types = @import("../../aggregation/types.zig");
const split_leaf_statement = @import("split_leaf_statement.zig");
const subject = @import("split_leaf_prepare.zig");

const Authorities = struct {
    accepted: aggregation_types.AcceptedProtocolV1,
    caller: subject.CallerPrepareAuthorityV1,
    provider: subject.ProviderPrepareAuthorityV1,
};

fn authorities(
    call_count: u32,
    job_marker: u8,
    protocol_marker: u8,
) !Authorities {
    const accepted = aggregation_types.AcceptedProtocolV1{
        .proof_protocol_digest = aggregation_fixture.digest(protocol_marker),
        .relation_registry_digest = aggregation_fixture.digest(
            protocol_marker +% 1,
        ),
    };
    return .{
        .accepted = accepted,
        .caller = try subject.CallerPrepareAuthorityV1.canonical(
            accepted,
            aggregation_fixture.digest(job_marker),
            aggregation_fixture.digest(0xc1),
            call_count,
        ),
        .provider = try subject.ProviderPrepareAuthorityV1.canonical(
            accepted,
            aggregation_fixture.digest(job_marker),
            aggregation_fixture.digest(0xc2),
            call_count,
        ),
    };
}

fn callerIdentities(
    prepared: *const subject.PreparedCallerLeafV1,
) !split_leaf_statement.VerifierOwnedLeafIdentitiesV1 {
    return .{
        .protocol = try split_leaf_statement.VerifierOwnedProtocolIdentityV1.canonical(
            prepared.authority.accepted_protocol,
        ),
        .artifact = .{
            .role = .core_request,
            .air_artifact_digest = prepared.authority.air_artifact_digest,
            .preprocessed_root = prepared.descriptor.preprocessed_root,
            .component = prepared.authority.component,
        },
    };
}

fn providerIdentities(
    prepared: *const subject.PreparedProviderLeafV1,
) !split_leaf_statement.VerifierOwnedLeafIdentitiesV1 {
    return .{
        .protocol = try split_leaf_statement.VerifierOwnedProtocolIdentityV1.canonical(
            prepared.authority.accepted_protocol,
        ),
        .artifact = .{
            .role = .poseidon2_provider,
            .air_artifact_digest = prepared.authority.air_artifact_digest,
            .preprocessed_root = prepared.descriptor.preprocessed_root,
            .component = prepared.authority.component,
        },
    };
}

const CallerRunner = struct {
    allocator: std.mem.Allocator,
    authority: subject.CallerPrepareAuthorityV1,
    core: *const support.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    logs: *const support.OwnedLogs,
    result: ?subject.PreparedCallerLeafV1 = null,
    failure: ?anyerror = null,

    fn run(self: *CallerRunner) void {
        self.result = subject.prepareCaller(
            self.allocator,
            self.authority,
            self.core,
            self.extension,
            &self.logs.calls,
            &self.logs.rows,
        ) catch |err| {
            self.failure = err;
            return;
        };
    }
};

const ProviderRunner = struct {
    allocator: std.mem.Allocator,
    authority: subject.ProviderPrepareAuthorityV1,
    core: *const support.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    logs: *const support.OwnedLogs,
    result: ?subject.PreparedProviderLeafV1 = null,
    failure: ?anyerror = null,

    fn run(self: *ProviderRunner) void {
        self.result = subject.prepareProvider(
            self.allocator,
            self.authority,
            self.core,
            self.extension,
            &self.logs.calls,
            &self.logs.rows,
        ) catch |err| {
            self.failure = err;
            return;
        };
    }
};

test "role preparations run independently in parallel before one stable barrier" {
    comptime {
        if (subject.PreparedCallerLeafV1 == subject.PreparedProviderLeafV1)
            @compileError("R-008 role prepare types collapsed");
    }
    var core = support.coreFixture(17);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 17);
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();
    const authority = try authorities(17, 0x18, 0xa1);

    // Distinct arenas ensure the workers share no allocator state. Their
    // backing pages remain stable while the prepared values move out of the
    // runner structs and through the manifest barrier.
    var caller_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer caller_arena.deinit();
    var provider_arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer provider_arena.deinit();
    var caller_runner = CallerRunner{
        .allocator = caller_arena.allocator(),
        .authority = authority.caller,
        .core = &core,
        .extension = &extension,
        .logs = &logs,
    };
    var provider_runner = ProviderRunner{
        .allocator = provider_arena.allocator(),
        .authority = authority.provider,
        .core = &core,
        .extension = &extension,
        .logs = &logs,
    };
    const caller_thread = try std.Thread.spawn(
        .{},
        CallerRunner.run,
        .{&caller_runner},
    );
    const provider_thread = try std.Thread.spawn(
        .{},
        ProviderRunner.run,
        .{&provider_runner},
    );
    caller_thread.join();
    provider_thread.join();
    if (caller_runner.failure) |err| return err;
    if (provider_runner.failure) |err| return err;
    var caller = caller_runner.result.?;
    defer caller.deinit();
    var provider = provider_runner.result.?;
    defer provider.deinit();

    try caller.validate();
    try provider.validate();
    try std.testing.expectEqualSlices(
        u8,
        &caller.guest_call_commitment,
        &provider.guest_call_commitment,
    );
    try std.testing.expectEqual(@as(u64, 17), caller.guest_call_count);
    try std.testing.expectEqual(@as(usize, 2), caller.workProfile().construction_allocations);
    try std.testing.expectEqual(@as(usize, 2), provider.workProfile().construction_allocations);
    try std.testing.expectEqual(
        subject.selector_column_count * caller.main.domain_size,
        caller.workProfile().selector_cells,
    );
    try std.testing.expectEqual(
        caller.workProfile().retained_cells,
        caller.workProfile().construction_hash_pass_cells,
    );
    try std.testing.expectEqual(
        caller.workProfile().retained_cells + caller.workProfile().selector_cells,
        caller.workProfile().validation_total_read_cells,
    );
    try std.testing.expectEqual(
        provider.workProfile().retained_cells * @sizeOf(M31),
        provider.workProfile().retained_bytes,
    );

    const barrier = try subject.ManifestBarrierV1.create(
        std.testing.allocator,
        authority.accepted,
        &caller,
        &provider,
    );
    defer barrier.deinit();
    try std.testing.expectEqual(@as(u32, 2), barrier.session.header.leaf_count);
    try std.testing.expectEqual(@as(usize, 2), barrier.session.leaves.len);
    try std.testing.expectEqual(@as(u64, 34), barrier.session.total_leaf_call_count);
    try std.testing.expect(!aggregation_hash.isZero(barrier.session.session_digest));
    try std.testing.expect(!barrier.session.challenge.z.isZero());
    try std.testing.expectEqual(
        @as(usize, 1),
        barrier.workProfile().challenge_derivations,
    );
    try std.testing.expectEqual(
        @sizeOf(subject.ManifestBarrierV1),
        barrier.workProfile().retained_bytes,
    );

    const caller_ids = try callerIdentities(&caller);
    const provider_ids = try providerIdentities(&provider);
    const caller_statement = try barrier.callerStatement(&caller_ids);
    const provider_statement = try barrier.providerStatement(&provider_ids);
    try caller_statement.validateAgainstSession(&barrier.session, &caller_ids);
    try provider_statement.validateAgainstSession(&barrier.session, &provider_ids);
    try std.testing.expect(!aggregation_hash.eql(
        try caller_statement.sessionEnvelopeDigest(&barrier.session, &caller_ids),
        try provider_statement.sessionEnvelopeDigest(&barrier.session, &provider_ids),
    ));

    try std.testing.expect(subject.RESEARCH_ONLY);
    try std.testing.expect(!subject.ACTIVATES_PRODUCTION_PROOF);
    try std.testing.expect(!subject.RETAINS_PCS_SCHEME);
    try std.testing.expect(!subject.SHADOW_ROOTS_ARE_PCS_ROOTS);
    try std.testing.expect(!subject.CALL_COMMITMENT_IS_AIR_PROVED);
    try std.testing.expect(!subject.CALLER_SEAL_INCLUDES_BASE_RISCV_TRACE);
    try std.testing.expect(subject.PREPARES_BEFORE_SHARED_CHALLENGE);
    try std.testing.expect(subject.ALLOWS_PARALLEL_ROLE_PREPARE);
    try std.testing.expect(subject.PREPARED_STATE_IS_MOVE_SAFE);
}

test "ordered call commitment is canonical duplicate preserving and IO scoped" {
    var logs = try support.logsFixture(std.testing.allocator, 3);
    defer logs.deinit();
    const records = logs.calls.records();
    const baseline = try subject.orderedCallCommitment(records);

    var swapped = [_]call_buffer.Record{ records[2], records[1], records[0] };
    try std.testing.expect(!aggregation_hash.eql(
        baseline,
        try subject.orderedCallCommitment(&swapped),
    ));
    var changed_io = [_]call_buffer.Record{ records[0], records[1], records[2] };
    changed_io[0].input[0] +%= 1;
    try std.testing.expect(!aggregation_hash.eql(
        baseline,
        try subject.orderedCallCommitment(&changed_io),
    ));

    // Execution metadata belongs to caller-local relations, not the exported
    // 32-word caller/provider boundary.
    var changed_clock = [_]call_buffer.Record{ records[0], records[1], records[2] };
    changed_clock[0].execution_clock +%= 1;
    try std.testing.expectEqualSlices(
        u8,
        &baseline,
        &(try subject.orderedCallCommitment(&changed_clock)),
    );

    const duplicates = [_]call_buffer.Record{ records[0], records[0] };
    try std.testing.expect(!aggregation_hash.eql(
        try subject.orderedCallCommitment(duplicates[0..1]),
        try subject.orderedCallCommitment(&duplicates),
    ));
    try std.testing.expectEqualSlices(
        u8,
        &aggregation_hash.emptyCallCommitment(),
        &(try subject.orderedCallCommitment(&.{})),
    );
    changed_io[0].input[0] = aggregation_types.M31_MODULUS;
    try std.testing.expectError(
        error.NonCanonicalCallWord,
        subject.orderedCallCommitment(&changed_io),
    );
}

test "zero-call role owners retain canonical geometry and empty commitment" {
    var core = support.coreFixture(0);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 0);
    var logs = try support.logsFixture(std.testing.allocator, 0);
    defer logs.deinit();
    const authority = try authorities(0, 0x18, 0xa1);
    var caller = try subject.prepareCaller(
        std.testing.allocator,
        authority.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer caller.deinit();
    var provider = try subject.prepareProvider(
        std.testing.allocator,
        authority.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer provider.deinit();
    try std.testing.expectEqual(
        component_registry.minimum_log_size,
        caller.main.log_size,
    );
    try std.testing.expectEqual(@as(u64, 0), caller.guest_call_count);
    try std.testing.expectEqualSlices(
        u8,
        &aggregation_hash.emptyCallCommitment(),
        &caller.guest_call_commitment,
    );
    const barrier = try subject.ManifestBarrierV1.create(
        std.testing.allocator,
        authority.accepted,
        &caller,
        &provider,
    );
    defer barrier.deinit();
    try std.testing.expectEqual(@as(u64, 0), barrier.session.total_leaf_call_count);
    try barrier.session.challenge.validate();
}

fn callerAllocationCase(
    allocator: std.mem.Allocator,
    authority: *const subject.CallerPrepareAuthorityV1,
    core: *const support.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    logs: *const support.OwnedLogs,
) !void {
    var prepared = try subject.prepareCaller(
        allocator,
        authority.*,
        core,
        extension,
        &logs.calls,
        &logs.rows,
    );
    defer prepared.deinit();
}

fn providerAllocationCase(
    allocator: std.mem.Allocator,
    authority: *const subject.ProviderPrepareAuthorityV1,
    core: *const support.RiscVStatement,
    extension: *const guest_statement.ExtensionStatement,
    logs: *const support.OwnedLogs,
) !void {
    var prepared = try subject.prepareProvider(
        allocator,
        authority.*,
        core,
        extension,
        &logs.calls,
        &logs.rows,
    );
    defer prepared.deinit();
}

test "each role uses exactly two allocations and rolls back every failure" {
    var core = support.coreFixture(17);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 17);
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();
    const authority = try authorities(17, 0x18, 0xa1);

    var caller_exact = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = subject.role_prepare_allocation_count },
    );
    var caller = try subject.prepareCaller(
        caller_exact.allocator(),
        authority.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    try std.testing.expect(!caller_exact.has_induced_failure);
    try std.testing.expectEqual(
        subject.role_prepare_allocation_count,
        caller_exact.alloc_index,
    );
    caller.deinit();
    try std.testing.expectEqual(
        caller_exact.allocated_bytes,
        caller_exact.freed_bytes,
    );

    var provider_exact = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = subject.role_prepare_allocation_count },
    );
    var provider = try subject.prepareProvider(
        provider_exact.allocator(),
        authority.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    try std.testing.expect(!provider_exact.has_induced_failure);
    try std.testing.expectEqual(
        subject.role_prepare_allocation_count,
        provider_exact.alloc_index,
    );
    provider.deinit();
    try std.testing.expectEqual(
        provider_exact.allocated_bytes,
        provider_exact.freed_bytes,
    );

    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        callerAllocationCase,
        .{ &authority.caller, &core, &extension, &logs },
    );
    try std.testing.checkAllAllocationFailures(
        std.testing.allocator,
        providerAllocationCase,
        .{ &authority.provider, &core, &extension, &logs },
    );

    // Production semantic preflight precedes even the selector allocation.
    logs.calls.storage.items[0].output[0] +%= 1;
    var no_allocation = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.ProviderOutputMismatch,
        subject.prepareCaller(
            no_allocation.allocator(),
            authority.caller,
            &core,
            &extension,
            &logs.calls,
            &logs.rows,
        ),
    );
    try std.testing.expect(!no_allocation.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 0), no_allocation.alloc_index);
}

test "barrier rejects role state and pair mutations before allocating or drawing" {
    var core = support.coreFixture(17);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 17);
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();
    const authority = try authorities(17, 0x18, 0xa1);
    var caller = try subject.prepareCaller(
        std.testing.allocator,
        authority.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer caller.deinit();
    var provider = try subject.prepareProvider(
        std.testing.allocator,
        authority.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer provider.deinit();

    var selector_index: usize = 0;
    while (!caller.selectors.storage[selector_index].isZero()) : (selector_index += 1) {}
    const saved_selector = caller.selectors.storage[selector_index];
    caller.selectors.storage[selector_index] = M31.one();
    var no_barrier_alloc = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.NonCanonicalPreparedSelectors,
        subject.ManifestBarrierV1.create(
            no_barrier_alloc.allocator(),
            authority.accepted,
            &caller,
            &provider,
        ),
    );
    try std.testing.expect(!no_barrier_alloc.has_induced_failure);
    caller.selectors.storage[selector_index] = saved_selector;

    caller.main.storage[0] = caller.main.storage[0].add(M31.one());
    try std.testing.expectError(
        error.PreparedRoleMutated,
        subject.ManifestBarrierV1.create(
            no_barrier_alloc.allocator(),
            authority.accepted,
            &caller,
            &provider,
        ),
    );
    caller.main.storage[0] = caller.main.storage[0].sub(M31.one());

    caller.descriptor.main_root[0] ^= 1;
    try std.testing.expectError(
        error.PreparedRoleMutated,
        subject.ManifestBarrierV1.create(
            no_barrier_alloc.allocator(),
            authority.accepted,
            &caller,
            &provider,
        ),
    );
    caller.descriptor.main_root[0] ^= 1;

    provider.descriptor.role = .core_request;
    try std.testing.expectError(
        error.PreparedRoleMutated,
        subject.ManifestBarrierV1.create(
            no_barrier_alloc.allocator(),
            authority.accepted,
            &caller,
            &provider,
        ),
    );
    provider.descriptor.role = .poseidon2_provider;
    try std.testing.expectEqual(@as(usize, 0), no_barrier_alloc.alloc_index);

    var barrier_oom = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.OutOfMemory,
        subject.ManifestBarrierV1.create(
            barrier_oom.allocator(),
            authority.accepted,
            &caller,
            &provider,
        ),
    );
    try std.testing.expect(barrier_oom.has_induced_failure);
    // The barrier borrows no role ownership, so an aborted publication leaves
    // both move-safe owners valid and available for deterministic cleanup.
    try caller.validate();
    try provider.validate();

    // A valid barrier owns exactly one stable object allocation.
    var exact = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = subject.manifest_barrier_allocation_count },
    );
    const barrier = try subject.ManifestBarrierV1.create(
        exact.allocator(),
        authority.accepted,
        &caller,
        &provider,
    );
    try std.testing.expect(!exact.has_induced_failure);
    try std.testing.expectEqual(@as(usize, 1), exact.alloc_index);
    barrier.deinit();
    try std.testing.expectEqual(exact.allocated_bytes, exact.freed_bytes);
}

test "barrier rejects cross-job cross-count and cross-protocol prepared pairs" {
    var core = support.coreFixture(17);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 17);
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();
    const authority = try authorities(17, 0x18, 0xa1);
    var caller = try subject.prepareCaller(
        std.testing.allocator,
        authority.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer caller.deinit();
    var provider = try subject.prepareProvider(
        std.testing.allocator,
        authority.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer provider.deinit();

    const other_job_authority = try authorities(17, 0x19, 0xa1);
    var other_job_provider = try subject.prepareProvider(
        std.testing.allocator,
        other_job_authority.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer other_job_provider.deinit();
    var no_allocation = std.testing.FailingAllocator.init(
        std.testing.allocator,
        .{ .fail_index = 0 },
    );
    try std.testing.expectError(
        error.PairJobMismatch,
        subject.ManifestBarrierV1.create(
            no_allocation.allocator(),
            authority.accepted,
            &caller,
            &other_job_provider,
        ),
    );
    try std.testing.expect(!no_allocation.has_induced_failure);

    const other_protocol_authority = try authorities(17, 0x18, 0xb1);
    var other_protocol_provider = try subject.prepareProvider(
        std.testing.allocator,
        other_protocol_authority.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer other_protocol_provider.deinit();
    try std.testing.expectError(
        error.PairProtocolMismatch,
        subject.ManifestBarrierV1.create(
            no_allocation.allocator(),
            authority.accepted,
            &caller,
            &other_protocol_provider,
        ),
    );

    var core_18 = support.coreFixture(18);
    const extension_18 = try guest_statement.ExtensionStatement.canonical(
        &core_18,
        18,
    );
    var logs_18 = try support.logsFixture(std.testing.allocator, 18);
    defer logs_18.deinit();
    const authority_18 = try authorities(18, 0x18, 0xa1);
    var count_provider = try subject.prepareProvider(
        std.testing.allocator,
        authority_18.provider,
        &core_18,
        &extension_18,
        &logs_18.calls,
        &logs_18.rows,
    );
    defer count_provider.deinit();
    try std.testing.expectError(
        error.PairCallCommitmentMismatch,
        subject.ManifestBarrierV1.create(
            no_allocation.allocator(),
            authority.accepted,
            &caller,
            &count_provider,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), no_allocation.alloc_index);
}

test "session-bound role envelope cannot cross a sibling or job barrier" {
    var core = support.coreFixture(17);
    const extension = try guest_statement.ExtensionStatement.canonical(&core, 17);
    var logs = try support.logsFixture(std.testing.allocator, 17);
    defer logs.deinit();
    const authority_a = try authorities(17, 0x18, 0xa1);
    var caller_a = try subject.prepareCaller(
        std.testing.allocator,
        authority_a.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer caller_a.deinit();
    var provider_a = try subject.prepareProvider(
        std.testing.allocator,
        authority_a.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer provider_a.deinit();
    const barrier_a = try subject.ManifestBarrierV1.create(
        std.testing.allocator,
        authority_a.accepted,
        &caller_a,
        &provider_a,
    );
    defer barrier_a.deinit();
    const caller_ids_a = try callerIdentities(&caller_a);
    const statement_a = try barrier_a.callerStatement(&caller_ids_a);

    const authority_b = try authorities(17, 0x19, 0xa1);
    var caller_b = try subject.prepareCaller(
        std.testing.allocator,
        authority_b.caller,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer caller_b.deinit();
    var provider_b = try subject.prepareProvider(
        std.testing.allocator,
        authority_b.provider,
        &core,
        &extension,
        &logs.calls,
        &logs.rows,
    );
    defer provider_b.deinit();
    const barrier_b = try subject.ManifestBarrierV1.create(
        std.testing.allocator,
        authority_b.accepted,
        &caller_b,
        &provider_b,
    );
    defer barrier_b.deinit();
    try std.testing.expectError(
        error.SessionMismatch,
        statement_a.validateAgainstSession(&barrier_b.session, &caller_ids_a),
    );
}
