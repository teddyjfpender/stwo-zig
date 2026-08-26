//! Ownership, ordering, rejection, and allocation evidence for profile components.

const std = @import("std");
const core_air_components = @import("stwo_core").air.components;
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const guest_relations = @import("../../air/guest_precompile/relation_challenges.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const base_statement = @import("../../air/statement.zig");
const proof_workspace = @import("../proof_workspace.zig");
const subject = @import("component_assembly.zig");

const Fixture = struct {
    core: base_statement.RiscVStatement,
    extension: guest_statement.ExtensionStatement,
    caller_authority: component_registry.CallerConstruction,
    provider_authority: component_registry.ProviderConstruction,
    caller_claim: caller_component.Claim,
    provider_claim: provider_component.Claim,
    relations: guest_relations.Poseidon2V1Relations,

    fn init(n_guest: u32) !Fixture {
        const core = support.coreFixture(n_guest);
        const extension = try guest_statement.ExtensionStatement.canonical(
            &core,
            n_guest,
        );
        const registry = component_registry.Registry.forProfile(extension.profile);
        const caller_authority = switch (try registry.verifierConstruction(
            extension.components[0],
        )) {
            .caller => |value| value,
            .provider => return error.TestExpectedCallerAuthority,
        };
        const provider_authority = switch (try registry.verifierConstruction(
            extension.components[1],
        )) {
            .provider => |value| value,
            .caller => return error.TestExpectedProviderAuthority,
        };
        return .{
            .core = core,
            .extension = extension,
            .caller_authority = caller_authority,
            .provider_authority = provider_authority,
            .caller_claim = try caller_component.Claim.canonical(
                caller_authority,
                .{QM31.zero()} ** caller_component.batch_count,
            ),
            .provider_claim = try provider_component.Claim.canonical(
                provider_authority,
                .{QM31.zero()} ** provider_component.batch_count,
            ),
            .relations = guest_relations.Poseidon2V1Relations.dummy(),
        };
    }
};

fn seedBaseComponents(
    fixture: *const Fixture,
    result: *[3]caller_component.CallerComponent,
) !void {
    for (result, 0..) |*component, index| {
        const offset = 8 * index;
        component.* = try caller_component.CallerComponent.initProver(
            fixture.caller_authority,
            fixture.caller_claim,
            .{
                .is_first_col_idx = offset,
                .is_active_col_idx = offset + 1,
                .main_col_offset = offset,
                .interaction_col_offset = offset,
            },
            &fixture.relations,
        );
    }
}

fn proverHandles(
    components: *const [3]caller_component.CallerComponent,
) [3]prover_component.ComponentProver {
    var result: [3]prover_component.ComponentProver = undefined;
    for (&result, components) |*handle, *component| {
        handle.* = component.asProverComponent();
    }
    return result;
}

fn verifierHandles(
    components: *const [3]caller_component.CallerComponent,
) [3]core_air_components.Component {
    var result: [3]core_air_components.Component = undefined;
    for (&result, components) |*handle, *component| {
        handle.* = component.asVerifierComponent();
    }
    return result;
}

fn expectContext(expected: anytype, actual: *const anyopaque) !void {
    try std.testing.expectEqual(@intFromPtr(expected), @intFromPtr(actual));
}

fn expectInside(comptime T: type, owner: *const T, pointer: *const anyopaque) !void {
    const start = @intFromPtr(owner);
    const end = start + @sizeOf(T);
    const address = @intFromPtr(pointer);
    try std.testing.expect(address >= start and address < end);
}

test "profile component owner appends exact caller provider order and placements symmetrically" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(1);
    var base_components: [3]caller_component.CallerComponent = undefined;
    try seedBaseComponents(&fixture, &base_components);
    const base_provers = proverHandles(&base_components);
    const base_verifiers = verifierHandles(&base_components);
    const expected = try subject.placements(&fixture.core);

    try std.testing.expectEqual(
        @as(usize, fixture.core.nPreprocessedColumns()),
        expected.caller.is_first_col_idx,
    );
    try std.testing.expectEqual(
        expected.caller.is_first_col_idx + 1,
        expected.caller.is_active_col_idx,
    );
    try std.testing.expectEqual(
        @as(usize, fixture.core.nMainColumns()),
        expected.caller.main_col_offset,
    );
    try std.testing.expectEqual(
        @as(usize, fixture.core.nInteractionColumns()),
        expected.caller.interaction_col_offset,
    );
    try std.testing.expectEqual(
        expected.caller.is_first_col_idx + caller_component.preprocessed_column_count,
        expected.provider.is_first_col_idx,
    );
    try std.testing.expectEqual(
        expected.caller.main_col_offset + caller_component.main_column_count,
        expected.provider.main_col_offset,
    );
    try std.testing.expectEqual(
        expected.caller.interaction_col_offset + caller_component.interaction_column_count,
        expected.provider.interaction_col_offset,
    );

    const prover = try subject.ProverAssembly.create(
        allocator,
        &fixture.core,
        &fixture.extension,
        &fixture.relations,
        &base_provers,
        fixture.caller_claim,
        fixture.provider_claim,
    );
    defer prover.destroy(allocator);
    const verifier = try subject.VerifierAssembly.create(
        allocator,
        &fixture.core,
        &fixture.extension,
        &fixture.relations,
        &base_verifiers,
        fixture.caller_claim,
        fixture.provider_claim,
    );
    defer verifier.destroy(allocator);

    const prover_active = prover.active();
    const verifier_active = verifier.active();
    try std.testing.expectEqual(@as(usize, 5), prover_active.len);
    try std.testing.expectEqual(prover_active.len, verifier_active.len);
    for (0..base_components.len) |index| {
        try expectContext(&base_components[index], prover_active[index].ctx);
        try expectContext(&base_components[index], verifier_active[index].ctx);
    }
    try expectContext(&prover.caller, prover_active[3].ctx);
    try expectContext(&prover.provider, prover_active[4].ctx);
    try expectContext(&verifier.caller, verifier_active[3].ctx);
    try expectContext(&verifier.provider, verifier_active[4].ctx);
    try std.testing.expect(std.meta.eql(expected.caller, prover.caller.placement));
    try std.testing.expect(std.meta.eql(expected.provider, prover.provider.placement));
    try std.testing.expect(std.meta.eql(expected.caller, verifier.caller.placement));
    try std.testing.expect(std.meta.eql(expected.provider, verifier.provider.placement));
    try std.testing.expectEqual(
        caller_component.constraint_count,
        prover_active[3].nConstraints(),
    );
    try std.testing.expectEqual(
        provider_component.constraint_count,
        prover_active[4].nConstraints(),
    );
    try std.testing.expectEqual(
        prover_active[3].nConstraints(),
        verifier_active[3].nConstraints(),
    );
    try std.testing.expectEqual(
        prover_active[4].nConstraints(),
        verifier_active[4].nConstraints(),
    );

    const caller_indices = try prover_active[3].preprocessedColumnIndices(allocator);
    defer allocator.free(caller_indices);
    const provider_indices = try verifier_active[4].preprocessedColumnIndices(allocator);
    defer allocator.free(provider_indices);
    try std.testing.expectEqualSlices(
        usize,
        &.{ expected.caller.is_first_col_idx, expected.caller.is_active_col_idx },
        caller_indices,
    );
    try std.testing.expectEqualSlices(
        usize,
        &.{ expected.provider.is_first_col_idx, expected.provider.is_active_col_idx },
        provider_indices,
    );
}

fn expectBothRejected(
    expected: anyerror,
    fixture: *const Fixture,
    extension: *const guest_statement.ExtensionStatement,
    caller_claim: caller_component.Claim,
    provider_claim: provider_component.Claim,
) !void {
    const no_provers = [_]prover_component.ComponentProver{};
    const no_verifiers = [_]core_air_components.Component{};
    const prover: ?*subject.ProverAssembly = subject.ProverAssembly.create(
        std.testing.allocator,
        &fixture.core,
        extension,
        &fixture.relations,
        &no_provers,
        caller_claim,
        provider_claim,
    ) catch |err| rejected: {
        try std.testing.expectEqual(expected, err);
        break :rejected null;
    };
    if (prover) |value| {
        value.destroy(std.testing.allocator);
        return error.TestExpectedProverAssemblyRejection;
    }
    const verifier: ?*subject.VerifierAssembly = subject.VerifierAssembly.create(
        std.testing.allocator,
        &fixture.core,
        extension,
        &fixture.relations,
        &no_verifiers,
        caller_claim,
        provider_claim,
    ) catch |err| rejected: {
        try std.testing.expectEqual(expected, err);
        break :rejected null;
    };
    if (verifier) |value| {
        value.destroy(std.testing.allocator);
        return error.TestExpectedVerifierAssemblyRejection;
    }
}

test "profile component owner rejects profile registry descriptor and detailed claim tampering" {
    const fixture = try Fixture.init(1);

    var wrong_profile = fixture.extension;
    wrong_profile.profile = .rv32im_zkvm_v1;
    try expectBothRejected(
        error.ProfileMismatch,
        &fixture,
        &wrong_profile,
        fixture.caller_claim,
        fixture.provider_claim,
    );

    var swapped = fixture.extension;
    const first = swapped.components[0];
    swapped.components[0] = swapped.components[1];
    swapped.components[1] = first;
    try expectBothRejected(
        error.ComponentOrderMismatch,
        &fixture,
        &swapped,
        fixture.caller_claim,
        fixture.provider_claim,
    );

    var malformed_descriptor = fixture.extension;
    malformed_descriptor.components[0].main_columns -= 1;
    try expectBothRejected(
        error.ComponentGeometryMismatch,
        &fixture,
        &malformed_descriptor,
        fixture.caller_claim,
        fixture.provider_claim,
    );

    var mismatched_descriptor_claim = fixture.caller_claim;
    mismatched_descriptor_claim.descriptor.n_rows += 1;
    try expectBothRejected(
        error.ClaimDescriptorMismatch,
        &fixture,
        &fixture.extension,
        mismatched_descriptor_claim,
        fixture.provider_claim,
    );

    var mismatched_aggregate = fixture.caller_claim;
    mismatched_aggregate.component_sum = mismatched_aggregate.component_sum.add(QM31.one());
    try expectBothRejected(
        error.ComponentClaimMismatch,
        &fixture,
        &fixture.extension,
        mismatched_aggregate,
        fixture.provider_claim,
    );

    var legacy_provider_claim = fixture.provider_claim;
    legacy_provider_claim.batch_sums[0] = QM31.one();
    legacy_provider_claim.component_sum = QM31.one();
    try expectBothRejected(
        error.NonzeroLegacyBatchClaim,
        &fixture,
        &fixture.extension,
        fixture.caller_claim,
        legacy_provider_claim,
    );
}

test "profile component owner admits exact base handle capacity and rejects one more before allocation" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(1);
    var seed: [3]caller_component.CallerComponent = undefined;
    try seedBaseComponents(&fixture, &seed);
    const prover_handle = seed[0].asProverComponent();
    const verifier_handle = seed[0].asVerifierComponent();
    const over_capacity = proof_workspace.MAX_COMPONENT_HANDLES + 1;
    const base_provers = try allocator.alloc(prover_component.ComponentProver, over_capacity);
    defer allocator.free(base_provers);
    @memset(base_provers, prover_handle);
    const base_verifiers = try allocator.alloc(core_air_components.Component, over_capacity);
    defer allocator.free(base_verifiers);
    @memset(base_verifiers, verifier_handle);

    const prover = try subject.ProverAssembly.create(
        allocator,
        &fixture.core,
        &fixture.extension,
        &fixture.relations,
        base_provers[0..proof_workspace.MAX_COMPONENT_HANDLES],
        fixture.caller_claim,
        fixture.provider_claim,
    );
    defer prover.destroy(allocator);
    const verifier = try subject.VerifierAssembly.create(
        allocator,
        &fixture.core,
        &fixture.extension,
        &fixture.relations,
        base_verifiers[0..proof_workspace.MAX_COMPONENT_HANDLES],
        fixture.caller_claim,
        fixture.provider_claim,
    );
    defer verifier.destroy(allocator);
    try std.testing.expectEqual(subject.max_component_handles, prover.active().len);
    try std.testing.expectEqual(subject.max_component_handles, verifier.active().len);
    try expectContext(
        &prover.caller,
        prover.active()[proof_workspace.MAX_COMPONENT_HANDLES].ctx,
    );
    try expectContext(
        &verifier.provider,
        verifier.active()[proof_workspace.MAX_COMPONENT_HANDLES + 1].ctx,
    );

    var fail_before_allocation = std.testing.FailingAllocator.init(allocator, .{});
    fail_before_allocation.fail_index = 0;
    try std.testing.expectError(
        error.TooManyComponentHandles,
        subject.ProverAssembly.create(
            fail_before_allocation.allocator(),
            &fixture.core,
            &fixture.extension,
            &fixture.relations,
            base_provers,
            fixture.caller_claim,
            fixture.provider_claim,
        ),
    );
    try std.testing.expectError(
        error.TooManyComponentHandles,
        subject.VerifierAssembly.create(
            fail_before_allocation.allocator(),
            &fixture.core,
            &fixture.extension,
            &fixture.relations,
            base_verifiers,
            fixture.caller_claim,
            fixture.provider_claim,
        ),
    );
    try std.testing.expectEqual(@as(usize, 0), fail_before_allocation.alloc_index);
    try std.testing.expect(!fail_before_allocation.has_induced_failure);
}

fn exerciseProverAllocation(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    seed: *const caller_component.CallerComponent,
) !void {
    const base = [_]prover_component.ComponentProver{seed.asProverComponent()};
    const assembly = try subject.ProverAssembly.create(
        allocator,
        &fixture.core,
        &fixture.extension,
        &fixture.relations,
        &base,
        fixture.caller_claim,
        fixture.provider_claim,
    );
    assembly.destroy(allocator);
}

fn exerciseVerifierAllocation(
    allocator: std.mem.Allocator,
    fixture: *const Fixture,
    seed: *const caller_component.CallerComponent,
) !void {
    const base = [_]core_air_components.Component{seed.asVerifierComponent()};
    const assembly = try subject.VerifierAssembly.create(
        allocator,
        &fixture.core,
        &fixture.extension,
        &fixture.relations,
        &base,
        fixture.caller_claim,
        fixture.provider_claim,
    );
    assembly.destroy(allocator);
}

test "profile component owner rolls back every coordinator allocation failure" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(1);
    var seeds: [3]caller_component.CallerComponent = undefined;
    try seedBaseComponents(&fixture, &seeds);

    var prover_counter = std.testing.FailingAllocator.init(allocator, .{});
    try exerciseProverAllocation(prover_counter.allocator(), &fixture, &seeds[0]);
    try std.testing.expectEqual(@as(usize, 1), prover_counter.alloc_index);
    var verifier_counter = std.testing.FailingAllocator.init(allocator, .{});
    try exerciseVerifierAllocation(verifier_counter.allocator(), &fixture, &seeds[0]);
    try std.testing.expectEqual(@as(usize, 1), verifier_counter.alloc_index);

    try std.testing.checkAllAllocationFailures(
        allocator,
        exerciseProverAllocation,
        .{ &fixture, &seeds[0] },
    );
    try std.testing.checkAllAllocationFailures(
        allocator,
        exerciseVerifierAllocation,
        .{ &fixture, &seeds[0] },
    );
}

test "profile component fat pointers borrow heap assembly values for its exact lifetime" {
    const allocator = std.testing.allocator;
    const fixture = try Fixture.init(1);
    const no_provers = [_]prover_component.ComponentProver{};
    const no_verifiers = [_]core_air_components.Component{};

    var prover = try subject.ProverAssembly.create(
        allocator,
        &fixture.core,
        &fixture.extension,
        &fixture.relations,
        &no_provers,
        fixture.caller_claim,
        fixture.provider_claim,
    );
    var prover_active = prover.active();
    try expectContext(&prover.handles[0], prover_active.ptr);
    try expectContext(&prover.caller, prover_active[0].ctx);
    try expectContext(&prover.provider, prover_active[1].ctx);
    try expectInside(subject.ProverAssembly, prover, prover_active[0].ctx);
    try expectInside(subject.ProverAssembly, prover, prover_active[1].ctx);
    try std.testing.expectEqual(caller_component.constraint_count, prover_active[0].nConstraints());
    try std.testing.expectEqual(provider_component.constraint_count, prover_active[1].nConstraints());
    prover_active = undefined;
    prover.destroy(allocator);
    prover = undefined;

    var verifier = try subject.VerifierAssembly.create(
        allocator,
        &fixture.core,
        &fixture.extension,
        &fixture.relations,
        &no_verifiers,
        fixture.caller_claim,
        fixture.provider_claim,
    );
    var verifier_active = verifier.active();
    try expectContext(&verifier.handles[0], verifier_active.ptr);
    try expectContext(&verifier.caller, verifier_active[0].ctx);
    try expectContext(&verifier.provider, verifier_active[1].ctx);
    try expectInside(subject.VerifierAssembly, verifier, verifier_active[0].ctx);
    try expectInside(subject.VerifierAssembly, verifier, verifier_active[1].ctx);
    try std.testing.expectEqual(caller_component.constraint_count, verifier_active[0].nConstraints());
    try std.testing.expectEqual(provider_component.constraint_count, verifier_active[1].nConstraints());
    verifier_active = undefined;
    verifier.destroy(allocator);
    verifier = undefined;
}
