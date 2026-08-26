//! Ownership tests for Poseidon2 profile proof finalization.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_api = @import("stwo_prover_api");
const guest_relations = @import("../../air/guest_precompile/relation_challenges.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const support = @import("../../air/guest_precompile/main_trace_test_support.zig");
const proof_workspace = @import("../proof_workspace.zig");
const base_types = @import("../types.zig");
const profile_types = @import("types.zig");
const subject = @import("proof_finalize.zig");

const SchemeState = struct {
    live: bool = true,
    deinit_calls: usize = 0,
    prove_calls: usize = 0,
    prove_consumptions: usize = 0,
};

const FakeAux = struct {
    pub fn deinit(_: *FakeAux, _: std.mem.Allocator) void {}
};

const FakeEngine = struct {
    pub const Channel = struct {};
    pub const Scheme = struct { state: *SchemeState };
    pub const ExtendedProof = struct {
        proof: base_types.Proof,
        aux: FakeAux,
    };

    pub fn deinit(scheme: *Scheme, _: std.mem.Allocator) void {
        std.debug.assert(scheme.state.live);
        scheme.state.live = false;
        scheme.state.deinit_calls += 1;
        scheme.* = undefined;
    }

    pub fn prove(
        _: std.mem.Allocator,
        _: []const prover_component.ComponentProver,
        _: *Channel,
        scheme: Scheme,
        _: prover_api.ProveOptions,
    ) !ExtendedProof {
        std.debug.assert(scheme.state.live);
        scheme.state.live = false;
        scheme.state.prove_calls += 1;
        scheme.state.prove_consumptions += 1;
        return error.InjectedProveFailure;
    }
};

const Fixture = struct {
    workspace: *proof_workspace.ProofWorkspace,
    extension: guest_statement.ExtensionStatement,
    relations: guest_relations.Poseidon2V1Relations,
    claim: *profile_types.InteractionClaim,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const workspace = try proof_workspace.ProofWorkspace.create(allocator);
        errdefer workspace.destroy(allocator);
        workspace.statement = support.coreFixture(1);
        const extension = try guest_statement.ExtensionStatement.canonical(
            &workspace.statement,
            1,
        );

        const claim = try profile_types.InteractionClaim.initBaseInto(
            allocator,
            &workspace.statement,
            &extension,
        );
        errdefer claim.destroy(allocator);
        claim.base.initZeroInto();
        claim.base.n_components = workspace.statement.n_components;
        claim.base.n_infra = workspace.statement.n_infra;
        const caller_sums = [_]QM31{QM31.zero()} ** profile_types.caller_batch_count;
        const provider_sums = [_]QM31{QM31.zero()} ** profile_types.provider_batch_count;
        try claim.finishCanonical(
            &workspace.statement,
            &extension,
            &caller_sums,
            &provider_sums,
        );
        return .{
            .workspace = workspace,
            .extension = extension,
            .relations = .dummy(),
            .claim = claim,
        };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        self.claim.destroy(allocator);
        self.workspace.destroy(allocator);
        self.* = undefined;
    }

    fn prove(self: *Fixture, allocator: std.mem.Allocator, state: *SchemeState) !base_types.Proof {
        var channel = FakeEngine.Channel{};
        return subject.prove(
            FakeEngine,
            allocator,
            null,
            .{ .state = state },
            &channel,
            self.workspace,
            &self.extension,
            &self.relations,
            &self.claim.base,
            self.claim.caller,
            self.claim.provider,
        );
    }
};

test "profile finalizer deinitializes once when base claim validation fails" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
    fixture.claim.base.n_components = 0;
    var state = SchemeState{};

    try std.testing.expectError(
        error.InvalidInteractionClaim,
        fixture.prove(allocator, &state),
    );
    try expectPreTransferCleanup(&state);
}

test "profile finalizer deinitializes once when assembly allocation fails" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
    var state = SchemeState{};
    var failing = std.testing.FailingAllocator.init(
        allocator,
        .{ .fail_index = 0 },
    );

    try std.testing.expectError(
        error.OutOfMemory,
        fixture.prove(failing.allocator(), &state),
    );
    try std.testing.expect(failing.has_induced_failure);
    try expectPreTransferCleanup(&state);
}

test "profile finalizer cleans allocated assembly after component validation fails" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
    fixture.claim.caller.component_sum = QM31.one();
    var state = SchemeState{};

    try std.testing.expectError(
        error.ComponentClaimMismatch,
        fixture.prove(allocator, &state),
    );
    try expectPreTransferCleanup(&state);
}

test "profile finalizer transfers once before an engine failure" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
    var state = SchemeState{};

    try std.testing.expectError(
        error.InjectedProveFailure,
        fixture.prove(allocator, &state),
    );
    try std.testing.expect(!state.live);
    try std.testing.expectEqual(@as(usize, 0), state.deinit_calls);
    try std.testing.expectEqual(@as(usize, 1), state.prove_calls);
    try std.testing.expectEqual(@as(usize, 1), state.prove_consumptions);
}

fn expectPreTransferCleanup(state: *const SchemeState) !void {
    try std.testing.expect(!state.live);
    try std.testing.expectEqual(@as(usize, 1), state.deinit_calls);
    try std.testing.expectEqual(@as(usize, 0), state.prove_calls);
    try std.testing.expectEqual(@as(usize, 0), state.prove_consumptions);
}
