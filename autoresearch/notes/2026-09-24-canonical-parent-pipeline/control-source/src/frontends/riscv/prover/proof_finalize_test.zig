//! Ownership tests for the base RISC-V proof-finalization boundary.

const std = @import("std");
const prover_component = @import("stwo_prover_engine").air.component_prover;
const prover_api = @import("stwo_prover_api");
const relation_challenges = @import("../air/relation_challenges.zig");
const support = @import("../air/guest_precompile/main_trace_test_support.zig");
const proof_workspace = @import("proof_workspace.zig");
const types = @import("types.zig");
const subject = @import("proof_finalize.zig");

const Failure = enum { injected, out_of_memory };

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
        proof: types.Proof,
        aux: FakeAux,
    };

    var failure: Failure = .injected;

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
        return switch (failure) {
            .injected => error.InjectedProveFailure,
            .out_of_memory => error.OutOfMemory,
        };
    }
};

const Fixture = struct {
    workspace: *proof_workspace.ProofWorkspace,
    claim: *types.RiscVInteractionClaim,
    relations: relation_challenges.Relations,

    fn init(allocator: std.mem.Allocator) !Fixture {
        const workspace = try proof_workspace.ProofWorkspace.create(allocator);
        errdefer workspace.destroy(allocator);
        workspace.statement = support.coreFixture(1);

        const claim = try allocator.create(types.RiscVInteractionClaim);
        errdefer allocator.destroy(claim);
        claim.initZeroInto();
        claim.n_components = workspace.statement.n_components;
        claim.n_infra = workspace.statement.n_infra;
        return .{
            .workspace = workspace,
            .claim = claim,
            .relations = .dummy(),
        };
    }

    fn deinit(self: *Fixture, allocator: std.mem.Allocator) void {
        allocator.destroy(self.claim);
        self.workspace.destroy(allocator);
        self.* = undefined;
    }

    fn prove(self: *Fixture, allocator: std.mem.Allocator, state: *SchemeState) !types.Proof {
        var channel = FakeEngine.Channel{};
        return subject.prove(
            FakeEngine,
            allocator,
            null,
            .{ .state = state },
            &channel,
            self.workspace,
            &self.relations,
            self.claim,
            self.workspace.statement.nMainColumns(),
            self.workspace.statement.nInteractionColumns(),
        );
    }
};

test "base finalizer deinitializes its scheme once when claim assembly fails" {
    const allocator = std.testing.allocator;
    var fixture = try Fixture.init(allocator);
    defer fixture.deinit(allocator);
    fixture.claim.n_components = 0;
    var state = SchemeState{};

    try std.testing.expectError(
        error.InvalidInteractionClaim,
        fixture.prove(allocator, &state),
    );
    try expectPreTransferCleanup(&state);
}

test "base finalizer transfers once before injected and OOM engine failures" {
    inline for (.{
        .{ Failure.injected, error.InjectedProveFailure },
        .{ Failure.out_of_memory, error.OutOfMemory },
    }) |case| {
        const allocator = std.testing.allocator;
        var fixture = try Fixture.init(allocator);
        defer fixture.deinit(allocator);
        var state = SchemeState{};
        FakeEngine.failure = case[0];

        try std.testing.expectError(case[1], fixture.prove(allocator, &state));
        try std.testing.expect(!state.live);
        try std.testing.expectEqual(@as(usize, 0), state.deinit_calls);
        try std.testing.expectEqual(@as(usize, 1), state.prove_calls);
        try std.testing.expectEqual(@as(usize, 1), state.prove_consumptions);
    }
}

fn expectPreTransferCleanup(state: *const SchemeState) !void {
    try std.testing.expect(!state.live);
    try std.testing.expectEqual(@as(usize, 1), state.deinit_calls);
    try std.testing.expectEqual(@as(usize, 0), state.prove_calls);
    try std.testing.expectEqual(@as(usize, 0), state.prove_consumptions);
}
