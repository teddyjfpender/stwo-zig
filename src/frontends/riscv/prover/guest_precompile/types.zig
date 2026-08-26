//! Fixed-capacity ownership types for the Poseidon2 proof profile.
//!
//! The detailed interaction claim is boxed because the unchanged base claim
//! carries protocol-capacity arrays.  Its allocation count is independent of
//! the witness: orchestration performs exactly one allocation for the box and
//! every nested claim remains inline.

const std = @import("std");
const QM31 = @import("stwo_core").fields.qm31.QM31;
const caller_component = @import("../../air/guest_precompile/caller_component.zig");
const component_registry = @import("../../air/guest_precompile/component_registry.zig");
const artifact_identity = @import("../../air/guest_precompile/artifact_identity.zig");
const provider_component = @import("../../air/guest_precompile/provider_component.zig");
const guest_statement = @import("../../air/guest_precompile/statement.zig");
const base_statement = @import("../../air/statement.zig");
const base_types = @import("../types.zig");

pub const caller_batch_count = caller_component.batch_count;
pub const provider_batch_count = provider_component.batch_count;
pub const claim_box_allocation_count: usize = 1;

pub const Error = guest_statement.Error || component_registry.Error ||
    caller_component.InitError || provider_component.InitError || error{
    InteractionClaimAlreadyFinalized,
    InteractionClaimNotFinalized,
    BaseClaimCountMismatch,
    UnbalancedGuestRelation,
};

const Authorities = struct {
    caller: component_registry.CallerConstruction,
    provider: component_registry.ProviderConstruction,
};

/// Complete recurrence metadata retained beside a profile proof.
///
/// `base` is byte-for-type the existing fixed-capacity claim. The two detailed
/// extension claims own their physical batch sums and their separately
/// validated transcript-visible component aggregates.
pub const InteractionClaim = struct {
    base: base_statement.RiscVInteractionClaim,
    caller: caller_component.Claim,
    provider: provider_component.Claim,
    finalized: bool,

    /// Allocate the sole claim box before Tree 2. `base`, `caller`, and
    /// `provider` are deliberately uninitialized: orchestration passes
    /// `&result.base` directly to interaction generation, which initializes
    /// it in place, then calls `finishCanonical` once. Before generation, the
    /// box may only be used as that output destination or destroyed.
    pub fn initBaseInto(
        allocator: std.mem.Allocator,
        core: *const base_statement.RiscVStatement,
        extension: *const guest_statement.ExtensionStatement,
    ) !*InteractionClaim {
        try extension.validate(core);
        const result = try allocator.create(InteractionClaim);
        result.finalized = false;
        return result;
    }

    /// Authenticate and retain the component-local terminal sums after Tree 2
    /// generation. All fallible work uses small locals, so failure leaves the
    /// box in its initialized, retryable pre-finalization state.
    pub fn finishCanonical(
        self: *InteractionClaim,
        core: *const base_statement.RiscVStatement,
        extension: *const guest_statement.ExtensionStatement,
        caller_sums: *const [caller_batch_count]QM31,
        provider_sums: *const [provider_batch_count]QM31,
    ) Error!void {
        if (self.finalized) return error.InteractionClaimAlreadyFinalized;
        try extension.validate(core);
        try validateBaseCounts(&self.base, core);
        const authorities = try resolveAuthorities(extension);
        const caller = try caller_component.Claim.canonical(
            authorities.caller,
            caller_sums.*,
        );
        const provider = try provider_component.Claim.canonical(
            authorities.provider,
            provider_sums.*,
        );
        try validateGuestCancellation(&caller, &provider);

        self.caller = caller;
        self.provider = provider;
        self.finalized = true;
    }

    pub fn validate(
        self: *const InteractionClaim,
        core: *const base_statement.RiscVStatement,
        extension: *const guest_statement.ExtensionStatement,
    ) Error!void {
        if (!self.finalized) return error.InteractionClaimNotFinalized;
        try extension.validate(core);
        try validateBaseCounts(&self.base, core);
        const authorities = try resolveAuthorities(extension);
        try self.caller.validate(authorities.caller);
        try self.provider.validate(authorities.provider);
        try validateGuestCancellation(&self.caller, &self.provider);
    }

    /// The unchanged base claim is the single source of truth for profile PoW.
    pub fn interactionPow(self: *const InteractionClaim) u64 {
        std.debug.assert(self.finalized);
        return self.base.interaction_pow;
    }

    /// Canonicalize the base claim into caller-owned storage and return the
    /// small profile claim borrowing its base log-size slice from `scratch`.
    /// The scratch object must outlive the returned value.
    pub fn canonicalStatementClaim(
        self: *const InteractionClaim,
        core: *const base_statement.RiscVStatement,
        extension: *const guest_statement.ExtensionStatement,
        scratch: *base_statement.CanonicalInteractionClaim,
    ) !guest_statement.InteractionClaim {
        try self.validate(core, extension);
        try writeCanonicalBase(scratch, &self.base, core);
        return guest_statement.InteractionClaim.init(
            scratch.view(),
            self.caller.component_sum,
            self.provider.component_sum,
            extension,
        );
    }

    pub fn destroy(self: *InteractionClaim, allocator: std.mem.Allocator) void {
        allocator.destroy(self);
    }
};

/// Profile-specific proof envelope. Statements and identities are fixed-size;
/// proof allocations and the one detailed-claim box have explicit ownership.
pub const ProveOutput = struct {
    proof: base_types.Proof,
    statement: base_statement.RiscVStatement,
    extension: guest_statement.ExtensionStatement,
    artifact: artifact_identity.Identity,
    interaction_claim: *InteractionClaim,

    pub fn deinitAfterProofMoved(
        self: *ProveOutput,
        allocator: std.mem.Allocator,
    ) void {
        self.interaction_claim.destroy(allocator);
        self.* = undefined;
    }

    pub fn deinit(self: *ProveOutput, allocator: std.mem.Allocator) void {
        self.proof.deinit(allocator);
        self.interaction_claim.destroy(allocator);
        self.* = undefined;
    }
};

fn validateBaseCounts(
    base: *const base_statement.RiscVInteractionClaim,
    core: *const base_statement.RiscVStatement,
) error{BaseClaimCountMismatch}!void {
    if (base.n_components != core.n_components or base.n_infra != core.n_infra)
        return error.BaseClaimCountMismatch;
}

fn resolveAuthorities(
    extension: *const guest_statement.ExtensionStatement,
) component_registry.Error!Authorities {
    const registry = component_registry.Registry.forProfile(extension.profile);
    const caller = switch (try registry.verifierConstruction(
        extension.components[0],
    )) {
        .caller => |value| value,
        .provider => return error.ConstructionAuthorityMismatch,
    };
    const provider = switch (try registry.verifierConstruction(
        extension.components[1],
    )) {
        .provider => |value| value,
        .caller => return error.ConstructionAuthorityMismatch,
    };
    return .{ .caller = caller, .provider = provider };
}

fn validateGuestCancellation(
    caller: *const caller_component.Claim,
    provider: *const provider_component.Claim,
) error{UnbalancedGuestRelation}!void {
    if (!caller.batch_sums[caller_batch_count - 1]
        .add(provider.batch_sums[provider_batch_count - 1]).isZero())
    {
        return error.UnbalancedGuestRelation;
    }
}

/// Keep the ~124 KiB base canonicalization temporary out of orchestration
/// frames. `scratch` is normally a field of a heap verification workspace.
noinline fn writeCanonicalBase(
    scratch: *base_statement.CanonicalInteractionClaim,
    base: *const base_statement.RiscVInteractionClaim,
    core: *const base_statement.RiscVStatement,
) !void {
    scratch.* = try base.canonical(core);
}

comptime {
    if (caller_batch_count != 77 or provider_batch_count != 2 or
        component_registry.extension_component_count != 2)
    {
        @compileError("guest proof-output claim geometry drifted");
    }
}
